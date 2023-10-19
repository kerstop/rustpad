mod authentication;
mod templates;

use core::panic;

use anyhow::anyhow;
use authentication::User;
use axum::{
    http::StatusCode,
    http::{header, HeaderMap},
    response::{Html, IntoResponse},
    routing::{get, post},
    Form, Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Scrypt,
};
use serde::{Deserialize, Serialize};
use templates::TodoPage;
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

static DB_CONN: Lazy<sqlx::PgPool> = Lazy::new(|| {
    let db_connection_string = std::env::var("DATABASE_URL")
        .expect("env variable `DATABASE_URL` should describe where the db is located");

    match sqlx::PgPool::connect_lazy(&db_connection_string) {
        Ok(pool) => pool,
        Err(e) => panic!("{e}"),
    }
});

static JWT_SECRET: once_cell::sync::Lazy<(EncodingKey, DecodingKey)> = Lazy::new(|| {
    use rand::Rng;
    let secret: [u8; 1024] = {
        let mut tmp: [u8; 1024] = [0; 1024];
        rand::rngs::OsRng.fill(&mut tmp);
        tmp
    };
    (
        EncodingKey::from_secret(&secret),
        DecodingKey::from_secret(&secret),
    )
});

struct RustpadError(anyhow::Error);

impl<T> From<T> for RustpadError
where
    T: std::error::Error,
{
    fn from(value: T) -> Self {
        RustpadError(anyhow!(value.to_string()))
    }
}

#[derive(Serialize)]
struct TodoItem {
    id: i64,
    item_description: String,
    is_complete: bool,
    owner_id: i64,
}

#[tokio::main]
async fn main() {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let middleware = tower::ServiceBuilder::new().layer(TraceLayer::new_for_http());

    let app = Router::new()
        //.nest("/", axum_static::static_router("static"))
        .route_service("/", ServeFile::new("static/index.html"))
        .route("/todo", get(get_todo_page))
        .route_service("/login", ServeFile::new("static/login.html"))
        .nest_service("/static", ServeDir::new("static"))
        .route(
            "/api/todo",
            post(todo_post_handler)
                .get(todo_get_handler)
                .delete(todo_delete_handler),
        )
        .route("/api/login", post(login_post_handler))
        .route("/api/createUser", post(create_user_post_handler))
        .layer(middleware);

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Deserialize)]
struct CreateTodoRequest {
    description: String,
}

async fn todo_post_handler(user: User, form: Form<CreateTodoRequest>) -> Result<Html<String>, RustpadError> {
    let todo_item = sqlx::query_as!(
        TodoItem,
        "INSERT INTO todo_items (item_description, owner_id) VALUES ($1, $2) RETURNING *;",
        form.description, user.id
    )
    .fetch_one(&*DB_CONN)
    .await?;

    Ok(Html(templates::TodoItems::new(vec![todo_item]).to_string()))
}

async fn todo_get_handler(user: User) -> Result<Html<String>, RustpadError> {
    let todo_items = sqlx::query_as!(
        TodoItem,
        "SELECT id, item_description, is_complete, owner_id FROM todo_items WHERE owner_id = $1;", user.id
    )
    .fetch_all(&*DB_CONN)
    .await?;

    Ok(Html(templates::TodoItems::new(todo_items).to_string()))
}

#[derive(Deserialize)]
struct TodoDeleteRequest {
    pub id: i32,
}

async fn todo_delete_handler(user: User, request: axum::extract::Query<TodoDeleteRequest>) -> StatusCode {
    match sqlx::query!("DELETE FROM todo_items WHERE id=$1 AND owner_id = $2", request.id, user.id)
        .execute(&*DB_CONN)
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn login_post_handler(login_request: Form<LoginRequest>) -> impl IntoResponse {
    use jsonwebtoken::{encode, Algorithm, Header};
    let mut header_map = HeaderMap::new();

    let password_hash: String = match sqlx::query!(
        "SELECT password_hash FROM users WHERE username = $1",
        login_request.username
    )
    .fetch_one(&*DB_CONN)
    .await
    {
        Ok(h) => h.password_hash,
        Err(_e) => {
            return (
                header_map,
                Html(
                    templates::ErrorMessage {
                        message: "Incorrect username or password",
                    }
                    .to_string(),
                ),
            );
        }
    };

    let parsed_hash = PasswordHash::new(&password_hash).expect(&format!(
        "There is a malformated password for user {0}",
        login_request.username
    ));

    match Scrypt.verify_password(login_request.password.as_bytes(), &parsed_hash) {
        Ok(()) => {
            let token = encode(
                &Header::new(Algorithm::HS512),
                &JwtClaims {
                    username: login_request.username.clone(),
                    exp: (chrono::offset::Utc::now() + std::time::Duration::from_secs(86400)).timestamp()
                },
                &JWT_SECRET.0,
            )
            .expect("JWT token creation to succeed");
            let cookie_value = format!("login_token={}; Secure; HttpOnly; Path=/", token)
                .parse()
                .unwrap();
            header_map.append(header::SET_COOKIE, cookie_value);
            header_map.append("HX-Redirect", "/todo".parse().unwrap());
            return (header_map, Html("".into()));
        }
        Err(_) => {
            return (
                header_map,
                Html(
                    templates::ErrorMessage {
                        message: "Incorrect username or password",
                    }
                    .to_string(),
                ),
            )
        }
    }
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    username: String,
    exp: i64,
}

async fn create_user_post_handler(
    create_user_request: Form<CreateUserRequest>,
) -> impl IntoResponse {
    use jsonwebtoken::{encode, Algorithm, Header};

    let salt = SaltString::generate(&mut OsRng);

    let hash = Scrypt
        .hash_password(create_user_request.password.as_bytes(), &salt)
        .expect("The hash to work")
        .to_string();

    sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2);",
        create_user_request.username,
        hash
    )
    .execute(&*DB_CONN)
    .await
    .unwrap();

    let token = encode(
        &Header::new(Algorithm::HS512),
        &JwtClaims {
            username: create_user_request.username.clone(),
            exp: (chrono::offset::Utc::now() + std::time::Duration::from_secs(86400)).timestamp()
        },
        &JWT_SECRET.0,
    )
    .expect("JWT token creation to succeed");

    let mut header_map = HeaderMap::new();

    let cookie = format!("login_token={}; Secure; HttpOnly; Path=/", token);

    header_map.append(header::SET_COOKIE, cookie.parse().unwrap());
    header_map.append("HX-Redirect", "/todo".parse().unwrap());

    header_map
}

impl IntoResponse for RustpadError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

async fn get_todo_page(user: User) -> impl IntoResponse {
    TodoPage {
        username: user.username,
    }
    .into_response()
}
