mod authentication;
mod templates;

use core::panic;

use anyhow::anyhow;
use axum::{
    http::{header, HeaderMap},
    http::StatusCode,
    response::{ Html, IntoResponse},
    routing::{get, post},
    Form, Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Scrypt,
};
use serde::{Deserialize, Serialize};
use tower_http::{trace::TraceLayer, services::{ServeFile, ServeDir}};
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
        .nest_service("/static", ServeDir::new("static"))
        .route(
            "/todo",
            post(todo_post_handler)
                .get(todo_get_handler)
                .delete(todo_delete_handler),
        )
        .route("/login", post(login_post_handler))
        .route("/createUser", post(create_user_post_handler))
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

async fn todo_post_handler(form: Form<CreateTodoRequest>) -> Result<Html<String>, RustpadError> {
    let todo_item = sqlx::query_as!(
        TodoItem,
        "INSERT INTO todo_items (item_description) VALUES ($1) RETURNING *;",
        form.description
    )
    .fetch_one(&*DB_CONN)
    .await?;

    Ok(Html(templates::TodoItems::new(vec![todo_item]).to_string()))
}

async fn todo_get_handler() -> Result<Html<String>, RustpadError> {
    let todo_items = sqlx::query_as!(
        TodoItem,
        "SELECT id, item_description, is_complete, owner_id FROM todo_items;"
    )
    .fetch_all(&*DB_CONN)
    .await?;

    Ok(Html(templates::TodoItems::new(todo_items).to_string()))
}

#[derive(Deserialize)]
struct TodoDeleteRequest {
    pub id: i32,
}

async fn todo_delete_handler(request: axum::extract::Query<TodoDeleteRequest>) -> StatusCode {
    match sqlx::query!("DELETE FROM todo_items WHERE id=$1", request.id)
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
    let cookie = format!("login_token={}; Secure; HttpOnly", "not_set");

    let mut header_map = HeaderMap::new();

    let salt = SaltString::generate(&mut OsRng);

    let hash = Scrypt
        .hash_password(login_request.password.as_bytes(), &salt)
        .expect("the hash to work");

    let challenge_hash: String = match sqlx::query!( "SELECT password_hash FROM users WHERE username = $1", login_request.username).fetch_one(&*DB_CONN).await {
        Ok(h) => h.password_hash,
        Err(_e) => {
            return (header_map, Html(templates::ErrorMessage{message: "Incorrect username or password"}.to_string()));
        }
    };

    if hash.to_string() == challenge_hash {
        let cookie_value = format!("login_token={}; Secure; HttpOnly", "not_set").parse().unwrap();
        header_map.append(header::SET_COOKIE, cookie_value);
        return (header_map, Html("".into()))
    }

    return (header_map, Html(templates::ErrorMessage{message: "Incorrect username or password"}.to_string()));

}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct JwtClaims {
    username: String,
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

    let q = sqlx::query!(
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
        },
        &JWT_SECRET.0,
    ).expect("JWT token creation to succeed");

    let cookie = format!("login_token={}; Secure; HttpOnly", token);
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
