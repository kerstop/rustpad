mod api;
mod authentication;
mod error;
mod templates;

use core::panic;

use anyhow::anyhow;
use authentication::User;
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
    Form, Router,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use once_cell::sync::Lazy;
use scrypt::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Scrypt,
};
use serde::{Deserialize, Serialize};
use templates::TodoPage;
use tower_http::{services::ServeDir, trace::TraceLayer};
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

#[tokio::main]
async fn main() {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let middleware = tower::ServiceBuilder::new().layer(TraceLayer::new_for_http());

    let app = Router::new()
        //.nest("/", axum_static::static_router("static"))
        .route("/", get(index_get_handler))
        .route("/todo", get(get_todo_page))
        .route(
            "/login",
            get(|| async { templates::LoginPage {}.into_response() }),
        )
        .nest_service("/static", ServeDir::new("static"))
        .route(
            "/api/todo",
            post(api::todo::post_handler).get(api::todo::get_handler),
        )
        .route(
            "/api/todo/:id",
            delete(api::todo::delete_handler).patch(api::todo::patch_handler),
        )
        .route("/api/login", post(api::auth::post_handler))
        .route("/api/createUser", post(create_user_post_handler))
        .layer(middleware);

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
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

async fn index_get_handler(_user: authentication::User) -> impl IntoResponse {
    Redirect::to("/todo")
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
            exp: (chrono::offset::Utc::now() + std::time::Duration::from_secs(86400)).timestamp(),
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
