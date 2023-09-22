mod authentication;
mod templates;

use core::panic;

use anyhow::anyhow;
use axum::{
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Form, Router,
};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

static DB_CONN: OnceCell<sqlx::PgPool> = OnceCell::new();

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
}

#[tokio::main]
async fn main() {
    // tracing_subscriber::fmt::init();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let db_connection_string = std::env::var("DATABASE_URL")
        .expect("env variable `DATABASE_URL` should describe where the db is located");

    DB_CONN
        .set(match sqlx::PgPool::connect(&db_connection_string).await {
            Ok(pool) => pool,
            Err(e) => panic!("{e}"),
        })
        .unwrap();

    let middleware = tower::ServiceBuilder::new().layer(TraceLayer::new_for_http());

    let app = Router::new()
        .route("/", get(index))
        .nest("/static", axum_static::static_router("static"))
        .route(
            "/todo",
            post(todo_post_handler)
                .get(todo_get_handler)
                .delete(todo_delete_handler),
        )
        .layer(middleware);

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn index() -> Html<String> {
    Html(templates::Index.to_string())
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
    .fetch_one(DB_CONN.get().unwrap())
    .await?;

    Ok(Html(templates::TodoItems::new(vec![todo_item]).to_string()))
}

async fn todo_get_handler() -> Result<Html<String>, RustpadError> {
    let todo_items = sqlx::query_as!(TodoItem, "SELECT * FROM todo_items;")
        .fetch_all(DB_CONN.get().unwrap())
        .await?;

    Ok(Html(templates::TodoItems::new(todo_items).to_string()))
}

#[derive(Deserialize)]
struct TodoDeleteRequest {
    pub id: i32,
}

async fn todo_delete_handler(request: axum::extract::Query<TodoDeleteRequest>) -> StatusCode {
    match sqlx::query!("DELETE FROM todo_items WHERE id=$1", request.id)
        .execute(DB_CONN.get().unwrap())
        .await
    {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl axum::response::IntoResponse for RustpadError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}
