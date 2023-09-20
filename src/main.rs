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

impl axum::response::IntoResponse for RustpadError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() {
    let db_connection_string = std::env::var("DATABASE_URL")
        .expect("env variable `DATABASE_URL` should describe where the db is located");

    DB_CONN
        .set(match sqlx::PgPool::connect(&db_connection_string).await {
            Ok(pool) => pool,
            Err(e) => panic!("{e}"),
        })
        .unwrap();

    let app = Router::new()
        .route("/", get(index))
        .nest("/static", axum_static::static_router("static"))
        .route("/todo", post(todo_post_handler).get(todo_get_handler));

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
    .fetch_one(DB_CONN.get().unwrap()).await?;

    Ok(Html(templates::TodoItems(vec![todo_item]).to_string()))
}

async fn todo_get_handler() -> Result<Html<String>, RustpadError> {
    let todo_items = sqlx::query_as!(TodoItem, "SELECT * FROM todo_items;")
        .fetch_all(DB_CONN.get().unwrap())
        .await?;

    Ok(Html(templates::TodoItems(todo_items).to_string()))
}
