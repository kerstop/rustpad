use crate::RustpadError;
use crate::User;
use crate::DB_CONN;

use askama::Template;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::Form;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize)]
pub struct TodoItem {
    pub id: i64,
    pub item_description: String,
    pub is_complete: bool,
    pub owner_id: i64,
}

#[derive(Template)]
#[template(path = "todo_items.html")]
pub struct TodoItems {
    pub todo_items: Vec<TodoItem>,
}

impl TodoItems {
    pub fn new(todo_items: Vec<TodoItem>) -> Self {
        TodoItems { todo_items }
    }
}

#[derive(Deserialize)]
pub struct CreateTodoRequest {
    description: String,
}

pub async fn post_handler(
    user: User,
    form: Form<CreateTodoRequest>,
) -> Result<TodoItems, RustpadError> {
    let todo_item = sqlx::query_as!(
        TodoItem,
        "INSERT INTO todo_items (item_description, owner_id) VALUES ($1, $2) RETURNING *;",
        form.description,
        user.id
    )
    .fetch_one(&*DB_CONN)
    .await?;

    Ok(TodoItems::new(vec![todo_item]))
}

pub async fn get_handler(user: User) -> Result<TodoItems, RustpadError> {
    let todo_items = sqlx::query_as!(
        TodoItem,
        "SELECT id, item_description, is_complete, owner_id FROM todo_items WHERE owner_id = $1;",
        user.id
    )
    .fetch_all(&*DB_CONN)
    .await?;

    Ok(TodoItems::new(todo_items))
}

#[derive(Deserialize)]
pub struct TodoDeleteRequest {
    pub id: i32,
}

pub async fn delete_handler(user: User, request: Path<TodoDeleteRequest>) -> StatusCode {
    match sqlx::query!(
        "DELETE FROM todo_items WHERE id=$1 AND owner_id = $2",
        request.id,
        user.id
    )
    .execute(&*DB_CONN)
    .await
    {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
pub struct TodoPatchRequest {
    is_complete: bool,
}

pub async fn patch_handler(
    user: User,
    Path(todo_id): Path<i32>,
    request: axum::extract::Query<TodoPatchRequest>,
) -> Result<TodoItems, StatusCode> {
    match sqlx::query!("SELECT owner_id FROM todo_items WHERE id = $1", todo_id)
        .fetch_one(&*DB_CONN)
        .await
    {
        Ok(record) => {
            if record.owner_id != user.id {
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Err(_e) => return Err(StatusCode::FORBIDDEN),
    };

    match sqlx::query_as!(
        TodoItem,
        "UPDATE todo_items SET is_complete = $1 WHERE id = $2 RETURNING *;",
        request.is_complete,
        todo_id
    )
    .fetch_one(&*DB_CONN)
    .await
    {
        Ok(item) => Ok(TodoItems { todo_items: vec![item] }),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR)
    }

}
