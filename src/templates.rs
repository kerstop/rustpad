use askama::Template;

use crate::api::todo::TodoItems;




#[derive(Template)]
#[template(path = "todo.html")]
pub struct TodoPage {
    pub username: String,
}