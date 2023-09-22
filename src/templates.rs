use askama::Template;

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index;

#[derive(Template)]
#[template(path = "todo_items.html")]
pub struct TodoItems {
    todo_items: Vec<super::TodoItem>,
}

impl TodoItems {
    pub fn new(todo_items: Vec<super::TodoItem>) -> Self {
        TodoItems { todo_items }
    }
}