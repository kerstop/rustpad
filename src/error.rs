use askama::Template;


#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorMessage {
    pub message: &'static str,
}