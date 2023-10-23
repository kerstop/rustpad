use axum::http::{header, HeaderMap};
use axum::response::IntoResponse;
use axum::Form;
use scrypt::password_hash::{PasswordHash, PasswordVerifier};
use scrypt::Scrypt;
use serde::Deserialize;

use crate::{DB_CONN, JWT_SECRET};

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn post_handler(login_request: Form<LoginRequest>) -> impl IntoResponse {
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
                crate::error::ErrorMessage {
                    message: "Incorrect username or password",
                }
                .into_response(),
            )
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
                &crate::JwtClaims {
                    username: login_request.username.clone(),
                    exp: (chrono::offset::Utc::now() + std::time::Duration::from_secs(86400))
                        .timestamp(),
                },
                &JWT_SECRET.0,
            )
            .expect("JWT token creation to succeed");
            let cookie_value = format!("login_token={}; Secure; HttpOnly; Path=/", token)
                .parse()
                .unwrap();
            header_map.append(header::SET_COOKIE, cookie_value);
            header_map.append("HX-Redirect", "/todo".parse().unwrap());
            return (header_map, "".into_response());
        }
        Err(_) => {
            return (
                header_map,
                crate::error::ErrorMessage {
                    message: "Incorrect username or password",
                }
                .into_response(),
            )
        }
    }
}
