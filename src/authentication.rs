use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    RequestPartsExt,
};

use axum_extra::extract::CookieJar;
use jsonwebtoken::{decode, Algorithm, Validation};
use serde::Deserialize;

use super::DB_CONN;
use super::JWT_SECRET;

#[derive(Deserialize)]
pub struct User {
    pub id: i32,
    pub username: String,
}

impl<S> FromRequestParts<S> for User {
    type Rejection = StatusCode;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        _state: &'life1 S,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = Result<Self, Self::Rejection>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {
            let cookies = parts.extract::<CookieJar>().await.unwrap();

            let token = match cookies.get("login_token") {
                Some(t) => t,
                None => return Err(StatusCode::UNAUTHORIZED),
            };

            let username = match decode::<super::JwtClaims>(
                token.value(),
                &JWT_SECRET.1,
                &Validation::new(Algorithm::HS512),
            ) {
                Ok(data) => data.claims.username,
                Err(_e) => {
                    return Err(StatusCode::UNAUTHORIZED);
                }
            };

            let user = match sqlx::query_as!(
                User,
                "SELECT id, username FROM users WHERE username = $1;",
                username
            )
            .fetch_one(&*DB_CONN)
            .await
            {
                Ok(u) => u,
                Err(_) => return Err(StatusCode::UNAUTHORIZED),
            };

            return Ok(user);
        })
    }
}
