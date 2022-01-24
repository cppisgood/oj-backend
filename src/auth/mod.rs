use crate::utils;
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts},
    http::StatusCode,
    Json, Router, routing::{post, delete},
};
use serde::Deserialize;
use serde_json::Value;
use tower_cookies::Cookies;

pub mod login;
pub mod logout;

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
pub struct LoggedUser {
    username: String,
    session_id: String,
}

#[async_trait]
impl<B> FromRequest<B> for LoggedUser
where
    B: Send,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<RedisSessionStore>::from_request(req)
            .await
            .expect("`RedisSessionStore` extension missing");

        let cookie = Cookies::from_request(req).await.unwrap();

        let session_id = cookie.get("session_id");
        match session_id {
            Some(session_id) => match store
                .load_session(session_id.value().to_string())
                .await
                .unwrap()
            {
                Some(session) => {
                    let username: String = session.get("username").unwrap();
                    Ok(Self {
                        username,
                        session_id: session_id.value().to_string(),
                    })
                }
                None => Err((
                    StatusCode::UNAUTHORIZED,
                    utils::gen_response(1, "login required"),
                )),
            },
            None => Err((
                StatusCode::UNAUTHORIZED,
                utils::gen_response(1, "login required"),
            )),
        }
    }
}


pub fn get_router() -> Router {
    Router::new()
        .route("/login", post(login::login_handler))
        .route("/logout", delete(logout::logout_handler))
}