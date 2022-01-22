use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts, TypedHeader},
    headers::Cookie,
    http::StatusCode,
};
use serde::Deserialize;

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
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<RedisSessionStore>::from_request(req)
            .await
            .expect("`MemoryStore` extension missing");

        let cookie = Option::<TypedHeader<Cookie>>::from_request(req)
            .await
            .unwrap();

        let session_id = cookie.as_ref().and_then(|cookie| cookie.get("session_id"));
        match session_id {
            Some(session_id) => match store.load_session(session_id.to_string()).await.unwrap() {
                Some(session) => {
                    let username = session.get::<String>("username").unwrap();
                    Ok(Self {
                        username,
                        session_id: session_id.to_string(),
                    })
                }
                None => Err((StatusCode::UNAUTHORIZED, "login required")),
            },
            None => Err((StatusCode::UNAUTHORIZED, "login required")),
        }
    }
}
