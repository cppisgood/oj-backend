use super::LoggedUser;
use crate::utils;
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{extract::Extension, http::StatusCode, response::IntoResponse};
use axum_csrf::CsrfToken;

pub async fn logout_handler(
    _token: CsrfToken,
    user: LoggedUser,
    Extension(store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    if let Some(session) = store.load_session(user.session_id).await.unwrap() {
        store.destroy_session(session).await.unwrap();
        (StatusCode::OK, utils::gen_response(0, "bye"))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            utils::gen_response(1, "not logged yet"),
        )
    }
}
