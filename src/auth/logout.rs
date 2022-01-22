use super::LoggedUser;
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{extract::Extension, http::StatusCode, response::IntoResponse};
use axum_csrf::CsrfToken;

pub async fn logout_handler(
    _token: CsrfToken,
    user: LoggedUser,
    Extension(store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    if let Some(mut session) = store.load_session(user.session_id).await.unwrap() {
        session.destroy();
        (StatusCode::OK, "bye")
    } else {
        (StatusCode::UNAUTHORIZED, "not logged yet")
    }
}
