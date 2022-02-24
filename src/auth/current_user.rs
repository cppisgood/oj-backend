use axum::response::IntoResponse;
use axum_csrf::CsrfToken;

use crate::utils;

use super::LoggedUser;

pub async fn current_user_handler(_token: CsrfToken, user: LoggedUser) -> impl IntoResponse {
    return utils::gen_response(0, &user.username);
}
