pub mod register;

use axum::{routing, Router};

pub fn get_router() -> Router {
    Router::new()
        .route("/captcha", routing::get(register::captcha_handler))
        .route("/", routing::post(register::register_handler))
}
