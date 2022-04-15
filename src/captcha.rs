use async_redis_session::RedisSessionStore;
use axum::{extract::Extension, response::IntoResponse, routing, Router};
use captcha::{filters::Noise, Captcha};
use chrono::Duration;
use tower_cookies::Cookies;
use tracing::debug;

use crate::utils;

fn get_captcha() -> (String, String) {
    let mut captcha = Captcha::new();
    captcha
        .add_chars(4)
        .view(120, 60)
        .apply_filter(Noise::new(0.2));
    (
        captcha.chars().into_iter().collect::<String>(),
        captcha.as_base64().unwrap(),
    )
}

pub async fn captcha_handler(
    cookies: Cookies,
    Extension(store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    let (captcha, base64) = get_captcha();
    let ttl = Duration::hours(1).to_std().unwrap();
    let session = utils::gen_session(&[("captcha", &captcha)], ttl);
    let cookie = utils::sotre_session_and_gen_cookie(store.clone(), session, ttl).await;
    cookies.add(cookie);
    debug!("{}", captcha);

    utils::gen_response(0, base64)
}

pub fn get_router() -> Router {
    Router::new().route("/", routing::post(captcha_handler))
}
