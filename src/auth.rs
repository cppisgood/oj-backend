use crate::{logged_user::LoggedUser, utils};
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing, Router,
};
use axum_csrf::CsrfToken;
use bson::{doc, Document};
use chrono::{Duration, Local};
use config::Config;
use cookie::Cookie;
use mongodb::Database;
use serde::Deserialize;
use serde_json::json;
use tower_cookies::Cookies;
use tracing::debug;

#[derive(Deserialize, Debug)]
pub struct LoginUser {
    username: String,
    password: String,
    remember_me: Option<bool>,
}

pub async fn login_handler(
    _token: CsrfToken,
    Json(user): Json<LoginUser>,
    cookies: Cookies,
    Extension(config): Extension<Config>,
    Extension(mongo): Extension<Database>,
    Extension(session_store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    let data = mongo
        .collection::<Document>("users")
        .find_one(
            doc! {
                "username": &user.username,
            },
            None,
        )
        .await
        .unwrap();

    match data {
        Some(data) => {
            let password_hash = data.get_str("password").unwrap();

            if utils::verify_password(&user.password, &password_hash) {
                let ttl = if user.remember_me.eq(&Some(true)) {
                    Duration::days(config.get_int("session_long_ttl").unwrap_or(30))
                } else {
                    Duration::hours(config.get_int("session_ttl").unwrap_or(24))
                }
                .to_std()
                .unwrap();

                let session = utils::gen_session(&[("username", &user.username)], ttl);
                debug!("{}", user.username);

                let cookie =
                    utils::sotre_session_and_gen_cookie(session_store.clone(), session, ttl).await;
                cookies.add(cookie);
                let _ = async {
                    debug!("{:?} {:?}", user, session_store.count().await);
                };

                (
                    StatusCode::OK,
                    utils::gen_response(
                        0,
                        json!({
                            "username": user.username,
                            "expire_time": (Local::now() + Duration::from_std(ttl).unwrap()).timestamp()
                        }),
                    ),
                )
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    utils::gen_response(2, "wrong password"),
                )
            }
        }
        None => (
            StatusCode::UNAUTHORIZED,
            utils::gen_response(1, "no such user"),
        ),
    }
}

pub async fn logout_handler(
    _token: CsrfToken,
    cookies: Cookies,
    user: LoggedUser,
    Extension(store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    cookies.remove(Cookie::build("session_id", "").path("/").finish());
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

pub fn get_router() -> Router {
    Router::new()
        .route("/login", routing::post(login_handler))
        .route("/logout", routing::delete(logout_handler))
        .route("/current", routing::get(current_user_handler))
}

pub async fn current_user_handler(_token: CsrfToken, user: LoggedUser) -> impl IntoResponse {
    return utils::gen_response(0, &user.username);
}
