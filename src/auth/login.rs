use crate::utils;
use async_redis_session::RedisSessionStore;
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use axum_csrf::CsrfToken;
use bson::{doc, Document};
use chrono::Duration;
use config::Config;
use mongodb::Database;
use serde::Deserialize;
use tower_cookies::Cookies;

#[derive(Deserialize, Debug)]
pub struct LoginUser {
    username: String,
    password: String,
    remember_me: Option<bool>,
}

pub async fn login_handler(
    _token: CsrfToken,
    Json(user): Json<LoginUser>,
    cookie: Cookies,
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
                println!("{}", user.username);

                let session_cookie =
                    utils::sotre_session_and_gen_cookie(session_store.clone(), session, ttl).await;
                cookie.add(session_cookie);
                println!("{:?} {:?}", user, session_store.count().await);

                (StatusCode::OK, utils::gen_response(0, "succsess"))
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
