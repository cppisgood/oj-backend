use crate::utils;
use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore};
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
use serde_json::json;
use time;
use tower_cookies::{Cookie, Cookies};

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
                        .to_std()
                        .unwrap()
                } else {
                    Duration::hours(config.get_int("session_ttl").unwrap_or(24))
                        .to_std()
                        .unwrap()
                };

                let session = {
                    let mut session = Session::new();
                    session.insert("username", &user.username).unwrap();
                    session.expire_in(ttl);
                    session
                };
                let session_cookie = {
                    let cookie = session_store.store_session(session).await.unwrap().unwrap();
                    let mut cookie = Cookie::new("session_id", cookie);
                    cookie.set_max_age(time::Duration::try_from(ttl).unwrap());
                    cookie
                };
                cookie.add(session_cookie);
                println!("{:?}", session_store.count().await);

                (
                    StatusCode::OK,
                    Json(json!({
                        "code": "0",
                        "msg": "succsess"
                    })),
                )
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "code": "2",
                        "msg": "wrong password"
                    })),
                )
            }
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "code": "1",
                "msg": "no such user"
            })),
        ),
    }
}
