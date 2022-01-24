use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    extract::Extension, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
};
use axum_csrf::CsrfToken;
use bson::doc;
use captcha_rust::Captcha;
use chrono::Duration;
use mongodb::Database;
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::utils;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    password: String,
    email: String,
    captcha: String,
}

pub async fn captcha_handler(
    _token: CsrfToken,
    cookie: Cookies,
    Extension(store): Extension<RedisSessionStore>,
) {
    let captcha = Captcha::new(5, 130, 40);
    println!("{}", captcha.text);
    let ttl = Duration::hours(1).to_std().unwrap();
    let session = utils::gen_session(&[("captcha", &captcha.text)], ttl);
    println!("{:?}", session);
    let session_cookie = utils::sotre_session_and_gen_cookie(store.clone(), session, ttl).await;
    cookie.add(session_cookie);
}

pub async fn user_post_handler(
    _token: CsrfToken,
    cookie: Cookies,
    Json(user): Json<RegisterUser>,
    Extension(store): Extension<RedisSessionStore>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    let session_id = cookie.get("session_id");
    println!("{:?}", session_id);

    match session_id {
        Some(session_id) => {
            match store
                .load_session(session_id.value().to_string())
                .await
                .unwrap()
            {
                Some(session) => {
                    println!("{:?}", session);
                    let captcha: String = session.get("captcha").unwrap();
                    if user.captcha == captcha {
                        mongo
                            .collection("users")
                            .insert_one(
                                doc! {
                                    "username": user.username,
                                    "password": utils::hash_password(&user.password),
                                    "email": user.email,
                                },
                                None,
                            )
                            .await
                            .unwrap();

                        (StatusCode::OK, utils::gen_response(0, "succsess"))
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            utils::gen_response(1, "wrong captcha"),
                        )
                    }
                }
                None => (
                    StatusCode::UNAUTHORIZED,
                    utils::gen_response(2, "bad `session_id`"),
                ),
            }
        }
        None => (
            StatusCode::UNAUTHORIZED,
            utils::gen_response(2, "`session_id` in cookies required"),
        ),
    }
}

pub fn get_router() -> Router {
    Router::new()
        .route("/captcha", post(captcha_handler))
        .route("/user", post(user_post_handler))
}

#[cfg(test)]
mod tests {
    use captcha_rust::Captcha;
    #[test]
    fn test_captcha_rust() {
        let a = Captcha::new(5, 130, 40);
        println!("test:{},base_img:{}", a.text, a.base_img);
    }
}
