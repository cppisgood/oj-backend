use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{extract::Extension, http::StatusCode, response::IntoResponse, Json};
use axum_csrf::CsrfToken;
use bson::doc;
// use captcha_rust::Captcha;
use crate::utils;
use captcha::{filters::Noise, Captcha};
use chrono::Duration;
use mongodb::Database;
use serde::Deserialize;
use tower_cookies::Cookies;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    password: String,
    email: String,
    captcha: String,
}

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
    _token: CsrfToken,
    cookies: Cookies,
    Extension(store): Extension<RedisSessionStore>,
) -> impl IntoResponse {
    let (captcha, base64) = get_captcha();
    let ttl = Duration::hours(1).to_std().unwrap();
    let session = utils::gen_session(&[("captcha", &captcha)], ttl);
    let cookie = utils::sotre_session_and_gen_cookie(store.clone(), session, ttl).await;
    cookies.add(cookie);
    println!("{}", captcha);

    utils::gen_response(0, base64)
}

pub async fn register_handler(
    _token: CsrfToken,
    cookie: Cookies,
    Json(user): Json<RegisterUser>,
    Extension(store): Extension<RedisSessionStore>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    let session_id = cookie.get("session_id");

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
                    println!("{} {}", user.captcha, captcha);
                    if user.captcha == captcha {
                        let res = mongo
                            .collection("users")
                            .insert_one(
                                doc! {
                                    "username": user.username,
                                    "password": utils::hash_password(&user.password),
                                    "email": user.email,
                                },
                                None,
                            )
                            .await;
                        match res {
                            Ok(_) => (StatusCode::OK, utils::gen_response(0, "succsess")),
                            Err(_) => (
                                StatusCode::BAD_REQUEST,
                                utils::gen_response(1, "username already been used"),
                            ),
                        }
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

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use captcha::{filters::Noise, Captcha};
    #[test]
    fn test_captchat() {
        let captcha = Captcha::new()
            .add_chars(4)
            .view(200, 100)
            .apply_filter(Noise::new(0.5))
            .as_png()
            .unwrap();
        let mut f = File::create("./tmp.png").unwrap();
        f.write(&captcha).unwrap();
        // println!("{}", captcha);
    }
}
