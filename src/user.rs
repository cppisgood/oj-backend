use crate::{
    auth::LoggedUser,
    db,
    rbac::{self, Action, Resource},
    utils,
};
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
    routing, Json, Router,
};
use axum_csrf::CsrfToken;
use bson::{doc, Document};
use config::Config;
use mongodb::Database;
use serde::Deserialize;
use tower_cookies::Cookies;
use tracing::debug;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    password: String,
    email: String,
    captcha: String,
}

/// create a new user and store into database
///
/// please get [`captcha`](crate::captcha) before register
///
/// http method: post
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
                    debug!("{:?}", session);
                    let captcha: String = {
                        match session.get("captcha") {
                            Some(captcha) => captcha,
                            None => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    utils::gen_response(4, "get captcha first"),
                                )
                            }
                        }
                    };

                    debug!("{} {}", user.captcha, captcha);
                    if user.captcha.to_lowercase() == captcha.to_lowercase() {
                        let res = mongo
                            .collection("users")
                            .insert_one(
                                doc! {
                                    "username": user.username,
                                    "password": utils::hash_password(&user.password),
                                    "email": user.email,
                                    "roles": ["normal"]
                                },
                                None,
                            )
                            .await;
                        match res {
                            Ok(_) => {
                                store.destroy_session(session).await.unwrap();
                                (StatusCode::OK, utils::gen_response(0, "success"))
                            }
                            Err(_) => (
                                StatusCode::BAD_REQUEST,
                                utils::gen_response(1, "username already been used"),
                            ),
                        }
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            utils::gen_response(2, "wrong captcha"),
                        )
                    }
                }
                None => (
                    StatusCode::UNAUTHORIZED,
                    utils::gen_response(3, "bad `session_id`"),
                ),
            }
        }
        None => (
            StatusCode::UNAUTHORIZED,
            utils::gen_response(2, "`session_id` in cookies required"),
        ),
    }
}

pub async fn user_handler(
    Path(username): Path<String>,
    Extension(config): Extension<Config>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    let user = db::find_one(
        &mongo,
        "users",
        doc! {
            "username": &username
        },
        doc! {
            "_id": 0,
            "password": 0
        },
        None,
    )
    .await;

    match user {
        Some(mut user) => {
            debug!("{:?}", user);
            if let Err(_) = user.get_str("avatar") {
                user.insert("avatar", config.get_str("default_avatar").unwrap());
            }
            debug!("{:?}", user);

            (StatusCode::OK, utils::gen_response(0, user))
        }
        None => (
            StatusCode::NOT_FOUND,
            utils::gen_response(1, "no such user"),
        ),
    }
}

pub async fn delete_user_handler(
    logged_user: LoggedUser,
    Path(username): Path<String>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    if rbac::check(
        &logged_user.username,
        Resource::User(username.clone()),
        Action::Delete,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::delete_one(
            &mongo,
            "users",
            doc! {
                "username": &username
            },
        )
        .await;

        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "no such user"),
            )
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub async fn update_user_handler(
    logged_user: LoggedUser,
    Path(username): Path<String>,
    Json(user): Json<Document>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    if rbac::check(
        &logged_user.username,
        Resource::User(username.clone()),
        Action::Write,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::update_one(
            &mongo,
            "users",
            doc! {
                "username": username
            },
            doc! {
                "$set": user
            },
            None,
        )
        .await;
        debug!("{:?}", res);

        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "no such user"),
            )
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub fn get_router() -> Router {
    Router::new()
        .route("/", routing::post(register_handler))
        .route("/:username", routing::patch(update_user_handler))
        .route("/:username", routing::get(user_handler))
        .route("/:username", routing::delete(delete_user_handler))
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
    }
}
