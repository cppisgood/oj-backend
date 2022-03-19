use crate::{db, utils};
use async_redis_session::RedisSessionStore;
use async_session::SessionStore;
use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing, Router,
};
use axum_csrf::CsrfToken;
use bson::doc;
use chrono::{Duration, Local};
use config::Config;
use cookie::Cookie;
use mongodb::Database;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_cookies::Cookies;
use tracing::debug;

#[derive(Deserialize, Debug)]
pub struct LoggedUser {
    pub username: String,
    pub session_id: String,
}

#[async_trait]
impl<B> FromRequest<B> for LoggedUser
where
    B: Send,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(store) = Extension::<RedisSessionStore>::from_request(req)
            .await
            .expect("`RedisSessionStore` extension missing");

        let cookie = Cookies::from_request(req).await.unwrap();

        let session_id = cookie.get("session_id");
        match session_id {
            Some(session_id) => match store
                .load_session(session_id.value().to_string())
                .await
                .unwrap()
            {
                Some(session) => {
                    let username: String = session.get("username").unwrap();
                    Ok(Self {
                        username,
                        session_id: session_id.value().to_string(),
                    })
                }
                None => Err((
                    StatusCode::UNAUTHORIZED,
                    utils::gen_response(1, "login required"),
                )),
            },
            None => Err((
                StatusCode::UNAUTHORIZED,
                utils::gen_response(1, "login required"),
            )),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CheckUser {
    pub username: String,
}

#[async_trait]
impl<B> FromRequest<B> for CheckUser
where
    B: Send,
{
    type Rejection = (StatusCode, Json<Value>);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let res = LoggedUser::from_request(req).await;

        Ok(match res {
            Ok(user) => CheckUser {
                username: user.username,
            },
            Err(_) => CheckUser {
                username: "NORMAL".to_string(),
            },
        })
    }
}

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
    let data = db::find_one(
        &mongo,
        "users",
        doc! {
            "username": &user.username
        },
        None,
        None,
    )
    .await;

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
