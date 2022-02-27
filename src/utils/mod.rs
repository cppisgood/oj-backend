use argon2::{self, Config};
use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore};
use axum::Json;
use cookie::{Cookie, SameSite};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;
use time;

pub fn verify_password<'a>(password: &str, hash: &str) -> bool {
    argon2::verify_encoded(hash, password.as_bytes()).eq(&Ok(true))
}

pub fn hash_password(password: &str) -> String {
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), "mylongsalt".as_bytes(), &config).unwrap()
}

pub fn gen_response<T: Serialize>(code: u32, msg: T) -> Json<Value> {
    Json(json!({
        "code": code,
        "msg": json!(msg)
    }))
}

pub fn gen_session(pairs: &[(&str, &str)], ttl: Duration) -> Session {
    let mut session = Session::new();
    for (key, value) in pairs {
        session.insert(key, value).unwrap();
    }
    session.expire_in(ttl);

    session
}

pub async fn sotre_session_and_gen_cookie(
    store: RedisSessionStore,
    session: Session,
    ttl: Duration,
) -> Cookie<'static> {
    let cookie = store.store_session(session).await.unwrap().unwrap();
    Cookie::build("session_id", cookie)
        .max_age(time::Duration::try_from(ttl).unwrap())
        .same_site(SameSite::Strict)
        .http_only(true)
        // .secure(true)
        .path("/")
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let password = "123";
        println!("{}", password);

        let hashed_password = hash_password(password);
        println!("{}", hashed_password);

        assert!(verify_password(password, &hashed_password));
    }
}
