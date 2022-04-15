use crate::utils;
use axum::{http::StatusCode, routing, Extension, Json, Router};
use config::Config;
use serde_json::Value;
use tracing::debug;

pub async fn language_handler(Extension(config): Extension<Config>) -> (StatusCode, Json<Value>) {
    let languages = config.get_table("language").unwrap();
    let languages: Vec<_> = languages.keys().collect();
    debug!("{:?}", languages);
    (StatusCode::OK, utils::gen_response(0, languages))
}

pub fn get_router() -> Router {
    Router::new().route("/", routing::get(language_handler))
}
