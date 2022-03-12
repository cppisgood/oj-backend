use axum::{
    extract::Query,
    http::{header, Method},
    AddExtensionLayer, Router,
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use dotenv;
use oj_backend::{auth, captcha, config, db, user, image, problem};
use std::{collections::HashMap, net::SocketAddr};
use tower_cookies::{self, CookieManagerLayer};
use tower_http::cors::{CorsLayer, Origin};
use tracing::debug;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    fmt::init();
    debug!("start");

    let config = config::get_config();
    let mongo = db::get_mongo_client().await.database("oj-test");
    let session_store = db::get_redis_store();
    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::PATCH,
            Method::PUT,
        ])
        .allow_origin(Origin::list(vec![
            "http://127.0.0.1:3000".parse().unwrap(),
            "http://127.0.0.1".parse().unwrap(),
        ]))
        .allow_headers(vec![header::CONTENT_TYPE])
        .allow_credentials(true);

    let app = Router::new().nest("/auth", auth::get_router());
    let app = app.merge(Router::new().nest("/user", user::get_router()));
    let app = app.merge(Router::new().nest("/captcha", captcha::get_router()));
    let app = app.merge(Router::new().nest("/image", image::get_router()));
    let app = app.merge(Router::new().nest("/problem", problem::get_router()));

    let app = Router::new()
        .nest("/api", app)
        .layer(CookieManagerLayer::new())
        .layer(cors)
        .layer(AddExtensionLayer::new(config))
        .layer(AddExtensionLayer::new(mongo))
        .layer(AddExtensionLayer::new(session_store))
        .layer(CsrfLayer::new(CsrfConfig::default()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

#[allow(dead_code)]
async fn test_handler(token: CsrfToken, Query(params): Query<HashMap<String, String>>) {
    debug!("{:?}", params);
    if let Some(csrftoken) = params.get("token") {
        match token.verify(csrftoken) {
            Ok(_) => debug!("ok"),
            Err(_) => debug!("no"),
        }
    }
}
