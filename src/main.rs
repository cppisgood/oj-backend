use axum::{
    extract::Query,
    AddExtensionLayer, Router,
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use oj_backend::{auth, config, db, user};
use std::{collections::HashMap, net::SocketAddr};
use tower_cookies::{self, CookieManagerLayer};

#[tokio::main]
async fn main() {
    let config = config::get_config();
    let mongo = db::get_mongo_client().await.database("oj-test");
    let session_store = db::get_redis_store();

    let app = Router::new().nest("/auth", auth::get_router());
    let app = app.merge(Router::new().nest("/user", user::get_router()));


    let app = Router::new()
        .nest("/api", app)
        .layer(AddExtensionLayer::new(config))
        .layer(AddExtensionLayer::new(mongo))
        .layer(AddExtensionLayer::new(session_store))
        .layer(CookieManagerLayer::new())
        .layer(CsrfLayer::new(CsrfConfig::default()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

#[allow(dead_code)]
async fn test_handler(token: CsrfToken, Query(params): Query<HashMap<String, String>>) {
    println!("{:?}", params);
    if let Some(csrftoken) = params.get("token") {
        match token.verify(csrftoken) {
            Ok(_) => println!("ok"),
            Err(_) => println!("no"),
        }
    }
}
