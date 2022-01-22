use axum::{
    extract::Query,
    routing::{get, post},
    AddExtensionLayer, Router,
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use oj_backend::{auth::login, config, db};
use std::{collections::HashMap, net::SocketAddr};
use tower_cookies::{self, CookieManagerLayer};

#[tokio::main]
async fn main() {
    let config = config::get_config();
    let mongo = db::get_mongo_client().await.database("oj-test");
    let session_store = db::get_redis_store();

    let app = Router::new()
        .route("/test", get(test_handler))
        .route("/api/login", post(login::login_handler))
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

async fn test_handler(token: CsrfToken, Query(params): Query<HashMap<String, String>>) {
    println!("{:?}", params);
    if let Some(csrftoken) = params.get("token") {
        match token.verify(csrftoken) {
            Ok(_) => println!("ok"),
            Err(_) => println!("no"),
        }
    }
}
