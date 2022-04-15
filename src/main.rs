use axum::{
    extract::Extension,
    http::{header, Method},
    Router,
};
use dotenv;
use nats;
use oj_backend::{
    auth, captcha, config,
    contest::{self, contests},
    db, image, language,
    problem::{self, problems},
    submission, user,
};
use std::{env, net::SocketAddr};
use tokio::task;
use tower_cookies::{self, CookieManagerLayer};
use tower_http::cors::{CorsLayer, Origin};
use tracing::debug;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    fmt::init();
    debug!("start");

    let nat_url = env::var("NATS_URL").expect("NATS_URL must be set");
    let nc = nats::connect(&nat_url).expect("connect nats server failed");
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

    {
        let mongo = mongo.clone();
        let nc = nc.clone();
        let config = config.clone();
        // thread::spawn(move || {
        //     async {
        //         debug!("submission watcher start");
        //     }
        // });
        task::spawn(async {
            debug!("submission watcher start success1");
            submission::wait_submission_reply(mongo, nc, config).await;
        });
    }
    debug!("submission watcher start success2");

    let app = Router::new();
    let app = app.merge(Router::new().nest("/auth", auth::get_router()));
    let app = app.merge(Router::new().nest("/user", user::get_router()));
    let app = app.merge(Router::new().nest("/captcha", captcha::get_router()));
    let app = app.merge(Router::new().nest("/image", image::get_router()));
    let app = app.merge(Router::new().nest("/language", language::get_router()));
    let app = app.merge(Router::new().nest("/problem", problem::get_router()));
    let app = app.merge(Router::new().nest("/problems", problems::get_router()));
    let app = app.merge(Router::new().nest("/contest", contest::get_router()));
    let app = app.merge(Router::new().nest("/contests", contests::get_router()));
    let app = app.merge(Router::new().nest("/submission", submission::get_router()));

    let app = app
        .layer(CookieManagerLayer::new())
        .layer(cors)
        .layer(Extension(config))
        .layer(Extension(mongo))
        .layer(Extension(nc))
        .layer(Extension(session_store));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}
