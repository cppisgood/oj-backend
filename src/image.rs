use std::{
    fs::{read, File},
    io::Write,
    path::Path as StdPath,
};

use axum::{
    extract::{Extension, Multipart, Path},
    headers::{HeaderMap, HeaderValue},
    http::{header, StatusCode},
    response::IntoResponse,
    routing, Router,
};
use config::Config;
use tracing::debug;

use crate::utils;

pub async fn upload_handler(
    mut multipart: Multipart,
    Extension(config): Extension<Config>,
) -> impl IntoResponse {
    if let Some(field) = multipart.next_field().await.unwrap() {
        let file_type = field.content_type().unwrap();
        debug!("file type: {}", file_type);
        if file_type.starts_with("image") {
            let name = format!(
                "{}.{}",
                utils::gen_random_string(10),
                StdPath::new(field.name().unwrap())
                    .extension()
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
            let path = config.get_string("images_path").unwrap() + &name;
            let data = field.bytes().await.unwrap();

            let mut f = File::create(&path).unwrap();
            f.write(&data).unwrap();

            debug!("Length of `{}` is {} bytes", name, data.len());
            (StatusCode::OK, utils::gen_response(0, name))
        } else {
            (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "unexpected file type"),
            )
        }
    } else {
        (
            StatusCode::OK,
            utils::gen_response(2, "cannot extract file from request"),
        )
    }
}

pub async fn image_handler(
    Path(image_name): Path<String>,
    Extension(config): Extension<Config>,
) -> impl IntoResponse {
    let path = config.get_string("images_path").unwrap() + &image_name;
    let path = StdPath::new(&path);
    debug!("{:?}", path);

    if path.exists() {
        let mime = mime_guess::from_path(&image_name).first().unwrap();
        let mime_type = mime.type_().as_str();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(mime_type).unwrap(),
        );
        let image = read(path).unwrap();
        (StatusCode::OK, headers, image)
    } else {
        (
            StatusCode::BAD_REQUEST,
            HeaderMap::new(),
            serde_json::to_vec(&utils::gen_response(1, "no such image").take()).unwrap(),
        )
    }
}

pub fn get_router() -> Router {
    Router::new()
        .route("/", routing::post(upload_handler))
        .route("/:image_name", routing::get(image_handler))
}
