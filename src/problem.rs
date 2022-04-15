use crate::{
    auth::{CheckUser, LoggedUser},
    counter, db,
    rbac::{self, Action, Resource},
    utils,
};
use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::IntoResponse,
    routing, Json, Router,
};
use bson::{doc, Document};
use mongodb::Database;
use serde_json::json;
use tracing::debug;

pub async fn add_handler(
    user: LoggedUser,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    debug!("{:?}", user);
    if rbac::check(
        &user.username,
        Resource::Problem(String::new()),
        Action::Write,
        &mongo,
    )
    .await
    .is_ok()
    {
        let cnt = counter::increase(&mongo, "problem_id").await;
        let res = db::insert_one(
            &mongo,
            "problems",
            doc! {
                "problem_id": cnt.to_string(),
                "creator": user.username,
                "visible": false,
            },
        )
        .await;
        match res {
            Ok(_) => (
                StatusCode::OK,
                utils::gen_response(0, json!({ "problem_id": cnt.to_string() })),
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                utils::gen_response(0, "insert failed"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub async fn update_handler(
    Path(problem_id): Path<String>,
    user: LoggedUser,
    Json(problem): Json<Document>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    debug!("{:?} {}", user, problem);
    if rbac::check(
        &user.username,
        Resource::Problem(problem_id.clone()),
        Action::Add,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::update_one(
            &mongo,
            "problems",
            doc! {
                "problem_id": problem_id
            },
            doc! {
                "$set": problem
            },
            None,
        )
        .await;
        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "update failed"),
            )
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub async fn problem_handler(
    user: CheckUser,
    Path(problem_id): Path<String>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    debug!("{:?} {}", user, problem_id);
    if rbac::check(
        &user.username,
        Resource::Problem(problem_id.clone()),
        Action::Read,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::find_one(
            &mongo,
            "problems",
            doc! {
                "problem_id": problem_id
            },
            doc! {
                "_id": 0
            },
            None,
        )
        .await;

        match res {
            Some(problem) => (StatusCode::OK, utils::gen_response(0, problem)),
            None => (
                StatusCode::BAD_REQUEST,
                utils::gen_response(2, "no such problem"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub async fn delete_handler(
    Path(problem_id): Path<String>,
    user: LoggedUser,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    if rbac::check(
        &user.username,
        Resource::Problem(problem_id.clone()),
        Action::Delete,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::delete_one(
            &mongo,
            "problems",
            doc! {
                "problem_id": problem_id
            },
        )
        .await;
        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::BAD_REQUEST,
                utils::gen_response(2, "no such problem"),
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
        .route("/", routing::post(add_handler))
        .route("/:problem_id", routing::patch(update_handler))
        .route("/:problem_id", routing::get(problem_handler))
        .route("/:problem_id", routing::delete(delete_handler))
}

pub mod problems {
    use axum::{
        extract::{Extension, Query},
        http::StatusCode,
        response::IntoResponse,
        routing, Router,
    };
    use bson::{bson, doc, Regex};
    use mongodb::Database;
    use serde::Deserialize;
    use serde_json::json;
    use tracing::debug;

    use crate::{db, utils};

    #[derive(Debug, Deserialize)]
    pub struct ListProblemsOption {
        page: Option<usize>,
        page_size: Option<usize>,
        search: Option<String>,
    }

    pub async fn problems_handler(
        query: Query<ListProblemsOption>,
        Extension(mongo): Extension<Database>,
    ) -> impl IntoResponse {
        let page = query.page.unwrap_or(1);
        let page_size = query.page_size.unwrap_or(20);
        let skip = (page_size * (page - 1)) as u64;
        let limit = page_size as i64;

        let mut filter = doc! {"$and": [{"visible": true}]};
        if let Some(search) = &query.search {
            filter.get_array_mut("$and").unwrap().push(bson! ({
                "$or": [
                    {"problem_id": Regex {pattern: search.clone(), options: String::new() }},
                    {"title": Regex {pattern: search.clone(), options: String::new() }}
                ]
            }))
        }

        let count = db::count(&mongo, "problems", filter.clone()).await;
        debug!("count: {}", count);

        let res = db::find(
            &mongo,
            "problems",
            filter,
            doc! {
                "_id": 0,
                "problem_id": 1,
                "title": 1,
                "tags": 1,
                "difficulty": 1
            },
            None,
            Some(skip),
            Some(limit),
        )
        .await;

        (
            StatusCode::OK,
            utils::gen_response(
                0,
                json!({
                    "problems": res,
                    "total": count
                }),
            ),
        )
    }

    pub fn get_router() -> Router {
        Router::new().route("/", routing::get(problems_handler))
    }
}
