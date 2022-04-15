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
use serde_json::{json, Value};
use tracing::debug;

pub async fn create_handler(
    user: LoggedUser,
    Extension(mongo): Extension<Database>,
) -> (StatusCode, Json<Value>) {
    debug!("{:?}", user);
    if rbac::check(
        &user.username,
        Resource::Contest(String::new()),
        Action::Write,
        &mongo,
    )
    .await
    .is_ok()
    {
        let cnt = counter::increase(&mongo, "contest_id").await;
        let res = db::insert_one(
            &mongo,
            "contests",
            doc! {
                "contest_id": cnt.to_string(),
                "creator": user.username,
                "visible": false,
                "problems": Vec::<String>::new()
            },
        )
        .await;
        match res {
            Ok(_) => (
                StatusCode::OK,
                utils::gen_response(0, json!({ "contest_id": cnt.to_string() })),
            ),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                utils::gen_response(0, "create failed"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not permitted operation"),
        )
    }
}

pub async fn contest_handler(
    user: CheckUser,
    Path(contest_id): Path<String>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    debug!("{:?} {}", user, contest_id);
    if rbac::check(
        &user.username,
        Resource::Contest(contest_id.clone()),
        Action::Read,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::find_one(
            &mongo,
            "contests",
            doc! {
                "contest_id": &contest_id,
            },
            doc! {
                "_id": 0,
                "contest_id": 1,
                "creator": 1,
                "start_at": 1,
                "end_at": 1,
                "title": 1,
            },
            None,
        )
        .await;
        match res {
            Some(contest) => (StatusCode::OK, utils::gen_response(0, contest)),
            None => (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "no such contest"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(2, "not permitted operation"),
        )
    }
}

pub async fn update_handler(
    user: LoggedUser,
    Path(contest_id): Path<String>,
    Json(contest): Json<Document>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    if rbac::check(
        &user.username,
        Resource::Contest(contest_id.clone()),
        Action::Write,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::update_one(
            &mongo,
            "contests",
            doc! {"contest_id": &contest_id},
            doc! { "$set": contest},
            None,
        )
        .await;
        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
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

pub async fn delete_handler(
    user: LoggedUser,
    Path(contest_id): Path<String>,
    Extension(mongo): Extension<Database>,
) -> impl IntoResponse {
    if rbac::check(
        &user.username,
        Resource::Contest(contest_id.clone()),
        Action::Delete,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::delete_one(
            &mongo,
            "contests",
            doc! {
                "contest_id": &contest_id,
            },
        )
        .await;
        if res.is_ok() {
            (StatusCode::OK, utils::gen_response(0, "success"))
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
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

pub async fn problems_handler(
    user: CheckUser,
    Path(contest_id): Path<String>,
    Extension(mongo): Extension<Database>,
) -> (StatusCode, Json<Value>) {
    if rbac::check(
        &user.username,
        Resource::Contest(contest_id.clone()),
        Action::Read,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::find_one(
            &mongo,
            "contests",
            doc! {
                "contest_id": &contest_id,
            },
            doc! {
                "_id": 0,
                "problems": 1
            },
            None,
        )
        .await;
        match res {
            Some(contest) => {
                let problems = {
                    let problems: Vec<_> = contest
                        .get_array("problems")
                        .unwrap()
                        .iter()
                        .map(|problem| problem.as_str().unwrap())
                        .collect();
                    let mut problems = db::find(
                        &mongo,
                        "problems",
                        doc! {
                            "problem_id": {
                                "$in": problems
                            }
                        },
                        doc! {
                            "_id": 0,
                            "problem_id": 1,
                            "title": 1,
                        },
                        None,
                        None,
                        None,
                    )
                    .await;
                    for (i, problem) in problems.iter_mut().enumerate() {
                        problem.insert("problem_id", (i + 1).to_string());
                    }
                    problems
                };
                (StatusCode::OK, utils::gen_response(0, problems))
            }
            None => (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "no such contest"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(2, "not permitted operation"),
        )
    }
}

pub async fn problem_handler(
    user: CheckUser,
    Path((contest_id, problem_id)): Path<(String, usize)>,
    Extension(mongo): Extension<Database>,
) -> (StatusCode, Json<Value>) {
    if rbac::check(
        &user.username,
        Resource::Contest(contest_id.clone()),
        Action::Read,
        &mongo,
    )
    .await
    .is_ok()
    {
        let res = db::find_one(
            &mongo,
            "contests",
            doc! {
                "contest_id": &contest_id,
            },
            doc! {
                "_id": 0,
                "problems": 1
            },
            None,
        )
        .await;
        match res {
            Some(contest) => {
                let problems = {
                    let problems: Vec<_> = contest
                        .get_array("problems")
                        .unwrap()
                        .iter()
                        .map(|problem| problem.as_str().unwrap())
                        .collect();
                    if problem_id > problems.len() {
                        return (
                            StatusCode::BAD_REQUEST,
                            utils::gen_response(3, "no such problem"),
                        );
                    }

                    let problem_id = problems[problem_id - 1];
                    db::find_one(
                        &mongo,
                        "problems",
                        doc! {
                            "problem_id": problem_id
                        },
                        doc! {
                            "_id": 0,
                            "content": 1,
                            "memory_limit": 1,
                            "time_limit": 1,
                            "title": 1,
                        },
                        None,
                    )
                    .await
                };
                (StatusCode::OK, utils::gen_response(0, problems))
            }
            None => (
                StatusCode::BAD_REQUEST,
                utils::gen_response(1, "no such contest"),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            utils::gen_response(2, "not permitted operation"),
        )
    }
}

pub fn get_router() -> Router {
    Router::new()
        .route("/", routing::post(create_handler))
        .route("/:contest_id", routing::patch(update_handler))
        .route("/:contest_id", routing::get(contest_handler))
        .route("/:contest_id", routing::delete(delete_handler))
        .route(
            "/:contest_id/problem/:problem_id",
            routing::get(problem_handler),
        )
        .route("/:contest_id/problems", routing::get(problems_handler))
}

pub mod contests {
    use crate::{db, utils};
    use axum::{
        extract::Query, http::StatusCode, response::IntoResponse, routing, Extension, Router,
    };
    use bson::{bson, doc, Regex};
    use mongodb::Database;
    use serde::Deserialize;
    use serde_json::json;
    use tracing::debug;

    #[derive(Debug, Deserialize)]
    pub struct ListContestsOption {
        page: Option<usize>,
        page_size: Option<usize>,
        search: Option<String>,
    }

    pub async fn contests_handler(
        query: Query<ListContestsOption>,
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
                    {"contest_id": Regex {pattern: search.clone(), options: String::new() }},
                    {"title": Regex {pattern: search.clone(), options: String::new() }}
                ]
            }))
        }

        let count = db::count(&mongo, "contests", filter.clone()).await;
        debug!("count: {}", count);

        let res = db::find(
            &mongo,
            "contests",
            filter,
            doc! {
                "_id": 0,
                "contest_id": 1,
                "title": 1,
                "start_at": 1,
                "end_at": 1,
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
                    "contests": res,
                    "total": count
                }),
            ),
        )
    }

    pub fn get_router() -> Router {
        Router::new().route("/", routing::get(contests_handler))
    }
}
