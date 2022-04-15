use crate::{auth::LoggedUser, db, utils};
use axum::{http::StatusCode, routing, Extension, Json, Router};
use bson::doc;
use config::Config;
use mongodb::Database;
use nats::Connection;
use oj_judger::judge::{JudgeInfo, JudgeResult, JudgeStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::debug;

#[derive(Debug, Deserialize, Serialize)]
pub struct JudgeRequest {
    pub language: String,
    pub code: String,
    pub contest_id: Option<String>,
    pub problem_id: String,
}

pub async fn submit_handler(
    user: LoggedUser,
    Json(judge_request): Json<JudgeRequest>,
    Extension(config): Extension<Config>,
    Extension(nc): Extension<Connection>,
    Extension(mongo): Extension<Database>,
) -> (StatusCode, Json<Value>) {
    debug!("{:?}", judge_request);
    let language = config.get_table(&format!("language.{}", judge_request.language));
    let subject = config.get_string("nats.judge_queue_subject").unwrap();
    let reply = config.get_string("nats.reply_subject").unwrap();
    match language {
        Ok(language) => {
            let submission_id = utils::gen_random_string(8);
            let compile_cmd = language
                .get("compile_cmd")
                .map(|value| value.to_owned().into_string().unwrap());
            let run_cmd = language
                .get("run_cmd")
                .unwrap()
                .to_owned()
                .into_string()
                .unwrap();
            let src_file_name = language
                .get("src_file_name")
                .unwrap()
                .to_owned()
                .into_string()
                .unwrap();

            let problem_id = match &judge_request.contest_id {
                Some(contest_id) => {
                    let res = db::find_one(
                        &mongo,
                        "contests",
                        doc! {
                            "contest_id": contest_id,
                        },
                        doc! {
                            "_id": 0,
                            "problems": 1
                        },
                        None,
                    )
                    .await
                    .unwrap();
                    let problems: Vec<_> = res
                        .get_array("problems")
                        .unwrap()
                        .iter()
                        .map(|problem| problem.as_str().unwrap())
                        .collect();
                    let problem_id: usize = judge_request.problem_id.parse().unwrap();
                    if problem_id > problems.len() {
                        return (
                            StatusCode::BAD_REQUEST,
                            utils::gen_response(3, "no such problem"),
                        );
                    }
                    problems[problem_id - 1].to_owned()
                }
                None => judge_request.problem_id.clone(),
            };

            // res is not `Send`, see async book 7.2 for more infomation
            {
                let res = db::insert_one(
                    &mongo,
                    "submissions",
                    doc! {
                        "submission_id": &submission_id,
                        "creator": user.username,
                        "contest_id": &judge_request.contest_id,
                        "problem_id": judge_request.problem_id,
                        "code": &judge_request.code,
                        "language": &judge_request.language,
                        "result": JudgeStatus::Judging.to_string(),
                        "visible": &judge_request.contest_id.is_some()
                    },
                )
                .await;

                if res.is_err() {
                    return (
                        StatusCode::BAD_REQUEST,
                        utils::gen_response(2, "submit failed, system error"),
                    );
                }
            }

            let problem = db::find_one(
                &mongo,
                "problems",
                doc! {
                    "problem_id": &problem_id
                },
                doc! {
                    "_id": 0,
                    "time_limit": 1,
                    "memory_limit": 1
                },
                None,
            )
            .await
            .unwrap();

            let cpu_time_limit = problem.get_i32("time_limit").unwrap();
            let real_time_limit = cpu_time_limit * 2; // TODO move to config file
            let memory_limit = problem.get_i32("memory_limit").unwrap();

            let judge_info = JudgeInfo {
                submission_id,
                compile_cmd,
                run_cmd,
                src_file_name,
                language: judge_request.language,
                code: judge_request.code,
                problem_id,
                data_version: "NOCHECK".to_owned(),
                cpu_time_limit: cpu_time_limit as u64,
                real_time_limit: real_time_limit as u64,
                memory_limit: memory_limit as u64,
            };
            let judge_info = serde_json::to_string(&judge_info).unwrap();
            nc.publish_request(&subject, &reply, &judge_info).unwrap();

            (StatusCode::OK, utils::gen_response(0, "submit success"))
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            utils::gen_response(1, "not support language"),
        ),
    }
}

pub async fn wait_submission_reply(mongo: Database, nc: Connection, config: Config) {
    let reply = config.get_string("nats.reply_subject").unwrap();
    let sub = nc.subscribe(&reply).unwrap();
    while let Some(msg) = sub.next() {
        let result = serde_json::from_slice::<JudgeResult>(&msg.data).unwrap();
        debug!("{:?}", result);

        let res = db::update_one(
            &mongo,
            "submissions",
            doc! {
                "submission_id": result.submission_id.clone()
            },
            doc! {
                "$set": {
                    "result": result.status.to_string(),
                    "time": result.cpu_time as i64,
                    "memory": result.memory as i64
                }
            },
            None,
        )
        .await;
        debug!("{:?}", res);
    }
}

pub fn get_router() -> Router {
    Router::new().route("/", routing::post(submit_handler))
}
