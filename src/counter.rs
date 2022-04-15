use crate::db;
use bson::doc;
use mongodb::Database;
use tracing::debug;

pub async fn increase(mongo: &Database, counter: &str) -> u64 {
    db::update_one(
        &mongo,
        "counters",
        doc! {},
        doc! {
            "$inc": {
                counter: 1
            },
        },
        doc! {
            "_id": 1
        },
    )
    .await
    .unwrap();
    let res = db::find_one(
        &mongo,
        "counters",
        None,
        doc! {
            "_id": 0,
            counter: 1
        },
        doc! {
            "_id": 1
        },
    )
    .await;
    debug!("{:?}", res);
    match res {
        Some(cnt) => cnt.get_i64(counter).unwrap_or(0) as u64,
        None => 0,
    }
}
