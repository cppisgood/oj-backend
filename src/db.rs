use async_redis_session::RedisSessionStore;
use bson::{doc, Document};
use dotenv::dotenv;
use futures::stream::StreamExt;
use mongodb::{
    options::{FindOneAndUpdateOptions, FindOneOptions, FindOptions, UpdateModifications},
    results::DeleteResult,
    Client, Database,
};
use std::{env, error::Error};
use tracing::debug;

pub fn get_redis_store() -> RedisSessionStore {
    dotenv().ok();

    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");

    RedisSessionStore::new(redis_url).unwrap()
}

pub async fn get_mongo_client() -> Client {
    dotenv().ok();

    let mongo_url = env::var("MONGO_URL").expect("MONGO_URL must be set");

    Client::with_uri_str(mongo_url).await.unwrap()
}

pub async fn find_one(
    mongo: &Database,
    collection: &str,
    filter: impl Into<Option<Document>>,
    projection: impl Into<Option<Document>>,
    sort: impl Into<Option<Document>>,
) -> Option<Document> {
    let res = mongo
        .collection::<Document>(collection)
        .find_one(
            filter,
            FindOneOptions::builder()
                .projection(projection)
                .sort(sort)
                .build(),
        )
        .await
        .expect("database error");
    debug!("{:?}", res);
    res
}

pub async fn update_one(
    mongo: &Database,
    collection: &str,
    filter: Document,
    update: impl Into<UpdateModifications>,
    sort: impl Into<Option<Document>>,
) -> Result<(), Box<dyn Error>> {
    match mongo
        .collection::<Document>(collection)
        .find_one_and_update(
            filter,
            update,
            FindOneAndUpdateOptions::builder()
                .sort(sort)
                .projection(doc! {
                    "_id": 1
                })
                .build(),
        )
        .await
        .expect("database error")
    {
        Some(_) => Ok(()),
        None => Err("".into()),
    }
}

pub async fn delete_one(
    mongo: &Database,
    collection: &str,
    filter: Document,
) -> Result<(), Box<dyn Error>> {
    let DeleteResult { deleted_count, .. } = mongo
        .collection::<Document>(collection)
        .delete_one(filter, None)
        .await
        .expect("database error");
    if deleted_count == 1 {
        Ok(())
    } else {
        Err("".into())
    }
}

pub async fn insert_one(
    mongo: &Database,
    collection: &str,
    doc: Document,
) -> Result<(), Box<dyn Error>> {
    let res = mongo.collection(collection).insert_one(doc, None).await;
    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(e)?,
    }
}

pub async fn find(
    mongo: &Database,
    collection: &str,
    filter: impl Into<Option<Document>>,
    projection: impl Into<Option<Document>>,
    sort: impl Into<Option<Document>>,
    skip: Option<u64>,
    limit: Option<i64>,
) -> Vec<Document> {
    let cursor = mongo
        .collection::<Document>(collection)
        .find(
            filter,
            FindOptions::builder()
                .projection(projection)
                .skip(skip)
                .limit(limit)
                .sort(sort)
                .build(),
        )
        .await
        .expect("database error");
    cursor.map(|document| document.unwrap()).collect().await
}

pub async fn count(mongo: &Database, collection: &str, filter: impl Into<Option<Document>>) -> u64 {
    mongo
        .collection::<Document>(collection)
        .count_documents(filter, None)
        .await
        .expect("database error")
}

#[cfg(test)]
mod tests {
    use bson::{doc, Document};
    use mongodb::options::FindOneOptions;

    use super::*;

    #[test]
    fn test_redis() {
        let _store = get_redis_store();
    }

    #[tokio::test]
    async fn test_mongo() {
        let client = get_mongo_client().await;

        for db in client.list_database_names(None, None).await.unwrap() {
            println!("{}", db);
        }

        let db = client.database("test");

        let collection = db.collection::<Document>("table1");

        let result = collection
            .find_one(
                doc! {
                    "name": "name2"
                },
                FindOneOptions::builder()
                    .projection(doc! {
                        "name": 1,
                        "_id": 0
                    })
                    .build(),
            )
            .await;
        println!("{:?}", result);
    }
}
