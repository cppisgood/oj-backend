use async_redis_session::RedisSessionStore;
use dotenv::dotenv;
use mongodb::Client;
use std::env;

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

        // let result = collection.insert_many(
        //     [
        //         doc! {
        //             "name": "name1",
        //             "age": 19
        //         },
        //         doc! {
        //             "name": "name2",
        //             "height": 123
        //         },
        //     ],
        //     None,
        // ).await.unwrap();
        // println!("{:?}", result);

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
