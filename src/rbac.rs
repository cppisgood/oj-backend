use std::error::Error;

use bson::{doc, Document};
use mongodb::{options::FindOneOptions, Database};
use tracing::debug;

#[derive(Debug)]
pub enum Action {
    Read,
    Write,
    Add,
    Delete,
}
#[derive(Debug)]
pub enum Resource {
    User(String),
    Problem(String),
    Contest(String),
    Submission(String),
    Blog(String),
}

// TODO use real rbac
pub async fn check(
    username: &str,
    resource: Resource,
    action: Action,
    mongo: &Database,
) -> Result<(), Box<dyn Error>> {
    debug!("{} {:?} {:?}", username, resource, action);
    let roles = {
        let user = mongo
            .collection::<Document>("users")
            .find_one(
                doc! {
                    "username": username,
                },
                FindOneOptions::builder()
                    .projection(doc! {
                        "roles": 1
                    })
                    .build(),
            )
            .await?
            .unwrap();
        debug!("{}", user);
        user.get_array("roles")
            .unwrap_or(&vec![])
            .into_iter()
            .map(|role| role.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    if roles.iter().any(|role| role == "root") {
        Ok(())
    } else {
        match resource {
            Resource::User(user) => match action {
                Action::Read => Ok(()),
                Action::Write => (user == username).then(|| ()).ok_or("".into()),
                Action::Delete => Err("".into()),
                Action::Add => Ok(()),
            },
            Resource::Problem(_pid) => match action {
                Action::Read => todo!(),
                Action::Write => todo!(),
                Action::Add => roles
                    .iter()
                    .any(|role| role == "root" || role == "admin")
                    .then(|| ())
                    .ok_or("".into()),
                Action::Delete => todo!(),
            },
            Resource::Contest(_cid) => todo!(),
            Resource::Submission(_sid) => todo!(),
            Resource::Blog(_bid) => todo!(),
        }
    }
}
