use std::error::Error;

use bson::doc;
use mongodb::Database;
use tracing::debug;

use crate::db;

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
    let (roles, contest_passwords) = {
        let user = db::find_one(
            &mongo,
            "users",
            doc! {
                "username": username
            },
            doc! {
                "_id": 0,
                "roles": 1,
                "contest_passwords": 1
            },
            None,
        )
        .await
        .expect("logged user not found in database");

        debug!("{}", user);
        (
            user.get_array("roles")
                .unwrap_or(&vec![])
                .into_iter()
                .map(|role| role.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            user.get_array("contest_passwords")
                .unwrap_or(&vec![])
                .into_iter()
                .map(|contest_password| {
                    let contest_password = contest_password.as_document().unwrap();
                    (
                        contest_password.get_str("contest_id").unwrap().to_owned(),
                        contest_password.get_str("password").unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    };

    if roles.iter().any(|role| role == "root") {
        Ok(())
    } else {
        if let Resource::User(user) = resource {
            match action {
                Action::Read => Ok(()),
                Action::Write => (user == username).then(|| ()).ok_or("".into()),
                Action::Delete => Err("".into()),
                Action::Add => Ok(()),
            }
        } else {
            if roles.iter().any(|role| role == "admin") {
                Ok(())
            } else {
                match resource {
                    Resource::Problem(problem_id) => {
                        let (creator, visible) = {
                            let res = db::find_one(
                                &mongo,
                                "problems",
                                doc! {
                                    "problem_id": problem_id
                                },
                                doc! {
                                    "_id": 0,
                                    "creator": 1,
                                    "visible": 1
                                },
                                None,
                            )
                            .await
                            .ok_or("")?;

                            (res.get_str("creator")?.to_owned(), res.get_bool("visible")?)
                        };
                        debug!("{} {}", creator, visible);

                        match action {
                            Action::Read => (creator == username || visible)
                                .then(|| ())
                                .ok_or("".into()),
                            Action::Write => (creator == username).then(|| ()).ok_or("".into()),
                            Action::Add => roles
                                .iter()
                                .any(|role| role == "author")
                                .then(|| ())
                                .ok_or("".into()),
                            Action::Delete => Err("".into()),
                        }
                    }
                    Resource::Contest(contest_id) => match action {
                        Action::Read => {
                            let contest_password = db::find_one(
                                &mongo,
                                "contests",
                                doc! {
                                    "contest_id": &contest_id
                                },
                                doc! {
                                    "_id": 0,
                                    "password": 1
                                },
                                None,
                            )
                            .await
                            .unwrap();

                            debug!("contest: {:?}", contest_password);
                            if let Ok(password) = contest_password.get_str("password") {
                                debug!("password: {:?}", password);
                                contest_passwords
                                    .iter()
                                    .any(|(contest_id_, password_)| {
                                        contest_id_ == &contest_id && password_ == password
                                    })
                                    .then(|| ())
                                    .ok_or("".into())
                            } else {
                                Ok(())
                            }
                        }
                        Action::Write => Err("".into()),
                        Action::Add => Err("".into()),
                        Action::Delete => Err("".into()),
                    },
                    Resource::Submission(submission_id) => {
                        let (creator, visible) = {
                            let res = db::find_one(
                                &mongo,
                                "submissions",
                                doc! {
                                    "submission_id": &submission_id
                                },
                                doc! {
                                    "_id": 0,
                                    "creator": 1,
                                    "visible": 1
                                },
                                None,
                            )
                            .await
                            .ok_or("")?;
                            (
                                res.get_str("creator")?.to_string(),
                                res.get_bool("visible")?,
                            )
                        };
                        // TODO let author see user submissions of owned problem
                        match action {
                            Action::Read => (visible || &creator == username)
                                .then(|| ())
                                .ok_or("".into()),
                            Action::Write => (&creator == username).then(|| ()).ok_or("".into()),
                            Action::Add => roles
                                .iter()
                                .all(|role| role != "UNLOGGED")
                                .then(|| ())
                                .ok_or("".into()),
                            Action::Delete => Err("".into()),
                        }
                    }
                    Resource::Blog(_) => Err("".into()),
                    _ => unreachable!(),
                }
            }
        }
    }
}
