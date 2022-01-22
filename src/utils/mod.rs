use argon2::{self, Config};

pub fn verify_password<'a>(password: &str, hash: &str) -> bool {
    argon2::verify_encoded(hash, password.as_bytes()).eq(&Ok(true))
}

pub fn hash_password(password: &str) -> String {
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), "mylongsalt".as_bytes(), &config).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let password = "123";
        println!("{}", password);

        let hashed_password = hash_password(password);
        println!("{}", hashed_password);

        assert!(verify_password(password, &hashed_password));
    }
}
