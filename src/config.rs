use config::{Config, File};

pub fn get_config() -> Config {
    let mut config = Config::default();
    config
        .merge(vec![File::with_name("config/config.toml")])
        .unwrap();
    config
}
