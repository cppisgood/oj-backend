use config::{Config, File, FileFormat};

pub fn get_config() -> Config {
    let config = Config::builder()
        .add_source(File::new("config/config.toml", FileFormat::Toml))
        .build()
        .unwrap();
    config
}
