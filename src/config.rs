use serde::Deserialize;
use config::Config;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    pub yara: YaraConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub url_path: UrlPath,
}

#[derive(Debug, Deserialize)]
pub struct UrlPath {
    pub content: String,
    pub url: String,
    pub reload: String,
}

#[derive(Debug, Deserialize)]
pub struct YaraConfig {
    pub rule_dir: String,
}

impl Settings {
    pub fn from_yaml(path: &str) -> Result<Self, config::ConfigError> {
        let s = Config::builder()
            .add_source(config::File::from(Path::new(path)))
            .build()?;

        s.try_deserialize::<Settings>()
    }
}
