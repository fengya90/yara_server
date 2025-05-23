use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct UrlDto {
    pub need_to_unzip: bool,
    pub url: String,
}

#[derive(Serialize)]
pub struct MatchedRules {
    pub rule: String,
    pub namespace: String,
    pub meta: Value,
}

#[derive(Serialize)]
pub struct YaraResult {
    pub matched_rule_count: usize,
    pub matched_rules: Vec<MatchedRules>,
    pub error: Option<String>,
}
