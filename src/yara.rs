use crate::dto::{MatchedRules, YaraResult};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::{Arc, RwLock};
use tracing::info;
use yara_x::{Compiler, Rules};

static RULES_DIR: OnceLock<PathBuf> = OnceLock::new();
static GLOBAL_RULES: RwLock<Option<Arc<Rules>>> = RwLock::new(None);

fn load_rules_from_dir(dir: &Path) -> io::Result<Arc<Rules>> {
    let mut compiler = Compiler::new();
    let mut file_count = 0;

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|ext| ext == "yar").unwrap_or(false) {
            let content: String = fs::read_to_string(&path)?;
            compiler.add_source(content.as_str()).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Compile error in {:?}: {:?}", path, e),
                )
            })?;
            file_count += 1;
        }
    }

    let rules = compiler.build();
    info!("load {} rules", file_count);
    Ok(Arc::new(rules))
}

pub fn init_rules(dir: PathBuf) -> io::Result<()> {
    let rules = load_rules_from_dir(&dir)?;
    RULES_DIR
        .set(dir)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Rules dir already set"))?;
    let mut global_rules = GLOBAL_RULES.write().unwrap();
    *global_rules = Some(rules);
    Ok(())
}

pub fn reload_rules() -> io::Result<()> {
    let dir = RULES_DIR
        .get()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Rules dir not initialized"))?;
    let new_rules = load_rules_from_dir(dir)?;
    let mut global_rules = GLOBAL_RULES.write().unwrap();
    *global_rules = Some(new_rules);
    Ok(())
}

pub fn match_yara_rules(bytes: &[u8]) -> YaraResult {
    let global_rules = GLOBAL_RULES.read().unwrap();
    let rules = global_rules.as_ref().expect("Rules not initialized");

    let mut scanner = yara_x::Scanner::new(rules);
    let results = scanner.scan(&bytes).unwrap();
    let matched_rules = results.matching_rules();
    let mut matched_info: Vec<MatchedRules> = vec![];

    for rule in matched_rules {
        let identifier = rule.identifier();
        let namespace = rule.namespace();
        let meta = rule.metadata().into_json();
        let matched_rule = MatchedRules {
            rule: identifier.to_string(),
            namespace: namespace.to_string(),
            meta,
        };
        matched_info.push(matched_rule);
    }

    YaraResult {
        matched_rule_count: matched_info.len(),
        matched_rules: matched_info,
    }
}
