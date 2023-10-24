use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

const CONFIG_FILE: &str = "Config.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub suite: Vec<TestSuite>,
    pub set: Vec<TestsSet>,
    #[serde(default)]
    pub skip_paths: Vec<SkipPaths>,
    #[serde(default)]
    pub skip_tests: Vec<SkipTests>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestSuite {
    pub id: String,
    pub path: String,
    pub max_gas: u64,
    pub max_steps: u64,

    ignore_tests: Option<Filter>,
    allow_tests: Option<Filter>,
}

impl Default for TestSuite {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            path: String::default(),
            max_gas: u64::MAX,
            max_steps: u64::MAX,
            ignore_tests: Some(Filter::any()),
            allow_tests: None,
        }
    }
}

impl TestSuite {
    pub fn allowed(&self, test_id: &str) -> bool {
        if let Some(ignore_tests) = &self.ignore_tests {
            !ignore_tests.matches(test_id)
        } else if let Some(allow_tests) = &self.allow_tests {
            allow_tests.matches(test_id)
        } else {
            unreachable!()
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let content = std::fs::read_to_string(CONFIG_FILE)
            .context(format!("Unable to open {CONFIG_FILE}"))?;
        let config: Config = toml::from_str(&content).context("parsing toml")?;
        Ok(config)
    }
    pub fn suite(&self, name: &str) -> Result<&TestSuite> {
        self.suite
            .iter()
            .find(|s| s.id == name)
            .ok_or_else(|| anyhow!("Suite not found"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestsSet {
    pub id: String,
    pub desc: Option<String>,
    pub tests: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SkipPaths {
    pub desc: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SkipTests {
    pub desc: Option<String>,
    pub tests: Vec<String>,
}

#[derive(Debug)]
struct FilterBuilder {
    regex: Vec<String>,
}

impl From<&[&str]> for FilterBuilder {
    fn from(value: &[&str]) -> Self {
        let regex = value
            .iter()
            .map(|s| {
                let glob = regex::escape(s)
                    .replace(r"\*", ".*")
                    .replace(r"\?", ".")
                    .replace(r"\[!", "[^")
                    .replace(r"\[", "[")
                    .replace(r"\]", "]");
                format!("(?:{glob})")
            })
            .collect();
        Self { regex }
    }
}

impl FilterBuilder {
    fn build(self) -> Filter {
        let regex = regex::Regex::new(&format!("^{}$", self.regex.join("|"))).unwrap();
        Filter(regex)
    }
}

#[derive(Debug, Clone)]
pub struct Filter(regex::Regex);

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let strings: Vec<&str> = Deserialize::deserialize(deserializer)?;
        let builder = FilterBuilder::from(strings.as_slice());
        Ok(builder.build())
    }
}

impl Filter {
    pub fn any() -> Self {
        Filter(regex::Regex::new("^.*$").unwrap())
    }
    pub fn matches(&self, test_id: &str) -> bool {
        self.0.is_match(test_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILTER_TESTS: &[&str] = &["tests/src/GeneralStateTestsFiller/**/*"];

    #[test]
    fn test_filter() {
        let builder = FilterBuilder::from(FILTER_TESTS);
        println!("{builder:?}");
    }
}
