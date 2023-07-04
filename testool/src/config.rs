use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Deserialize;

const CONFIG_FILE: &str = "Config.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub suite: Vec<TestSuite>,
    pub set: Vec<TestsSet>,
    pub skip_paths: Vec<SkipPaths>,
    pub skip_tests: Vec<SkipTests>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TestSuite {
    pub id: String,
    pub path: String,
    pub max_gas: u64,
    pub max_steps: u64,

    ignore_tests: Option<Vec<String>>,
    allow_tests: Option<Vec<String>>,
}

impl Default for TestSuite {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            path: String::default(),
            max_gas: u64::MAX,
            max_steps: u64::MAX,
            ignore_tests: Some(Vec::new()),
            allow_tests: None,
        }
    }
}

impl TestSuite {
    pub fn allowed(&self, test_id: &str) -> bool {
        if let Some(ignore_tests) = &self.ignore_tests {
            ignore_tests
                .binary_search_by(|id| id.as_str().cmp(test_id))
                .is_err()
        } else if let Some(allow_tests) = &self.allow_tests {
            allow_tests
                .binary_search_by(|id| id.as_str().cmp(test_id))
                .is_ok()
        } else {
            unreachable!()
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let content = std::fs::read_to_string(CONFIG_FILE)
            .context(format!("Unable to open {CONFIG_FILE}"))?;
        let mut config: Config = toml::from_str(&content).context("parsing toml")?;

        // Append all tests defined in sets into the tests
        config.suite = config
            .suite
            .clone()
            .into_iter()
            .map(|mut suite| {
                let (allow, defined) = match (&suite.allow_tests, &suite.ignore_tests) {
                    (Some(allow), None) => (true, allow),
                    (None, Some(ignore)) => (false, ignore),
                    _ => bail!("ignore_tests or allow_tests should be specified"),
                };
                let mut all = Vec::new();
                for test_name in defined {
                    if let Some(setname) = test_name.strip_prefix('&') {
                        let set: Vec<_> = config.set.iter().filter(|ts| ts.id == setname).collect();
                        ensure!(!set.is_empty(), "no tests sets found for id '{}'", setname);
                        set.iter().for_each(|ts| all.append(&mut ts.tests.clone()));
                    } else {
                        all.push(test_name.clone());
                    }
                }
                all.sort();
                if allow {
                    suite.allow_tests = Some(all);
                } else {
                    suite.ignore_tests = Some(all);
                }
                Ok(suite)
            })
            .collect::<Result<_>>()?;
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
