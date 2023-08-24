use super::{executor::run_test, CircuitsConfig, JsonStateTestBuilder, Results, StateTest};
use crate::{
    compiler::Compiler,
    config::{Config, TestSuite},
    statetest::{
        results::{ResultInfo, ResultLevel},
        YamlStateTestBuilder,
    },
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::{
    panic::AssertUnwindSafe,
    sync::{Arc, RwLock},
};

pub fn load_statetests_suite(
    path: &str,
    config: Config,
    compiler: Compiler,
) -> Result<Vec<StateTest>> {
    let skip_paths: Vec<&String> = config.skip_paths.iter().flat_map(|t| &t.paths).collect();
    let skip_tests: Vec<&String> = config.skip_tests.iter().flat_map(|t| &t.tests).collect();

    let tcs = glob::glob(path)
        .context("failed to read glob")?
        .filter_map(|v| v.ok())
        .filter(|f| {
            !skip_paths
                .iter()
                .any(|e| f.as_path().to_string_lossy().contains(*e))
        })
        .par_bridge()
        .filter_map(|file| {
            file.extension().and_then(|ext| {
                let ext = &*ext.to_string_lossy();
                if !["yml", "json"].contains(&ext) {
                    return None;
                }
                let path = file.as_path().to_string_lossy();
                let tcs = (|| -> Result<Vec<StateTest>> {
                    let src = std::fs::read_to_string(&file)?;
                    log::debug!(target: "testool", "Reading file {:?}", file);
                    let tcs = match ext {
                        "yml" => YamlStateTestBuilder::new(&compiler).load_yaml(&path, &src),
                        "json" => JsonStateTestBuilder::new(&compiler).load_json(&path, &src),
                        _ => unreachable!(),
                    };
                    let mut tcs = match tcs {
                        Ok(tcs) => tcs,
                        Err(e) => {
                            panic!("fail to load {:?}, err {:?}", path, e);
                        }
                    };

                    tcs.retain(|v| !skip_tests.contains(&&v.id));
                    Ok(tcs)
                })();

                Some(tcs)
            })
        })
        .collect::<Result<Vec<Vec<StateTest>>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<StateTest>>();
    Ok(tcs)
}

pub fn run_statetests_suite(
    tcs: Vec<StateTest>,
    circuits_config: &CircuitsConfig,
    suite: &TestSuite,
    results: &mut Results,
) -> Result<()> {
    // Filter already cached entries
    let all_test_count = tcs.len();
    let tcs: Vec<StateTest> = tcs
        .into_iter()
        .filter(|t| !results.contains(&format!("{}#{}", t.id, t.path)))
        .collect();

    log::info!(
        "{} test results cached, {} remaining",
        all_test_count - tcs.len(),
        tcs.len()
    );

    let results = Arc::new(RwLock::from(results));

    // for each test
    let test_count = tcs.len();
    tcs.into_par_iter().for_each(|ref tc| {
        let (test_id, path) = (tc.id.clone(), tc.path.clone());
        if !suite.allowed(&test_id) {
            results
                .write()
                .unwrap()
                .insert(ResultInfo {
                    test_id,
                    level: ResultLevel::Ignored,
                    details: "Ignored in config file".to_string(),
                    path,
                })
                .unwrap();
            return;
        }

        std::panic::set_hook(Box::new(|_info| {}));

        log::debug!(
            target : "testool",
            "🐕 running test (done {}/{}) {}#{}...",
            1 + results.read().unwrap().tests.len(),
            test_count,
            test_id,
            path,
        );
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            run_test(tc.clone(), suite.clone(), circuits_config.clone())
        }));

        // handle panic
        let result = match result {
            Ok(res) => res,
            Err(err) => {
                let panic_err = if let Some(s) = err.downcast_ref::<String>() {
                    s.to_string()
                } else if let Some(s) = err.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "unable to get panic info".into()
                };

                let level = if panic_err.contains("circuit was not satisfied") {
                    ResultLevel::Fail
                } else if panic_err.contains("evm_unimplemented") {
                    ResultLevel::Ignored
                } else {
                    ResultLevel::Panic
                };
                results
                    .write()
                    .unwrap()
                    .insert(ResultInfo {
                        test_id,
                        level,
                        details: panic_err,
                        path,
                    })
                    .unwrap();
                return;
            }
        };

        // handle known error
        if let Err(err) = result {
            results
                .write()
                .unwrap()
                .insert(ResultInfo {
                    test_id,
                    level: if err.is_skip() {
                        ResultLevel::Ignored
                    } else {
                        ResultLevel::Fail
                    },
                    details: err.to_string(),
                    path,
                })
                .unwrap();
            return;
        }

        results
            .write()
            .unwrap()
            .insert(ResultInfo {
                test_id,
                level: ResultLevel::Success,
                details: String::default(),
                path,
            })
            .unwrap();
    });

    Ok(())
}
