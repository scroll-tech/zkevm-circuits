#[macro_use]
extern crate prettytable;

use crate::statetest::StateTest;
use log::info;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub mod abi;
pub mod compiler;
pub mod config;
pub mod statetest;
pub mod utils;

pub const REPORT_FOLDER: &str = "report";
pub const CODEHASH_FILE: &str = "./codehash.txt";
pub const TEST_IDS_FILE: &str = "./test_ids.txt";

pub fn read_test_ids<P: AsRef<Path>>(file_path: P) -> anyhow::Result<Vec<String>> {
    let file_path = file_path.as_ref();
    let worker_index = env::var("WORKER_INDEX")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .expect("WORKER_INDEX not set");
    let total_workers = env::var("TOTAL_WORKERS")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .expect("TOTAL_WORKERS not set");
    info!("total workers: {total_workers}, worker index: {worker_index}");

    info!("read_test_ids from {:?}", file_path);
    let mut total_jobs = 0;
    let test_ids = BufReader::new(File::open(file_path)?)
        .lines()
        .map(|r| r.map(|line| line.trim().to_string()))
        .inspect(|_| total_jobs += 1)
        .enumerate()
        .filter_map(|(idx, line)| {
            if idx % total_workers == worker_index {
                Some(line)
            } else {
                None
            }
        })
        .collect::<anyhow::Result<Vec<String>, std::io::Error>>()?;

    info!("read_test_ids {} of {total_jobs}", test_ids.len());
    Ok(test_ids)
}

pub fn write_test_ids(test_ids: &[String]) -> anyhow::Result<()> {
    let mut fd = File::create(TEST_IDS_FILE)?;
    fd.write_all(test_ids.join("\n").as_bytes())?;

    Ok(())
}

pub fn load_tests(
    state_tests: &mut Vec<StateTest>,
    test_ids_path: Option<PathBuf>,
    exclude_test_ids_path: Option<PathBuf>,
) -> anyhow::Result<()> {
    if let Some(test_ids_path) = test_ids_path {
        if exclude_test_ids_path.is_some() {
            log::warn!("--exclude-test-ids is ignored");
        }
        let test_ids = read_test_ids(test_ids_path)?;
        let id_to_test: HashMap<_, _> = state_tests
            .iter()
            .map(|t| (t.id.clone(), t.clone()))
            .collect();
        state_tests.clear();
        state_tests.extend(
            test_ids
                .into_iter()
                .filter_map(|test_id| id_to_test.get(&test_id).cloned()),
        );
    } else {
        // sorting with reversed id string to prevent similar tests go together, so that
        // computing heavy tests will not trigger OOM.
        if let Some(exclude_test_ids_path) = exclude_test_ids_path {
            let buf = std::fs::read_to_string(exclude_test_ids_path)?;
            let set = buf.lines().map(|s| s.trim()).collect::<HashSet<_>>();
            state_tests.retain(|t| !set.contains(t.id.as_str()));
        }
        state_tests.sort_by_key(|t| t.id.chars().rev().collect::<String>());
    }

    Ok(())
}
