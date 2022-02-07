//! Generate the benchmark file for State Circuit fetching the bench parameters
//! from ENV.

use std::env::var;
use std::fs::*;
use std::io::Write;

fn main() {
    let degree: usize = var("DEGREE")
        .unwrap_or_else(|_| "11".to_string())
        .parse()
        .expect("Cannot parse DEGREE env var as usize");
    let memory_address_max: usize = var("MEMORY_ADDRESS_MAX")
        .unwrap_or_else(|_| "2000".to_string())
        .parse()
        .expect("Cannot parse MEMORY_ADDRESS_MAX env var as usize");
    let stack_address_max: usize = var("STACK_ADDRESS_MAX")
        .unwrap_or_else(|_| "1300".to_string())
        .parse()
        .expect("Cannot parse STACK_ADDRESS_MAX env var as usize");

    // Add state_circuit module to `lib.rs`
    let consts = format!(
        "pub(crate) const DEGREE: usize = {};
pub(crate) const MEMORY_ADDRESS_MAX: usize = {};
pub(crate) const STACK_ADDRESS_MAX: usize = {};
",
        degree, memory_address_max, stack_address_max
    );

    let mut state_file =
        File::create("src/bench_params.rs").expect("Error generating bench_params.rs file");
    state_file
        .write_all(consts.as_bytes())
        .expect("Error writing to bench_params.rs file");
}
