//! Generate the benchmark file for State Circuit fetching the bench parameters
//! from ENV.

use std::env::var;
use std::fs::*;
use std::io::Write;

fn main() {
    let degree: usize = var("DEGREE")
        .unwrap_or_else(|_| "17".to_string())
        .parse()
        .expect("Cannot parse DEGREE env var as usize");

    // Add state_circuit module to `lib.rs`
    let consts = format!("pub(crate) const DEGREE: usize = {};\n", degree,);

    let mut state_file =
        File::create("src/bench_params.rs").expect("Error generating bench_params.rs file");
    state_file
        .write_all(consts.as_bytes())
        .expect("Error writing to bench_params.rs file");
}
