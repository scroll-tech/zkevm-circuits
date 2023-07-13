RUST_LOG=trace cargo test --release --features=print-trace,disable_proof_aggregation -- --nocapture 2>&1 | tee tests.log
