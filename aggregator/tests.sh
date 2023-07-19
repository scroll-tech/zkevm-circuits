RUST_LOG=trace cargo test --release --features=print-trace,disable_proof_aggregation -- --nocapture 2>&1 | tee tests_without_proof_agg.log
RUST_LOG=trace cargo test --release --features=print-trace,disable_pi_aggregation -- --nocapture 2>&1 | tee tests_without_pi_agg.log
RUST_LOG=trace cargo test --release --features=print-trace -- --nocapture 2>&1 | tee tests_aggregation.log