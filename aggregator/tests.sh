RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_pi_aggregation_mock_prover -- --nocapture 2>&1 | tee pi_mock.log
RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_pi_aggregation_real_prover -- --nocapture 2>&1 | tee pi_real.log
RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_chunk_prover -- --nocapture 2>&1 | tee mock_chunk.log


# the following 3 tests takes super long time
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_chunk_prover -- --nocapture 2>&1 | tee mock_chunk.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_two_layer_proof_compression -- --ignored --nocapture 2>&1 | tee compression2.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_aggregation_circuit -- --ignored --nocapture 2>&1 | tee aggregation.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_e2e -- --ignored --nocapture 2>&1 | tee aggregation.log
