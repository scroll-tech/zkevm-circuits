RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_chunk_prover -- --nocapture 2>&1 | tee mock_chunk.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_aggregation -- --nocapture 2>&1 | tee mock_aggregation.log
RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_mock_compression -- --nocapture 2>&1 | tee compression.log

# the following 3 tests takes super long time
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_aggregation_circuit -- --ignored --nocapture 2>&1 | tee aggregation.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_two_layer_proof_compression -- --ignored --nocapture 2>&1 | tee compression_2_layer.log
# RUST_LOG=trace MODE=greeter cargo test --release --features=print-trace test_e2e -- --ignored --nocapture 2>&1 | tee aggregation_e2e.log
