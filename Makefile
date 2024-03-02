help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

clippy: ## Run clippy checks over all workspace members
	@cargo check --all-features
	@cargo clippy --all-features --all-targets -- -D warnings

doc: ## Generate and tests docs including private items
	@cargo doc --no-deps --all --document-private-items

fmt: ## Check whether the code is formated correctly
	@cargo check --all-features
	@cargo fmt --all -- --check

test-light: ## Run light tests
	@cargo test --release --workspace --exclude integration-tests --exclude circuit-benchmarks

test-heavy: ## Run heavy tests serially to avoid OOM
	@cargo test --release --features scroll --all --exclude integration-tests --exclude circuit-benchmarks serial_  -- --ignored --skip max_tx # --test-threads 1

test: test-light test-heavy ## Run tests for all the workspace members

test-doc: ## Test the docs
	@cargo test --release --all --all-features --doc

test-benches: ## Compiles the benchmarks
	@cargo test --verbose --release --all-features -p circuit-benchmarks --no-run

test-all: fmt doc clippy test-doc test-benches test ## Run all the CI checks locally (in your actual toolchain)

super_bench: ## Run Super Circuit benchmarks
	@cargo test --profile bench bench_super_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

evm_bench: ## Run Evm Circuit benchmarks
	@cargo test --profile bench bench_evm_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

state_bench: ## Run State Circuit benchmarks
	@cargo test --profile bench bench_state_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

packed_multi_keccak_bench: ## Run Packed Multi Keccak Circuit benchmarks
	@cargo test --profile bench bench_packed_multi_keccak_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

bytecode_bench: ## Run Bytecode Circuit benchmarks
	@cargo test --profile bench bench_bytecode_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

pi_bench: ## Run Public Input Circuit benchmarks
	@cargo test --profile bench bench_pi_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

copy_bench: ## Run Copy Circuit benchmarks
	@cargo test --profile bench bench_copy_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

tx_bench: ## Run Tx Circuit benchmarks
	@cargo test --profile bench bench_tx_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

exp_bench: ## Run Exp Circuit benchmarks
	@cargo test --profile bench bench_exp_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture

circuit_benches: evm_bench state_bench ## Run All Circuit benchmarks

stats_state_circuit: # Print a table with State Circuit stats by ExecState/opcode
	@cargo test -p zkevm-circuits --features=test,warn-unimplemented get_state_states_stats -- --nocapture --ignored

stats_evm_circuit: # Print a table with EVM Circuit stats by ExecState/opcode
	@cargo test -p zkevm-circuits --features=test,warn-unimplemented get_evm_states_stats -- --nocapture --ignored

stats_copy_circuit: # Print a table with Copy Circuit stats by ExecState/opcode
	@cargo test -p zkevm-circuits --features=test,warn-unimplemented get_copy_states_stats -- --nocapture --ignored

evm_exec_steps_occupancy: # Print a table for each EVM-CellManager CellType with the top 10 occupancy ExecutionSteps associated
	@cargo test -p zkevm-circuits --release get_exec_steps_occupancy --features=test,warn-unimplemented -- --nocapture --ignored

testool_docker_build_inner_prove:
	docker build --build-arg TESTOOL_FEATURE=inner-prove -f docker/testool/gpu/Dockerfile -t testool-inner-prove:v0.1 .

testool_docker_build_chunk_prove:
	docker build --build-arg TESTOOL_FEATURE=chunk-prove -f docker/testool/gpu/Dockerfile -t testool-chunk-prove:v0.1 .

.PHONY: clippy doc fmt test test_benches test-all evm_bench state_bench circuit_benches evm_exec_steps_occupancy stats_state_circuit stats_evm_circuit stats_copy_circuit help testool_docker_build_inner_prove testool_docker_build_chunk_prove
