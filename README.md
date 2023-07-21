# zkEVM Circuits

This repo contains all the zkEVM circuits code.

To learn about internal mechanics, please refer to [specification](https://github.com/privacy-scaling-explorations/zkevm-specs).

## Code Structure

```
.
├── README.md
├── aggregator                // An aggregation circuit takes in a batch of k proofs, each for a chunk of blocks. It generates a single proof asserting the validity of all the proofs
├── bus-mapping               // a crate designed to parse EVM execution traces and manipulate all of the data they provide in order to obtain structured witness inputs for the EVM Proof and the State Proof
├── circuit-benchmarks        // Measures performance of each circuit based on proving and verifying time and execution trace parsing and generation for each subcircuit
├── eth-types                 // Different types helpful for various components of the zkevm, such as execution trace parsing or circuits
├── external-tracer           // Generates traces by connecting to an external tracer
├── gadgets                   // Custom circuits that abstracts away low-level circuit detail. [What are gadgets?](https://zcash.github.io/halo2/concepts/gadgets.html)
├── geth-utils                // Provides output from latest geth APIs (debug_trace) as test vectors
├── integration-tests         // Integration tests for all circuits
├── keccak256                 // Modules for Keccak hash circuit
├── mock                      // Mock definitions and methods that are used to test circuits or opcodes
├── testool                   // CLI that provides tools for testing
├── zkevm-circuits            // Main package that contains all circuit logic
└── zktrie                    // Modules for Merkle Patricia Trie circuit
```

## Development

### Run Tests

```
# Install packages
# Install Golang: https://go.dev/doc/install

# Run the same tests as the CI
make test-all

# Run integration test
cargo test --release --workspace

# Run single unit test by a single file
cargo test --test file_name (do not ending with '.rs')

# Run format check
cargo fmt -- --check tests/filename.rs

# Format code
cargo fmt -- tests/filename.rs
```

### Merge Changes from Original Repo

```
# Fetch latest changes
git remote add upstream https://github.com/scroll-tech/zkevm-circuits.git
git fetch upstream
git checkout develop
git merge upstream/develop

# Then we can create a new branch and file a PR for the latest changes
git checkout -b new-branch
```

### Run Benchmarks

There are currently several benchmarks to run in the workspace in regards to the circuits.
All use the `DEGREE` env var to specify the degree of the `K` parameter that you want 
to use for your circuit in the bench process.
-   Keccak Circuit prover benches. -> `DEGREE=16 make packed_multi_keccak_bench`
-   EVM Circuit prover benches. -> `DEGREE=18 make evm_bench`.
-   State Circuit prover benches. -> `DEGREE=18 make state_bench`

You can also run all benchmarks by running: `make circuit_benches DEGREE=18`.

Circuit Benchmark Results are accessible here: https://grafana.zkevm-testnet.org/d/vofy8DAVz/circuit-benchmarks?orgId=1

- circuit_benchmarks panel displays:
    - overall test result
    - timers and system statistics
    - url for downloading prover log and sys stat files
    - clickable sysstats_url element that loads the memory and cpu utilization profiles for the given test
