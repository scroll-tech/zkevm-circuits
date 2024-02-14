# Circuits for zkEVM

[![CI checks](https://github.com/scroll-tech/zkevm-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/scroll-tech/zkevm-circuits/actions/workflows/ci.yml)

Check out the work in progress [specification](https://github.com/privacy-scaling-explorations/zkevm-specs) to learn how it works.


## Getting started

To run the same tests as the CI, please use: `make test-all`.

## Running benchmarks

There are currently several benchmarks to run in the workspace in regards to the circuits.
All use the `DEGREE` env var to specify the degree of the `K` parameter that you want
to use for your circuit in the bench process.
-   Keccak Circuit prover benches. -> `DEGREE=16 make packed_multi_keccak_bench`
-   EVM Circuit prover benches. -> `DEGREE=18 make evm_bench`.
-   State Circuit prover benches. -> `DEGREE=18 make state_bench`

You can also run all benchmarks by running: `make circuit_benches DEGREE=18`.

## GH Actions Benchmark Results

Circuit Benchmark Results are accessible here: https://grafana.zkevm-testnet.org/d/vofy8DAVz/circuit-benchmarks?orgId=1

- circuit_benchmarks panel displays:
    - overall test result
    - timers and system statistics
    - url for downloading prover log and sys stat files
    - clickable sysstats_url element that loads the memory and cpu utilization profiles for the given test


## Project Layout

This repository contains several Rust packages that implement the zkevm. The high-level structure of the repository is as follows:

[`bus-mapping`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/bus-mapping)

- a crate designed to parse EVM execution traces and manipulate all of the data they provide in order to obtain structured witness inputs for the EVM Proof and the State Proof.

[`circuit-benchmarks`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/circuit-benchmarks)

- Measures performance of each circuit based on proving and verifying time and execution trace parsing and generation for each subcircuit

[`eth-types`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/eth-types)

- Different types helpful for various components of the zkevm, such as execution trace parsing or circuits

[`external-tracer`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/external-tracer)

- Generates traces by connecting to an external tracer

[`gadgets`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/gadgets)

- Custom circuits that abstracts away low-level circuit detail.
- [What are gadgets?](https://zcash.github.io/halo2/concepts/gadgets.html)

[`geth-utils`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/geth-utils)

- Provides output from latest geth APIs (debug_trace) as test vectors

[`integration-tests`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/integration-tests)

- Integration tests for all circuits

[`keccak256`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/keccak256)

- Modules for Keccak hash circuit

[`mock`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/mock)

- Mock definitions and methods that are used to test circuits or opcodes

[`testool`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/testool)

- CLI that provides tools for testing

[`zkevm-circuits`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/zkevm-circuits/src)

- Main package that contains all circuit logic

[`zktrie`](https://github.com/scroll-tech/zkevm-circuits/tree/develop/zktrie)

- Modules for Merkle Patricia Trie circuit
