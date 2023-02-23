# Circuits for zkEVM

[![CI checks](https://github.com/privacy-scaling-explorations/zkevm-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/privacy-scaling-explorations/zkevm-circuits/actions/workflows/ci.yml)

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
