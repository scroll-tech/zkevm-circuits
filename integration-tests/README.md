# Integration Tests

Integration tests are located in this crate.  Each test group can be found
under a different file in `tests/`.

Contracts for tests are found in `contracts/`.

The full integration tests flow can be executed with the `run.sh` script, which
is used like this:
```
$ ./run.sh --help                
        Usage: ./run.sh [OPTIONS]
        Options:
          --sudo         Use sudo for docker compose commands.
          --steps ARG    Space separated list of steps to do.
                         Default: "setup gendata tests cleanup".
          --tests ARG    Space separated list of tests to run.
                         Default: "rpc".
          -h | --help    Show help
```

## Steps
1. Setup: Start the docker container that runs a fresh geth in dev mode, via
   docker compose.
2. Gendata: Run the `gen_blockchain_data` binary found in
   `src/bin/gen_blockchain_data.rs` which compiles the contracts, deploys them,
   and executes transactions; in order to generate blocks with a variety of
   data and transactions to be used in the tests.  The compiled output of the
   contracts will be written as json files in `contracts` next to the solidity
   source.  After completion, `gendata_output.json` will be generated with
   details of the executed transactions to be used as input vectors for the tests.
3. Tests: Run the specified tests groups.
4. Cleanup: Remove the geth docker container.

By default the `run.sh` script runs all the steps.  Specifying a smaller
combination of steps can be very useful for development: you can run the
`setup` and `gendata` once, and then iterate over the `tests` step to debug
specific functions being tested.

## Lib

Functions and constant parameters shared both in the `gendata` step and the tests
themselves are defined in `lib.rs`.

## Requirements

The following software needs to be installed to run the integration tests script:
- docker compose
- Rust toolchain
- `solc` version 0.7.x or 0.8.x
