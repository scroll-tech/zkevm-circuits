# Testool

The `testool` is a binary cli that focus on provide tools for testing.

To use it, just compile with `cargo build --release` and run `../target/release/testool`.

This tool at this moment has 2 main functionalities: run raw bytecode and run ethereum tests.

## Run oneliner spec

The oneliner spec is invoked by using `--oneliner` parameter

The spec has the following form

`txparams` `account 1` `account 2` ... `account n`

where 

- `txparams` have the form `call|create`;`calldata`;`value`;`gas`
  - if `create`is specified the `to` field in the tx is left blank, is not the first account specified is used as the contract to call
  - `calldata`,`value` and `gas` are optional
- `account` have the form `address`;`code`;`balance`;`slot 1`:`value 1`;..`slot n`..`value n`
  - `address` can be shortened, eg.`10` and `0x10` is expanded to `0x....10`
  - `code` is optional, and can be specified in hex or in asm (`PUSH1(1),PUSH1(1),MLOAD`)
  - `balance` and `value` are optional
  - `slot` and `value` can be specified multiple times 

example

- `../target/release/testool --oneliner "call 12;60016002"`: call contract `0x...12` that contains the code PUSH1(1) PUSH1(2)
- `../target/release/testool --oneliner "call;;2000 12;PUSH1(0),SLOAD,CALLVALUE,EQ,PUSH1(1),SSTORE;;00:2000"`: call the contract and send 2000 as value, and compare with the stored value (2000) in the slot 0, write into slot 1 

## Run the ethereum tests

Run

```
 ../target/release/testool --suite default
```
or

```
 ../target/release/testool --suite nightly
```

The "official EVM" ethereum tests are cloned as a gitmodule in `testool/tests`.
We are using the tests located in `testool/tests/src/GeneralStateTestsFiller`, but other locations can be specified, also.


### The ethereum tests files

These tests are written in `json` or `yml`, and, in general it specifies 4 sections:

- General environment to generate a block (blocknumber, timestamp, gaslimit, etc...)
- Initial account states (with its balance, nonce, storage, and code)
- A set of transactions to be executed from the initial state, each transaction defines one test
- The account states resulting of the execution of these transactions

You can find (here)[https://ethereum-tests.readthedocs.io/en/latest/test_filler/blockchain_filler.html] the specification for these files in detail.

Official ethereum tests are maintained by the foundation but you can write your own.

### Configuration file

The `Config.toml` configuration defines which files and tests to process.

#### Defining test suites

In the config file you define `[[suite]]`s that defines how tests will be executed.

- `id` is the identifier of the suite. The default suite is called `default`.
- `max_steps` the maximum number of executed opcodes. If this is reached, the test is marked to be ignored.
- `max_gas` the maximum gas of a test. If the specified maximum gas is reached, the test is marked to be ignored. Put a `0` if you do not want to limit it.
- you should define also only one of these parameters:
   - `allow_tests` with the list of tests or test sets to execute. All others will be excluded. Test sets should be prefixed with `&`
   - `ignore_tests` with the list of test or test sets to ignore. All others will be included. Test sets should be prefixed with `&`

#### Test sets

Test sets are created by using the `[[set]]` section and should define
- `id` the identification of the set (without any `&`). Note that ids can be duplicated, this means that are tests with the same id are joined together when used. 
- `desc` a description of the test set
- `tests` a list of tests

#### Skipping the execution of problematic tests

Sometimes there are some files or specific tests that we want to disable at all. Those are defined with:

- `[[skip_test]]` defines a set of tests that are always ignored.
- `[[skip_path]]` defined a set of files/folders that are always ignored. This is useful since sometimes there are some tests with weird encodings.

### Generating reports

When the command line parameter `--report` is defined, it automatically: 

- After the execution, a two files are created in the `report` folder. They are
   - `<timestamp>-<git_commit>.hml` with the browseable results of the execution.
   - `<timestamp>-<git_commit>.csv` with the raw results of the execution
- The HTML file also contains the diff with the previous result. The previous result file is the more recent csv file with different commit from the current one

Sometimes do you want to only re-execute tests that are marked as `Ignored` (because you are implementing something new). In this case, you can specify `--cache <>.csv` to use the previous results.

NOTE: if you do not execute with `--report` the tool will exit the process with `1` if there is any test that is not working.


### Manually executing the tests

Usually we have to debug and run the tests manually to check if everything works ok. We provide a set of command line parameters to help with this.

- `testool [--suite xxx] --cache <cache_file>` to execute all tests, and keeping the results (cache) CSV file. If you delete entries from the cache file, and re-run the tool again, only the deleted tests will be executed again

- `testool [--suite xxx] --inspect <test_id>` only executed the selected test (even if cached, or ignored). Use `RUST_BACKTRACE=1` here to check if anything fails. Also gives a dump of the test as also to the geth steps executed.
