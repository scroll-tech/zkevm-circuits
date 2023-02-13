//! ![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/appliedzkp/zkevm-circuits/CI%20checks/main?style=for-the-badge)
//! Bus-Mapping is a crate designed to parse EVM execution traces and manipulate
//! all of the data they provide in order to obtain structured witness inputs
//! for the EVM Proof and the State Proof.
//!
//! ## Introduction
//! At the moment every node on ethereum has to validate every transaction in
//! the ethereum virtual machine. This means that every transaction adds work
//! that everyone needs to do to verify Ethereum’s history. Worse still is that
//! each transaction needs to be verified by every new node. Which means the
//! amount of work a new node needs to do the sync the network is growing
//! constantly. We want to build a proof of validity for the Ethereum blocks to
//! avoid this.
//!
//! This means making a proof of validity for the EVM + state reads / writes +
//! signatures.
//! To simplify we separate our proofs into two components.
//!
//! - State proof: State/memory/stack ops have been performed correctly. This
//! does not check if the correct location has been read/written. We allow our
//! prover to pick any location here and in the EVM proof confirm it is correct.
//!
//! - EVM proof: This checks that the correct opcode is called at the correct
//! time. It checks the validity of these opcodes. It also confirms that for
//! each of these opcodes the state proof performed the correct operation.
//!
//! Only after verifying both proofs are we confident that that Ethereum block
//! is executed correctly.
//!
//! ## Bus Mapping
//! The goal of this crate is to serve as:
//! - A parsing lib for EVM execution traces.
//! - A way to infer some witness data that can only be constructed once we've
//!   analyzed the full exec trace.
//! - An easy interface to collect all of the data to witness into the circuits
//!   and witness it with few function calls.
//!
//! ## Parsing
//! Provided a JSON file or a JSON as a stream of bytes, which contains an
//! execution trace from an EVM, you can parse it and construct an
//! `ExecutionTrace` instance from it. That will automatically fill all of the
//! bus-mapping instances of each
//! [`GethExecStep`](eth_types::GethExecStep).  Then the
//! [`CircuitInputBuilder`](crate::circuit_input_builder::CircuitInputBuilder)
//! will fill in an
//! [`OperationContainer`](crate::operation::container::OperationContainer)
//! with all of the Memory, Stack and Storage ops performed
//! by the provided trace.
//!
//! ```rust
//! use bus_mapping::{Error, mock::BlockData};
//! use bus_mapping::state_db::{self, StateDB, CodeDB};
//! use eth_types::{
//!     self, address, Address, Word, Hash, U64, GethExecTrace, GethExecStep, geth_types::GethData, bytecode
//! };
//! use mock::test_ctx::{TestContext, helpers::*};
//! use eth_types::evm_types::Gas;
//! use bus_mapping::circuit_input_builder::{Block, CircuitInputBuilder};
//!
//! let input_trace = r#"
//! [
//!     {
//!         "pc": 5,
//!         "op": "PUSH1",
//!         "gas": 82,
//!         "gasCost": 3,
//!         "refund": 0,
//!         "depth": 1,
//!         "stack": [],
//!         "memory": [
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000080"
//!         ]
//!       },
//!       {
//!         "pc": 7,
//!         "op": "MLOAD",
//!         "gas": 79,
//!         "gasCost": 3,
//!         "refund": 0,
//!         "depth": 1,
//!         "stack": [
//!           "40"
//!         ],
//!         "memory": [
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000080"
//!         ]
//!       },
//!       {
//!         "pc": 8,
//!         "op": "STOP",
//!         "gas": 76,
//!         "gasCost": 0,
//!         "refund": 0,
//!         "depth": 1,
//!         "stack": [
//!           "80"
//!         ],
//!         "memory": [
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000000",
//!           "0000000000000000000000000000000000000000000000000000000000000080"
//!         ]
//!       }
//! ]
//! "#;
//!
//! // We use the [`TestContext`] struct to mock a block.
//! let code = bytecode! {
//!     // Write 0x6f to storage slot 0
//!     PUSH1(0x6fu64)
//!     PUSH1(0x00u64)
//!     SSTORE
//!     // Load storage slot 0
//!     PUSH1(0x00u64)
//!     SLOAD
//!     STOP
//! };
//!
//! // Get the execution steps from the external tracer
//! let block: GethData = TestContext::<2, 1>::new(
//!     None,
//!     account_0_code_account_1_no_code(code),
//!     tx_from_1_to_0,
//!     |block, _tx| block.number(0xcafeu64),
//! )
//! .unwrap()
//! .into();
//!
//! // Here we update the circuit input with the data from the transaction trace.
//! let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
//! builder
//!     .handle_block(&block.eth_block, &block.geth_traces)
//!     .unwrap();
//!
//! let geth_steps: Vec<GethExecStep> = serde_json::from_str(input_trace).unwrap();
//! let geth_trace = GethExecTrace {
//!     return_value: "".to_string(),
//!     gas: Gas(block.eth_block.transactions[0].gas.as_u64()),
//!     failed: false,
//!     struct_logs: geth_steps,
//! };
//!
//! // Get an ordered vector with all of the Stack operations of this trace.
//! let stack_ops = builder.block.container.sorted_stack();
//!
//! // You can also iterate over the steps of the trace and witness the EVM Proof.
//! builder.block.txs()[0].steps().iter();
//! ```
//!
//! Assume we have the following trace:
//! ```text,ignore
//! pc  op              stack (top -> down)                  memory
//! --  --------------  ----------------------------------   ---------------------------------------
//! ...
//! 53  JUMPDEST        [    ,          ,           ,    ]   {40: 80,  80:          ,  a0:         }
//! 54  PUSH1 40        [    ,          ,           ,  40]   {40: 80,  80:          ,  a0:         }
//! 56  MLOAD           [    ,          ,           ,  80]   {40: 80,  80:          ,  a0:         }
//! 57  PUSH4 deadbeaf  [    ,          ,   deadbeef,  80]   {40: 80,  80:          ,  a0:         }
//! 62  DUP2            [    ,        80,   deadbeef,  80]   {40: 80,  80:          ,  a0:         }
//! 63  MSTORE          [    ,          ,           ,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 64  PUSH4 faceb00c  [    ,          ,   faceb00c,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 69  DUP2            [    ,        80,   faceb00c,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 70  MLOAD           [    ,  deadbeef,   faceb00c,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 71  ADD             [    ,          ,  1d97c6efb,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 72  DUP2            [    ,        80,  1d97c6efb,  80]   {40: 80,  80:  deadbeef,  a0:         }
//! 73  MSTORE          [    ,          ,           ,  80]   {40: 80,  80: 1d97c6efb,  a0:         }
//! 74  PUSH4 cafeb0ba  [    ,          ,   cafeb0ba,  80]   {40: 80,  80: 1d97c6efb,  a0:         }
//! 79  PUSH1 20        [    ,        20,   cafeb0ba,  80]   {40: 80,  80: 1d97c6efb,  a0:         }
//! 81  DUP3            [  80,        20,   cafeb0ba,  80]   {40: 80,  80: 1d97c6efb,  a0:         }
//! 82  ADD             [    ,        a0,   cafeb0ba,  80]   {40: 80,  80: 1d97c6efb,  a0:         }
//! 83  MSTORE          [    ,          ,           ,  80]   {40: 80,  80: 1d97c6efb,  a0: cafeb0ba}
//! 84  POP             [    ,          ,           ,    ]   {40: 80,  80: 1d97c6efb,  a0: cafeb0ba}
//! ...
//! ```
//!
//! Once you have the trace built (following the code found above) you can
//! basically:
//! - Get an iterator/vector over the `Stack`, `Memory` or `Storage` operations
//!   ordered on the way the State Proof needs.
//!
//! On that way, we would get something like this for the Memory ops:
//! ```text,ignore
//! | `key`  | `val`         | `rw`    | `gc` | Note                                     |
//! |:------:| ------------- | ------- | ---- | ---------------------------------------- |
//! | `0x40` | `0`           | `Write` |      | Init                                     |
//! | `0x40` | `0x80`        | `Write` | 0    | Assume written at the begining of `code` |
//! | `0x40` | `0x80`        | `Read`  | 4    | `56 MLOAD`                               |
//! |   -    |               |         |      |                                          |
//! | `0x80` | `0`           | `Write` |      | Init                                     |
//! | `0x80` | `0xdeadbeef`  | `Write` | 10   | `63 MSTORE`                              |
//! | `0x80` | `0xdeadbeef`  | `Read`  | 16   | `70 MLOAD`                               |
//! | `0x80` | `0x1d97c6efb` | `Write` | 24   | `73 MSTORE`                              |
//! |   -    |               |         |      |                                          |
//! | `0xa0` | `0`           | `Write` |      | Init                                     |
//! | `0xa0` | `0xcafeb0ba`  | `Write` | 34   | `83 MSTORE`
//! ```
//!
//! Where as you see, we group by `memory_address` and then order by
//! `global_counter`.
//!
//! - Iterate over the `ExecutionTrace` itself over
//! each `ExecutionStep`'s is formed by and check which Stack/Memory&Storage
//! operations are linked to each step. This is also automatically done via the
//! [`Opcode`](crate::evm::opcodes::Opcode) trait defined in this crate.
//!
//! ## Documentation
//! For extra documentation, check the book with the specs written for the
//! entire ZK-EVM solution.
//! See: <https://hackmd.io/@liangcc/zkvmbook/https%3A%2F%2Fhackmd.io%2FAmhZ2ryITxicmhYFyQ0DEw#Bus-Mapping>

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// We want to have UPPERCASE idents sometimes.
#![allow(non_snake_case)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
//#![deny(unsafe_code)] Allowed now until we find a
// better way to handle downcasting from Operation into it's variants.
#![allow(clippy::upper_case_acronyms)] // Too pedantic
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::result_large_err)] // it's large, but what can we do?

extern crate alloc;
extern crate core;

pub mod circuit_input_builder;
pub mod error;
pub mod evm;
pub mod exec_trace;
pub(crate) mod geth_errors;
pub mod mock;
pub mod operation;
pub mod precompile;
pub mod rpc;
pub mod state_db;
pub mod util;

pub use error::Error;
