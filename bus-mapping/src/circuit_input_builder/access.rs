use crate::{operation::RW, Error};
use eth_types::{
    evm_types::OpcodeId, Address, GethExecStep, GethExecTrace, GethPrestateTrace, ToAddress, Word,
};
use ethers_core::utils::get_contract_address;
use std::collections::{hash_map::Entry, HashMap, HashSet};

use AccessValue::{Account, Code, Storage};
use RW::{READ, WRITE};

/// State and Code Access with "keys/index" used in the access operation.
#[derive(Debug, PartialEq, Eq)]
pub enum AccessValue {
    /// Account access
    Account {
        /// Account address
        address: Address,
    },
    /// Storage access
    Storage {
        /// Storage account address
        address: Address,
        /// Storage key
        key: Word,
    },
    /// Code access
    Code {
        /// Code address
        address: Address,
    },
}

/// State Access caused by a transaction or an execution step
#[derive(Debug, PartialEq, Eq)]
pub struct Access {
    step_index: Option<usize>,
    rw: RW,
    value: AccessValue,
}

impl Access {
    pub(crate) fn new(step_index: Option<usize>, rw: RW, value: AccessValue) -> Self {
        Self {
            step_index,
            rw,
            value,
        }
    }
}

/// Given a trace and assuming that the first step is a *CALL*/CREATE* kind
/// opcode, return the result if found.
fn get_call_result(trace: &[GethExecStep]) -> Option<Word> {
    let depth = trace[0].depth;
    trace[1..]
        .iter()
        .find(|s| s.depth == depth)
        .and_then(|s| s.stack.last().ok())
}

/// State and Code Access set.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct AccessSet {
    /// Set of accounts
    pub state: HashMap<Address, HashSet<Word>>,
    /// Set of accounts code
    pub code: HashSet<Address>,
}

impl AccessSet {
    #[inline(always)]
    pub(crate) fn add_account(&mut self, address: Address) {
        self.state.entry(address).or_default();
    }

    #[inline(always)]
    pub(crate) fn add_storage(&mut self, address: Address, key: Word) {
        match self.state.entry(address) {
            Entry::Vacant(entry) => {
                let mut storage = HashSet::new();
                storage.insert(key);
                entry.insert(storage);
            }
            Entry::Occupied(mut entry) => {
                entry.get_mut().insert(key);
            }
        }
    }

    #[inline(always)]
    pub(crate) fn add_code(&mut self, address: Address) {
        self.state.entry(address).or_default();
        self.code.insert(address);
    }

    pub(crate) fn extend_from_access(&mut self, list: Vec<Access>) {
        for access in list {
            match access.value {
                AccessValue::Account { address } => self.add_account(address),
                AccessValue::Storage { address, key } => self.add_storage(address, key),
                AccessValue::Code { address } => self.add_code(address),
            }
        }
    }

    pub(crate) fn extend_from_traces(&mut self, traces: &HashMap<Address, GethPrestateTrace>) {
        for (address, trace) in traces.iter() {
            self.add_account(*address);
            self.add_code(*address);
            if let Some(ref storage) = trace.storage {
                for key in storage.keys() {
                    self.add_storage(*address, *key);
                }
            }
        }
    }

    pub(crate) fn extend(&mut self, other: &mut Self) {
        self.state.extend(other.state.drain());
        self.code.extend(other.code.drain());
    }
}

impl From<Vec<Access>> for AccessSet {
    fn from(list: Vec<Access>) -> Self {
        let mut access_set = AccessSet::default();
        access_set.extend_from_access(list);
        access_set
    }
}

/// Source of the code in the EVM execution.
#[derive(Debug, Clone, Copy)]
pub enum CodeSource {
    /// Code comes from a deployed contract at `Address`.
    Address(Address),
    /// Code comes from tx.data when tx.to == null.
    Tx,
    /// Code comes from Memory by a CREATE* opcode.
    Memory,
}

impl Default for CodeSource {
    fn default() -> Self {
        Self::Tx
    }
}

/// Generate the State Access trace from the given trace.  All state read/write
/// accesses are reported, without distinguishing those that happen in revert
/// sections.
pub fn gen_state_access_trace<TX>(
    _block: &eth_types::Block<TX>,
    tx: &eth_types::Transaction,
    geth_trace: &GethExecTrace,
) -> Result<Vec<Access>, Error> {
    let mut call_stack: Vec<(Address, CodeSource)> = Vec::new();
    let mut accs = vec![Access::new(None, WRITE, Account { address: tx.from })];
    if let Some(to) = tx.to {
        call_stack.push((to, CodeSource::Address(to)));
        accs.push(Access::new(None, WRITE, Account { address: to }));
        // Code may be null if the account is not a contract
        accs.push(Access::new(None, READ, Code { address: to }));
    } else {
        let address = get_contract_address(tx.from, tx.nonce);
        call_stack.push((address, CodeSource::Tx));
        accs.push(Access::new(None, WRITE, Account { address }));
        accs.push(Access::new(None, WRITE, Code { address }));
    }

    for (index, step) in geth_trace.struct_logs.iter().enumerate() {
        let next_step = geth_trace.struct_logs.get(index + 1);
        let i = Some(index);
        let (contract_address, code_source) = &call_stack[call_stack.len() - 1];
        let (contract_address, code_source) = (*contract_address, *code_source);

        let (mut push_call_stack, mut pop_call_stack) = (false, false);
        if let Some(next_step) = next_step {
            push_call_stack = step.depth + 1 == next_step.depth;
            pop_call_stack = step.depth - 1 == next_step.depth;
        }

        let result: Result<(), Error> = (|| {
            match step.op {
                OpcodeId::SSTORE => {
                    let address = contract_address;
                    let key = step.stack.last()?;
                    accs.push(Access::new(i, WRITE, Storage { address, key }));
                }
                OpcodeId::SLOAD => {
                    let address = contract_address;
                    let key = step.stack.last()?;
                    accs.push(Access::new(i, READ, Storage { address, key }));
                }
                OpcodeId::SELFBALANCE => {
                    let address = contract_address;
                    accs.push(Access::new(i, READ, Account { address }));
                }
                OpcodeId::CODESIZE => {
                    if let CodeSource::Address(address) = code_source {
                        accs.push(Access::new(i, READ, Code { address }));
                    }
                }
                OpcodeId::CODECOPY => {
                    if let CodeSource::Address(address) = code_source {
                        accs.push(Access::new(i, READ, Code { address }));
                    }
                }
                OpcodeId::BALANCE => {
                    let address = step.stack.last()?.to_address();
                    accs.push(Access::new(i, READ, Account { address }));
                }
                OpcodeId::EXTCODEHASH => {
                    let address = step.stack.last()?.to_address();
                    accs.push(Access::new(i, READ, Account { address }));
                }
                OpcodeId::EXTCODESIZE => {
                    let address = step.stack.last()?.to_address();
                    accs.push(Access::new(i, READ, Code { address }));
                }
                OpcodeId::EXTCODECOPY => {
                    let address = step.stack.last()?.to_address();
                    accs.push(Access::new(i, READ, Code { address }));
                }
                OpcodeId::SELFDESTRUCT => {
                    let address = contract_address;
                    accs.push(Access::new(i, WRITE, Account { address }));
                    let address = step.stack.last()?.to_address();
                    accs.push(Access::new(i, WRITE, Account { address }));
                }
                OpcodeId::CREATE => {
                    if push_call_stack {
                        // Find CREATE result
                        let address = get_call_result(&geth_trace.struct_logs[index..])
                            .unwrap_or_else(Word::zero)
                            .to_address();
                        if !address.is_zero() {
                            accs.push(Access::new(i, WRITE, Account { address }));
                            accs.push(Access::new(i, WRITE, Code { address }));
                        }
                        call_stack.push((address, CodeSource::Address(address)));
                    }
                }
                OpcodeId::CREATE2 => {
                    if push_call_stack {
                        // Find CREATE2 result
                        let address = get_call_result(&geth_trace.struct_logs[index..])
                            .unwrap_or_else(Word::zero)
                            .to_address();
                        if !address.is_zero() {
                            accs.push(Access::new(i, WRITE, Account { address }));
                            accs.push(Access::new(i, WRITE, Code { address }));
                        }
                        call_stack.push((address, CodeSource::Address(address)));
                    }
                }
                OpcodeId::CALL => {
                    let address = contract_address;
                    accs.push(Access::new(i, WRITE, Account { address }));

                    let address = step.stack.nth_last(1)?.to_address();
                    accs.push(Access::new(i, WRITE, Account { address }));
                    accs.push(Access::new(i, READ, Code { address }));
                    if push_call_stack {
                        call_stack.push((address, CodeSource::Address(address)));
                    }
                }
                OpcodeId::CALLCODE => {
                    let address = contract_address;
                    accs.push(Access::new(i, WRITE, Account { address }));

                    let address = step.stack.nth_last(1)?.to_address();
                    accs.push(Access::new(i, WRITE, Account { address }));
                    accs.push(Access::new(i, READ, Code { address }));
                    if push_call_stack {
                        call_stack.push((address, CodeSource::Address(address)));
                    }
                }
                OpcodeId::DELEGATECALL => {
                    let address = step.stack.nth_last(1)?.to_address();
                    accs.push(Access::new(i, READ, Code { address }));
                    if push_call_stack {
                        call_stack.push((contract_address, CodeSource::Address(address)));
                    }
                }
                OpcodeId::STATICCALL => {
                    let address = step.stack.nth_last(1)?.to_address();
                    accs.push(Access::new(i, READ, Code { address }));
                    if push_call_stack {
                        call_stack.push((address, CodeSource::Address(address)));
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(e) = result {
            log::warn!("err when parsing access: {:?}, step {:?}", e, step);
        }

        if pop_call_stack {
            if call_stack.len() == 1 {
                return Err(Error::InvalidGethExecStep(
                    "gen_state_access_trace: call stack will be empty",
                    Box::new(step.clone()),
                ));
            }
            call_stack.pop().expect("call stack is empty");
        }
    }
    Ok(accs)
}
