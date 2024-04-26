use super::{CodeDB, StateDB};
use crate::{
    evm_types::OpcodeId,
    l2_types::{BlockTrace, ExecStep},
    utils::is_precompiled,
    Address, Error, H256,
};
use ethers_core::types::Bytes;
use std::collections::hash_map::Entry;

impl CodeDB {
    /// Update codedb from statedb and trace
    pub fn update_codedb(&mut self, sdb: &StateDB, block: &BlockTrace) -> Result<(), Error> {
        log::debug!("build_codedb for block {:?}", block.header.number);
        for (er_idx, execution_result) in block.execution_results.iter().enumerate() {
            if let Some(bytecode) = &execution_result.byte_code {
                let bytecode = decode_bytecode(bytecode)?.to_vec();

                let code_hash = execution_result
                    .to
                    .as_ref()
                    .and_then(|t| t.poseidon_code_hash)
                    .unwrap_or_else(|| CodeDB::hash(&bytecode));
                let code_hash = if code_hash.is_zero() {
                    CodeDB::hash(&bytecode)
                } else {
                    code_hash
                };
                if let Entry::Vacant(e) = self.0.entry(code_hash) {
                    e.insert(bytecode);
                    //log::debug!("inserted tx bytecode {:?} {:?}", code_hash, hash);
                }
                if execution_result.account_created.is_none() {
                    //assert_eq!(Some(hash), execution_result.code_hash);
                }
            }

            // filter all precompile calls, empty calls and create
            let mut call_trace = execution_result
                .call_trace
                .flatten_trace(&execution_result.prestate)
                .into_iter()
                .filter(|call| {
                    let is_call_to_precompile =
                        call.to.as_ref().map(is_precompiled).unwrap_or(false);
                    let is_call_to_empty = call.gas_used.is_zero()
                        && !call.call_type.is_create()
                        && call.is_callee_code_empty;
                    !(is_call_to_precompile || is_call_to_empty || call.call_type.is_create())
                })
                .collect::<Vec<_>>();
            log::trace!("call_trace: {call_trace:?}");

            for (idx, step) in execution_result.exec_steps.iter().enumerate().rev() {
                if step.op.is_create() {
                    continue;
                }
                let call = if step.op.is_call_or_create() {
                    // filter call to empty/precompile/!precheck_ok
                    if let Some(next_step) = execution_result.exec_steps.get(idx + 1) {
                        // the call doesn't have inner steps, it could be:
                        // - a call to a precompiled contract
                        // - a call to an empty account
                        // - a call that !is_precheck_ok
                        if next_step.depth != step.depth + 1 {
                            log::trace!("skip call step due to no inner step, curr: {step:?}, next: {next_step:?}");
                            continue;
                        }
                    } else {
                        // this is the final step, no inner steps
                        log::trace!("skip call step due this is the final step: {step:?}");
                        continue;
                    }
                    let call = call_trace.pop();
                    log::trace!("call_trace pop: {call:?}, current step: {step:?}");
                    call
                } else {
                    None
                };

                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let call = call.unwrap();
                            assert_eq!(call.call_type, step.op, "{call:?}");
                            let code_idx = if block.transactions[er_idx].to.is_none() {
                                0
                            } else {
                                1
                            };
                            let callee_code = data.get_code_at(code_idx);
                            // TODO: make nil code ("0x") is not None and assert None case
                            // assert!(
                            //     callee_code.is_none(),
                            //     "invalid trace: cannot get code of call: {step:?}"
                            // );
                            let code_hash = match step.op {
                                OpcodeId::CALL | OpcodeId::CALLCODE => data.get_code_hash_at(1),
                                OpcodeId::STATICCALL => data.get_code_hash_at(0),
                                _ => None,
                            };
                            let addr = call.to.unwrap();
                            self.trace_code(
                                code_hash,
                                callee_code.unwrap_or_default(),
                                step,
                                Some(addr),
                                sdb,
                            );
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                            unreachable!()
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            if code.is_none() {
                                log::warn!("unable to fetch code from step. {step:?}");
                                continue;
                            }
                            self.trace_code(None, code.unwrap(), step, None, sdb);
                        }

                        _ => {}
                    }
                }
            }
        }

        log::debug!("updating codedb done");
        Ok(())
    }

    fn trace_code(
        &mut self,
        code_hash: Option<H256>,
        code: Bytes,
        step: &ExecStep,
        addr: Option<Address>,
        sdb: &StateDB,
    ) {
        // first, try to read from sdb
        // let stack = match step.stack.as_ref() {
        //     Some(stack) => stack,
        //     None => {
        //         log::error!("stack underflow, step {step:?}");
        //         return;
        //     }
        // };
        // if stack_pos >= stack.len() {
        //     log::error!("stack underflow, step {step:?}");
        //     return;
        // }
        // let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos
        //
        let code_hash = code_hash.or_else(|| {
            addr.and_then(|addr| {
                let (_existed, acc_data) = sdb.get_account(&addr);
                if acc_data.code_hash != CodeDB::empty_code_hash() && !code.is_empty() {
                    // they must be same
                    Some(acc_data.code_hash)
                } else {
                    // let us re-calculate it
                    None
                }
            })
        });
        let code_hash = match code_hash {
            Some(code_hash) => {
                if code_hash.is_zero() {
                    CodeDB::hash(&code)
                } else {
                    if log::log_enabled!(log::Level::Trace) {
                        assert_eq!(
                            code_hash,
                            CodeDB::hash(&code),
                            "bytecode len {:?}, step {:?}",
                            code.len(),
                            step
                        );
                    }
                    code_hash
                }
            }
            None => {
                let hash = CodeDB::hash(&code);
                log::debug!(
                    "hash_code done: addr {addr:?}, size {}, hash {hash:?}",
                    &code.len()
                );
                hash
            }
        };

        self.0.entry(code_hash).or_insert_with(|| {
            log::trace!(
                "trace code addr {:?}, size {} hash {:?}",
                addr,
                &code.len(),
                code_hash
            );
            code.to_vec()
        });
    }
}

fn decode_bytecode(bytecode: &str) -> Result<Vec<u8>, Error> {
    let mut stripped = if let Some(stripped) = bytecode.strip_prefix("0x") {
        stripped.to_string()
    } else {
        bytecode.to_string()
    };

    let bytecode_len = stripped.len() as u64;
    if (bytecode_len & 1) != 0 {
        stripped = format!("0{stripped}");
    }

    hex::decode(stripped).map_err(Error::HexError)
}
