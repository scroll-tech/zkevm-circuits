use crate::{
    evm_types::OpcodeId,
    l2_types::BlockTrace,
    state_db::{CodeDB, StateDB},
    utils::is_precompiled,
    Address, Error, H256,
};
use ethers_core::types::Bytes;
use itertools::Itertools;

/// Update codedb from statedb and trace
pub fn collect_codes(
    block: &BlockTrace,
    sdb: Option<&StateDB>,
) -> Result<Vec<(H256, Vec<u8>)>, Error> {
    if !block.codes.is_empty() {
        log::debug!("codes available in trace, skip collecting");
        return Ok(block
            .codes
            .iter()
            .map(|b| (b.hash, b.code.to_vec()))
            .collect_vec());
    }

    log::debug!("collect_codes for block {:?}", block.header.number);
    if sdb.is_none() {
        log::warn!("collect_codes without sdb can be slow");
    }
    let mut codes = Vec::new();
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
            codes.push((code_hash, bytecode));
            //log::debug!("inserted tx bytecode {:?} {:?}", code_hash, hash);
        }

        // filter all precompile calls, empty calls and create
        let mut call_trace = execution_result
            .call_trace
            .flatten_trace(&execution_result.prestate)
            .into_iter()
            .filter(|call| {
                let is_call_to_precompile = call.to.as_ref().map(is_precompiled).unwrap_or(false);
                let is_call_to_empty = call.gas_used.is_zero()
                    && !call.call_type.is_create()
                    && call.is_callee_code_empty;
                !(is_call_to_precompile || is_call_to_empty || call.call_type.is_create())
            })
            .collect::<Vec<_>>();
        //log::trace!("call_trace: {call_trace:?}");

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
                //log::trace!("call_trace pop: {call:?}, current step: {step:?}");
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
                        let code_hash = match step.op {
                            OpcodeId::CALL | OpcodeId::CALLCODE => data.get_code_hash_at(1),
                            OpcodeId::STATICCALL => data.get_code_hash_at(0),
                            _ => None,
                        };
                        let addr = call.to.unwrap();
                        trace_code(
                            &mut codes,
                            code_hash,
                            callee_code.unwrap_or_default(),
                            Some(addr),
                            sdb,
                        );
                    }
                    OpcodeId::EXTCODECOPY => {
                        let code = data.get_code_at(0);
                        if code.is_none() {
                            log::warn!("unable to fetch code from step. {step:?}");
                            continue;
                        }
                        trace_code(&mut codes, None, code.unwrap(), None, sdb);
                    }

                    _ => {}
                }
            }
        }
    }

    log::debug!("collect codes done");
    Ok(codes)
}

fn trace_code(
    codes: &mut Vec<(H256, Vec<u8>)>,
    code_hash: Option<H256>,
    code: Bytes,
    addr: Option<Address>,
    // sdb is used to read codehash if available without recomputing
    sdb: Option<&StateDB>,
) {
    let code_hash = code_hash.or_else(|| {
        let addr = addr?;
        let sdb = sdb.as_ref()?;
        let (_existed, acc_data) = sdb.get_account(&addr);
        if acc_data.code_hash != CodeDB::empty_code_hash() && !code.is_empty() {
            Some(acc_data.code_hash)
        } else {
            None
        }
    });
    let code_hash = match code_hash {
        Some(code_hash) if !code_hash.is_zero() => code_hash,
        _ => {
            let hash = CodeDB::hash(&code);
            log::debug!(
                "hash_code done: addr {addr:?}, size {}, hash {hash:?}",
                &code.len()
            );
            hash
        }
    };
    codes.push((code_hash, code.to_vec()));
    log::trace!(
        "trace code addr {:?}, size {} hash {:?}",
        addr,
        &code.len(),
        code_hash
    );
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
