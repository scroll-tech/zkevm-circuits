pub use super::block::{Block, BlockContext};
use crate::{
    circuit_input_builder::{self, BlockHead, CircuitInputBuilder, CircuitsParams},
    error::Error,
    state_db::{self, CodeDB, StateDB},
};
use eth_types::{
    self,
    evm_types::OpcodeId,
    l2_types::{BlockTrace, EthBlock, ExecStep, StorageTrace},
    Address, ToAddress, ToWord, Word, H256,
};
use ethers_core::types::Bytes;
use mpt_zktrie::state::{AccountData, ZktrieState};
use std::collections::hash_map::{Entry, HashMap};

impl From<&AccountData> for state_db::Account {
    fn from(acc_data: &AccountData) -> Self {
        if acc_data.keccak_code_hash.is_zero() {
            state_db::Account::zero()
        } else {
            Self {
                nonce: acc_data.nonce.into(),
                balance: acc_data.balance,
                code_hash: acc_data.poseidon_code_hash,
                keccak_code_hash: acc_data.keccak_code_hash,
                code_size: acc_data.code_size.into(),
                storage: Default::default(),
            }
        }
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

fn trace_code(
    cdb: &mut CodeDB,
    code_hash: Option<H256>,
    code: Bytes,
    step: &ExecStep,
    sdb: &StateDB,
    stack_pos: usize,
) {
    // first, try to read from sdb
    let stack = match step.stack.as_ref() {
        Some(stack) => stack,
        None => {
            log::error!("stack underflow, step {step:?}");
            return;
        }
    };
    if stack_pos >= stack.len() {
        log::error!("stack underflow, step {step:?}");
        return;
    }
    let addr = stack[stack.len() - stack_pos - 1].to_address(); //stack N-stack_pos

    let code_hash = code_hash.or_else(|| {
        let (_existed, acc_data) = sdb.get_account(&addr);
        if acc_data.code_hash != CodeDB::empty_code_hash() && !code.is_empty() {
            // they must be same
            Some(acc_data.code_hash)
        } else {
            // let us re-calculate it
            None
        }
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

    cdb.0.entry(code_hash).or_insert_with(|| {
        log::trace!(
            "trace code addr {:?}, size {} hash {:?}",
            addr,
            &code.len(),
            code_hash
        );
        code.to_vec()
    });
}

fn update_codedb(cdb: &mut CodeDB, sdb: &StateDB, block: &BlockTrace) -> Result<(), Error> {
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
            if let Entry::Vacant(e) = cdb.0.entry(code_hash) {
                e.insert(bytecode);
                //log::debug!("inserted tx bytecode {:?} {:?}", code_hash, hash);
            }
            if execution_result.account_created.is_none() {
                //assert_eq!(Some(hash), execution_result.code_hash);
            }
        }

        for step in execution_result.exec_steps.iter().rev() {
            if let Some(data) = &step.extra_data {
                match step.op {
                    OpcodeId::CALL
                    | OpcodeId::CALLCODE
                    | OpcodeId::DELEGATECALL
                    | OpcodeId::STATICCALL => {
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
                        trace_code(
                            cdb,
                            code_hash,
                            callee_code.unwrap_or_default(),
                            step,
                            sdb,
                            1,
                        );
                    }
                    OpcodeId::CREATE | OpcodeId::CREATE2 => {
                        // notice we do not need to insert code for CREATE,
                        // bustmapping do this job
                    }
                    OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                        let code = data.get_code_at(0);
                        if code.is_none() {
                            log::warn!("unable to fetch code from step. {step:?}");
                            continue;
                        }
                        trace_code(cdb, None, code.unwrap(), step, sdb, 0);
                    }

                    _ => {}
                }
            }
        }
    }

    log::debug!("updating codedb done");
    Ok(())
}

fn dump_code_db(cdb: &CodeDB) {
    for (k, v) in &cdb.0 {
        assert!(!k.is_zero());
        log::trace!("codedb codehash {:?}, len {}", k, v.len());
    }
}

impl CircuitInputBuilder {
    fn apply_l2_trace(&mut self, block_trace: &BlockTrace, is_last: bool) -> Result<(), Error> {
        log::trace!(
            "apply_l2_trace start, block num {:?}, is_last {is_last}",
            block_trace.header.number
        );
        //self.sdb.list_accounts();
        if is_last {
            dump_code_db(&self.code_db);
        }

        let geth_trace: Vec<eth_types::GethExecTrace> = block_trace
            .execution_results
            .iter()
            .map(From::from)
            .collect();
        let eth_block: EthBlock = block_trace.clone().into();
        assert_eq!(
            self.block.chain_id, block_trace.chain_id,
            "unexpected chain id in new block_trace"
        );
        // TODO: Get the history_hashes.
        let mut header = BlockHead::new_with_l1_queue_index(
            self.block.chain_id,
            block_trace.start_l1_queue_index,
            Vec::new(),
            &eth_block,
        )?;
        // override zeroed minder field with additional "coinbase" field in blocktrace
        if let Some(address) = block_trace.coinbase.address {
            header.coinbase = address;
        }
        let block_num = header.number.as_u64();
        // TODO: should be check the block number is in sequence?
        self.block.headers.insert(block_num, header);
        // note the actions when `handle_rwc_reversion` argument (the 4th one)
        // is true is executing outside this closure
        self.handle_block_inner(&eth_block, &geth_trace, false, is_last)?;
        log::debug!("apply_l2_trace done for block {:?}", block_num);
        //self.sdb.list_accounts();
        Ok(())
    }

    fn collect_account_proofs(
        storage_trace: &StorageTrace,
    ) -> impl Iterator<Item = (&Address, impl IntoIterator<Item = &[u8]>)> + Clone {
        storage_trace.proofs.iter().flat_map(|kv_map| {
            kv_map
                .iter()
                .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
        })
    }

    fn collect_storage_proofs(
        storage_trace: &StorageTrace,
    ) -> impl Iterator<Item = (&Address, &Word, impl IntoIterator<Item = &[u8]>)> + Clone {
        storage_trace.storage_proofs.iter().flat_map(|(k, kv_map)| {
            kv_map
                .iter()
                .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
        })
    }

    /// Create a new CircuitInputBuilder from the given `eth_block` and
    /// `StateDB`, `CodeDB`, `ZktrieState`
    pub fn new_with_trie_state(
        sdb: StateDB,
        code_db: CodeDB,
        mpt_init_state: ZktrieState,
        block: &Block,
    ) -> Self {
        Self {
            sdb,
            code_db,
            block: block.clone(),
            block_ctx: BlockContext::new(),
            mpt_init_state: Some(mpt_init_state),
        }
    }

    /// Create a new CircuitInputBuilder from the given `l2_trace` and `circuits_params`
    pub fn new_from_l2_trace(
        circuits_params: CircuitsParams,
        l2_trace: &BlockTrace,
        more: bool,
        light_mode: bool,
    ) -> Result<Self, Error> {
        let chain_id = l2_trace.chain_id;

        let old_root = l2_trace.storage_trace.root_before;
        log::debug!(
            "building zktrie state for block {:?}, old root {}",
            l2_trace.header.number,
            hex::encode(old_root),
        );

        let mpt_init_state = if !light_mode {
            let mpt_init_state = ZktrieState::from_trace_with_additional(
                old_root,
                Self::collect_account_proofs(&l2_trace.storage_trace),
                Self::collect_storage_proofs(&l2_trace.storage_trace),
                l2_trace
                    .storage_trace
                    .deletion_proofs
                    .iter()
                    .map(Bytes::as_ref),
            )
            .map_err(Error::IoError)?;

            log::debug!(
                "building partial statedb done, root {}",
                hex::encode(mpt_init_state.root())
            );

            Some(mpt_init_state)
        } else {
            None
        };

        let mut sdb = StateDB::new();
        for parsed in ZktrieState::parse_account_from_proofs(Self::collect_account_proofs(
            &l2_trace.storage_trace,
        )) {
            let (addr, acc) = parsed.map_err(Error::IoError)?;
            sdb.set_account(&addr, state_db::Account::from(&acc));
        }

        for parsed in ZktrieState::parse_storage_from_proofs(Self::collect_storage_proofs(
            &l2_trace.storage_trace,
        )) {
            let ((addr, key), val) = parsed.map_err(Error::IoError)?;
            *sdb.get_storage_mut(&addr, &key).1 = val.into();
        }

        /*
        let (zero_coinbase_exist, _) = sdb.get_account(&Default::default());
        if !zero_coinbase_exist {
            sdb.set_account(&Default::default(), state_db::Account::zero());
        }
        */

        let mut code_db = CodeDB::new();
        code_db.insert(Vec::new());
        update_codedb(&mut code_db, &sdb, l2_trace)?;

        let mut builder_block = circuit_input_builder::Block::from_headers(&[], circuits_params);
        builder_block.chain_id = chain_id;
        builder_block.prev_state_root = old_root.to_word();
        builder_block.start_l1_queue_index = l2_trace.start_l1_queue_index;
        let mut builder = Self {
            sdb,
            code_db,
            block: builder_block,
            block_ctx: BlockContext::new(),
            mpt_init_state,
        };

        builder.apply_l2_trace(l2_trace, !more)?;
        Ok(builder)
    }

    /// ...
    pub fn add_more_l2_trace(&mut self, l2_trace: &BlockTrace, more: bool) -> Result<(), Error> {
        // update init state new data from storage
        if let Some(mpt_init_state) = &mut self.mpt_init_state {
            mpt_init_state.update_from_trace(
                Self::collect_account_proofs(&l2_trace.storage_trace),
                Self::collect_storage_proofs(&l2_trace.storage_trace),
                l2_trace
                    .storage_trace
                    .deletion_proofs
                    .iter()
                    .map(Bytes::as_ref),
            );
        }

        let new_accounts = ZktrieState::parse_account_from_proofs(
            Self::collect_account_proofs(&l2_trace.storage_trace).filter(|(addr, _)| {
                let (existed, _) = self.sdb.get_account(addr);
                !existed
            }),
        )
        .fold(
            Ok(HashMap::new()),
            |m, parsed| -> Result<HashMap<_, _>, Error> {
                let mut m = m?;
                let (addr, acc) = parsed.map_err(Error::IoError)?;
                m.insert(addr, acc);
                Ok(m)
            },
        )?;

        for (addr, acc) in new_accounts {
            self.sdb.set_account(&addr, state_db::Account::from(&acc));
        }

        let new_storages = ZktrieState::parse_storage_from_proofs(
            Self::collect_storage_proofs(&l2_trace.storage_trace).filter(|(addr, key, _)| {
                let (existed, _) = self.sdb.get_committed_storage(addr, key);
                !existed
            }),
        )
        .fold(
            Ok(HashMap::new()),
            |m, parsed| -> Result<HashMap<(Address, Word), Word>, Error> {
                let mut m = m?;
                let ((addr, key), val) = parsed.map_err(Error::IoError)?;
                m.insert((addr, key), val.into());
                Ok(m)
            },
        )?;

        for ((addr, key), val) in new_storages {
            *self.sdb.get_storage_mut(&addr, &key).1 = val;
        }

        update_codedb(&mut self.code_db, &self.sdb, l2_trace)?;

        self.apply_l2_trace(l2_trace, !more)?;
        Ok(())
    }

    /// make finalize actions on building, must called after
    /// all block trace have been input
    pub fn finalize_building(&mut self) -> Result<(), Error> {
        self.set_value_ops_call_context_rwc_eor();
        self.set_end_block()
    }
}
