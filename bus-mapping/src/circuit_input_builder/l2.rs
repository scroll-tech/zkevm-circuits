pub use super::block::{BlockContext, Blocks};
use crate::{
    circuit_input_builder::{self, Block, CircuitInputBuilder, CircuitsParams},
    error::Error,
};
use eth_types::{
    self,
    l2_types::{trace::collect_codes, BlockTrace, StorageTrace},
    state_db::{self, CodeDB, StateDB},
    Address, EthBlock, ToWord, Word, H256,
};
use ethers_core::types::Bytes;
use mpt_zktrie::state::ZktrieState;
use std::collections::hash_map::HashMap;

fn dump_code_db(cdb: &CodeDB) {
    for (k, v) in &cdb.0 {
        assert!(!k.is_zero());
        log::trace!("codedb codehash {:?}, len {}", k, v.len());
    }
}

impl CircuitInputBuilder {
    fn apply_l2_trace(&mut self, block_trace: BlockTrace) -> Result<(), Error> {
        log::trace!(
            "apply_l2_trace start, block num {:?}",
            block_trace.header.number
        );
        //self.sdb.list_accounts();
        //dump_code_db(&self.code_db);

        let eth_block = EthBlock::from(&block_trace);
        log::trace!("eth_block block number {:?}", eth_block.number);
        let geth_trace: Vec<eth_types::GethExecTrace> = block_trace
            .execution_results
            .into_iter()
            .map(From::from)
            .collect();
        assert_eq!(
            self.block.chain_id, block_trace.chain_id,
            "unexpected chain id in new block_trace"
        );
        // Scroll EVM disables BLOCKHASH opcode, so here we don't need any hashes.
        let mut block = Block::new_with_l1_queue_index(
            self.block.chain_id,
            block_trace.start_l1_queue_index,
            Vec::new(),
            &eth_block,
        )?;
        // override zeroed minder field with additional "coinbase" field in blocktrace
        block.coinbase = block_trace.coinbase.address;
        let block_num = block.number.as_u64();
        // TODO: should be check the block number is in sequence?
        self.block.add_block(block);
        // note the actions when `handle_rwc_reversion` argument (the 4th one)
        // is true is executing outside this closure
        self.handle_block_inner(&eth_block, &geth_trace)?;

        // TODO: remove this when GethExecStep don't contains heap data
        // send to another thread to drop the heap data
        // here we use a magic number from benchmark to decide whether to
        // spawn-drop or not
        if !geth_trace.is_empty() && geth_trace[0].struct_logs.len() > 2000 {
            std::thread::spawn(move || {
                std::mem::drop(eth_block);
                std::mem::drop(geth_trace);
            });
        }

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
    ) -> impl Iterator<Item = (&Address, &H256, impl IntoIterator<Item = &[u8]>)> + Clone {
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
        block: &Blocks,
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
        l2_trace: BlockTrace,
    ) -> Result<Self, Error> {
        let chain_id = l2_trace.chain_id;

        let old_root = l2_trace.storage_trace.root_before;
        log::debug!(
            "building zktrie state for block {:?}, old root {}",
            l2_trace.header.number,
            hex::encode(old_root),
        );

        let mpt_init_state = if !l2_trace.storage_trace.flatten_proofs.is_empty() {
            log::info!("always init mpt state with flatten proofs");
            let mut state = ZktrieState::construct(old_root);
            let zk_db = state.expose_db();
            for (k, bytes) in &l2_trace.storage_trace.flatten_proofs {
                zk_db.add_node_bytes(bytes, Some(k.as_bytes())).unwrap();
            }
            zk_db.with_key_cache(
                l2_trace
                    .storage_trace
                    .address_hashes
                    .iter()
                    .map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            );
            zk_db.with_key_cache(
                l2_trace
                    .storage_trace
                    .store_key_hashes
                    .iter()
                    .map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            );

            log::debug!(
                "building partial ZktrieState done from new trace, root {}",
                hex::encode(state.root())
            );

            Some(state)
        } else {
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
                "building partial ZktrieState done, root {}",
                hex::encode(mpt_init_state.root())
            );

            Some(mpt_init_state)
        };

        let mut sdb = StateDB::new();
        if let Some(zk_state) = &mpt_init_state {
            for (addr, acc) in zk_state.query_accounts(
                Self::collect_account_proofs(&l2_trace.storage_trace).map(|(addr, _)| addr),
            ) {
                if let Some(acc) = acc {
                    log::trace!("sdb trace[query mode] {:?} {:?}", addr, acc);
                    sdb.set_account(&addr, state_db::Account::from(&acc));
                } else {
                    log::trace!("sdb trace[query mode] {:?} for zero account", addr);
                    sdb.set_account(&addr, state_db::Account::zero());
                }
            }

            for ((addr, key), val) in zk_state.query_storages(
                Self::collect_storage_proofs(&l2_trace.storage_trace)
                    .map(|(addr, key, _)| (addr, key)),
            ) {
                let key = key.to_word();
                if let Some(val) = val {
                    log::trace!(
                        "sdb trace storage[query mode] {:?} {:?} {:?}",
                        addr,
                        key,
                        val
                    );
                    *sdb.get_storage_mut(&addr, &key).1 = val.into();
                } else {
                    log::trace!(
                        "sdb trace storage[query mode] {:?} {:?} for zero",
                        addr,
                        key
                    );
                    *sdb.get_storage_mut(&addr, &key).1 = Default::default();
                }
            }
        } else {
            for parsed in ZktrieState::parse_account_from_proofs(Self::collect_account_proofs(
                &l2_trace.storage_trace,
            )) {
                let (addr, acc) = parsed.map_err(Error::IoError)?;
                log::trace!("sdb trace {:?} {:?}", addr, acc);
                sdb.set_account(&addr, state_db::Account::from(&acc));
            }

            for parsed in ZktrieState::parse_storage_from_proofs(Self::collect_storage_proofs(
                &l2_trace.storage_trace,
            )) {
                let ((addr, key), val) = parsed.map_err(Error::IoError)?;
                let key = key.to_word();
                log::trace!("sdb trace storage {:?} {:?} {:?}", addr, key, val);
                *sdb.get_storage_mut(&addr, &key).1 = val.into();
            }
        }

        let mut code_db = CodeDB::new();
        code_db.insert(Vec::new());

        let codes = collect_codes(&l2_trace)?;
        for (hash, code) in codes {
            code_db.insert_with_hash(hash, code);
        }

        let mut builder_block = circuit_input_builder::Blocks::init(chain_id, circuits_params);
        builder_block.prev_state_root = old_root;
        builder_block.start_l1_queue_index = l2_trace.start_l1_queue_index;
        let mut builder = Self {
            sdb,
            code_db,
            block: builder_block,
            block_ctx: BlockContext::new(),
            mpt_init_state,
        };

        builder.apply_l2_trace(l2_trace)?;
        Ok(builder)
    }

    /// Apply more l2 traces
    pub fn add_more_l2_trace(&mut self, l2_trace: BlockTrace) -> Result<(), Error> {
        // update init state new data from storage
        if !l2_trace.storage_trace.flatten_proofs.is_empty() {
            let mpt_state = self
                .mpt_init_state
                .as_mut()
                .expect("should have inited with flatten proof");
            log::info!("add more flatten proofs to mpt state");
            let zk_db = mpt_state.expose_db();
            for (k, bytes) in &l2_trace.storage_trace.flatten_proofs {
                zk_db.add_node_bytes(bytes, Some(k.as_bytes())).unwrap();
            }
            zk_db.with_key_cache(
                l2_trace
                    .storage_trace
                    .address_hashes
                    .iter()
                    .map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            );
            zk_db.with_key_cache(
                l2_trace
                    .storage_trace
                    .store_key_hashes
                    .iter()
                    .map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            );
        } else if let Some(mpt_init_state) = &mut self.mpt_init_state {
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

        let filtered_accounts =
            Self::collect_account_proofs(&l2_trace.storage_trace).filter(|(addr, _)| {
                let (existed, _) = self.sdb.get_account(addr);
                !existed
            });

        let new_accounts = if let Some(zk_state) = &self.mpt_init_state {
            zk_state
                .query_accounts(filtered_accounts.map(|(addr, _)| addr))
                .fold(HashMap::new(), |mut m, (addr, acc)| {
                    m.insert(addr, acc.unwrap_or_default());
                    m
                })
        } else {
            ZktrieState::parse_account_from_proofs(filtered_accounts).try_fold(
                HashMap::new(),
                |mut m, parsed| -> Result<HashMap<_, _>, Error> {
                    let (addr, acc) = parsed.map_err(Error::IoError)?;
                    m.insert(addr, acc);
                    Ok(m)
                },
            )?
        };

        for (addr, acc) in new_accounts {
            self.sdb.set_account(&addr, state_db::Account::from(&acc));
        }

        let filtered_storages =
            Self::collect_storage_proofs(&l2_trace.storage_trace).filter(|(addr, key, _)| {
                let key = key.to_word();
                let (existed, _) = self.sdb.get_committed_storage(addr, &key);
                !existed
            });

        let new_storages = if let Some(zk_state) = &self.mpt_init_state {
            zk_state
                .query_storages(filtered_storages.map(|(addr, key, _)| (addr, key)))
                .fold(HashMap::new(), |mut m, ((addr, key), val)| {
                    if let Some(val) = val {
                        m.insert((addr, key.to_word()), val.into());
                    } else {
                        m.insert((addr, key.to_word()), Default::default());
                    }
                    m
                })
        } else {
            ZktrieState::parse_storage_from_proofs(filtered_storages).try_fold(
                HashMap::new(),
                |mut m, parsed| -> Result<HashMap<(Address, Word), Word>, Error> {
                    let ((addr, key), val) = parsed.map_err(Error::IoError)?;
                    m.insert((addr, key.to_word()), val.into());
                    Ok(m)
                },
            )?
        };

        for ((addr, key), val) in new_storages {
            *self.sdb.get_storage_mut(&addr, &key).1 = val;
        }

        let codes = collect_codes(&l2_trace)?;
        for (hash, code) in codes {
            self.code_db.insert_with_hash(hash, code);
        }

        self.apply_l2_trace(l2_trace)?;
        Ok(())
    }
}
