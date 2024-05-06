pub use super::block::{Block, BlockContext};
use crate::{
    circuit_input_builder::{self, BlockHead, CircuitInputBuilder, CircuitsParams},
    error::Error,
};
use eth_types::{
    self,
    l2_types::{BlockTrace, EthBlock, StorageTrace},
    state_db::{self, CodeDB, StateDB},
    Address, ToWord, Word,
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
    fn apply_l2_trace(&mut self, block_trace: BlockTrace, is_last: bool) -> Result<(), Error> {
        log::trace!(
            "apply_l2_trace start, block num {:?}, is_last {is_last}",
            block_trace.header.number
        );
        //self.sdb.list_accounts();
        if is_last {
            dump_code_db(&self.code_db);
        }

        let eth_block = EthBlock::from(&block_trace);
        let geth_trace: Vec<eth_types::GethExecTrace> = block_trace
            .execution_results
            .into_iter()
            .map(From::from)
            .collect();
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
        l2_trace: BlockTrace,
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
        code_db.update_codedb(&sdb, &l2_trace)?;

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
    pub fn add_more_l2_trace(&mut self, l2_trace: BlockTrace, more: bool) -> Result<(), Error> {
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
        .try_fold(
            HashMap::new(),
            |mut m, parsed| -> Result<HashMap<_, _>, Error> {
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
        .try_fold(
            HashMap::new(),
            |mut m, parsed| -> Result<HashMap<(Address, Word), Word>, Error> {
                let ((addr, key), val) = parsed.map_err(Error::IoError)?;
                m.insert((addr, key), val.into());
                Ok(m)
            },
        )?;

        for ((addr, key), val) in new_storages {
            *self.sdb.get_storage_mut(&addr, &key).1 = val;
        }

        self.code_db.update_codedb(&self.sdb, &l2_trace)?;

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
