use eth_types::{
    constants::SCROLL_COINBASE,
    geth_types::{self, Account, BlockConstants},
    state_db::{self, CodeDB, StateDB},
    utils::hash_code_keccak,
    Address, EthBlock, GethExecTrace, ToWord, Word, H256, KECCAK_CODE_HASH_EMPTY,
};
use ethers_providers::JsonRpcClient;
use hex::decode_to_slice;

use super::{AccessSet, Block, Blocks, CircuitInputBuilder, CircuitsParams};
use crate::{error::Error, rpc::GethClient};

use std::str::FromStr;
use std::{collections::HashMap, iter};

/// Struct that wraps a GethClient and contains methods to perform all the steps
/// necessary to generate the circuit inputs for a block by querying geth for
/// the necessary information and using the CircuitInputBuilder.
pub struct BuilderClient<P: JsonRpcClient> {
    cli: GethClient<P>,
    chain_id: u64,
    circuits_params: CircuitsParams,
}

/// Build a partial StateDB from step 3
pub fn build_state_code_db(
    proofs: Vec<eth_types::EIP1186ProofResponse>,
    codes: HashMap<Address, Vec<u8>>,
) -> (StateDB, CodeDB) {
    let mut sdb = StateDB::new();
    for proof in proofs {
        let mut storage = HashMap::new();
        for storage_proof in proof.storage_proof {
            storage.insert(storage_proof.key, storage_proof.value);
        }
        sdb.set_account(
            &proof.address,
            state_db::Account {
                nonce: proof.nonce,
                balance: proof.balance,
                storage,
                code_hash: proof.code_hash,
                keccak_code_hash: proof.keccak_code_hash,
                code_size: proof.code_size,
            },
        )
    }

    let mut code_db = CodeDB::new();
    for (_address, code) in codes {
        code_db.insert(code.clone());
    }
    (sdb, code_db)
}

impl<P: JsonRpcClient> BuilderClient<P> {
    /// Create a new BuilderClient
    pub async fn new(
        client: GethClient<P>,
        circuits_params: CircuitsParams,
    ) -> Result<Self, Error> {
        let chain_id = client.get_chain_id().await?;

        Ok(Self {
            cli: client,
            chain_id,
            circuits_params,
        })
    }

    /// Step 1. Query geth for Block, Txs, TxExecTraces, history block hashes
    /// and previous state root.
    pub async fn get_block(
        &self,
        block_num: u64,
    ) -> Result<(EthBlock, Vec<eth_types::GethExecTrace>, Vec<Word>, Word), Error> {
        let eth_block = self.cli.get_block_by_number(block_num.into()).await?;
        let geth_traces = self.cli.trace_block_by_number(block_num.into()).await?;

        // fetch up to 256 blocks
        let mut n_blocks = 0; // std::cmp::min(256, block_num as usize);
        let mut next_hash = eth_block.parent_hash;
        let mut prev_state_root: Option<Word> = None;
        let mut history_hashes = vec![Word::default(); n_blocks];
        while n_blocks > 0 {
            n_blocks -= 1;

            // TODO: consider replacing it with `eth_getHeaderByHash`, it's faster
            let header = self.cli.get_block_by_hash(next_hash).await?;

            // set the previous state root
            if prev_state_root.is_none() {
                prev_state_root = Some(header.state_root.to_word());
            }

            // latest block hash is the last item
            let block_hash = header
                .hash
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .to_word();
            history_hashes[n_blocks] = block_hash;

            // continue
            next_hash = header.parent_hash;
        }

        Ok((
            eth_block,
            geth_traces,
            history_hashes,
            prev_state_root.unwrap_or_default(),
        ))
    }

    /// Step 2. Get State Accesses from TxExecTraces
    pub async fn get_state_accesses(&self, eth_block: &EthBlock) -> Result<AccessSet, Error> {
        let mut access_set = AccessSet::default();
        access_set.add_account(
            eth_block
                .author
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
        );
        let traces = self
            .cli
            .trace_block_prestate_by_hash(
                eth_block
                    .hash
                    .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?,
            )
            .await?;
        for trace in traces.into_iter() {
            access_set.extend_from_traces(&trace);
        }

        Ok(access_set)
    }

    /// Step 3. Query geth for all accounts, storage keys, and codes from
    /// Accesses
    pub async fn get_state(
        &self,
        block_num: u64,
        access_set: AccessSet,
    ) -> Result<
        (
            Vec<eth_types::EIP1186ProofResponse>,
            HashMap<Address, Vec<u8>>,
        ),
        Error,
    > {
        let mut proofs = Vec::new();
        for (address, key_set) in access_set.state {
            let mut keys: Vec<Word> = key_set.iter().cloned().collect();
            keys.sort();
            let proof = self
                .cli
                .get_proof(address, keys, (block_num - 1).into())
                .await
                .unwrap();
            proofs.push(proof);
        }
        let mut codes: HashMap<Address, Vec<u8>> = HashMap::new();
        for address in access_set.code {
            let code = self
                .cli
                .get_code(address, (block_num - 1).into())
                .await
                .unwrap();
            codes.insert(address, code);
        }
        Ok((proofs, codes))
    }

    /// Yet-another Step 3. Build account state and codes from geth tracing
    /// (of which has include the prestate tracing inside)
    /// the account state is limited since proof is not included,
    /// but it is enough to build the sdb/cdb
    /// for a block, it would handle exec traces of every tx in sequence
    #[allow(clippy::type_complexity)]
    pub fn get_pre_state<'a>(
        &self,
        traces: impl Iterator<Item = &'a GethExecTrace>,
    ) -> Result<
        (
            Vec<eth_types::EIP1186ProofResponse>,
            HashMap<Address, Vec<u8>>,
        ),
        Error,
    > {
        let mut account_set =
            HashMap::<Address, (eth_types::EIP1186ProofResponse, HashMap<Word, Word>)>::new();
        let mut code_set = HashMap::new();

        for trace in traces.map(|tr| tr.prestate.clone()) {
            for (addr, prestate) in trace.into_iter() {
                let (_, storages) = account_set.entry(addr).or_insert_with(|| {
                    let code_size =
                        Word::from(prestate.code.as_ref().map(|bt| bt.len()).unwrap_or(0));
                    let (code_hash, keccak_code_hash) = if let Some(bt) = prestate.code {
                        let h = CodeDB::hash(&bt);
                        // only require for L2
                        let keccak_h = if cfg!(feature = "scroll") {
                            hash_code_keccak(&bt)
                        } else {
                            h
                        };
                        code_set.insert(addr, Vec::from(bt.as_ref()));
                        (h, keccak_h)
                    } else {
                        (CodeDB::empty_code_hash(), *KECCAK_CODE_HASH_EMPTY)
                    };

                    (
                        eth_types::EIP1186ProofResponse {
                            address: addr,
                            balance: prestate.balance.unwrap_or_default(),
                            nonce: prestate.nonce.unwrap_or_default().into(),
                            code_hash,
                            keccak_code_hash,
                            code_size,
                            ..Default::default()
                        },
                        HashMap::new(),
                    )
                });

                if let Some(stg) = prestate.storage {
                    for (k, v) in stg {
                        storages.entry(k).or_insert(v);
                    }
                }
            }
        }

        Ok((
            account_set
                .into_iter()
                .map(|(_, (mut acc_resp, storage_proofs))| {
                    acc_resp.storage_proof = storage_proofs
                        .into_iter()
                        .map(|(key, value)| eth_types::StorageProof {
                            key,
                            value,
                            ..Default::default()
                        })
                        .collect();
                    acc_resp
                })
                .collect::<Vec<_>>(),
            code_set,
        ))
    }

    /// Yet-another Step 3-1. (hacking?) replenish the pre state proof
    /// with coinbase account
    /// since current the coibase is not touched in prestate tracing
    pub async fn complete_prestate(
        &self,
        eth_block: &EthBlock,
        mut proofs: Vec<eth_types::EIP1186ProofResponse>,
    ) -> Result<Vec<eth_types::EIP1186ProofResponse>, Error> {
        // a hacking? since the coinbase address is not touch in prestate
        let coinbase_addr = eth_block
            .author
            .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?;
        let block_num = eth_block
            .number
            .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?;
        assert_ne!(
            block_num.as_u64(),
            0,
            "is not expected to access genesis block"
        );

        if !proofs.iter().any(|pr| pr.address == coinbase_addr) {
            let coinbase_proof = self
                .cli
                .get_proof(coinbase_addr, Vec::new(), (block_num - 1).into())
                .await?;
            proofs.push(coinbase_proof);
        }
        Ok(proofs)
    }

    /// Step 4. Build a partial StateDB from step 3
    pub fn build_state_code_db(
        proofs: Vec<eth_types::EIP1186ProofResponse>,
        codes: HashMap<Address, Vec<u8>>,
    ) -> (StateDB, CodeDB) {
        build_state_code_db(proofs, codes)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        eth_block: &EthBlock,
        geth_traces: &[eth_types::GethExecTrace],
        history_hashes: Vec<Word>,
        _prev_state_root: Word,
    ) -> Result<CircuitInputBuilder, Error> {
        let mut blocks = Blocks::init(self.chain_id, self.circuits_params);
        let block = Block::new(self.chain_id, history_hashes, eth_block)?;
        blocks.add_block(block);
        let mut builder = CircuitInputBuilder::new(sdb, code_db, &blocks);
        builder.handle_block(eth_block, geth_traces)?;
        Ok(builder)
    }

    /// Step 5. For each step in TxExecTraces, gen the associated ops and state
    /// circuit inputs
    pub fn gen_inputs_from_state_multi_blocks(
        &self,
        sdb: StateDB,
        code_db: CodeDB,
        blocks_and_traces: &[(EthBlock, Vec<eth_types::GethExecTrace>)],
    ) -> Result<CircuitInputBuilder, Error> {
        let mut builder =
            CircuitInputBuilder::new_from_params(self.chain_id, self.circuits_params, sdb, code_db);
        for (eth_block, geth_traces) in blocks_and_traces {
            let block = Block::new(self.chain_id, Default::default(), eth_block)?;
            builder.block.blocks.insert(block.number.as_u64(), block);
            builder.handle_block_inner(eth_block, geth_traces)?;
        }
        builder.finalize_building()?;
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    #[allow(unused_mut)]
    #[allow(unused_variables)]
    pub async fn gen_inputs(
        &self,
        block_num: u64,
    ) -> Result<
        (
            CircuitInputBuilder,
            eth_types::Block<eth_types::Transaction>,
        ),
        Error,
    > {
        let (mut eth_block, mut geth_traces, history_hashes, prev_state_root) =
            self.get_block(block_num).await?;

        #[cfg(feature = "retrace-tx")]
        let builder = {
            let trace_config = self
                .get_trace_config(&eth_block, geth_traces.iter(), false)
                .await?;

            self.trace_to_builder(&eth_block, &trace_config)?
        };
        #[cfg(not(feature = "retrace-tx"))]
        let builder = {
            let (proofs, codes) = self.get_pre_state(geth_traces.iter())?;
            let proofs = self.complete_prestate(&eth_block, proofs).await?;
            let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
            if eth_block.transactions.len() > self.circuits_params.max_txs {
                log::error!(
                    "max_txs too small: {} < {} for block {}",
                    self.circuits_params.max_txs,
                    eth_block.transactions.len(),
                    eth_block.number.unwrap_or_default()
                );
                eth_block
                    .transactions
                    .truncate(self.circuits_params.max_txs);
                geth_traces.truncate(self.circuits_params.max_txs);
            }
            self.gen_inputs_from_state(
                state_db,
                code_db,
                &eth_block,
                &geth_traces,
                history_hashes,
                prev_state_root,
            )?
        };
        Ok((builder, eth_block))
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_multi_blocks(
        &self,
        block_num_begin: u64,
        block_num_end: u64,
    ) -> Result<CircuitInputBuilder, Error> {
        let mut blocks_and_traces = Vec::new();
        let mut access_set = AccessSet::default();
        for block_num in block_num_begin..block_num_end {
            let (eth_block, geth_traces, _, _) = self.get_block(block_num).await?;
            let mut access_list = self.get_state_accesses(&eth_block).await?;
            access_set.extend(&mut access_list);
            blocks_and_traces.push((eth_block, geth_traces));
        }
        let (proofs, codes) = self.get_state(block_num_begin, access_set).await?;
        let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
        let builder =
            self.gen_inputs_from_state_multi_blocks(state_db, code_db, &blocks_and_traces)?;
        Ok(builder)
    }

    /// Perform all the steps to generate the circuit inputs
    pub async fn gen_inputs_tx(&self, hash_str: &str) -> Result<CircuitInputBuilder, Error> {
        let mut hash: [u8; 32] = [0; 32];
        let hash_str = if &hash_str[0..2] == "0x" {
            &hash_str[2..]
        } else {
            hash_str
        };
        decode_to_slice(hash_str, &mut hash).unwrap();
        let tx_hash = H256::from(hash);

        let mut tx: eth_types::Transaction = self.cli.get_tx_by_hash(tx_hash).await?;
        tx.transaction_index = Some(0.into());
        let geth_trace = if cfg!(feature = "rpc-legacy-tracer") {
            self.cli.trace_tx_by_hash_legacy(tx_hash).await
        } else {
            self.cli.trace_tx_by_hash(tx_hash).await
        }?;
        let mut eth_block = self
            .cli
            .get_block_by_number(tx.block_number.unwrap().into())
            .await?;

        eth_block.transactions = vec![tx.clone()];

        #[cfg(feature = "retrace-tx")]
        let builder = {
            let trace_config = self
                .get_trace_config(&eth_block, iter::once(&geth_trace), true)
                .await?;

            self.trace_to_builder(&eth_block, &trace_config)?
        };
        #[cfg(not(feature = "retrace-tx"))]
        let builder = {
            let (proofs, codes) = self.get_pre_state(iter::once(&geth_trace))?;
            let proofs = self.complete_prestate(&eth_block, proofs).await?;
            let (state_db, code_db) = Self::build_state_code_db(proofs, codes);
            self.gen_inputs_from_state(
                state_db,
                code_db,
                &eth_block,
                &[geth_trace],
                Default::default(),
                Default::default(),
            )?
        };

        Ok(builder)
    }

    #[cfg(feature = "retrace-tx")]
    async fn get_trace_config(
        &self,
        eth_block: &EthBlock,
        geth_traces: impl Iterator<Item = &GethExecTrace>,
        complete_prestate: bool,
    ) -> Result<external_tracer::TraceConfig, Error> {
        let (proofs, codes) = self.get_pre_state(geth_traces)?;
        let proofs = if complete_prestate {
            self.complete_prestate(eth_block, proofs).await?
        } else {
            proofs
        };

        // We will not need to regen pk each time if we use same coinbase.
        //let coinbase =  eth_block.author.unwrap();
        let coinbase = Address::from_str(SCROLL_COINBASE).unwrap();
        //let difficulty = eth_block.difficulty;
        let difficulty = Word::zero();

        Ok(external_tracer::TraceConfig {
            chain_id: self.chain_id,
            history_hashes: vec![eth_block.parent_hash.to_word()],
            block_constants: BlockConstants {
                coinbase,
                timestamp: eth_block.timestamp,
                number: eth_block.number.unwrap(),
                difficulty,
                gas_limit: eth_block.gas_limit,
                base_fee: eth_block.base_fee_per_gas.unwrap(),
            },
            accounts: proofs
                .into_iter()
                .map(|proof| {
                    let acc = Account {
                        address: proof.address,
                        nonce: proof.nonce,
                        balance: proof.balance,
                        code: codes
                            .get(&proof.address)
                            .cloned()
                            .unwrap_or_default()
                            .into(),
                        storage: proof
                            .storage_proof
                            .into_iter()
                            .map(|proof| (proof.key, proof.value))
                            .collect(),
                    };
                    (proof.address, acc)
                })
                .collect(),
            transactions: eth_block
                .transactions
                .iter()
                .map(geth_types::Transaction::from)
                .collect(),
            logger_config: Default::default(),
            chain_config: None,
            #[cfg(feature = "scroll")]
            l1_queue_index: 0,
        })
    }

    #[cfg(feature = "retrace-tx")]
    fn trace_to_builder(
        &self,
        _eth_block: &EthBlock,
        trace_config: &external_tracer::TraceConfig,
    ) -> Result<CircuitInputBuilder, Error> {
        let block_trace = external_tracer::l2trace(trace_config)?;
        let mut builder =
            CircuitInputBuilder::new_from_l2_trace(self.circuits_params, block_trace, false)?;
        builder
            .finalize_building()
            .expect("could not finalize building block");
        Ok(builder)
    }

    /*
    // Seems useless?
    fn trace_to_builder(
        &self,
        eth_block: &EthBlock,
        trace_config: &TraceConfig,
    ) -> Result<CircuitInputBuilder, Error> {
        let geth_traces = external_tracer::trace(trace_config)?;
        let geth_data = geth_types::GethData {
            chain_id: trace_config.chain_id,
            history_hashes: trace_config.history_hashes.clone(),
            geth_traces: geth_traces.clone(),
            accounts: trace_config.accounts.values().cloned().collect(),
            eth_block: eth_block.clone(),
        };
        let block_data =
            crate::mock::BlockData::new_from_geth_data_with_params(geth_data, self.circuits_params);
        let mut builder = block_data.new_circuit_input_builder();
        builder.handle_block(eth_block, &geth_traces)?;
        Ok(builder)
    }
    */
}
