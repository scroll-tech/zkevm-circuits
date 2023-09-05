use super::{AccountMatch, StateTest, StateTestResult};
use crate::config::TestSuite;
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams, PrecompileEcParams},
    state_db::CodeDB,
};

#[cfg(feature = "scroll")]
use eth_types::ToBigEndian;
use eth_types::{
    geth_types, geth_types::TxType, Address, Bytes, GethExecTrace, ToWord, H256, U256, U64,
};
use ethers_core::{
    types::{transaction::eip2718::TypedTransaction, TransactionRequest},
    utils::keccak256,
};
use ethers_signers::LocalWallet;
use external_tracer::{LoggerConfig, TraceConfig};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit};
use itertools::Itertools;
use once_cell::sync::Lazy;
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;
use zkevm_circuits::{
    bytecode_circuit::circuit::BytecodeCircuit, ecc_circuit::EccCircuit,
    modexp_circuit::ModExpCircuit, sig_circuit::SigCircuit, super_circuit::SuperCircuit,
    test_util::CircuitTestBuilder, util::SubCircuit, witness::Block,
};

/// Read env var with default value
pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}
/// Which circuit to test. Default is evm + state.
pub static CIRCUIT: Lazy<String> = Lazy::new(|| read_env_var("CIRCUIT", "".to_string()));

#[derive(PartialEq, Eq, Error, Debug)]
pub enum StateTestError {
    #[cfg(not(feature = "scroll"))]
    #[error("CannotGenerateCircuitInput({0})")]
    CircuitInput(String),
    #[error("BalanceMismatch(expected:{expected:?}, found:{found:?})")]
    BalanceMismatch { expected: U256, found: U256 },
    #[error("NonceMismatch(expected:{expected:?}, found:{found:?})")]
    NonceMismatch { expected: U256, found: U256 },
    #[error("CodeMismatch(expected: {expected:?}, found:{found:?})")]
    CodeMismatch { expected: Bytes, found: Bytes },
    #[error("StorgeMismatch(slot:{slot:?} expected:{expected:?}, found: {found:?})")]
    StorageMismatch {
        slot: U256,
        expected: U256,
        found: U256,
    },
    #[error("SkipTestMaxGasLimit({0})")]
    SkipTestMaxGasLimit(u64),
    #[error("SkipTestMaxSteps({0})")]
    SkipTestMaxSteps(usize),
    #[error("SkipTestSelfDestruct")]
    SkipTestSelfDestruct,
    #[error("SkipTestDifficulty")]
    // scroll evm always returns 0 for "difficulty" opcode
    SkipTestDifficulty,
    #[error("SkipTestBalanceOverflow")]
    SkipTestBalanceOverflow,
    #[error("Exception(expected:{expected:?}, found:{found:?})")]
    Exception { expected: bool, found: String },
}

impl StateTestError {
    pub fn is_skip(&self) -> bool {
        // Avoid lint `variant is never constructed` if no feature skip-self-destruct.
        let _ = StateTestError::SkipTestSelfDestruct;
        let _ = StateTestError::SkipTestDifficulty;
        let _ = StateTestError::SkipTestBalanceOverflow;

        matches!(
            self,
            StateTestError::SkipTestMaxSteps(_)
                | StateTestError::SkipTestMaxGasLimit(_)
                | StateTestError::SkipTestSelfDestruct
                | StateTestError::SkipTestBalanceOverflow
                | StateTestError::SkipTestDifficulty
        )
    }
}

#[derive(Default, Debug, Clone)]
pub struct CircuitsConfig {
    pub super_circuit: bool,
    pub verbose: bool,
}

fn check_post(
    builder: &CircuitInputBuilder,
    post: &HashMap<Address, AccountMatch>,
) -> Result<(), StateTestError> {
    log::trace!("check post");
    // check if the generated account data is the expected one
    for (address, expected) in post {
        let (_, actual) = builder.sdb.get_account(address);

        if expected.balance.map(|v| v == actual.balance) == Some(false) {
            log::error!("balance mismatch, expected {expected:?} actual {actual:?}");
            return Err(StateTestError::BalanceMismatch {
                expected: expected.balance.unwrap(),
                found: actual.balance,
            });
        }

        if expected.nonce.map(|v| v == actual.nonce) == Some(false) {
            log::error!("nonce mismatch, expected {expected:?} actual {actual:?}");
            return Err(StateTestError::NonceMismatch {
                expected: expected.nonce.unwrap(),
                found: actual.nonce,
            });
        }

        if let Some(expected_code) = &expected.code {
            let actual_code = if actual.code_hash.is_zero() {
                std::borrow::Cow::Owned(Vec::new())
            } else {
                std::borrow::Cow::Borrowed(&builder.code_db.0[&actual.code_hash])
            };
            if &actual_code as &[u8] != expected_code.0 {
                return Err(StateTestError::CodeMismatch {
                    expected: expected_code.clone(),
                    found: Bytes::from(actual_code.to_vec()),
                });
            }
        }
        for (slot, expected_value) in &expected.storage {
            let actual_value = actual.storage.get(slot).cloned().unwrap_or_else(U256::zero);
            if expected_value != &actual_value {
                log::error!(
                    "StorageMismatch address {address:?}, expected {expected:?} actual {actual:?}"
                );
                return Err(StateTestError::StorageMismatch {
                    slot: *slot,
                    expected: *expected_value,
                    found: actual_value,
                });
            }
        }
    }
    log::trace!("check post done");
    Ok(())
}

fn into_traceconfig(st: StateTest) -> (String, TraceConfig, StateTestResult) {
    let chain_id = 1;
    let wallet = LocalWallet::from_str(&hex::encode(st.secret_key.0)).unwrap();
    let mut tx = TransactionRequest::new()
        .chain_id(chain_id)
        .from(st.from)
        .nonce(st.nonce)
        .value(st.value)
        .data(st.data.clone())
        .gas(st.gas_limit)
        .gas_price(st.gas_price);

    if let Some(to) = st.to {
        tx = tx.to(to);
    }
    let rlp_unsigned = tx.rlp().to_vec();
    let tx: TypedTransaction = tx.into();

    let sig = wallet.sign_transaction_sync(&tx);
    let rlp_signed = tx.rlp_signed(&sig).to_vec();
    let tx_hash = keccak256(tx.rlp_signed(&sig));
    let accounts = st.pre;

    (
        st.id,
        TraceConfig {
            chain_id: 1,
            history_hashes: vec![U256::from_big_endian(st.env.previous_hash.as_bytes())],
            block_constants: geth_types::BlockConstants {
                coinbase: st.env.current_coinbase,
                timestamp: U256::from(st.env.current_timestamp),
                number: U64::from(st.env.current_number),
                difficulty: st.env.current_difficulty,
                gas_limit: U256::from(st.env.current_gas_limit),
                base_fee: st.env.current_base_fee,
            },

            transactions: vec![geth_types::Transaction {
                tx_type: TxType::Eip155,
                from: st.from,
                to: st.to,
                nonce: st.nonce,
                value: st.value,
                gas_limit: U256::from(st.gas_limit),
                gas_price: st.gas_price,
                gas_fee_cap: U256::zero(),
                gas_tip_cap: U256::zero(),
                call_data: st.data,
                access_list: None,
                v: sig.v,
                r: sig.r,
                s: sig.s,
                rlp_bytes: rlp_signed,
                rlp_unsigned_bytes: rlp_unsigned,
                hash: tx_hash.into(),
            }],
            accounts,
            logger_config: LoggerConfig {
                enable_memory: *bus_mapping::util::CHECK_MEM_STRICT,
                ..Default::default()
            },
            #[cfg(feature = "shanghai")]
            chain_config: Some(external_tracer::ChainConfig::shanghai()),
            #[cfg(not(feature = "shanghai"))]
            chain_config: None,
            #[cfg(feature = "scroll")]
            l1_queue_index: 0,
        },
        st.result,
    )
}

/*
pub fn geth_trace(st: StateTest) -> Result<GethExecTrace, StateTestError> {
    let (_, trace_config, _) = into_traceconfig(st);

    let mut geth_traces = external_tracer::trace(&trace_config)
        .map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

    Ok(geth_traces.remove(0))
}
*/

fn check_geth_traces(
    geth_traces: &[GethExecTrace],
    suite: &TestSuite,
    verbose: bool,
) -> Result<(), StateTestError> {
    #[cfg(feature = "skip-self-destruct")]
    if geth_traces.iter().any(|gt| {
        gt.struct_logs.iter().any(|sl| {
            sl.op == eth_types::evm_types::OpcodeId::SELFDESTRUCT
                || sl.op == eth_types::evm_types::OpcodeId::INVALID(0xff)
        })
    }) {
        return Err(StateTestError::SkipTestSelfDestruct);
    }

    #[cfg(feature = "scroll")]
    if geth_traces.iter().any(|gt| {
        gt.struct_logs
            .iter()
            .any(|sl| sl.op == eth_types::evm_types::OpcodeId::DIFFICULTY)
    }) {
        return Err(StateTestError::SkipTestDifficulty);
    }

    if geth_traces[0].struct_logs.len() as u64 > suite.max_steps {
        return Err(StateTestError::SkipTestMaxSteps(
            geth_traces[0].struct_logs.len(),
        ));
    }

    if suite.max_gas > 0 && geth_traces[0].gas.0 > suite.max_gas {
        return Err(StateTestError::SkipTestMaxGasLimit(geth_traces[0].gas.0));
    }
    if verbose {
        if let Err(e) = crate::utils::print_trace(geth_traces[0].clone()) {
            log::error!("fail to pretty print trace {e:?}");
        }
    }
    Ok(())
}

/// Use scroll l2 evm to get a l2 BlockTrace
#[cfg(feature = "scroll")]
fn trace_config_to_witness_block_l2(
    trace_config: TraceConfig,
    st: StateTest,
    suite: TestSuite,
    circuits_params: CircuitsParams,
    verbose: bool,
) -> Result<Option<(Block<Fr>, CircuitInputBuilder)>, StateTestError> {
    let block_trace = external_tracer::l2trace(&trace_config);

    let block_trace = match (block_trace, st.exception) {
        (Ok(res), false) => res,
        (Ok(_), true) => {
            return Err(StateTestError::Exception {
                expected: true,
                found: "no error".into(),
            })
        }
        (Err(_), true) => return Ok(None),
        (Err(err), false) => {
            return Err(StateTestError::Exception {
                expected: false,
                found: err.to_string(),
            })
        }
    };

    let geth_traces = block_trace
        .execution_results
        .iter()
        .map(From::from)
        .collect::<Vec<_>>();
    check_geth_traces(&geth_traces, &suite, verbose)?;

    std::env::set_var(
        "COINBASE",
        format!("0x{}", hex::encode(block_trace.coinbase.address.unwrap())),
    );
    std::env::set_var("CHAIN_ID", format!("{}", block_trace.chain_id));
    let difficulty_be_bytes = [0u8; 32];
    std::env::set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));
    let mut builder =
        CircuitInputBuilder::new_from_l2_trace(circuits_params, &block_trace, false, false)
            .expect("could not handle block tx");
    builder
        .finalize_building()
        .expect("could not finalize building block");
    let mut block =
        zkevm_circuits::witness::block_convert(&builder.block, &builder.code_db).unwrap();
    zkevm_circuits::witness::block_apply_mpt_state(&mut block, &builder.mpt_init_state);
    Ok(Some((block, builder)))
}

#[cfg(not(feature = "scroll"))]
fn trace_config_to_witness_block_l1(
    trace_config: TraceConfig,
    st: StateTest,
    suite: TestSuite,
    circuits_params: CircuitsParams,
    verbose: bool,
) -> Result<Option<(Block<Fr>, CircuitInputBuilder)>, StateTestError> {
    use ethers_signers::Signer;

    let geth_traces = external_tracer::trace(&trace_config);

    let geth_traces = match (geth_traces, st.exception) {
        (Ok(res), false) => res,
        (Ok(_), true) => {
            return Err(StateTestError::Exception {
                expected: true,
                found: "no error".into(),
            })
        }
        (Err(_), true) => return Ok(None),
        (Err(err), false) => {
            return Err(StateTestError::Exception {
                expected: false,
                found: err.to_string(),
            })
        }
    };

    check_geth_traces(&geth_traces, &suite, verbose)?;

    let transactions = trace_config
        .transactions
        .into_iter()
        .enumerate()
        .map(|(index, tx)| eth_types::Transaction {
            from: tx.from,
            to: tx.to,
            value: tx.value,
            input: tx.call_data,
            gas_price: Some(tx.gas_price),
            access_list: tx.access_list,
            nonce: tx.nonce,
            gas: tx.gas_limit,
            transaction_index: Some(U64::from(index)),
            r: tx.r,
            s: tx.s,
            v: U64::from(tx.v),
            block_number: Some(U64::from(trace_config.block_constants.number.as_u64())),
            chain_id: Some(trace_config.chain_id.into()),
            ..eth_types::Transaction::default()
        })
        .collect();

    let eth_block = eth_types::Block {
        author: Some(trace_config.block_constants.coinbase),
        timestamp: trace_config.block_constants.timestamp,
        number: Some(U64::from(trace_config.block_constants.number.as_u64())),
        difficulty: trace_config.block_constants.difficulty,
        gas_limit: trace_config.block_constants.gas_limit,
        base_fee_per_gas: Some(trace_config.block_constants.base_fee),
        transactions,
        parent_hash: st.env.previous_hash,
        ..eth_types::Block::default()
    };

    let wallet: LocalWallet = ethers_core::k256::ecdsa::SigningKey::from_bytes(&st.secret_key)
        .unwrap()
        .into();
    let mut wallets = HashMap::new();
    wallets.insert(
        wallet.address(),
        wallet.with_chain_id(trace_config.chain_id),
    );

    // process the transaction
    let geth_data = eth_types::geth_types::GethData {
        chain_id: trace_config.chain_id,
        history_hashes: trace_config.history_hashes.clone(),
        geth_traces: geth_traces.clone(),
        accounts: trace_config.accounts.values().cloned().collect(),
        eth_block: eth_block.clone(),
    };

    let block_data =
        bus_mapping::mock::BlockData::new_from_geth_data_with_params(geth_data, circuits_params);

    let mut builder = block_data.new_circuit_input_builder();
    builder
        .handle_block(&eth_block, &geth_traces)
        .map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

    let block: Block<Fr> =
        zkevm_circuits::evm_circuit::witness::block_convert(&builder.block, &builder.code_db)
            .unwrap();
    Ok(Some((block, builder)))
}

////// params for degree = 20 ////////////
pub const MAX_TXS: usize = 100;
pub const MAX_INNER_BLOCKS: usize = 100;
pub const MAX_EXP_STEPS: usize = 10_000;
pub const MAX_CALLDATA: usize = 350_000;
pub const MAX_RLP_ROWS: usize = 800_000;
pub const MAX_BYTECODE: usize = 600_000;
pub const MAX_MPT_ROWS: usize = 1_000_000;
pub const MAX_KECCAK_ROWS: usize = 1_000_000;
pub const MAX_POSEIDON_ROWS: usize = 1_000_000;
pub const MAX_VERTICLE_ROWS: usize = 1_000_000;
pub const MAX_RWS: usize = 1_000_000;
pub const MAX_PRECOMPILE_EC_ADD: usize = 50;
pub const MAX_PRECOMPILE_EC_MUL: usize = 50;
pub const MAX_PRECOMPILE_EC_PAIRING: usize = 2;

// TODO: refactor & usage
fn get_sub_circuit_limit_l2() -> Vec<usize> {
    vec![
        MAX_RWS,           // evm
        MAX_RWS,           // state
        MAX_BYTECODE,      // bytecode
        MAX_RWS,           // copy
        MAX_KECCAK_ROWS,   // keccak
        MAX_RWS,           // tx
        MAX_RLP_ROWS,      // rlp
        8 * MAX_EXP_STEPS, // exp
        MAX_KECCAK_ROWS,   // modexp
        MAX_RWS,           // pi
        MAX_POSEIDON_ROWS, // poseidon
        MAX_VERTICLE_ROWS, // sig
        MAX_VERTICLE_ROWS, // ecc
        MAX_MPT_ROWS,      // mpt
    ]
}

fn get_params_for_super_circuit_test_l2() -> CircuitsParams {
    CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_poseidon_rows: MAX_POSEIDON_ROWS,
        max_vertical_circuit_rows: MAX_VERTICLE_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
        max_rlp_rows: MAX_RLP_ROWS,
        max_ec_ops: PrecompileEcParams {
            ec_add: MAX_PRECOMPILE_EC_ADD,
            ec_mul: MAX_PRECOMPILE_EC_MUL,
            ec_pairing: MAX_PRECOMPILE_EC_PAIRING,
        },
    }
}

fn get_params_for_super_circuit_test() -> CircuitsParams {
    CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 256,
        max_copy_rows: 256,
        max_mpt_rows: 256,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_poseidon_rows: 0,
        max_vertical_circuit_rows: 0,
        max_inner_blocks: 64,
        max_rlp_rows: 512,
        max_ec_ops: PrecompileEcParams {
            ec_add: 50,
            ec_mul: 50,
            ec_pairing: 2,
        },
    }
}

fn get_params_for_sub_circuit_test() -> CircuitsParams {
    CircuitsParams {
        max_txs: 1,
        max_rws: 0,      // dynamic
        max_calldata: 0, // dynamic
        max_bytecode: 5000,
        max_mpt_rows: 5000,
        max_copy_rows: 0, // dynamic
        max_evm_rows: 0,  // dynamic
        max_exp_steps: 5000,
        max_keccak_rows: 0, // dynamic?
        max_poseidon_rows: 0,
        max_vertical_circuit_rows: 0,
        max_inner_blocks: 64,
        max_rlp_rows: 6000,
        max_ec_ops: PrecompileEcParams {
            ec_add: 50,
            ec_mul: 50,
            ec_pairing: 2,
        },
    }
}

fn test_with<C: SubCircuit<Fr> + Circuit<Fr>>(block: &Block<Fr>) -> MockProver<Fr> {
    let num_row = C::min_num_rows_block(block).1;
    let k = zkevm_circuits::util::log2_ceil(num_row + 256);
    log::debug!(
        "{} circuit needs k = {k}, num_row {num_row} + 256",
        *CIRCUIT,
    );
    //debug_assert!(k <= 22);
    let circuit = C::new_from_block(block);
    MockProver::<Fr>::run(k, &circuit, circuit.instance()).unwrap()
}

type ScrollSuperCircuit = SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, 0x100>;

pub fn run_test(
    st: StateTest,
    suite: TestSuite,
    circuits_config: CircuitsConfig,
) -> Result<(), StateTestError> {
    // get the geth traces

    let (_, trace_config, post) = into_traceconfig(st.clone());

    #[cfg(feature = "scroll")]
    for acc in trace_config.accounts.values() {
        if acc.balance.to_be_bytes()[0] != 0u8 {
            return Err(StateTestError::SkipTestBalanceOverflow);
        }
    }
    log::debug!("trace_config generated");
    let circuits_params = if !circuits_config.super_circuit {
        get_params_for_sub_circuit_test()
    } else {
        // params for super circuit
        if cfg!(feature = "scroll") {
            get_params_for_super_circuit_test_l2()
        } else {
            get_params_for_super_circuit_test()
        }
    };

    #[cfg(feature = "scroll")]
    let result = trace_config_to_witness_block_l2(
        trace_config.clone(),
        st.clone(),
        suite.clone(),
        circuits_params,
        circuits_config.verbose,
    )?;
    #[cfg(not(feature = "scroll"))]
    let result = trace_config_to_witness_block_l1(
        trace_config.clone(),
        st.clone(),
        suite.clone(),
        circuits_params,
        circuits_config.verbose,
    )?;

    let (witness_block, mut builder) = match result {
        Some((witness_block, builder)) => (witness_block, builder),
        None => return Ok(()),
    };

    log::debug!("witness_block created");
    //builder.sdb.list_accounts();

    if !circuits_config.super_circuit {
        if (*CIRCUIT).is_empty() {
            CircuitTestBuilder::<1, 1>::new_from_block(witness_block)
                .copy_checks(None)
                .run();
        } else {
            let prover = match (*CIRCUIT).as_str() {
                "modexp" => test_with::<ModExpCircuit<Fr>>(&witness_block),
                "bytecode" => test_with::<BytecodeCircuit<Fr>>(&witness_block),
                "ecc" => test_with::<EccCircuit<Fr, 9>>(&witness_block),
                "sig" => test_with::<SigCircuit<Fr>>(&witness_block),
                _ => unimplemented!(),
            };
            prover.assert_satisfied_par();
        }
    } else {
        log::debug!("test super circuit {}", *CIRCUIT);
        if (*CIRCUIT) == "ccc" {
            let row_usage = ScrollSuperCircuit::min_num_rows_block_subcircuits(&witness_block);
            let mut overflow = false;
            for (num, limit) in row_usage.iter().zip_eq(get_sub_circuit_limit_l2().iter()) {
                if num.row_num_real > *limit {
                    log::warn!(
                        "ccc detail: suite.id {}, st.id {}, circuit {}, num {}, limit {}",
                        suite.id,
                        st.id,
                        num.name,
                        num.row_num_real,
                        limit
                    );
                    overflow = true;
                }
            }
            let max_row_usage = row_usage.iter().max_by_key(|r| r.row_num_real).unwrap();
            if overflow {
                log::warn!(
                    "ccc overflow: st.id {}, detail {} {}",
                    st.id,
                    max_row_usage.name,
                    max_row_usage.row_num_real
                );
                panic!("{} {}", max_row_usage.name, max_row_usage.row_num_real);
            } else {
                log::info!(
                    "ccc ok: st.id {}, detail {} {}",
                    st.id,
                    max_row_usage.name,
                    max_row_usage.row_num_real
                );
            }
        } else {
            // TODO: do we need to automatically adjust this k?
            let k = 20;
            // TODO: remove this MOCK_RANDOMNESS?
            let circuit = ScrollSuperCircuit::new_from_block(&witness_block);
            let instance = circuit.instance();
            let prover = MockProver::run(k, &circuit, instance).unwrap();
            prover.assert_satisfied_par();
        }
    };
    //#[cfg(feature = "scroll")]
    {
        // fill these "untouched" storage slots
        // It is better to fill these info after (instead of before) bus-mapping re-exec.
        // To prevent these data being used unexpectedly.
        // TODO: another method will be to skip empty account inside check_post?
        for account in trace_config.accounts.values() {
            builder.code_db.insert(account.code.to_vec());
            let (exist, acc_in_local_sdb) = builder.sdb.get_account_mut(&account.address);
            if !exist {
                // modified from bus-mapping/src/mock.rs
                let keccak_code_hash = H256(keccak256(account.code.to_vec()));
                let code_hash = CodeDB::hash(&account.code.to_vec());
                *acc_in_local_sdb = bus_mapping::state_db::Account {
                    nonce: account.nonce,
                    balance: account.balance,
                    storage: account.storage.clone(),
                    code_hash,
                    keccak_code_hash,
                    code_size: account.code.len().to_word(),
                };
            } else {
                for (k, v) in &account.storage {
                    if !acc_in_local_sdb.storage.contains_key(k) {
                        acc_in_local_sdb.storage.insert(*k, *v);
                    }
                }
            }
        }
    }
    check_post(&builder, &post)?;

    Ok(())
}
