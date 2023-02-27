use super::{AccountMatch, StateTest, StateTestResult};
use crate::config::TestSuite;
use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use bus_mapping::mock::BlockData;
use eth_types::{geth_types, Address, Bytes, GethExecTrace, U256, U64};
use ethers_core::k256::ecdsa::SigningKey;
use ethers_core::types::transaction::eip2718::TypedTransaction;
use ethers_core::types::TransactionRequest;
use ethers_core::utils::keccak256;
use ethers_signers::{LocalWallet, Signer};
use external_tracer::{LoggerConfig, TraceConfig};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::test_util::CircuitTestBuilder;
use zkevm_circuits::witness::Block;

const MAX_TXS: usize = 1;
const MAX_CALLDATA: usize = 32;

#[derive(PartialEq, Eq, Error, Debug)]
pub enum StateTestError {
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
    #[error("Exception(expected:{expected:?}, found:{found:?})")]
    Exception { expected: bool, found: String },
}

impl StateTestError {
    pub fn is_skip(&self) -> bool {
        matches!(
            self,
            StateTestError::SkipTestMaxSteps(_) | StateTestError::SkipTestMaxGasLimit(_)
        )
    }
}

#[derive(Default, Debug, Clone)]
pub struct CircuitsConfig {
    pub super_circuit: bool,
}

fn check_post(
    builder: &CircuitInputBuilder,
    post: &HashMap<Address, AccountMatch>,
) -> Result<(), StateTestError> {
    // check if the generated account data is the expected one
    for (address, expected) in post {
        let (_, actual) = builder.sdb.get_account(address);

        if expected.balance.map(|v| v == actual.balance) == Some(false) {
            return Err(StateTestError::BalanceMismatch {
                expected: expected.balance.unwrap(),
                found: actual.balance,
            });
        }

        if expected.nonce.map(|v| v == actual.nonce) == Some(false) {
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
                return Err(StateTestError::StorageMismatch {
                    slot: *slot,
                    expected: *expected_value,
                    found: actual_value,
                });
            }
        }
    }
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
    let tx: TypedTransaction = tx.into();

    let sig = wallet.sign_transaction_sync(&tx);
    let tx_hash = keccak256(tx.rlp_signed(&sig));

    (
        st.id,
        TraceConfig {
            chain_id: U256::one(),
            history_hashes: vec![U256::from_big_endian(st.env.previous_hash.as_bytes())],
            block_constants: geth_types::BlockConstants {
                coinbase: st.env.current_coinbase,
                timestamp: U256::from(st.env.current_timestamp),
                number: U64::from(st.env.current_number),
                difficulty: st.env.current_difficulty,
                gas_limit: U256::from(st.env.current_gas_limit),
                base_fee: U256::one(),
            },

            transactions: vec![geth_types::Transaction {
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
                hash: tx_hash.into(),
            }],
            accounts: st.pre,
            logger_config: LoggerConfig {
                enable_memory: *bus_mapping::util::CHECK_MEM_STRICT,
                ..Default::default()
            },
        },
        st.result,
    )
}

pub fn geth_trace(st: StateTest) -> Result<GethExecTrace, StateTestError> {
    let (_, trace_config, _) = into_traceconfig(st);

    let mut geth_traces = external_tracer::trace(&trace_config)
        .map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

    Ok(geth_traces.remove(0))
}

pub fn run_test(
    st: StateTest,
    suite: TestSuite,
    circuits_config: CircuitsConfig,
) -> Result<(), StateTestError> {
    // get the geth traces

    let (_, trace_config, post) = into_traceconfig(st.clone());

    let geth_traces = external_tracer::trace(&trace_config);

    let geth_traces = match (geth_traces, st.exception) {
        (Ok(res), false) => res,
        (Ok(_), true) => {
            return Err(StateTestError::Exception {
                expected: true,
                found: "no error".into(),
            })
        }
        (Err(_), true) => return Ok(()),
        (Err(err), false) => {
            return Err(StateTestError::Exception {
                expected: false,
                found: err.to_string(),
            })
        }
    };

    if geth_traces[0].struct_logs.len() as u64 > suite.max_steps {
        return Err(StateTestError::SkipTestMaxSteps(
            geth_traces[0].struct_logs.len(),
        ));
    }

    if suite.max_gas > 0 && geth_traces[0].gas.0 > suite.max_gas {
        return Err(StateTestError::SkipTestMaxGasLimit(geth_traces[0].gas.0));
    }

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
            chain_id: Some(trace_config.chain_id),
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
        ..eth_types::Block::default()
    };

    let wallet: LocalWallet = SigningKey::from_bytes(&st.secret_key).unwrap().into();
    let mut wallets = HashMap::new();
    wallets.insert(
        wallet.address(),
        wallet.with_chain_id(trace_config.chain_id.as_u64()),
    );

    // process the transaction
    let mut geth_data = eth_types::geth_types::GethData {
        chain_id: trace_config.chain_id,
        history_hashes: trace_config.history_hashes.clone(),
        geth_traces: geth_traces.clone(),
        accounts: trace_config.accounts.values().cloned().collect(),
        eth_block: eth_block.clone(),
    };

    let mut builder;

    if !circuits_config.super_circuit {
        let circuits_params = CircuitsParams {
            max_txs: 1,
            max_rws: 55000,
            max_calldata: 5000,
            max_bytecode: 5000,
            max_copy_rows: 55000,
            max_evm_rows: 0,
            max_exp_steps: 5000,
            keccak_padding: None,
            max_inner_blocks: 64,
        };
        let block_data = BlockData::new_from_geth_data_with_params(geth_data, circuits_params);

        builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&eth_block, &geth_traces)
            .map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

        let block: Block<Fr> =
            zkevm_circuits::evm_circuit::witness::block_convert(&builder.block, &builder.code_db)
                .unwrap();

        CircuitTestBuilder::<1, 1>::new_from_block(block).run();
    } else {
        geth_data.sign(&wallets);

        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            keccak_padding: None,
            max_inner_blocks: 64,
        };
        let (k, circuit, instance, _builder) =
            SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, 64, 0x100>::build(geth_data, circuits_params)
                .unwrap();
        builder = _builder;

        let prover = MockProver::run(k, &circuit, instance).unwrap();
        prover.assert_satisfied_par();
    };

    check_post(&builder, &post)?;

    Ok(())
}
