use super::{AccountMatch, StateTest, StateTestResult};
use crate::config::TestSuite;
use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use bus_mapping::mock::BlockData;
use eth_types::{geth_types, Address, Bytes, GethExecTrace, U256, U64};
use ethers_core::k256::ecdsa::SigningKey;
use ethers_core::types::TransactionRequest;
use ethers_signers::{LocalWallet, Signer};
use external_tracer::TraceConfig;
use halo2_proofs::dev::MockProver;
use std::{collections::HashMap, str::FromStr};
use thiserror::Error;
use zkevm_circuits::{super_circuit::SuperCircuit, test_util::BytecodeTestConfig};

const EVMERR_OOG: &str = "out of gas";
const EVMERR_STACKUNDERFLOW: &str = "stack underflow";
const EVMERR_GAS_UINT64OVERFLOW: &str = "gas uint64 overflow";

#[derive(PartialEq, Eq, Error, Debug)]
pub enum StateTestError {
    #[error("CannotGenerateCircuitInput({0})")]
    CircuitInput(String),
    #[error("VerifierError({0})")]
    VerifierError(String),
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
    #[error("SkipTesstMaxGasLimit({0})")]
    SkipTestMaxGasLimit(u64),
    #[error("SkipTestMaxSteps({0})")]
    SkipTestMaxSteps(usize),
    #[error("SkipUnimplemented({0})")]
    SkipUnimplemented(String),
    #[error("Exception(expected:{expected:?}, found:{found:?})")]
    Exception { expected: bool, found: bool },
}

impl StateTestError {
    pub fn is_skip(&self) -> bool {
        matches!(
            self,
            StateTestError::SkipUnimplemented(_)
                | StateTestError::SkipTestMaxSteps(_)
                | StateTestError::SkipTestMaxGasLimit(_)
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

    let sig = wallet.sign_transaction_sync(&tx.into());

    (
        st.id,
        TraceConfig {
            chain_id: U256::one(),
            history_hashes: Vec::new(),
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
            }],
            accounts: st.pre,
            ..Default::default()
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

    if st.to.is_none() {
        return Err(StateTestError::SkipUnimplemented(
            "TransactionCreation".to_string(),
        ));
    }

    let geth_traces = external_tracer::trace(&trace_config);
    if st.exception {
        if geth_traces.is_ok() {
            return Err(StateTestError::Exception {
                expected: st.exception,
                found: geth_traces.is_err(),
            });
        } else {
            return Ok(());
        }
    }

    let geth_traces = geth_traces.map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

    if geth_traces[0].struct_logs.len() as u64 > suite.max_steps {
        return Err(StateTestError::SkipTestMaxSteps(
            geth_traces[0].struct_logs.len(),
        ));
    }

    // we are not checking here geth_traces[0].failed, since
    // there are some tests that makes the tx failing
    // (eg memory filler tests)

    if let Some(step) = geth_traces[0]
        .struct_logs
        .iter()
        .find(|step| suite.unimplemented_opcodes.contains(&step.op))
    {
        return Err(StateTestError::SkipUnimplemented(format!(
            "OPCODE {:?}",
            step.op
        )));
    }

    for err in [EVMERR_STACKUNDERFLOW, EVMERR_OOG, EVMERR_GAS_UINT64OVERFLOW] {
        if geth_traces[0]
            .struct_logs
            .iter()
            .any(|step| step.error.as_ref().map(|e| e.contains(err)) == Some(true))
        {
            return Err(StateTestError::SkipUnimplemented(format!("Error {}", err)));
        }
    }

    if geth_traces[0].gas.0 > suite.max_gas {
        return Err(StateTestError::SkipTestMaxGasLimit(geth_traces[0].gas.0));
    }

    if let Some(acc) = st.pre.get(&st.to.unwrap()) {
        if acc.code.0.is_empty() {
            return Err(StateTestError::SkipUnimplemented(
                "Calling to empty accounts unimplemented (1)".to_string(),
            ));
        }
    } else {
        return Err(StateTestError::SkipUnimplemented(
            "Calling to empty accounts unimplemented (2)".to_string(),
        ));
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
    wallets.insert(wallet.address(), wallet.with_chain_id(1u64));

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
            keccak_padding: None,
        };
        let block_data = BlockData::new_from_geth_data_with_params(geth_data, circuits_params);

        builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&eth_block, &geth_traces)
            .map_err(|err| StateTestError::CircuitInput(err.to_string()))?;

        let block =
            zkevm_circuits::evm_circuit::witness::block_convert(&builder.block, &builder.code_db)
                .unwrap();

        let config = BytecodeTestConfig {
            enable_evm_circuit_test: true,
            enable_state_circuit_test: true,
            gas_limit: u64::MAX,
        };

        zkevm_circuits::test_util::test_circuits_witness_block(block, config)
            .map_err(|err| StateTestError::VerifierError(format!("{:#?}", err)))?;
    } else {
        geth_data.sign(&wallets);

        let (k, circuit, instance, _builder) =
            SuperCircuit::<_, 1, 32, 255>::build(geth_data).unwrap();
        builder = _builder;

        let prover = MockProver::run(k, &circuit, instance).unwrap();
        prover
            .verify_par()
            .map_err(|err| StateTestError::VerifierError(format!("{:#?}", err)))?;
    }

    check_post(&builder, &post)?;

    Ok(())
}
