use crate::{
    evm_circuit::{table::FixedTableTag, witness::Block},
    state_circuit::StateCircuit,
};
use bus_mapping::mock::BlockData;
use eth_types::{address, geth_types::GethData, Bytes, Word};
use halo2_proofs::dev::{MockProver, VerifyFailure};
use mock::TestContext;
use pairing::arithmetic::BaseExt;
use pairing::bn256::Fr;

pub enum FixedTableConfig {
    Incomplete,
    Complete,
}

pub fn get_fixed_table(conf: FixedTableConfig) -> Vec<FixedTableTag> {
    match conf {
        FixedTableConfig::Incomplete => {
            vec![
                FixedTableTag::Range5,
                FixedTableTag::Range16,
                FixedTableTag::Range32,
                FixedTableTag::Range256,
                FixedTableTag::Range512,
                FixedTableTag::SignByte,
                FixedTableTag::ResponsibleOpcode,
            ]
        }
        FixedTableConfig::Complete => FixedTableTag::iterator().collect(),
    }
}

#[derive(Debug, Clone)]
pub struct BytecodeTestConfig {
    pub enable_evm_circuit_test: bool,
    pub evm_circuit_lookup_tags: Vec<FixedTableTag>,
    pub enable_state_circuit_test: bool,
    pub gas_limit: u64,
}

impl Default for BytecodeTestConfig {
    fn default() -> Self {
        Self {
            enable_evm_circuit_test: true,
            enable_state_circuit_test: true,
            gas_limit: 1_000_000u64,
            evm_circuit_lookup_tags: get_fixed_table(FixedTableConfig::Incomplete),
        }
    }
}

pub fn run_test_circuits(bytecode: eth_types::Bytecode) -> Result<(), Vec<VerifyFailure>> {
    test_circuits_using_bytecode(bytecode, BytecodeTestConfig::default(), None)
}

pub fn test_circuits_using_bytecode(
    bytecode: eth_types::Bytecode,
    config: BytecodeTestConfig,
    call_data: Option<Vec<u8>>,
) -> Result<(), Vec<VerifyFailure>> {
    // Create a custom tx setting Gas to
    let block: GethData = TestContext::<2, 1>::new(
        None,
        |accs| {
            accs[0]
                .address(address!("0x0000000000000000000000000000000000000010"))
                .balance(Word::from(1u64 << 20))
                .code(bytecode);
            accs[1]
                .address(address!("0x0000000000000000000000000000000000000000"))
                .balance(Word::from(1u64 << 30));
        },
        |mut txs, accs| {
            txs[0]
                .to(accs[0].address)
                .from(accs[1].address)
                .gas(Word::from(config.gas_limit))
                .input(Bytes::from(call_data.unwrap_or_default()));
        },
        |block, _tx| block.number(0xcafeu64),
    )
    .unwrap()
    .into();

    let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
    builder
        .handle_block(&block.eth_block, &block.geth_traces)
        .unwrap();

    // build a witness block from trace result
    let block = crate::evm_circuit::witness::block_convert(&builder.block, &builder.code_db);

    // finish required tests according to config using this witness block
    test_circuits_using_witness_block(block, config)
}

pub fn test_circuits_using_witness_block(
    block: Block<Fr>,
    config: BytecodeTestConfig,
) -> Result<(), Vec<VerifyFailure>> {
    // run evm circuit test
    if config.enable_evm_circuit_test {
        crate::evm_circuit::test::run_test_circuit(block.clone(), config.evm_circuit_lookup_tags)?;
    }

    // run state circuit test
    // TODO:
    //     (1) calculate circuit size(like MEMORY_ROWS_MAX etc) from block
    // rather than hard code  (2) use randomness as one of the circuit
    // public input, since randomness in state circuit and evm
    // circuit must be same
    if config.enable_state_circuit_test {
        let state_circuit = StateCircuit::new(block.randomness, block.rws.clone());

        let power_of_randomness: Vec<_> = (1..32)
            .map(|exp| {
                vec![
                    block.randomness.pow(&[exp, 0, 0, 0]);
                    20 // number of rows in the rw table.
                ]
            })
            .collect();

        let prover = MockProver::<Fr>::run(18, &state_circuit, power_of_randomness).unwrap();
        prover.verify()?;
    }

    Ok(())
}
