use crate::{
    evm_circuit::{table::FixedTableTag, witness::Block},
    state_circuit::StateCircuit,
};
use eth_types::evm_types::Gas;
use halo2_proofs::dev::{MockProver, VerifyFailure};
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
                FixedTableTag::Bitslevel,
                FixedTableTag::Pow64,
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
    // execute the bytecode and get trace
    let block_trace = bus_mapping::mock::BlockData::new_from_geth_data(
        mock::new_single_tx_trace_code_gas(&bytecode, Gas(config.gas_limit), call_data).unwrap(),
    );
    let mut builder = block_trace.new_circuit_input_builder();
    builder
        .handle_block(&block_trace.eth_block, &block_trace.geth_traces)
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
        let state_circuit =
            StateCircuit::<Fr, true, 2000, 200, 1023, 2000>::new(block.randomness, &block.rws);
        let prover = MockProver::<Fr>::run(12, &state_circuit, vec![]).unwrap();
        prover.verify()?;
    }

    Ok(())
}
