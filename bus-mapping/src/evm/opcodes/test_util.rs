use eth_types::{evm_types::OpcodeId, geth_types::GethData, Bytecode};
use mock::{
    test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
    TestContext,
};

use crate::{
    circuit_input_builder::{Block, ExecState, ExecStep, Transaction},
    mock::BlockData,
    operation::OperationContainer,
    state_db::StateDB,
};

pub struct StepWitness {
    pub step: ExecStep,
    pub rws: OperationContainer,
}

pub struct TestCase {
    pub geth_data: GethData,
    pub block: Block,
    pub state_db: StateDB,
}
impl TestCase {
    pub fn new_from_geth_data(geth_data: GethData) -> Self {
        let mut builder =
            BlockData::new_from_geth_data(geth_data.clone()).new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .unwrap();
        println!("b {:?}", builder.block);
        Self {
            geth_data,
            block: builder.block,
            state_db: builder.sdb,
        }
    }
    pub fn new_from_bytecode(code: Bytecode) -> Self {
        // Get the execution steps from the external tracer
        let geth_data: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        Self::new_from_geth_data(geth_data)
    }

    pub fn state_db(&self) -> &StateDB {
        &self.state_db
    }
    pub fn block_input(&self) -> &eth_types::Block<eth_types::Transaction> {
        &self.geth_data.eth_block
    }
    pub fn tx_input(&self) -> &eth_types::Transaction {
        &self.geth_data.eth_block.transactions[0]
    }
    pub fn block_witness(&self) -> &Block {
        &self.block
    }
    pub fn tx_witness(&self) -> &Transaction {
        &self.block_witness().txs()[0]
    }
    pub fn step_witness(&self, op: OpcodeId, nth: usize) -> StepWitness {
        let block = self.block_witness();
        let tx = self.tx_witness();
        let step = tx
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(op))
            .nth(nth)
            .unwrap()
            .clone();
        //println!("step bus_mapping_instance {:?}", step.bus_mapping_instance);

        //println!("con {:?}", tx.container);
        //println!("slcie {:?}", step_witness.rws);
        StepWitness {
            rws: block.container.slice(&step.bus_mapping_instance),
            step,
        }
    }
}

/// Most commmonly used case. So we provide a short cut helper function here
pub fn step_witness_for_bytecode(code: Bytecode, op: OpcodeId) -> StepWitness {
    TestCase::new_from_bytecode(code).step_witness(op, 0)
}
