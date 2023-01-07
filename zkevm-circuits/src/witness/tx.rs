use crate::evm_circuit::step::ExecutionState;
use crate::util::Challenges;
use crate::{evm_circuit::util::RandomLinearCombination, table::TxContextFieldTag};
use bus_mapping::circuit_input_builder;
use eth_types::{Address, Field, Signature, ToLittleEndian, ToScalar, ToWord, Word, H256};
use halo2_proofs::circuit::Value;
use mock::MockTransaction;
use rlp::Encodable;

use super::{step::step_convert, Call, ExecStep};

/// Transaction in a witness block
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The block number in which this tx is included in
    pub block_number: u64,
    /// The transaction identifier in the block
    pub id: usize,
    /// The hash of the transaction
    pub hash: H256,
    /// The sender account nonce of the transaction
    pub nonce: u64,
    /// The gas limit of the transaction
    pub gas: u64,
    /// The gas price
    pub gas_price: Word,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Address,
    /// Whether it's a create transaction
    pub is_create: bool,
    /// The ether amount of the transaction
    pub value: Word,
    /// The call data
    pub call_data: Vec<u8>,
    /// The call data length
    pub call_data_length: usize,
    /// The gas cost for transaction call data
    pub call_data_gas_cost: u64,
    /// Chain ID as per EIP-155.
    pub chain_id: u64,
    /// The calls made in the transaction
    pub calls: Vec<Call>,
    /// The steps executioned in the transaction
    pub steps: Vec<ExecStep>,
}

impl Transaction {
    /// Assignments for tx table
    pub fn table_assignments<F: Field>(
        &self,
        challenges: Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        [
            vec![
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::Nonce as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.nonce)),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::Gas as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.gas)),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::GasPrice as u64)),
                    Value::known(F::zero()),
                    challenges.evm_word().map(|evm_word| {
                        RandomLinearCombination::random_linear_combine(
                            self.gas_price.to_le_bytes(),
                            evm_word,
                        )
                    }),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CallerAddress as u64)),
                    Value::known(F::zero()),
                    Value::known(self.caller_address.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CalleeAddress as u64)),
                    Value::known(F::zero()),
                    Value::known(self.callee_address.to_scalar().unwrap()),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::IsCreate as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.is_create as u64)),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::Value as u64)),
                    Value::known(F::zero()),
                    challenges.evm_word().map(|evm_word| {
                        RandomLinearCombination::random_linear_combine(
                            self.value.to_le_bytes(),
                            evm_word,
                        )
                    }),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CallDataLength as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.call_data_length as u64)),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CallDataGasCost as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.call_data_gas_cost)),
                ],
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::BlockNumber as u64)),
                    Value::known(F::zero()),
                    Value::known(F::from(self.block_number)),
                ],
            ],
            self.call_data
                .iter()
                .enumerate()
                .map(|(idx, byte)| {
                    [
                        Value::known(F::from(self.id as u64)),
                        Value::known(F::from(TxContextFieldTag::CallData as u64)),
                        Value::known(F::from(idx as u64)),
                        Value::known(F::from(*byte as u64)),
                    ]
                })
                .collect(),
        ]
        .concat()
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(9);
        s.append(&Word::from(self.nonce));
        s.append(&self.gas_price);
        s.append(&Word::from(self.gas));
        s.append(&self.callee_address);
        s.append(&self.value);
        s.append(&self.call_data);
        s.append(&Word::from(self.chain_id));
        s.append(&Word::zero());
        s.append(&Word::zero());
    }
}

/// Signed transaction in a witness block
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Transaction data.
    pub tx: Transaction,
    /// ECDSA signature on the transaction.
    pub signature: Signature,
}

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(9);
        s.append(&Word::from(self.tx.nonce));
        s.append(&self.tx.gas_price);
        s.append(&Word::from(self.tx.gas));
        s.append(&self.tx.callee_address);
        s.append(&self.tx.value);
        s.append(&self.tx.call_data);
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl From<MockTransaction> for SignedTransaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let is_create = mock_tx.to.is_none();
        Self {
            tx: Transaction {
                id: mock_tx.transaction_index.as_usize(),
                nonce: mock_tx.nonce.as_u64(),
                gas: mock_tx.gas.as_u64(),
                gas_price: mock_tx.gas_price,
                caller_address: mock_tx.from.address(),
                callee_address: match mock_tx.to {
                    Some(to) => to.address(),
                    None => Address::zero(),
                },
                is_create,
                value: mock_tx.value,
                call_data: mock_tx.input.to_vec(),
                call_data_length: mock_tx.input.len(),
                // chain_id: mock_tx.chain_id.as_u64(),
                ..Default::default()
            },
            signature: Signature {
                r: mock_tx.r.expect("tx expected to be signed"),
                s: mock_tx.s.expect("tx expected to be signed"),
                v: mock_tx.v.expect("tx expected to be signed").as_u64(),
            },
        }
    }
}

pub(super) fn tx_convert(
    tx: &circuit_input_builder::Transaction,
    id: usize,
    chain_id: u64,
    next_tx: Option<&circuit_input_builder::Transaction>,
) -> Transaction {
    Transaction {
        block_number: tx.block_num,
        id,
        hash: tx.hash,
        nonce: tx.nonce,
        gas: tx.gas,
        gas_price: tx.gas_price,
        caller_address: tx.from,
        callee_address: tx.to,
        is_create: tx.is_create(),
        value: tx.value,
        call_data: tx.input.clone(),
        call_data_length: tx.input.len(),
        call_data_gas_cost: tx
            .input
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
        chain_id,
        calls: tx
            .calls()
            .iter()
            .map(|call| Call {
                id: call.call_id,
                is_root: call.is_root,
                is_create: call.is_create(),
                code_hash: call.code_hash.to_word(),
                rw_counter_end_of_reversion: call.rw_counter_end_of_reversion,
                caller_id: call.caller_id,
                depth: call.depth,
                caller_address: call.caller_address,
                callee_address: call.address,
                call_data_offset: call.call_data_offset,
                call_data_length: call.call_data_length,
                return_data_offset: call.return_data_offset,
                return_data_length: call.return_data_length,
                value: call.value,
                is_success: call.is_success,
                is_persistent: call.is_persistent,
                is_static: call.is_static,
            })
            .collect(),
        steps: tx
            .steps()
            .iter()
            .map(|step| step_convert(step, tx.block_num))
            .chain(if let Some(next_tx) = next_tx {
                debug_assert!(next_tx.block_num >= tx.block_num);
                let block_gap = next_tx.block_num - tx.block_num;
                (0..block_gap)
                    .map(|i| {
                        let rwc = tx.steps().last().unwrap().rwc.0 + 9 - (id == 1) as usize;
                        ExecStep {
                            rw_counter: rwc,
                            execution_state: ExecutionState::EndInnerBlock,
                            block_num: tx.block_num + i,
                            ..Default::default()
                        }
                    })
                    .collect::<Vec<ExecStep>>()
            } else {
                let rwc = tx.steps().last().unwrap().rwc.0 + 9 - (id == 1) as usize;
                vec![
                    ExecStep {
                        rw_counter: rwc,
                        execution_state: ExecutionState::EndInnerBlock,
                        block_num: tx.block_num,
                        ..Default::default()
                    },
                    //ExecStep {
                    //    rw_counter: rwc,
                    //    execution_state: ExecutionState::EndBlock,
                    //    block_num: tx.block_num,
                    //    ..Default::default()
                    //},
                ]
            })
            .collect(),
    }
}

/// Convert eth_types::geth_types::Transaction to SignedTransaction that can be
/// used as witness in TxCircuit and RLP Circuit.
pub fn signed_tx_from_geth_tx(
    txs: &[eth_types::geth_types::Transaction],
    chain_id: u64,
) -> Vec<SignedTransaction> {
    let mut signed_txs = Vec::with_capacity(txs.len());
    for (i, geth_tx) in txs.iter().enumerate() {
        signed_txs.push(SignedTransaction {
            tx: Transaction {
                id: i + 1,
                nonce: geth_tx.nonce.as_u64(),
                gas: geth_tx.gas_limit.as_u64(),
                gas_price: geth_tx.gas_price,
                caller_address: geth_tx.from,
                callee_address: geth_tx.to.unwrap_or(Address::zero()),
                is_create: geth_tx.to.is_none(),
                value: geth_tx.value,
                call_data: geth_tx.call_data.to_vec(),
                call_data_length: geth_tx.call_data.len(),
                call_data_gas_cost: geth_tx
                    .call_data
                    .iter()
                    .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                chain_id,
                ..Default::default()
            },
            signature: Signature {
                r: geth_tx.r,
                s: geth_tx.s,
                v: geth_tx.v,
            },
        });
    }
    signed_txs
}
