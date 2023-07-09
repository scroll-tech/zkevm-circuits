//! Transaction & TransactionContext utility module.

use std::collections::BTreeMap;

use eth_types::{
    evm_types::{gas_utils::tx_data_gas_cost, Memory},
    geth_types,
    geth_types::{get_rlp_unsigned, TxType},
    Address, GethExecTrace, Signature, Word, H256,
};
use ethers_core::utils::get_contract_address;

use crate::{
    l2_predeployed::l1_gas_price_oracle,
    state_db::{CodeDB, StateDB},
    Error,
};

use super::{call::ReversionGroup, Call, CallContext, CallKind, CodeSource, ExecStep};

/// Precision of transaction L1 fee
pub const TX_L1_FEE_PRECISION: u64 = 1_000_000_000;
/// Extra cost as the bytes of rlped tx commited to L1 (assume to non-zero, overestimated a bit)
pub const TX_L1_COMMIT_EXTRA_COST: u64 = 64;

#[derive(Debug, Default)]
/// Context of a [`Transaction`] which can mutate in an [`ExecStep`].
pub struct TransactionContext {
    /// L1 fee
    pub l1_fee: u64,
    /// Unique identifier of transaction of the block. The value is `index + 1`.
    id: usize,
    /// The index of logs made in the transaction.
    pub(crate) log_id: usize,
    /// Identifier if this transaction is last one of the block or not.
    is_last_tx: bool,
    /// Call stack.
    pub(crate) calls: Vec<CallContext>,
    /// Call `is_success` indexed by `call_index`.
    pub(crate) call_is_success: Vec<bool>,
    /// Reversion groups by failure calls. We keep the reversion groups in a
    /// stack because it's possible to encounter a revert within a revert,
    /// and in such case, we must only process the reverted operation once:
    /// in the inner most revert (which we track with the last element in
    /// the reversion groups stack), and skip it in the outer revert.
    pub(crate) reversion_groups: Vec<ReversionGroup>,
}

impl TransactionContext {
    /// Create a new Self.
    pub fn new(
        eth_tx: &eth_types::Transaction,
        geth_trace: &GethExecTrace,
        is_last_tx: bool,
    ) -> Result<Self, Error> {
        // Iterate over geth_trace to inspect and collect each call's is_success, which
        // is at the top of stack at the step after a call.
        let call_is_success = {
            let mut call_is_success_map = BTreeMap::new();
            let mut call_indices = Vec::new();
            for (index, geth_step) in geth_trace.struct_logs.iter().enumerate() {
                if let Some(geth_next_step) = geth_trace.struct_logs.get(index + 1) {
                    // Dive into call
                    if geth_step.depth + 1 == geth_next_step.depth {
                        call_indices.push(index);
                    // Emerge from call
                    } else if geth_step.depth - 1 == geth_next_step.depth {
                        let is_success = !geth_next_step.stack.last()?.is_zero();
                        call_is_success_map.insert(call_indices.pop().unwrap(), is_success);
                    // Callee with empty code
                    } else if CallKind::try_from(geth_step.op).is_ok() {
                        let is_success = !geth_next_step.stack.last()?.is_zero();
                        call_is_success_map.insert(index, is_success);
                    }
                }
            }

            std::iter::once(!geth_trace.failed)
                .chain(call_is_success_map.into_values())
                .collect()
        };

        let mut tx_ctx = Self {
            id: eth_tx
                .transaction_index
                .ok_or(Error::EthTypeError(eth_types::Error::IncompleteBlock))?
                .as_u64() as usize
                + 1,
            log_id: 0,
            is_last_tx,
            call_is_success,
            calls: Vec::new(),
            reversion_groups: Vec::new(),
            l1_fee: geth_trace.l1_fee,
        };
        tx_ctx.push_call_ctx(0, eth_tx.input.to_vec());

        Ok(tx_ctx)
    }

    /// Return id of the this transaction.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Return is_last_tx of the this transaction.
    pub fn is_last_tx(&self) -> bool {
        self.is_last_tx
    }

    /// Return the calls in this transaction.
    pub fn calls(&self) -> &[CallContext] {
        &self.calls
    }

    /// Return the index of the caller (the second last call in the call stack).
    pub(crate) fn caller_index(&self) -> Result<usize, Error> {
        self.caller_ctx().map(|call| call.index)
    }

    /// Return the index of the current call (the last call in the call stack).
    pub(crate) fn call_index(&self) -> Result<usize, Error> {
        self.call_ctx().map(|call| call.index)
    }

    pub(crate) fn caller_ctx(&self) -> Result<&CallContext, Error> {
        self.calls
            .len()
            .checked_sub(2)
            .map(|idx| &self.calls[idx])
            .ok_or(Error::InvalidGethExecTrace(
                "Call stack is empty but call is used",
            ))
    }

    pub(crate) fn call_ctx(&self) -> Result<&CallContext, Error> {
        self.calls.last().ok_or(Error::InvalidGethExecTrace(
            "Call stack is empty but call is used",
        ))
    }

    pub(crate) fn call_ctx_mut(&mut self) -> Result<&mut CallContext, Error> {
        self.calls.last_mut().ok_or(Error::InvalidGethExecTrace(
            "Call stack is empty but call is used",
        ))
    }

    /// Push a new call context and its index into the call stack.
    pub(crate) fn push_call_ctx(&mut self, call_idx: usize, call_data: Vec<u8>) {
        if !self.call_is_success[call_idx] {
            self.reversion_groups
                .push(ReversionGroup::new(vec![(call_idx, 0)], Vec::new()))
        } else if let Some(reversion_group) = self.reversion_groups.last_mut() {
            let caller_ctx = self.calls.last().expect("calls should not be empty");
            let caller_reversible_write_counter = self
                .calls
                .last()
                .expect("calls should not be empty")
                .reversible_write_counter;
            let caller_reversible_write_counter_offset = reversion_group
                .calls
                .iter()
                .find(|(call_idx, _)| *call_idx == caller_ctx.index)
                .expect("calls should not be empty")
                .1;
            reversion_group.calls.push((
                call_idx,
                caller_reversible_write_counter + caller_reversible_write_counter_offset,
            ));
        }

        self.calls.push(CallContext {
            index: call_idx,
            reversible_write_counter: 0,
            call_data,
            memory: Memory::default(),
            return_data: vec![],
        });
    }

    /// Pop the last entry in the call stack.
    pub(crate) fn pop_call_ctx(&mut self) {
        let call = self.calls.pop().expect("calls should not be empty");
        // Accumulate reversible_write_counter if call is success
        if self.call_is_success[call.index] {
            if let Some(caller) = self.calls.last_mut() {
                caller.reversible_write_counter += call.reversible_write_counter;
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Result of the parsing of an Ethereum Transaction.
pub struct Transaction {
    /// ..
    pub block_num: u64,
    /// Type
    pub tx_type: TxType,
    /// Nonce
    pub nonce: u64,
    /// Hash
    pub hash: H256,
    /// Gas
    pub gas: u64,
    /// Gas price
    pub gas_price: Word,
    /// Gas fee cap
    pub gas_fee_cap: Word,
    /// Gas tip cap
    pub gas_tip_cap: Word,
    /// From / Caller Address
    pub from: Address,
    /// To / Callee Address
    pub to: Option<Address>,
    /// Value
    pub value: Word,
    /// Input / Call Data
    pub input: Vec<u8>,
    /// Chain_id
    pub chain_id: u64,
    /// Signature
    pub signature: Signature,
    /// RLP bytes
    pub rlp_bytes: Vec<u8>,
    /// RLP bytes for signing
    pub rlp_unsigned_bytes: Vec<u8>,
    /// Current values of L1 fee
    pub l1_fee: TxL1Fee,
    /// Committed values of L1 fee
    pub l1_fee_committed: TxL1Fee,
    /// Calls made in the transaction
    pub(crate) calls: Vec<Call>,
    /// Execution steps
    steps: Vec<ExecStep>,
}

impl From<&Transaction> for geth_types::Transaction {
    fn from(tx: &Transaction) -> geth_types::Transaction {
        geth_types::Transaction {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
            nonce: Word::from(tx.nonce),
            gas_limit: Word::from(tx.gas),
            value: tx.value,
            gas_price: tx.gas_price,
            call_data: tx.input.clone().into(),
            v: tx.signature.v,
            r: tx.signature.r,
            s: tx.signature.s,
            gas_fee_cap: tx.gas_fee_cap,
            gas_tip_cap: tx.gas_tip_cap,
            rlp_unsigned_bytes: tx.rlp_unsigned_bytes.clone(),
            rlp_bytes: tx.rlp_bytes.clone(),
            ..Default::default()
        }
    }
}

impl Transaction {
    /// Create a dummy Transaction with zero values
    pub fn dummy() -> Self {
        Self {
            nonce: 0,
            gas: 0,
            gas_price: Word::zero(),
            gas_fee_cap: Word::zero(),
            gas_tip_cap: Word::zero(),
            from: Address::zero(),
            to: Some(Address::zero()), // or use None?
            value: Word::zero(),
            input: Vec::new(),
            chain_id: 0,
            signature: Signature {
                r: Word::zero(),
                s: Word::zero(),
                v: 0,
            },
            rlp_bytes: vec![],
            rlp_unsigned_bytes: vec![],
            calls: Vec::new(),
            steps: Vec::new(),
            block_num: Default::default(),
            hash: Default::default(),
            tx_type: Default::default(),
            l1_fee: Default::default(),
            l1_fee_committed: Default::default(),
        }
    }

    /// Create a new Self.
    pub fn new(
        call_id: usize,
        sdb: &StateDB,
        code_db: &mut CodeDB,
        eth_tx: &eth_types::Transaction,
        is_success: bool,
    ) -> Result<Self, Error> {
        let (found, _) = sdb.get_account(&eth_tx.from);
        if !found {
            return Err(Error::AccountNotFound(eth_tx.from));
        }

        let call = if let Some(address) = eth_tx.to {
            // Contract Call / Transfer
            let (found, account) = sdb.get_account(&address);
            if !found {
                return Err(Error::AccountNotFound(address));
            }
            let code_hash = account.code_hash;
            Call {
                call_id,
                kind: CallKind::Call,
                is_root: true,
                is_persistent: is_success,
                is_success,
                caller_address: eth_tx.from,
                address,
                code_source: CodeSource::Address(address),
                code_hash,
                depth: 1,
                value: eth_tx.value,
                call_data_length: eth_tx.input.as_ref().len() as u64,
                ..Default::default()
            }
        } else {
            // Contract creation
            let code_hash = code_db.insert(eth_tx.input.to_vec());
            let address = get_contract_address(eth_tx.from, eth_tx.nonce);
            Call {
                call_id,
                kind: CallKind::Create,
                is_root: true,
                is_persistent: is_success,
                is_success,
                caller_address: eth_tx.from,
                address,
                code_source: CodeSource::Tx,
                code_hash,
                depth: 1,
                value: eth_tx.value,
                call_data_length: eth_tx.input.len().try_into().unwrap(),
                ..Default::default()
            }
        };

        log::debug!(
            "eth_tx's type: {:?}, idx: {:?}, hash: {:?}, tx: {:?}",
            eth_tx.transaction_type,
            eth_tx.transaction_index,
            eth_tx.hash,
            {
                let mut debug_tx = eth_tx.clone();
                debug_tx.input.0.clear();
                debug_tx
            }
        );

        let l1_fee = TxL1Fee::get_current_values_from_state_db(sdb);
        let l1_fee_committed = TxL1Fee::get_committed_values_from_state_db(sdb);

        log::debug!(
            "l1_fee: {:?}, l1_fee_committed: {:?}",
            l1_fee,
            l1_fee_committed
        );

        Ok(Self {
            block_num: eth_tx.block_number.unwrap().as_u64(),
            hash: eth_tx.hash,
            tx_type: TxType::get_tx_type(eth_tx),
            rlp_bytes: eth_tx.rlp().to_vec(),
            rlp_unsigned_bytes: get_rlp_unsigned(eth_tx),
            nonce: eth_tx.nonce.as_u64(),
            gas: eth_tx.gas.as_u64(),
            gas_price: eth_tx.gas_price.unwrap_or_default(),
            gas_fee_cap: eth_tx.max_fee_per_gas.unwrap_or_default(),
            gas_tip_cap: eth_tx.max_priority_fee_per_gas.unwrap_or_default(),
            from: eth_tx.from,
            to: eth_tx.to,
            value: eth_tx.value,
            input: eth_tx.input.to_vec(),
            chain_id: eth_tx.chain_id.unwrap_or_default().as_u64(), // FIXME
            calls: vec![call],
            steps: Vec::new(),
            signature: Signature {
                v: eth_tx.v.as_u64(),
                r: eth_tx.r,
                s: eth_tx.s,
            },
            l1_fee,
            l1_fee_committed,
        })
    }

    /// Whether this [`Transaction`] is a create one
    pub fn is_create(&self) -> bool {
        self.calls[0].is_create()
    }

    /// Return the list of execution steps of this transaction.
    pub fn steps(&self) -> &[ExecStep] {
        &self.steps
    }

    /// Return a mutable reference to the list of execution steps of this
    /// transaction.
    pub fn steps_mut(&mut self) -> &mut Vec<ExecStep> {
        &mut self.steps
    }

    /// Return the list of calls of this transaction.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Return a mutable reference to the list containing the calls of this
    /// transaction.
    pub fn calls_mut(&mut self) -> &mut Vec<Call> {
        &mut self.calls
    }

    pub(crate) fn push_call(&mut self, call: Call) {
        self.calls.push(call);
    }

    /// Return last step in this transaction.
    pub fn last_step(&self) -> &ExecStep {
        if self.steps().is_empty() {
            panic!("there is no steps in tx");
        }

        &self.steps[self.steps.len() - 1]
    }

    /// Return whether the steps in this transaction is empty
    pub fn is_steps_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Calculate L1 fee of this transaction.
    pub fn l1_fee(&self) -> u64 {
        let tx_data_gas_cost = tx_data_gas_cost(&self.rlp_bytes);

        self.l1_fee.tx_l1_fee(tx_data_gas_cost).0
    }
}

/// Transaction L1 fee for L1GasPriceOracle contract
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TxL1Fee {
    /// L1 base fee
    pub base_fee: u64,
    /// L1 fee overhead
    pub fee_overhead: u64,
    /// L1 fee scalar
    pub fee_scalar: u64,
}

impl TxL1Fee {
    /// Calculate L1 fee and remainder of transaction.
    pub fn tx_l1_fee(&self, tx_data_gas_cost: u64) -> (u64, u64) {
        // <https://github.com/scroll-tech/go-ethereum/blob/49192260a177f1b63fc5ea3b872fb904f396260c/rollup/fees/rollup_fee.go#L118>
        let tx_l1_gas = tx_data_gas_cost + self.fee_overhead + TX_L1_COMMIT_EXTRA_COST;
        let tx_l1_fee = self.fee_scalar as u128 * self.base_fee as u128 * tx_l1_gas as u128;

        (
            (tx_l1_fee / TX_L1_FEE_PRECISION as u128) as u64,
            (tx_l1_fee % TX_L1_FEE_PRECISION as u128) as u64,
        )
    }

    fn get_current_values_from_state_db(sdb: &StateDB) -> Self {
        let [base_fee, fee_overhead, fee_scalar] = [
            &l1_gas_price_oracle::BASE_FEE_SLOT,
            &l1_gas_price_oracle::OVERHEAD_SLOT,
            &l1_gas_price_oracle::SCALAR_SLOT,
        ]
        .map(|slot| {
            sdb.get_storage(&l1_gas_price_oracle::ADDRESS, slot)
                .1
                .as_u64()
        });

        Self {
            base_fee,
            fee_overhead,
            fee_scalar,
        }
    }

    fn get_committed_values_from_state_db(sdb: &StateDB) -> Self {
        let [base_fee, fee_overhead, fee_scalar] = [
            &l1_gas_price_oracle::BASE_FEE_SLOT,
            &l1_gas_price_oracle::OVERHEAD_SLOT,
            &l1_gas_price_oracle::SCALAR_SLOT,
        ]
        .map(|slot| {
            sdb.get_committed_storage(&l1_gas_price_oracle::ADDRESS, slot)
                .1
                .as_u64()
        });

        Self {
            base_fee,
            fee_overhead,
            fee_scalar,
        }
    }
}
