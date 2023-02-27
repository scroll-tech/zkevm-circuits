use super::{
    AccountOp, CallContextOp, MemoryOp, Op, OpEnum, Operation, RWCounter, StackOp, StartOp,
    StorageOp, Target, TxAccessListAccountOp, TxAccessListAccountStorageOp, TxLogOp, TxReceiptOp,
    TxRefundOp, RW,
};
use crate::exec_trace::OperationRef;
use itertools::Itertools;

/// The `OperationContainer` is meant to store all of the [`Operation`]s that an
/// [`ExecStep`](crate::circuit_input_builder::ExecStep) performs during its
/// execution.
///
/// Once an operation is inserted into the container, it returns an
/// [`OperationRef`] which holds an index to the operation just inserted.
/// These references are stored inside of the bus-mapping instances of each
/// [`ExecStep`](crate::circuit_input_builder::ExecStep).
///
/// Finally, the container also provides the capability of retrieving all of the
/// `Stack`, `Memory` or `Storage` operations ordered according to the criterias
/// they have specified.
/// That serves as a way to get an input with which is easy to work with in
/// order to construct the State proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationContainer {
    /// Operations of MemoryOp
    pub memory: Vec<Operation<MemoryOp>>,
    /// Operations of StackOp
    pub stack: Vec<Operation<StackOp>>,
    /// Operations of StorageOp
    pub storage: Vec<Operation<StorageOp>>,
    /// Operations of TxAccessListAccountOp
    pub tx_access_list_account: Vec<Operation<TxAccessListAccountOp>>,
    /// Operations of TxAccessListAccountStorageOp
    pub tx_access_list_account_storage: Vec<Operation<TxAccessListAccountStorageOp>>,
    /// Operations of TxRefundOp
    pub tx_refund: Vec<Operation<TxRefundOp>>,
    /// Operations of AccountOp
    pub account: Vec<Operation<AccountOp>>,
    /// Operations of CallContextOp
    pub call_context: Vec<Operation<CallContextOp>>,
    /// Operations of TxReceiptOp
    pub tx_receipt: Vec<Operation<TxReceiptOp>>,
    /// Operations of TxLogOp
    pub tx_log: Vec<Operation<TxLogOp>>,
    /// Operations of Start
    pub start: Vec<Operation<StartOp>>,
}

impl Default for OperationContainer {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: impl Index for OperationContainer
impl OperationContainer {
    /// Generates a new instance of an `OperationContainer`.
    pub fn new() -> Self {
        Self {
            memory: Vec::new(),
            stack: Vec::new(),
            storage: Vec::new(),
            tx_access_list_account: Vec::new(),
            tx_access_list_account_storage: Vec::new(),
            tx_refund: Vec::new(),
            account: Vec::new(),
            call_context: Vec::new(),
            tx_receipt: Vec::new(),
            tx_log: Vec::new(),
            start: Vec::new(),
        }
    }

    /// Inserts an [`Operation`] into the  container returning a lightweight
    /// reference to it in the form of an [`OperationRef`] which points to the
    /// location of the inserted operation inside the corresponding container
    /// vector.
    pub fn insert<T: Op>(&mut self, op: Operation<T>) -> OperationRef {
        let rwc = op.rwc();
        let rw = op.rw();
        let reversible = op.reversible();
        self.insert_op_enum(rwc, rw, reversible, op.op.into_enum())
    }

    /// Inserts an [`OpEnum`] into the  container returning a lightweight
    /// reference to it in the form of an [`OperationRef`] which points to the
    /// location of the inserted operation inside the corresponding container
    /// vector.
    pub fn insert_op_enum(
        &mut self,
        rwc: RWCounter,
        rw: RW,
        reversible: bool,
        op_enum: OpEnum,
    ) -> OperationRef {
        match op_enum {
            OpEnum::Memory(op) => {
                self.memory.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::Memory, self.memory.len() - 1))
            }
            OpEnum::Stack(op) => {
                self.stack.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::Stack, self.stack.len() - 1))
            }
            OpEnum::Storage(op) => {
                self.storage.push(if reversible {
                    Operation::new_reversible(rwc, rw, op)
                } else {
                    Operation::new(rwc, rw, op)
                });
                OperationRef::from((Target::Storage, self.storage.len() - 1))
            }
            OpEnum::TxAccessListAccount(op) => {
                self.tx_access_list_account.push(if reversible {
                    Operation::new_reversible(rwc, rw, op)
                } else {
                    Operation::new(rwc, rw, op)
                });
                OperationRef::from((
                    Target::TxAccessListAccount,
                    self.tx_access_list_account.len() - 1,
                ))
            }
            OpEnum::TxAccessListAccountStorage(op) => {
                self.tx_access_list_account_storage.push(if reversible {
                    Operation::new_reversible(rwc, rw, op)
                } else {
                    Operation::new(rwc, rw, op)
                });
                OperationRef::from((
                    Target::TxAccessListAccountStorage,
                    self.tx_access_list_account_storage.len() - 1,
                ))
            }
            OpEnum::TxRefund(op) => {
                self.tx_refund.push(if reversible {
                    Operation::new_reversible(rwc, rw, op)
                } else {
                    Operation::new(rwc, rw, op)
                });
                OperationRef::from((Target::TxRefund, self.tx_refund.len() - 1))
            }
            OpEnum::Account(op) => {
                self.account.push(if reversible {
                    Operation::new_reversible(rwc, rw, op)
                } else {
                    Operation::new(rwc, rw, op)
                });
                OperationRef::from((Target::Account, self.account.len() - 1))
            }
            OpEnum::CallContext(op) => {
                self.call_context.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::CallContext, self.call_context.len() - 1))
            }
            OpEnum::TxReceipt(op) => {
                self.tx_receipt.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::TxReceipt, self.tx_receipt.len() - 1))
            }
            OpEnum::TxLog(op) => {
                self.tx_log.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::TxLog, self.tx_log.len() - 1))
            }
            OpEnum::Start(op) => {
                self.start.push(Operation::new(rwc, rw, op));
                OperationRef::from((Target::Start, self.start.len() - 1))
            }
        }
    }

    /// Returns a sorted vector of all of the [`MemoryOp`]s contained inside of
    /// the container.
    pub fn sorted_memory(&self) -> Vec<Operation<MemoryOp>> {
        self.memory.iter().sorted().cloned().collect()
    }

    /// Returns a sorted vector of all of the [`StackOp`]s contained inside of
    /// the container.
    pub fn sorted_stack(&self) -> Vec<Operation<StackOp>> {
        self.stack.iter().sorted().cloned().collect()
    }

    /// Returns a sorted vector of all of the [`StorageOp`]s contained inside of
    /// the container.
    pub fn sorted_storage(&self) -> Vec<Operation<StorageOp>> {
        self.storage.iter().sorted().cloned().collect()
    }
}

#[cfg(test)]
mod container_test {
    use super::*;

    use crate::operation::{RWCounter, RW};
    use eth_types::evm_types::{MemoryAddress, StackAddress};
    use eth_types::{Address, Word};

    #[test]
    fn operation_container_test() {
        let mut global_counter = RWCounter::default();
        let mut operation_container = OperationContainer::default();
        let stack_operation = Operation::new(
            global_counter.inc_pre(),
            RW::WRITE,
            StackOp::new(1, StackAddress(1023), Word::from(0x100)),
        );
        let memory_operation = Operation::new(
            global_counter.inc_pre(),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 1),
        );
        let storage_operation = Operation::new(
            global_counter.inc_pre(),
            RW::WRITE,
            StorageOp::new(
                Address::zero(),
                Word::default(),
                Word::from(0x1),
                Word::default(),
                1usize,
                Word::default(),
            ),
        );
        let stack_ref = operation_container.insert(stack_operation.clone());
        let memory_ref = operation_container.insert(memory_operation.clone());
        let storage_ref = operation_container.insert(storage_operation.clone());

        assert_eq!(operation_container.sorted_stack()[0], stack_operation);
        assert_eq!(operation_container.sorted_memory()[0], memory_operation);
        assert_eq!(operation_container.sorted_storage()[0], storage_operation);
        assert_eq!(stack_ref, OperationRef::from((Target::Stack, 0)));
        assert_eq!(memory_ref, OperationRef::from((Target::Memory, 0)));
        assert_eq!(storage_ref, OperationRef::from((Target::Storage, 0)));
    }
}
