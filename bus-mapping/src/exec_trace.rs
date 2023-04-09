//! This module contains the logic for parsing and interacting with EVM
//! execution traces.
use crate::operation::Target;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
/// The target and index of an `Operation` in the context of an
/// `ExecutionTrace`.
pub struct OperationRef(pub Target, pub usize);

impl fmt::Debug for OperationRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "OperationRef{{ {}, {} }}",
            match self.0 {
                Target::Start => "Start",
                Target::Memory => "Memory",
                Target::Stack => "Stack",
                Target::Storage => "Storage",
                Target::TxAccessListAccount => "TxAccessListAccount",
                Target::TxAccessListAccountStorage => "TxAccessListAccountStorage",
                Target::TxRefund => "TxRefund",
                Target::Account => "Account",
                Target::CallContext => "CallContext",
                Target::TxReceipt => "TxReceipt",
                Target::TxLog => "TxLog",
            },
            self.1
        ))
    }
}

impl From<(Target, usize)> for OperationRef {
    fn from(op_ref_data: (Target, usize)) -> Self {
        Self(op_ref_data.0, op_ref_data.1)
    }
}

impl OperationRef {
    /// Return the `OperationRef` as a `usize`.
    pub const fn as_usize(&self) -> usize {
        self.1
    }

    /// Return the [`Target`] op type of the `OperationRef`.
    pub const fn target(&self) -> Target {
        self.0
    }
}
