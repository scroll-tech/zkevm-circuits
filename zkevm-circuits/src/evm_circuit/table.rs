use crate::{evm_circuit::step::ExecutionState, impl_expr};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

pub trait LookupTable<F: FieldExt, const W: usize> {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W];
}

impl<F: FieldExt, const W: usize> LookupTable<F, W> for [Column<Advice>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W] {
        self.map(|column| meta.query_advice(column, Rotation::cur()))
    }
}

impl<F: FieldExt, const W: usize> LookupTable<F, W> for [Column<Fixed>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> [Expression<F>; W] {
        self.map(|column| meta.query_fixed(column, Rotation::cur()))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FixedTableTag {
    Range5 = 1,
    Range16,
    Range32,
    Range64,
    Range256,
    Range512,
    Range1024,
    SignByte,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    ResponsibleOpcode,
}

impl FixedTableTag {
    pub fn iterator() -> impl Iterator<Item = Self> {
        [
            Self::Range5,
            Self::Range16,
            Self::Range32,
            Self::Range64,
            Self::Range256,
            Self::Range512,
            Self::Range1024,
            Self::SignByte,
            Self::BitwiseAnd,
            Self::BitwiseOr,
            Self::BitwiseXor,
            Self::ResponsibleOpcode,
        ]
        .iter()
        .copied()
    }

    pub fn build<F: FieldExt>(&self) -> Box<dyn Iterator<Item = [F; 4]>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Range5 => {
                Box::new((0..5).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range16 => {
                Box::new((0..16).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range32 => {
                Box::new((0..32).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range64 => {
                Box::new((0..64).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range256 => {
                Box::new((0..256).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range512 => {
                Box::new((0..512).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::Range1024 => {
                Box::new((0..1024).map(move |value| [tag, F::from(value), F::zero(), F::zero()]))
            }
            Self::SignByte => Box::new((0..256).map(move |value| {
                [
                    tag,
                    F::from(value),
                    F::from((value >> 7) * 0xFFu64),
                    F::zero(),
                ]
            })),
            Self::BitwiseAnd => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs & rhs)])
            })),
            Self::BitwiseOr => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs | rhs)])
            })),
            Self::BitwiseXor => Box::new((0..256).flat_map(move |lhs| {
                (0..256).map(move |rhs| [tag, F::from(lhs), F::from(rhs), F::from(lhs ^ rhs)])
            })),
            Self::ResponsibleOpcode => {
                Box::new(ExecutionState::iterator().flat_map(move |execution_state| {
                    execution_state
                        .responsible_opcodes()
                        .into_iter()
                        .map(move |opcode| {
                            [
                                tag,
                                F::from(execution_state.as_u64()),
                                F::from(opcode.as_u64()),
                                F::zero(),
                            ]
                        })
                }))
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TxContextFieldTag {
    Nonce = 1,
    Gas,
    GasPrice,
    CallerAddress,
    CalleeAddress,
    IsCreate,
    Value,
    CallDataLength,
    CallDataGasCost,
    CallData,
}

#[derive(Clone, Copy, Debug)]
pub enum BlockContextFieldTag {
    Coinbase = 1,
    GasLimit,
    Number,
    Timestamp,
    Difficulty,
    BaseFee,
    BlockHash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RwTableTag {
    Memory = 2,
    Stack,
    AccountStorage,
    TxAccessListAccount,
    TxAccessListAccountStorage,
    TxRefund,
    Account,
    AccountDestructed,
    CallContext,
}

impl RwTableTag {
    pub fn is_reversible(self) -> bool {
        return matches!(
            self,
            RwTableTag::TxAccessListAccount
                | RwTableTag::TxAccessListAccountStorage
                | RwTableTag::TxRefund
                | RwTableTag::Account
                | RwTableTag::AccountStorage
                | RwTableTag::AccountDestructed
        );
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AccountFieldTag {
    Nonce = 1,
    Balance,
    CodeHash,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CallContextFieldTag {
    RwCounterEndOfReversion = 1,
    CallerId,
    TxId,
    Depth,
    CallerAddress,
    CalleeAddress,
    CallDataOffset,
    CallDataLength,
    ReturnDataOffset,
    ReturnDataLength,
    Value,
    IsSuccess,
    IsPersistent,
    IsStatic,

    LastCalleeId,
    LastCalleeReturnDataOffset,
    LastCalleeReturnDataLength,

    IsRoot,
    IsCreate,
    CodeSource,
    ProgramCounter,
    StackPointer,
    GasLeft,
    MemorySize,
    StateWriteCounter,
}

impl_expr!(FixedTableTag);
impl_expr!(TxContextFieldTag);
impl_expr!(RwTableTag);
impl_expr!(AccountFieldTag);
impl_expr!(CallContextFieldTag);
impl_expr!(BlockContextFieldTag);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Table {
    Fixed,
    Tx,
    Rw,
    Bytecode,
    Block,
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    /// Lookup to fixed table, which contains serveral pre-built tables such as
    /// range tables or bitwise tables.
    Fixed {
        /// Tag to specify which table to lookup.
        tag: Expression<F>,
        /// Values that must satisfy the pre-built relationship.
        values: [Expression<F>; 3],
    },
    /// Lookup to tx table, which contains transactions of this block.
    Tx {
        /// Id of transaction, the first transaction has id = 1.
        id: Expression<F>,
        /// Tag to specify which field to read.
        field_tag: Expression<F>,
        /// Index to specify which byte of calldata, which is only used when
        /// field_tag is Calldata, otherwise should be set to 0.
        index: Expression<F>,
        /// Value of the field.
        value: Expression<F>,
    },
    /// Lookup to read-write table, which contains read-write access records of
    /// time-aware data.
    Rw {
        /// Counter for how much read-write have been done, which stands for
        /// the sequential timestamp.
        counter: Expression<F>,
        /// A boolean value to specify if the access record is a read or write.
        is_write: Expression<F>,
        /// Tag to specify which read-write data to access, see RwTableTag for
        /// all tags.
        tag: Expression<F>,
        /// Values corresponding to the tag.
        values: [Expression<F>; 8],
    },
    /// Lookup to bytecode table, which contains all used creation code and
    /// contract code.
    Bytecode {
        /// Hash to specify which code to read.
        hash: Expression<F>,
        /// Index to specify which byte of bytecode.
        index: Expression<F>,
        /// Value of the index.
        value: Expression<F>,
        /// A boolean value to specify if the value is executable opcode or the
        /// data portion of PUSH* operations.
        is_code: Expression<F>,
    },
    /// Lookup to block table, which contains constants of this block.
    Block {
        /// Tag to specify which field to read.
        field_tag: Expression<F>,
        /// Stores the block number only when field_tag is BlockHash, otherwise
        /// should be set to 0.
        number: Expression<F>,
        /// Value of the field.
        value: Expression<F>,
    },
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<Lookup<F>>),
}

impl<F: FieldExt> Lookup<F> {
    pub(crate) fn conditional(self, condition: Expression<F>) -> Self {
        Self::Conditional(condition, self.into())
    }

    pub(crate) fn table(&self) -> Table {
        match self {
            Self::Fixed { .. } => Table::Fixed,
            Self::Tx { .. } => Table::Tx,
            Self::Rw { .. } => Table::Rw,
            Self::Bytecode { .. } => Table::Bytecode,
            Self::Block { .. } => Table::Block,
            Self::Conditional(_, lookup) => lookup.table(),
        }
    }

    pub(crate) fn input_exprs(&self) -> Vec<Expression<F>> {
        match self {
            Self::Fixed { tag, values } => [vec![tag.clone()], values.to_vec()].concat(),
            Self::Tx {
                id,
                field_tag,
                index,
                value,
            } => vec![id.clone(), field_tag.clone(), index.clone(), value.clone()],
            Self::Rw {
                counter,
                is_write,
                tag,
                values,
            } => [
                vec![counter.clone(), is_write.clone(), tag.clone()],
                values.to_vec(),
            ]
            .concat(),
            Self::Bytecode {
                hash,
                index,
                value,
                is_code,
            } => {
                vec![hash.clone(), index.clone(), value.clone(), is_code.clone()]
            }
            Self::Block {
                field_tag,
                number,
                value,
            } => {
                vec![field_tag.clone(), number.clone(), value.clone()]
            }
            Self::Conditional(condition, lookup) => lookup
                .input_exprs()
                .into_iter()
                .map(|expr| condition.clone() * expr)
                .collect(),
        }
    }

    pub(crate) fn degree(&self) -> usize {
        self.input_exprs()
            .iter()
            .map(|expr| expr.degree())
            .max()
            .unwrap()
    }
}
