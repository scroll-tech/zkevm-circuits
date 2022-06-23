use crate::{evm_circuit::step::ExecutionState, impl_expr};
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

pub trait LookupTable<F: FieldExt> {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>>;
}

impl<F: FieldExt, const W: usize> LookupTable<F> for [Column<Advice>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_advice(*column, Rotation::cur()))
            .collect()
    }
}

impl<F: FieldExt, const W: usize> LookupTable<F> for [Column<Fixed>; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_fixed(*column, Rotation::cur()))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum FixedTableTag {
    Zero = 0,
    Range5,
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
    Pow2,
}

impl FixedTableTag {
    pub fn build<F: FieldExt>(&self) -> Box<dyn Iterator<Item = [F; 4]>> {
        let tag = F::from(*self as u64);
        match self {
            Self::Zero => Box::new((0..1).map(move |_| [tag, F::zero(), F::zero(), F::zero()])),
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
                Box::new(ExecutionState::iter().flat_map(move |execution_state| {
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
            Self::Pow2 => Box::new((0..65).map(move |value| {
                [
                    tag,
                    F::from(value),
                    F::from_u128(1_u128 << value),
                    F::zero(),
                ]
            })),
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

// Keep the sequence consistent with OpcodeId for scalar
#[derive(Clone, Copy, Debug)]
pub enum BlockContextFieldTag {
    Coinbase = 1,
    Timestamp,
    Number,
    Difficulty,
    GasLimit,
    BaseFee = 8,
    BlockHash,
    ChainId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum RwTableTag {
    Start = 1,
    Stack,
    Memory,
    AccountStorage,
    TxAccessListAccount,
    TxAccessListAccountStorage,
    TxRefund,
    Account,
    AccountDestructed,
    CallContext,
    TxLog,
    TxReceipt,
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

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum AccountFieldTag {
    Nonce = 1,
    Balance,
    CodeHash,
}

#[derive(Clone, Copy, Debug)]
pub enum BytecodeFieldTag {
    Length,
    Byte,
    Padding,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TxLogFieldTag {
    Address = 1,
    Topic,
    Data,
}

#[derive(Clone, Copy, Debug, PartialEq, EnumIter, EnumCount)]
pub enum TxReceiptFieldTag {
    PostStateOrStatus = 1,
    CumulativeGasUsed,
    LogLength,
}

#[derive(Clone, Copy, Debug, PartialEq, EnumIter)]
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
impl_expr!(BytecodeFieldTag);
impl_expr!(CallContextFieldTag);
impl_expr!(BlockContextFieldTag);
impl_expr!(TxLogFieldTag);
impl_expr!(TxReceiptFieldTag);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, EnumIter)]
pub(crate) enum Table {
    Fixed,
    Tx,
    Rw,
    Bytecode,
    Block,
    Byte,
}

#[derive(Clone, Debug)]
pub struct RwValues<F> {
    pub id: Expression<F>,
    pub address: Expression<F>,
    pub field_tag: Expression<F>,
    pub storage_key: Expression<F>,
    pub value: Expression<F>,
    pub value_prev: Expression<F>,
    pub aux1: Expression<F>,
    pub aux2: Expression<F>,
}

impl<F: Field> RwValues<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Expression<F>,
        address: Expression<F>,
        field_tag: Expression<F>,
        storage_key: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        aux1: Expression<F>,
        aux2: Expression<F>,
    ) -> Self {
        Self {
            id,
            address,
            field_tag,
            storage_key,
            value,
            value_prev,
            aux1,
            aux2,
        }
    }
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
        values: RwValues<F>,
    },
    /// Lookup to bytecode table, which contains all used creation code and
    /// contract code.
    Bytecode {
        /// Hash to specify which code to read.
        hash: Expression<F>,
        /// Tag to specify whether its the bytecode length or byte value in the
        /// bytecode.
        tag: Expression<F>,
        /// Index to specify which byte of bytecode.
        index: Expression<F>,
        /// A boolean value to specify if the value is executable opcode or the
        /// data portion of PUSH* operations.
        is_code: Expression<F>,
        /// Value corresponding to the tag.
        value: Expression<F>,
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
    /// Lookup to byte value.
    Byte {
        /// Value of the field.
        value: Expression<F>,
    },
    /// Conditional lookup enabled by the first element.
    Conditional(Expression<F>, Box<Lookup<F>>),
}

impl<F: Field> Lookup<F> {
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
            Self::Byte { .. } => Table::Byte,
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
            } => {
                vec![
                    counter.clone(),
                    is_write.clone(),
                    tag.clone(),
                    values.id.clone(),
                    values.address.clone(),
                    values.field_tag.clone(),
                    values.storage_key.clone(),
                    values.value.clone(),
                    values.value_prev.clone(),
                    values.aux1.clone(),
                    values.aux2.clone(),
                ]
            }
            Self::Bytecode {
                hash,
                tag,
                index,
                is_code,
                value,
            } => {
                vec![
                    hash.clone(),
                    tag.clone(),
                    index.clone(),
                    is_code.clone(),
                    value.clone(),
                ]
            }
            Self::Block {
                field_tag,
                number,
                value,
            } => {
                vec![field_tag.clone(), number.clone(), value.clone()]
            }
            Self::Byte { value } => {
                vec![value.clone()]
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
