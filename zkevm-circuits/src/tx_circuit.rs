//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
/// TxCircuitTester is the combined circuit of tx circuit and sig circuit.
mod dev;
#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::TxCircuitTester as TestTxCircuit;

use crate::util::Field;
use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    // sig_circuit::SigCircuit,
    table::{
        BlockContextFieldTag::{CumNumTxs, NumAllTxs, NumTxs},
        BlockTable, KeccakTable, LookupTable, PowOfRandTable, RlpFsmRlpTable as RlpTable, SigTable,
        TxFieldTag,
        TxFieldTag::{
            AccessListAddressesLen, AccessListRLC, AccessListStorageKeysLen, BlockNumber, CallData,
            CallDataGasCost, CallDataLength, CallDataRLC, CalleeAddress, CallerAddress, ChainID,
            Gas, GasPrice, IsCreate, MaxFeePerGas, MaxPriorityFeePerGas, Nonce, SigR, SigS, SigV,
            TxDataGasCost, TxHashLength, TxHashRLC, TxSignHash, TxSignLength, TxSignRLC,
        },
        TxTable, U16Table, U8Table,
    },
    util::{
        is_zero::{IsZeroChip, IsZeroConfig},
        keccak, rlc_be_bytes, SubCircuit, SubCircuitConfig,
    },
    witness,
    witness::{
        rlp_fsm::{Tag, ValueTagLength},
        Format::{
            L1MsgHash, TxHashEip155, TxHashEip1559, TxHashEip2930, TxHashPreEip155, TxSignEip155,
            TxSignEip1559, TxSignEip2930, TxSignPreEip155,
        },
        RlpTag,
        RlpTag::{GasCost, Len, Null, RLC},
        Tag::TxType as RLPTxType,
        Transaction,
    },
};
use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
use eth_types::{
    geth_types::{
        access_list_size, TxType,
        TxType::{Eip155, Eip1559, Eip2930, L1Msg, PreEip155},
    },
    sign_types::SignData,
    AccessList, Address, ToAddress, ToBigEndian, ToScalar,
};
use ethers_core::utils::keccak256;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    util::{and, not, select, sum, Expr},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use log::error;
use num::Zero;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, HashMap},
    iter,
    marker::PhantomData,
    ops::{Add, Mul},
};

use crate::{util::Challenges, witness::rlp_fsm::get_rlp_len_tag_length};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;
use halo2_proofs::plonk::{Any, Fixed};
use itertools::Itertools;

/// Number of rows of one tx occupies in the fixed part of tx table
pub const TX_LEN: usize = 28;
/// Offset of TxHash tag in the tx table
pub const TX_HASH_OFFSET: usize = 21;
/// Offset of CallerAddress in the tx table
pub const CALLER_ADDRESS_OFFSET: usize = 4;
/// Offset of TxHashRLC tag in the tx table. TxHashRLC = RLC(tx.rlp_signed)
pub const TX_HASH_RLC_OFFSET: usize = 20;
/// Offset of ChainID tag in the tx table
pub const CHAIN_ID_OFFSET: usize = 12;
/// Offset of HashLength in the tx table
pub const HASH_LENGTH_OFFSET: usize = 19;
/// Offset of HashRLC in the tx table
pub const HASH_RLC_OFFSET: usize = 20;

// TODO: Constants from aggregator shouldn't be manually copied,
// but importing aggregator causes cyclic dependency
// CHUNK_TXBYTES_BLOB_LIMIT =
//      (BLOB_WIDTH * N_BYTES_31) - (N_ROWS_NUM_CHUNKS + N_ROWS_CHUNK_SIZES)
// N_ROWS_CHUNK_SIZES = MAX_AGG_SNARKS * 4
const CHUNK_TXBYTES_BLOB_LIMIT: usize = (4096 * 31) - (2 + 15 * 4);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum LookupCondition {
    // lookup into tx table
    TxCalldata,
    // lookup into rlp table
    L1MsgHash,
    RlpSignTag,
    RlpHashTag,
    // lookup into keccak table
    Keccak,
    // lookup into dynamic access list section of tx table
    TxAccessList,
}

#[derive(Clone, Debug)]
struct RlpTableInputValue<F: Field> {
    tag: RlpTag,
    is_none: bool,
    be_bytes_len: u32,
    be_bytes_rlc: Value<F>,
}

/// Read-only Tx Memory table row.
#[derive(Debug, Clone)]
pub struct TxRomTableRow {
    pub(crate) tag: TxFieldTag,
    pub(crate) tag_next: TxFieldTag,
    pub(crate) is_tx_id_unchanged: u8,
    pub(crate) is_final: u8,
    pub(crate) is_next_dynamic_first: u8,
}

impl From<(TxFieldTag, TxFieldTag, u8, u8, u8)> for TxRomTableRow {
    fn from(value: (TxFieldTag, TxFieldTag, u8, u8, u8)) -> Self {
        Self {
            tag: value.0,
            tag_next: value.1,
            is_tx_id_unchanged: value.2,
            is_final: value.3,
            is_next_dynamic_first: value.4,
        }
    }
}

impl TxRomTableRow {
    pub(crate) fn values<F: Field>(&self) -> Vec<Value<F>> {
        vec![
            Value::known(F::from(usize::from(self.tag) as u64)),
            Value::known(F::from(usize::from(self.tag_next) as u64)),
            Value::known(F::from(self.is_tx_id_unchanged as u64)),
            Value::known(F::from(self.is_final as u64)),
            Value::known(F::from(self.is_next_dynamic_first as u64)),
        ]
    }
}

/// Read-only Memory table for verifying correct tag column transition within the TxCircuit.
#[derive(Clone, Copy, Debug)]
pub struct TxRomTable {
    /// Tag of the current row
    pub tag: Column<Fixed>,
    /// Tag of the next row
    pub tag_next: Column<Fixed>,
    /// Indicator for if the tx_id is the same for current and next tag
    pub is_tx_id_unchanged: Column<Fixed>,
    /// Indicator if the dynamic section tag is complete on current row
    /// This indicator only applies to the dynamic section
    pub is_final: Column<Fixed>,
    /// Indicator for the end of the fixed section
    /// The last tag of the fixed section should transition into either calldata or access_list
    pub is_next_dynamic_first: Column<Fixed>,
}

impl<F: Field> LookupTable<F> for TxRomTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.tag_next.into(),
            self.is_tx_id_unchanged.into(),
            self.is_final.into(),
            self.is_next_dynamic_first.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("tag_next"),
            String::from("is_tx_id_unchanged"),
            String::from("is_final"),
            String::from("is_next_dynamic_first"),
        ]
    }
}

impl TxRomTable {
    /// Construct the ROM table
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            is_tx_id_unchanged: meta.fixed_column(),
            is_final: meta.fixed_column(),
            is_next_dynamic_first: meta.fixed_column(),
        }
    }

    /// Load the ROM table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "Tx ROM table",
            |mut region| {
                let transition_scenarios: Vec<(TxFieldTag, TxFieldTag, u8, u8, u8)> = vec![
                    // All fixed section tags. tx_id stays the same except the last tx.
                    (TxFieldTag::Null, Nonce, 0, 1, 0),
                    (Nonce, GasPrice, 1, 1, 0),
                    (GasPrice, Gas, 1, 1, 0),
                    (Gas, CallerAddress, 1, 1, 0),
                    (CallerAddress, CalleeAddress, 1, 1, 0),
                    (CalleeAddress, IsCreate, 1, 1, 0),
                    (IsCreate, TxFieldTag::Value, 1, 1, 0),
                    (TxFieldTag::Value, CallDataRLC, 1, 1, 0),
                    (CallDataRLC, CallDataLength, 1, 1, 0),
                    (CallDataLength, CallDataGasCost, 1, 1, 0),
                    (CallDataGasCost, TxDataGasCost, 1, 1, 0),
                    (TxDataGasCost, ChainID, 1, 1, 0),
                    (ChainID, SigV, 1, 1, 0),
                    (SigV, SigR, 1, 1, 0),
                    (SigR, SigS, 1, 1, 0),
                    (SigS, TxSignLength, 1, 1, 0),
                    (TxSignLength, TxSignRLC, 1, 1, 0),
                    (TxSignRLC, TxSignHash, 1, 1, 0),
                    (TxSignHash, TxHashLength, 1, 1, 0),
                    (TxHashLength, TxHashRLC, 1, 1, 0),
                    (TxHashRLC, TxFieldTag::TxHash, 1, 1, 0),
                    (TxFieldTag::TxHash, TxFieldTag::TxType, 1, 1, 0),
                    (TxFieldTag::TxType, AccessListAddressesLen, 1, 1, 0),
                    (AccessListAddressesLen, AccessListStorageKeysLen, 1, 1, 0),
                    (AccessListStorageKeysLen, AccessListRLC, 1, 1, 0),
                    (AccessListRLC, MaxFeePerGas, 1, 1, 0),
                    (MaxFeePerGas, MaxPriorityFeePerGas, 1, 1, 0),
                    (MaxPriorityFeePerGas, BlockNumber, 1, 1, 0),
                    // Transition into dynamic section of tx_table
                    (BlockNumber, Nonce, 0, 1, 0),
                    (BlockNumber, CallData, 1, 1, 1),
                    (BlockNumber, CallData, 0, 1, 1),
                    (BlockNumber, TxFieldTag::AccessListAddress, 1, 1, 1),
                    (BlockNumber, TxFieldTag::AccessListAddress, 0, 1, 1),
                    // Transition between dynamic tags of tx_table
                    (CallData, CallData, 1, 0, 0),
                    (CallData, CallData, 0, 1, 0),
                    (CallData, TxFieldTag::AccessListAddress, 1, 1, 0),
                    (CallData, TxFieldTag::AccessListAddress, 0, 1, 0),
                    (
                        TxFieldTag::AccessListAddress,
                        TxFieldTag::AccessListAddress,
                        1,
                        0,
                        0,
                    ),
                    (
                        TxFieldTag::AccessListAddress,
                        TxFieldTag::AccessListAddress,
                        0,
                        1,
                        0,
                    ),
                    (
                        TxFieldTag::AccessListAddress,
                        TxFieldTag::AccessListStorageKey,
                        1,
                        0,
                        0,
                    ),
                    (
                        TxFieldTag::AccessListStorageKey,
                        TxFieldTag::AccessListStorageKey,
                        1,
                        0,
                        0,
                    ),
                    (
                        TxFieldTag::AccessListStorageKey,
                        TxFieldTag::AccessListAddress,
                        1,
                        0,
                        0,
                    ),
                    (
                        TxFieldTag::AccessListStorageKey,
                        TxFieldTag::AccessListAddress,
                        0,
                        1,
                        0,
                    ),
                    (TxFieldTag::AccessListAddress, CallData, 0, 1, 0),
                    (TxFieldTag::AccessListStorageKey, CallData, 0, 1, 0),
                    // Continue padding. Padding has the Calldata tag
                    (CallData, CallData, 1, 1, 0),
                ];

                for (offset, scenario) in transition_scenarios.into_iter().enumerate() {
                    for (&column, value) in <TxRomTable as LookupTable<F>>::fixed_columns(self)
                        .iter()
                        .zip(TxRomTableRow::from(scenario).values::<F>().into_iter())
                    {
                        region.assign_fixed(
                            || format!("rom table row: offset = {offset}"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    minimum_rows: usize,

    // This is only true at the first row of dynamic part of tx table
    q_dynamic_first: Column<Fixed>,
    q_dynamic_last: Column<Fixed>,
    // A selector which is enabled at 1st row
    q_first: Column<Fixed>,
    tx_table: TxTable,
    tx_tag_bits: BinaryNumberConfig<TxFieldTag, 5>,

    tx_type: Column<Advice>,
    tx_type_bits: BinaryNumberConfig<TxType, 3>,
    // The associated rlp tag to lookup in the RLP table
    rlp_tag: Column<Advice>,
    // Whether tag's RLP-encoded value is 0x80 = rlp([])
    is_none: Column<Advice>,
    tx_value_length: Column<Advice>,
    tx_value_rlc: Column<Advice>,

    u8_table: U8Table,
    u16_table: U16Table,

    /// Verify if the tx_id is zero or not.
    tx_id_is_zero: IsZeroConfig<F>,
    /// Primarily used to verify if the `CallDataLength` is zero or non-zero
    ///  and `CallData` byte is zero or non-zero.
    value_is_zero: IsZeroConfig<F>,
    /// We use an equality gadget to know whether the tx id changes between
    /// subsequent rows or not.
    tx_id_unchanged: IsEqualConfig<F>,

    /// Columns used to reduce degree
    is_tag_block_num: Column<Advice>,
    is_calldata: Column<Advice>,
    is_caller_address: Column<Advice>,
    is_row_hash_rlc: Column<Advice>,
    is_l1_msg: Column<Advice>,
    is_eip2930: Column<Advice>,
    is_eip1559: Column<Advice>,
    is_chain_id: Column<Advice>,
    is_tx_id_zero: Column<Advice>,
    lookup_conditions: HashMap<LookupCondition, Column<Advice>>,

    /// Columns for computing num_all_txs
    tx_nonce: Column<Advice>,
    block_num: Column<Advice>,
    block_num_unchanged: IsEqualConfig<F>,
    num_all_txs_acc: Column<Advice>,
    total_l1_popped_before: Column<Advice>,

    /// Columns for accumulating call_data_length and call_data_gas_cost
    /// A boolean advice column, which is turned on only for the last byte in
    /// call data.
    is_final: Column<Advice>,
    /// An accumulator value used to correctly calculate the calldata gas cost
    /// for a tx.
    calldata_gas_cost_acc: Column<Advice>,
    /// An accumulator value used to correctly calculate the RLC(calldata and access list) for a
    /// tx. contains two sections if access list is present on the tx
    section_rlc: Column<Advice>,
    /// 1st phase column which equals to tx_table.value when is_calldata is true
    /// We need this because tx_table.value is a 2nd phase column and is used to get section_rlc.
    /// It's not safe to do RLC on columns of same phase.
    calldata_byte: Column<Advice>,

    /// Columns for ensuring that BlockNum is correct
    is_padding_tx: Column<Advice>,
    /// Tx id must be no greater than cum_num_txs
    tx_id_cmp_cum_num_txs: ComparatorConfig<F, 2>,
    /// Cumulative number of txs up to a block
    cum_num_txs: Column<Advice>,
    /// Number of txs in a block
    num_txs: Column<Advice>,

    /// Address recovered by SignVerifyChip
    sv_address: Column<Advice>,

    sig_table: SigTable,

    // External tables
    block_table: BlockTable,
    rlp_table: RlpTable,
    keccak_table: KeccakTable,
    pow_of_rand_table: PowOfRandTable,

    // Access list columns
    al_idx: Column<Advice>,
    sk_idx: Column<Advice>,
    sks_acc: Column<Advice>,
    // section denoter for access list, reduces degree
    is_access_list: Column<Advice>,
    // access list tag denoter, reduces degree
    is_access_list_address: Column<Advice>,
    is_access_list_storage_key: Column<Advice>,
    // field_rlc holds tag rlc from RLP FSM
    // works together with section_rlc to ensure
    // no ommittance in access list dynamic section
    field_rlc: Column<Advice>,
    // column for reducing degree. Excludes L1Msg and padding tx
    is_chunk_bytes: Column<Advice>,
    // A tx's len for the chunk's hash is different from HashLen
    // A padding tx, for example, has a non-zero HashLen but isn't included in chunk hash.
    chunk_bytes_len: Column<Advice>,
    // chunk_txbytes_rlc is the rlc of all signed rlp bytes in the chunk
    // used for calculating hash of all chunk bytes
    chunk_txbytes_rlc: Column<Advice>,
    chunk_txbytes_len_acc: Column<Advice>,
    pow_of_rand: Column<Advice>,
    /// ROM table
    tx_rom_table: TxRomTable,

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct TxCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// Block Table
    pub block_table: BlockTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// RlpTable
    pub rlp_table: RlpTable,
    /// SigTable
    pub sig_table: SigTable,
    /// Reusable u8 lookup table,
    pub u8_table: U8Table,
    /// Reusable u16 lookup table,
    pub u16_table: U16Table,
    /// Reusable power of rand table,
    pub pow_of_rand_table: PowOfRandTable,
    /// Challenges
    pub challenges: crate::util::Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for TxCircuitConfig<F> {
    type ConfigArgs = TxCircuitConfigArgs<F>;

    /// Return a new TxCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            block_table,
            keccak_table,
            rlp_table,
            sig_table,
            u8_table,
            u16_table,
            pow_of_rand_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = tx_table.q_enable;

        let q_first = meta.fixed_column();
        let q_dynamic_first = meta.fixed_column();
        let q_dynamic_last = meta.fixed_column();
        // Since we allow skipping l1 txs that could cause potential circuit overflow,
        // the num_all_txs (num_l1_msgs + num_l2_txs) in the input to get chunk data hash
        // does not necessarily equal to num_txs (self.txs.len()) in block table.
        // Therefore we calculated two numbers (num_l1_msgs, num_l2_txs) in tx circuit
        // and then asserts that `num_l1_msgs + num_l2_txs = num_all_txs` in pi circuit.
        //
        // In more detail, all txs in same block are grouped together and we iterate over
        // its txs to get `num_all_txs`.
        //
        //  | is_l1_msg | queue_index | total_l1_popped_before |  num_all_txs  |
        //  |    true   |     q1      |           c            |    q1-c+1     |
        //  |    false  |             |         q1+1           |    q1-c+2     |
        //  |    true   |     q2      |         q1+1           |    q2-c+2     |
        //  |    true   |     q3      |         q2+1           |    q3-c+2     |

        let tx_nonce = meta.advice_column();
        let block_num = meta.advice_column();

        let total_l1_popped_before = meta.advice_column();
        // num_all_txs = num_l1_msgs + num_l2_txs
        let num_all_txs_acc = meta.advice_column();

        // tag, rlp_tag, tx_type, is_none
        let tx_type = meta.advice_column();
        let rlp_tag = meta.advice_column();
        let tx_value_rlc = meta.advice_column_in(SecondPhase);
        let tx_value_length = meta.advice_column();
        let is_none = meta.advice_column();
        let tag_bits = BinaryNumberChip::configure(meta, q_enable, Some(tx_table.tag.into()));
        let tx_type_bits = BinaryNumberChip::configure(meta, q_enable, Some(tx_type.into()));

        // columns for constraining BlockNum is valid
        let cum_num_txs = meta.advice_column();
        // num_of_txs that each block contains
        let num_txs = meta.advice_column();
        let is_padding_tx = meta.advice_column();

        // columns for accumulating length and gas_cost of call_data
        let is_final = meta.advice_column();
        let calldata_gas_cost_acc = meta.advice_column();
        let section_rlc = meta.advice_column_in(SecondPhase);
        let calldata_byte = meta.advice_column();

        // booleans to reduce degree
        let is_l1_msg = meta.advice_column();
        let is_eip2930 = meta.advice_column();
        let is_eip1559 = meta.advice_column();
        let is_calldata = meta.advice_column();
        let is_tx_id_zero = meta.advice_column();
        let is_caller_address = meta.advice_column();
        let is_row_hash_rlc = meta.advice_column();
        let is_chain_id = meta.advice_column();
        let is_tag_block_num = meta.advice_column();
        let lookup_conditions = [
            LookupCondition::TxCalldata,
            LookupCondition::L1MsgHash,
            LookupCondition::RlpSignTag,
            LookupCondition::RlpHashTag,
            LookupCondition::Keccak,
            LookupCondition::TxAccessList,
        ]
        .into_iter()
        .map(|condition| (condition, meta.advice_column()))
        .collect::<HashMap<LookupCondition, Column<Advice>>>();

        // access list columns
        let al_idx = meta.advice_column();
        let sk_idx = meta.advice_column();
        let sks_acc = meta.advice_column();
        let is_access_list = meta.advice_column();
        let is_access_list_address = meta.advice_column();
        let is_access_list_storage_key = meta.advice_column();
        let field_rlc = meta.advice_column();

        // Chunk bytes accumulator
        let is_chunk_bytes = meta.advice_column();
        let chunk_bytes_len = meta.advice_column();
        let chunk_txbytes_rlc = meta.advice_column_in(SecondPhase);
        let chunk_txbytes_len_acc = meta.advice_column();
        let pow_of_rand = meta.advice_column_in(SecondPhase);

        meta.enable_equality(chunk_bytes_len);
        meta.enable_equality(chunk_txbytes_rlc);
        meta.enable_equality(chunk_txbytes_len_acc);
        meta.enable_equality(pow_of_rand);
        meta.enable_equality(tx_table.chunk_txbytes_hash_rlc);

        // TODO: add lookup to SignVerify table for sv_address
        let sv_address = meta.advice_column();
        meta.enable_equality(tx_table.value);

        let log_deg = |s: &'static str, meta: &mut ConstraintSystem<F>| {
            debug_assert!(meta.degree() <= 9);
            log::info!("after {}, meta.degree: {}", s, meta.degree());
        };

        // tx_id == 0
        let tx_id_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            tx_table.tx_id,
            |meta| meta.advice_column(),
        );

        // macros
        macro_rules! is_tx_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tag_bits.value_equals(TxFieldTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }

        // tx tags
        is_tx_tag!(is_null, Null);
        is_tx_tag!(is_nonce, Nonce);
        is_tx_tag!(is_gas_price, GasPrice);
        is_tx_tag!(is_gas, Gas);
        is_tx_tag!(is_caller_addr, CallerAddress);
        is_tx_tag!(is_to, CalleeAddress);
        is_tx_tag!(is_create, IsCreate);
        is_tx_tag!(is_value, Value);
        is_tx_tag!(is_data, CallData);
        is_tx_tag!(is_data_length, CallDataLength);
        is_tx_tag!(is_data_gas_cost, CallDataGasCost);
        is_tx_tag!(is_tx_gas_cost, TxDataGasCost);
        is_tx_tag!(is_data_rlc, CallDataRLC);
        is_tx_tag!(is_chain_id_expr, ChainID);
        is_tx_tag!(is_sig_v, SigV);
        is_tx_tag!(is_sig_r, SigR);
        is_tx_tag!(is_sig_s, SigS);
        is_tx_tag!(is_sign_length, TxSignLength);
        is_tx_tag!(is_sign_rlc, TxSignRLC);
        is_tx_tag!(is_hash_length, TxHashLength);
        is_tx_tag!(is_hash_rlc, TxHashRLC);
        is_tx_tag!(is_sign_hash, TxSignHash);
        is_tx_tag!(is_hash, TxHash);
        is_tx_tag!(is_block_num, BlockNumber);
        is_tx_tag!(is_tx_type, TxType);
        is_tx_tag!(is_access_list_addresses_len, AccessListAddressesLen);
        is_tx_tag!(is_access_list_storage_keys_len, AccessListStorageKeysLen);
        is_tx_tag!(is_access_list_rlc, AccessListRLC);
        is_tx_tag!(is_tag_access_list_address, AccessListAddress);
        is_tx_tag!(is_tag_access_list_storage_key, AccessListStorageKey);
        is_tx_tag!(is_max_fee_per_gas, MaxFeePerGas);
        is_tx_tag!(is_max_priority_fee_per_gas, MaxPriorityFeePerGas);

        // testing if value is zero for tags
        let value_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    sum::expr(vec![
                        // if caller_address is zero, then skip the sig verify.
                        is_caller_addr(meta),
                        // if call_data_length is zero, then skip lookup to tx table for call data
                        is_data_length(meta),
                        // if call data byte is zero, then gas_cost = 4 (16 otherwise)
                        is_data(meta),
                        // if access_list_addresses_len is zero, then access_list_storage_keys_len
                        // = 0 and access_list_rlc = 0
                        is_access_list_addresses_len(meta),
                    ]),
                ])
            },
            tx_table.value,
            |meta| meta.advice_column_in(SecondPhase), // value is at 2nd phase
        );

        // tx_id transition in the fixed part of tx table
        meta.create_gate("tx_id starts with 1", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // the first row in tx table are all-zero rows
            cb.require_equal(
                "tx_id == 1",
                meta.query_advice(tx_table.tx_id, Rotation::next()),
                1.expr(),
            );

            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        meta.create_gate("tx_id transition in the fixed part of tx table", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // if tag_next == Nonce, then tx_id' = tx_id + 1
            cb.condition(tag_bits.value_equals(Nonce, Rotation::next())(meta), |cb| {
                cb.require_equal(
                    "tx_id increments",
                    meta.query_advice(tx_table.tx_id, Rotation::next()),
                    meta.query_advice(tx_table.tx_id, Rotation::cur()) + 1.expr(),
                );
            });
            // if tag_next != Nonce, then tx_id' = tx_id, tx_type' = tx_type
            cb.condition(
                not::expr(tag_bits.value_equals(Nonce, Rotation::next())(meta)),
                |cb| {
                    cb.require_equal(
                        "tx_id does not change",
                        meta.query_advice(tx_table.tx_id, Rotation::next()),
                        meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    );
                    // tx meta infos that extracted at some row and need to be copied to all rows of
                    // same tx
                    let tx_meta_info_fields = vec![
                        ("tx_type", tx_type),             // extracted at SigV row
                        ("is_padding_tx", is_padding_tx), // extracted at CallerAddress row
                        ("sv_address", sv_address),       // extracted at ChainID row
                        ("block_num", block_num),         // extracted at BlockNum row
                        ("total_l1_popped_before", total_l1_popped_before),
                        ("num_txs", num_txs),
                        ("cum_num_txs", cum_num_txs),
                        ("num_all_txs_acc", num_all_txs_acc),
                        ("tx_nonce", tx_nonce),
                        // is_l1_msg does not need to spread out as it's extracted from tx_type

                        // these do not need to spread out as they are related to tx_table.tag
                        // (which is fixed col) is_chain_id,
                        // is_caller_address, is_tag_block_num, is_calldata
                    ];
                    for (col_name, meta_info) in tx_meta_info_fields {
                        cb.require_equal(
                            col_name,
                            meta.query_advice(meta_info, Rotation::next()),
                            meta.query_advice(meta_info, Rotation::cur()),
                        );
                    }
                },
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_calldata, Rotation::cur())),
                not::expr(meta.query_advice(is_calldata, Rotation::next())),
            ]))
        });

        // Table for ensuring correct tx table tag transition
        let tx_rom_table = TxRomTable::construct(meta);

        let tx_id_unchanged = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::next()),
        );

        meta.lookup_any("tx table tag transition lookup", |meta| {
            let cond = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(q_enable, Rotation::next()),
                not::expr(meta.query_fixed(q_first, Rotation::next())),
            ]);
            vec![
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::next()),
                tx_id_unchanged.is_equal_expression.clone(),
                select::expr(
                    sum::expr([
                        meta.query_advice(is_calldata, Rotation::cur()),
                        meta.query_advice(is_access_list, Rotation::cur()),
                    ]),
                    meta.query_advice(is_final, Rotation::cur()),
                    1.expr(),
                ),
                meta.query_fixed(q_dynamic_first, Rotation::next()),
            ]
            .into_iter()
            .zip(tx_rom_table.table_exprs(meta))
            .map(|(arg, table)| (cond.expr() * arg, table))
            .collect()
        });

        // Basic constraints
        meta.create_gate("basic constraints", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let rlp_tag_map: Vec<(Expression<F>, RlpTag)> = vec![
                (is_nonce(meta), Tag::Nonce.into()),
                (is_gas_price(meta), Tag::GasPrice.into()),
                (is_gas(meta), Tag::Gas.into()),
                (is_to(meta), Tag::To.into()),
                (is_value(meta), Tag::Value.into()),
                (is_data_rlc(meta), Tag::Data.into()),
                (is_sig_v(meta), Tag::SigV.into()),
                (is_sig_r(meta), Tag::SigR.into()),
                (is_sig_s(meta), Tag::SigS.into()),
                (is_sign_length(meta), Len),
                (is_sign_rlc(meta), RLC),
                (is_hash_length(meta), Len),
                (is_hash_rlc(meta), RLC),
                (is_caller_addr(meta), Tag::Sender.into()),
                (is_tx_gas_cost(meta), GasCost),
                (
                    is_tag_access_list_address(meta),
                    Tag::AccessListAddress.into(),
                ),
                (
                    is_tag_access_list_storage_key(meta),
                    Tag::AccessListStorageKey.into(),
                ),
                (is_max_fee_per_gas(meta), Tag::MaxFeePerGas.into()),
                (
                    is_max_priority_fee_per_gas(meta),
                    Tag::MaxPriorityFeePerGas.into(),
                ),
                // tx tags which correspond to Null
                (is_null(meta), Null),
                (is_create(meta), Null),
                (is_data_length(meta), Null),
                (is_data_gas_cost(meta), Null),
                (is_sign_hash(meta), Null),
                (is_hash(meta), Null),
                (is_data(meta), Null),
                (is_block_num(meta), Null),
                (is_chain_id_expr(meta), Tag::ChainId.into()),
                (is_tx_type(meta), Null),
                (is_access_list_addresses_len(meta), Null),
                (is_access_list_storage_keys_len(meta), Null),
                (is_access_list_rlc(meta), RLC),
            ];

            cb.require_boolean(
                "is_none is boolean",
                meta.query_advice(is_none, Rotation::cur()),
            );

            cb.require_in_set(
                "tx_type supported",
                meta.query_advice(tx_type, Rotation::cur()),
                vec![
                    usize::from(PreEip155).expr(),
                    usize::from(Eip155).expr(),
                    usize::from(L1Msg).expr(),
                    usize::from(Eip2930).expr(),
                    usize::from(Eip1559).expr(),
                ],
            );

            cb.condition(is_tx_type(meta), |cb| {
                cb.require_equal(
                    "associated tx type to tag",
                    meta.query_advice(tx_type, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                );
            });

            cb.require_equal(
                "associated rlp_tag",
                meta.query_advice(rlp_tag, Rotation::cur()),
                rlp_tag_map.into_iter().fold(0.expr(), |acc, (expr, tag)| {
                    acc + usize::from(tag).expr() * expr
                }),
            );

            cb.condition(is_to(meta), |cb| {
                cb.require_equal(
                    "is_create == is_none",
                    // we rely on the assumption that IsCreate is next to CalleeAddress
                    meta.query_advice(tx_table.value, Rotation::next()),
                    meta.query_advice(is_none, Rotation::cur()),
                );
            });

            let is_none_expr = meta.query_advice(is_none, Rotation::cur());
            // is_none == true
            cb.condition(is_none_expr.expr(), |cb| {
                // value == 0
                cb.require_equal(
                    "is_none is true => value == 0",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    0.expr(),
                );
            });

            // CallData is none =>
            // 1. CallDataLength == 0
            // 2. CallDataGasCost == 0
            cb.condition(and::expr([is_data_rlc(meta), is_none_expr.expr()]), |cb| {
                // we rely on the assumption that CallDataLength and CallDataGasCost are after
                // CallDataRLC
                cb.require_equal(
                    "CallDataLength.value == 0",
                    meta.query_advice(tx_table.value, Rotation::next()),
                    0.expr(),
                );
                cb.require_equal(
                    "CallDataGasCost.value == 0",
                    meta.query_advice(tx_table.value, Rotation(2)),
                    0.expr(),
                );
            });

            // CallData is not none => CallDataLength != 0
            cb.condition(
                and::expr([is_data_rlc(meta), not::expr(is_none_expr)]),
                |cb| {
                    cb.require_zero(
                        "CallDataLength != 0",
                        value_is_zero.expr(Rotation::next())(meta),
                    );
                },
            );

            // AccessListAddressLen = 0 must force AccessListStorageKeysLen = 0 and AccessListRLC =
            // 0
            cb.condition(
                and::expr([
                    is_access_list_addresses_len(meta),
                    meta.query_advice(is_none, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "AccessListStorageKeysLen = 0",
                        meta.query_advice(tx_table.value, Rotation::next()),
                        0.expr(),
                    );
                    cb.require_equal(
                        "AccessListRLC = 0",
                        meta.query_advice(tx_table.value, Rotation(2)),
                        0.expr(),
                    );
                },
            );

            // AccessListAddressLen != 0 must force AccessListRLC != 0
            cb.condition(
                and::expr([
                    is_access_list_addresses_len(meta),
                    not::expr(meta.query_advice(is_none, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_zero("AccessListRLC != 0", value_is_zero.expr(Rotation(2))(meta));
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        //////////////////////////////////////////////////////////
        ///// Constraints for booleans that reducing degree  /////
        //////////////////////////////////////////////////////////
        meta.create_gate("is_calldata", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_calldata",
                is_data(meta),
                meta.query_advice(is_calldata, Rotation::cur()),
            );

            // Ensure continuity of is_calldata when is_final is false
            cb.condition(
                and::expr([
                    meta.query_advice(is_calldata, Rotation::cur()),
                    not::expr(meta.query_advice(is_final, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_zero(
                        "is_calldata is continuous when is_final is false.",
                        meta.query_advice(is_calldata, Rotation::next()) - 1.expr(),
                    )
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("is_tx_id_zero", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_tx_id_zero",
                tx_id_is_zero.expr(Rotation::cur())(meta),
                meta.query_advice(is_tx_id_zero, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("is_access_list", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_access_list",
                sum::expr([
                    meta.query_advice(is_access_list_address, Rotation::cur()),
                    meta.query_advice(is_access_list_storage_key, Rotation::cur()),
                ]),
                meta.query_advice(is_access_list, Rotation::cur()),
            );

            // Ensure continuity of is_access_list when is_final is false
            cb.condition(
                and::expr([
                    meta.query_advice(is_access_list, Rotation::cur()),
                    not::expr(meta.query_advice(is_final, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_zero(
                        "is_access_list is continuous when is_final is false",
                        meta.query_advice(is_access_list, Rotation::next()) - 1.expr(),
                    )
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate(
            "is_access_list_address and is_access_list_storage_key",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "is_access_list_address",
                    tag_bits.value_equals(TxFieldTag::AccessListAddress, Rotation::cur())(meta),
                    meta.query_advice(is_access_list_address, Rotation::cur()),
                );

                cb.require_equal(
                    "is_access_list_storage_key",
                    tag_bits.value_equals(TxFieldTag::AccessListStorageKey, Rotation::cur())(meta),
                    meta.query_advice(is_access_list_storage_key, Rotation::cur()),
                );

                cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
            },
        );

        meta.create_gate("is_caller_address", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_caller_address",
                is_caller_addr(meta),
                meta.query_advice(is_caller_address, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("is_row_hash_rlc", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_row_hash_rlc",
                is_hash_rlc(meta),
                meta.query_advice(is_row_hash_rlc, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("is_chain_id", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_chain_id",
                is_chain_id_expr(meta),
                meta.query_advice(is_chain_id, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("is_tag_block_num", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_tag_block_num = (tag == BlockNum)",
                is_block_num(meta),
                meta.query_advice(is_tag_block_num, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate(
            "distinguish tx type: is_l1_msg, is_eip2930, is_eip1559",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "is_l1_msg = (tx_type == L1Msg)",
                    meta.query_advice(is_l1_msg, Rotation::cur()),
                    tx_type_bits.value_equals(L1Msg, Rotation::cur())(meta),
                );

                cb.require_equal(
                    "is_eip2930 = (tx_type == Eip2930)",
                    meta.query_advice(is_eip2930, Rotation::cur()),
                    tx_type_bits.value_equals(Eip2930, Rotation::cur())(meta),
                );

                cb.require_equal(
                    "is_eip1559 = (tx_type == Eip1559)",
                    meta.query_advice(is_eip1559, Rotation::cur()),
                    tx_type_bits.value_equals(Eip1559, Rotation::cur())(meta),
                );

                cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
            },
        );

        meta.create_gate("calldata lookup into tx table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "condition",
                and::expr([
                    is_data_length(meta),
                    not::expr(value_is_zero.expr(Rotation::cur())(meta)),
                ]),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxCalldata],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("lookup to access list dynamic section condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "condition",
                and::expr([
                    is_access_list_addresses_len(meta),
                    not::expr(value_is_zero.expr(Rotation::cur())(meta)),
                ]),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxAccessList],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("sign tag lookup into RLP table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_in_tx_sign = sum::expr([
                is_nonce(meta),
                and::expr([
                    not::expr(meta.query_advice(is_eip1559, Rotation::cur())),
                    is_gas_price(meta),
                ]),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_data_rlc(meta),
                and::expr([
                    meta.query_advice(is_chain_id, Rotation::cur()),
                    sum::expr([
                        tx_type_bits.value_equals(Eip155, Rotation::cur())(meta),
                        meta.query_advice(is_eip2930, Rotation::cur()),
                        meta.query_advice(is_eip1559, Rotation::cur()),
                    ]),
                ]),
                and::expr([
                    meta.query_advice(is_eip1559, Rotation::cur()),
                    is_max_fee_per_gas(meta),
                ]),
                and::expr([
                    meta.query_advice(is_eip1559, Rotation::cur()),
                    is_max_priority_fee_per_gas(meta),
                ]),
                is_sign_length(meta),
                is_sign_rlc(meta),
            ]);

            cb.require_equal(
                "condition",
                is_tag_in_tx_sign,
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpSignTag],
                    Rotation::cur(),
                ),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
            ]))
        });

        meta.create_gate("hash tag lookup into RLP table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_in_tx_hash = sum::expr([
                is_nonce(meta),
                and::expr([
                    not::expr(meta.query_advice(is_eip1559, Rotation::cur())),
                    is_gas_price(meta),
                ]),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_tx_gas_cost(meta),
                is_data_rlc(meta),
                is_sig_v(meta),
                is_sig_r(meta),
                is_sig_s(meta),
                is_hash_length(meta),
                is_hash_rlc(meta),
                and::expr([
                    meta.query_advice(is_eip1559, Rotation::cur()),
                    is_max_fee_per_gas(meta),
                ]),
                and::expr([
                    meta.query_advice(is_eip1559, Rotation::cur()),
                    is_max_priority_fee_per_gas(meta),
                ]),
            ]);

            cb.require_equal(
                "condition",
                is_tag_in_tx_hash,
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpHashTag],
                    Rotation::cur(),
                ),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
            ]))
        });

        meta.create_gate("l1 msg lookup into RLP table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let is_tag_in_l1_msg_hash = sum::expr([
                is_nonce(meta),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_data_rlc(meta),
                is_caller_addr(meta),
                is_hash_length(meta),
                is_hash_rlc(meta),
            ]);

            cb.require_equal(
                "lookup into RLP table iff tag in l1 msg hash",
                is_tag_in_l1_msg_hash,
                meta.query_advice(
                    lookup_conditions[&LookupCondition::L1MsgHash],
                    Rotation::cur(),
                ),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_l1_msg, Rotation::cur()),
            ]))
        });

        meta.create_gate("lookup into Keccak table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_sign_or_l1_hash = sum::expr([
                and::expr([
                    is_sign_length(meta),
                    not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
                ]),
                and::expr([
                    is_hash_length(meta),
                    meta.query_advice(is_l1_msg, Rotation::cur()),
                ]),
            ]);
            cb.require_equal(
                "condition",
                is_tag_sign_or_l1_hash,
                meta.query_advice(lookup_conditions[&LookupCondition::Keccak], Rotation::cur()),
            );

            // For L2 tx hash, it should be assigned 0 (not included in Keccak lookup in this case)
            let is_l2_hash = and::expr([
                is_hash(meta),
                not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
            ]);
            cb.condition(is_l2_hash, |cb| {
                cb.require_zero(
                    "L2 tx hash value is 0",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                )
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // lookups to RLP table, Tx table, Keccak table
        Self::configure_lookups(
            meta,
            q_enable,
            q_dynamic_first,
            rlp_tag,
            tx_value_rlc,
            tx_value_length,
            tx_type_bits,
            tx_id_is_zero.clone(),
            is_none,
            &lookup_conditions,
            is_final,
            is_calldata,
            is_chain_id,
            is_l1_msg,
            is_eip2930,
            is_eip1559,
            sv_address,
            calldata_gas_cost_acc,
            section_rlc,
            field_rlc,
            tx_table.clone(),
            keccak_table.clone(),
            rlp_table,
            sig_table,
            is_access_list,
            is_access_list_address,
            is_access_list_storage_key,
            al_idx,
            sk_idx,
            sks_acc,
            chunk_txbytes_rlc,
            chunk_txbytes_len_acc,
        );

        meta.create_gate("tx_gas_cost == 0 for L1 msg", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(is_tx_gas_cost(meta), |cb| {
                cb.require_zero(
                    "tx_gas_cost == 0",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_l1_msg, Rotation::cur()),
            ]))
        });

        ///////////////////////////////////////////////////////////////////////
        ///////////////  constraints on num_all_txs  // ///////////////////////
        ///////////////////////////////////////////////////////////////////////
        meta.create_gate("copy tx_nonce", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(is_nonce(meta), |cb| {
                cb.require_equal(
                    "tx_nonce = tx_table.value if tag == Nonce",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(tx_nonce, Rotation::cur()),
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("copy block_num", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(meta.query_advice(is_tag_block_num, Rotation::cur()), |cb| {
                cb.require_equal(
                    "block_num = tx_table.value if tag == BlockNum",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(block_num, Rotation::cur()),
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // block num is the last row of each tx's fixed rows and since block num is
        // copied to TX_LEN rows. The row at which tag = BlockNum and tx_id = i,
        // its next row has tx_id = i+1. That is, we can use Rotation::next() to get next
        // tx's all meta-infos (including block_num, tx_nonce, num_all_txs_acc, ...)
        let block_num_unchanged = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_tag_block_num, Rotation::cur()),
                ])
            },
            |meta| meta.query_advice(block_num, Rotation::next()),
            |meta| meta.query_advice(block_num, Rotation::cur()),
        );

        meta.lookup("block_num is non-decreasing till padding txs", |meta| {
            // Block nums like this [1, 3, 5, 4, 0] is rejected by this. But [1, 2, 3, 5, 0] is
            // acceptable.
            let lookup_condition = and::expr([
                // next row should not belong to a padding tx
                not::expr(meta.query_advice(is_padding_tx, Rotation::next())),
                // next row should not be in the calldata region
                not::expr(meta.query_advice(is_calldata, Rotation::next())),
                meta.query_advice(is_tag_block_num, Rotation::cur()),
            ]);

            let block_num_diff = meta.query_advice(block_num, Rotation::next())
                - meta.query_advice(block_num, Rotation::cur());

            vec![(lookup_condition * block_num_diff, u16_table.into())]
        });

        meta.create_gate("num_all_txs in a block", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let queue_index = tx_nonce;
            // first tx in tx table
            cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                cb.require_equal(
                    "num_all_txs_acc = is_l1_msg ? queue_index - total_l1_popped_before + 1 : 1",
                    meta.query_advice(num_all_txs_acc, Rotation::cur()),
                    select::expr(
                        meta.query_advice(is_l1_msg, Rotation::cur()),
                        // first tx is l1 msg
                        meta.query_advice(queue_index, Rotation::cur())
                            - meta.query_advice(total_l1_popped_before, Rotation::cur())
                            + 1.expr(),
                        1.expr(),
                    ),
                );
            });

            // non-last tx in cur block
            cb.condition(
                and::expr([
                    // see the comment below
                    not::expr(meta.query_advice(is_calldata, Rotation::next())),
                    block_num_unchanged.expr(),
                ]),
                |cb| {
                    cb.require_equal(
                        "total_l1_popped' = tx.is_l1_msg ? queue_index + 1 : total_l1_popped",
                        meta.query_advice(total_l1_popped_before, Rotation::next()),
                        select::expr(
                            meta.query_advice(is_l1_msg, Rotation::cur()),
                            meta.query_advice(queue_index, Rotation::cur()) + 1.expr(),
                            meta.query_advice(total_l1_popped_before, Rotation::cur()),
                        ),
                    );

                    // num_all_txs_acc' - num_all_txs_acc = is_l1_msg' ? queue_index' -
                    // total_l1_popped' + 1 : 1
                    cb.require_equal(
                        "num_all_txs_acc' - num_all_txs_acc",
                        meta.query_advice(num_all_txs_acc, Rotation::next())
                            - meta.query_advice(num_all_txs_acc, Rotation::cur()),
                        select::expr(
                            meta.query_advice(is_l1_msg, Rotation::next()),
                            meta.query_advice(tx_nonce, Rotation::next())
                                - meta.query_advice(total_l1_popped_before, Rotation::next())
                                + 1.expr(),
                            1.expr(),
                        ),
                    );
                },
            );

            // last tx in cur block (next tx is the first tx in next block)
            // and cur block is not the last block (s.t. we can init next block's num_all_txs)
            cb.condition(
                and::expr([
                    // We need this condition because if this is the last tx of fixed part of tx
                    // table, not(block_num_unchanged.expr()) is very likely to
                    // be true. Since it does not make sense to assign values
                    // to `num_all_txs` col in the calldata part of tx table.
                    // Therefore we can skip assign any values to fixed part related cols
                    // (e.g. block_num, tx_type, is_padding_tx, ....). The witness assignment of
                    // calldata part need only make sure that (is_final,
                    // calldata_gas_cost_acc) are correctly assigned.
                    not::expr(meta.query_advice(is_calldata, Rotation::next())),
                    not::expr(block_num_unchanged.expr()),
                ]),
                |cb| {
                    cb.require_equal(
                        "total_l1_popped' = tx.is_l1_msg ? queue_index + 1 : total_l1_popped",
                        meta.query_advice(total_l1_popped_before, Rotation::next()),
                        select::expr(
                            meta.query_advice(is_l1_msg, Rotation::cur()),
                            meta.query_advice(queue_index, Rotation::cur()) + 1.expr(),
                            meta.query_advice(total_l1_popped_before, Rotation::cur()),
                        ),
                    );

                    // init new block's num_all_txs
                    // num_all_txs_acc' = is_l1_msg' ? queue_index' - total_l1_popped_before' + 1 :
                    // 1
                    cb.require_equal(
                        "init new block's num_all_txs",
                        meta.query_advice(num_all_txs_acc, Rotation::next()),
                        select::expr(
                            meta.query_advice(is_l1_msg, Rotation::next()),
                            meta.query_advice(tx_nonce, Rotation::next())
                                - meta.query_advice(total_l1_popped_before, Rotation::next())
                                + 1.expr(),
                            1.expr(),
                        ),
                    );
                },
            );

            // no constraints on last tx in the fixed part of tx table

            cb.gate(and::expr([
                meta.query_fixed(tx_table.q_enable, Rotation::cur()),
                // we are in the fixed part of tx table
                not::expr(meta.query_advice(is_calldata, Rotation::cur())),
                // calculate num_all_txs at tag = BlockNum row
                meta.query_advice(is_tag_block_num, Rotation::cur()),
            ]))
        });

        meta.lookup_any("num_all_txs in block table", |meta| {
            let is_tag_block_num = meta.query_advice(is_tag_block_num, Rotation::cur());
            let block_num = meta.query_advice(tx_table.value, Rotation::cur());
            let num_all_txs_acc = meta.query_advice(num_all_txs_acc, Rotation::cur());

            let input_expr = vec![NumAllTxs.expr(), block_num, num_all_txs_acc];
            let table_expr = block_table.table_exprs(meta);
            let condition = and::expr([
                is_tag_block_num,
                not::expr(block_num_unchanged.expr()), // the last tx in each block
                not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
            ]);

            input_expr
                .into_iter()
                .zip(table_expr)
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        ///////////////////////////////////////////////////////////////////////
        ///////  constraints on block_table's num_txs & num_cum_txs  //////////
        ///////////////////////////////////////////////////////////////////////
        meta.create_gate("is_padding_tx", |meta| {
            let is_tag_caller_addr = is_caller_addr(meta);
            let mut cb = BaseConstraintBuilder::default();

            // is_padding_tx is boolean
            cb.require_boolean(
                "is_padding_tx is boolean",
                meta.query_advice(is_padding_tx, Rotation::cur()),
            );

            // is_padding_tx starts with 0
            cb.condition(meta.query_fixed(q_first, Rotation::cur()), |cb| {
                cb.require_zero(
                    "is_padding_tx = 0 on the first row",
                    meta.query_advice(is_padding_tx, Rotation::cur()),
                );
            });

            // is_padding_tx changes only once from 0 -> 1
            cb.condition(
                and::expr([
                    not::expr(meta.query_fixed(q_first, Rotation::next())),
                    not::expr(sum::expr([
                        meta.query_advice(is_calldata, Rotation::next()),
                        meta.query_advice(is_access_list, Rotation::next()),
                    ])),
                ]),
                |cb| {
                    cb.require_zero(
                        "is_padding_tx changes from 0 -> 1 only once in the fixed section",
                        meta.query_advice(is_padding_tx, Rotation::cur())
                            * (meta.query_advice(is_padding_tx, Rotation::next())
                                - meta.query_advice(is_padding_tx, Rotation::cur())),
                    );
                },
            );

            // if tag == CallerAddress
            cb.condition(is_tag_caller_addr.expr(), |cb| {
                cb.require_equal(
                    "is_padding_tx = true if caller_address = 0",
                    meta.query_advice(is_padding_tx, Rotation::cur()),
                    value_is_zero.expr(Rotation::cur())(meta),
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // last non-padding tx must have tx_id == cum_num_txs
        meta.create_gate(
            "last non-padding tx must have tx_id == cum_num_txs",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let is_tag_block_num = meta.query_advice(is_tag_block_num, Rotation::cur());
                let is_cur_tx_non_padding =
                    not::expr(meta.query_advice(is_padding_tx, Rotation::cur()));
                let is_next_tx_padding = meta.query_advice(is_padding_tx, Rotation::next());
                let cum_num_txs = meta.query_advice(cum_num_txs, Rotation::cur());
                let tx_id = meta.query_advice(tx_table.tx_id, Rotation::cur());

                // tag == BlockNum && cur tx is the last non-padding tx
                cb.condition(
                    and::expr([is_tag_block_num, is_cur_tx_non_padding, is_next_tx_padding]),
                    |cb| {
                        cb.require_equal("tx_id == cum_num_txs", tx_id, cum_num_txs);
                    },
                );

                cb.gate(meta.query_fixed(tx_table.q_enable, Rotation::cur()))
            },
        );

        // tx_id <= cum_num_txs
        let tx_id_cmp_cum_num_txs = ComparatorChip::configure(
            meta,
            |meta| {
                and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_tag_block_num, Rotation::cur()),
                ])
            },
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(cum_num_txs, Rotation::cur()),
            u8_table.into(),
        );

        meta.create_gate("tx_id <= cum_num_txs", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (lt_expr, eq_expr) = tx_id_cmp_cum_num_txs.expr(meta, None);
            cb.condition(is_block_num(meta), |cb| {
                cb.require_equal("lt or eq", sum::expr([lt_expr, eq_expr]), true.expr());
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
            ]))
        });

        meta.lookup_any("num_txs in block table", |meta| {
            let is_tag_block_num = meta.query_advice(is_tag_block_num, Rotation::cur());
            let block_num = meta.query_advice(tx_table.value, Rotation::cur());
            let num_txs = meta.query_advice(num_txs, Rotation::cur());

            let input_expr = vec![NumTxs.expr(), block_num, num_txs];
            let table_expr = block_table.table_exprs(meta);
            let condition = and::expr([
                is_tag_block_num,
                not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
                meta.query_fixed(q_enable, Rotation::cur()),
            ]);

            input_expr
                .into_iter()
                .zip(table_expr)
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        meta.lookup_any("cum_num_txs in block table", |meta| {
            let is_tag_block_num = meta.query_advice(is_tag_block_num, Rotation::cur());
            let block_num = meta.query_advice(tx_table.value, Rotation::cur());
            let cum_num_txs = meta.query_advice(cum_num_txs, Rotation::cur());

            let input_expr = vec![CumNumTxs.expr(), block_num, cum_num_txs];
            let table_expr = block_table.table_exprs(meta);
            let condition = and::expr([
                is_tag_block_num,
                not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
                meta.query_fixed(q_enable, Rotation::cur()),
            ]);

            input_expr
                .into_iter()
                .zip(table_expr)
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        ////////////////////////////////////////////////////////////////////////
        ///////////  CallData length and gas_cost calculation  /////////////////
        ////////////////////////////////////////////////////////////////////////
        meta.lookup("tx_id_diff must in u16", |meta| {
            let q_enable = meta.query_fixed(q_enable, Rotation::next());
            let is_calldata = meta.query_advice(is_calldata, Rotation::cur());
            let tx_id = meta.query_advice(tx_table.tx_id, Rotation::cur());
            let tx_id_next = meta.query_advice(tx_table.tx_id, Rotation::next());
            let tx_id_next_is_zero = tx_id_is_zero.expr(Rotation::next())(meta);

            let lookup_condition =
                and::expr([q_enable, is_calldata, not::expr(tx_id_next_is_zero)]);

            vec![(lookup_condition * (tx_id_next - tx_id), u16_table.into())]
        });

        meta.create_gate("last row of call data", |meta| {
            let q_dynamic_last = meta.query_fixed(q_dynamic_last, Rotation::cur());
            let is_final = meta.query_advice(is_final, Rotation::cur());

            vec![(q_dynamic_last * (is_final - true.expr()))]
        });
        meta.create_gate("calldata_byte == tx_table.value", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let is_calldata = meta.query_advice(is_calldata, Rotation::cur());

            cb.condition(is_calldata, |cb| {
                cb.require_equal(
                    "calldata_byte == tx_table.value",
                    meta.query_advice(calldata_byte, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                );
            });

            cb.gate(meta.query_fixed(tx_table.q_enable, Rotation::cur()))
        });

        ////////////////////////////////////////////////////////////////////////
        ////////////  Calldata bytes dynamic section conditions ////////////////
        ////////////////////////////////////////////////////////////////////////
        meta.create_gate("tx call data bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_final_cur = meta.query_advice(is_final, Rotation::cur());
            cb.require_boolean("is_final is boolean", is_final_cur.clone());

            // checks for any row, except the final call data byte.
            cb.condition(not::expr(is_final_cur.clone()), |cb| {
                cb.require_equal(
                    "index::next == index::cur + 1",
                    meta.query_advice(tx_table.index, Rotation::next()),
                    meta.query_advice(tx_table.index, Rotation::cur()) + 1.expr(),
                );
                cb.require_equal(
                    "tx_id::next == tx_id::cur",
                    tx_id_unchanged.is_equal_expression.clone(),
                    1.expr(),
                );

                let value_next_is_zero = value_is_zero.expr(Rotation::next())(meta);
                let gas_cost_next = select::expr(value_next_is_zero, 4.expr(), 16.expr());
                // call data gas cost accumulator check.
                cb.require_equal(
                    "calldata_gas_cost_acc::next == calldata_gas_cost::cur + gas_cost_next",
                    meta.query_advice(calldata_gas_cost_acc, Rotation::next()),
                    meta.query_advice(calldata_gas_cost_acc, Rotation::cur()) + gas_cost_next,
                );
                cb.require_equal(
                    "section_rlc' = section_rlc * r + byte'",
                    meta.query_advice(section_rlc, Rotation::next()),
                    meta.query_advice(section_rlc, Rotation::cur()) * challenges.keccak_input()
                        + meta.query_advice(tx_table.value, Rotation::next()),
                );
            });

            // on the final call data byte, if there's no access list, tx_id must change.
            cb.condition(
                and::expr([
                    is_final_cur.expr(),
                    not::expr(meta.query_advice(is_access_list, Rotation::next())),
                ]),
                |cb| {
                    cb.require_zero(
                        "tx_id changes at is_final == 1",
                        tx_id_unchanged.is_equal_expression.clone(),
                    );
                },
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_calldata, Rotation::cur()),
                not::expr(meta.query_advice(is_tx_id_zero, Rotation::cur())),
            ]))
        });

        ////////////////////////////////////////////////////////////////////////
        ////////  Dynamic Section Init and Transition Conditions  //////////////
        ////////////////////////////////////////////////////////////////////////
        meta.create_gate("Dymamic section init with calldata", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let value_is_zero = value_is_zero.expr(Rotation::cur())(meta);
            let gas_cost = select::expr(value_is_zero, 4.expr(), 16.expr());

            cb.require_equal(
                "index == 0",
                meta.query_advice(tx_table.index, Rotation::cur()),
                0.expr(),
            );
            cb.require_equal(
                "calldata_gas_cost_acc == gas_cost",
                meta.query_advice(calldata_gas_cost_acc, Rotation::cur()),
                gas_cost,
            );
            cb.require_equal(
                "section_rlc == byte",
                meta.query_advice(section_rlc, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_dynamic_first, Rotation::cur()),
                not::expr(tx_id_is_zero.expr(Rotation::cur())(meta)),
                meta.query_advice(is_calldata, Rotation::cur()),
            ]))
        });

        meta.create_gate("Dymamic section init with access_list", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "al_idx starts with 1",
                meta.query_advice(al_idx, Rotation::next()),
                1.expr(),
            );
            cb.require_zero(
                "sks_acc starts with 0",
                meta.query_advice(sks_acc, Rotation::next()),
            );
            cb.require_equal(
                "section_rlc::cur == field_rlc::cur",
                meta.query_advice(section_rlc, Rotation::next()),
                meta.query_advice(field_rlc, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_dynamic_first, Rotation::cur()),
                not::expr(tx_id_is_zero.expr(Rotation::cur())(meta)),
                meta.query_advice(is_access_list, Rotation::cur()),
            ]))
        });

        meta.create_gate("Dynamic section transitions", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let is_final_cur = meta.query_advice(is_final, Rotation::cur());

            // Dynamic section transition #1: into calldata
            cb.condition(
                and::expr([meta.query_advice(is_calldata, Rotation::next())]),
                |cb| {
                    let value_next_is_zero = value_is_zero.expr(Rotation::next())(meta);
                    let gas_cost_next = select::expr(value_next_is_zero, 4.expr(), 16.expr());

                    cb.require_equal(
                        "index' == 0",
                        meta.query_advice(tx_table.index, Rotation::next()),
                        0.expr(),
                    );
                    cb.require_equal(
                        "calldata_gas_cost_acc' == gas_cost_next",
                        meta.query_advice(calldata_gas_cost_acc, Rotation::next()),
                        gas_cost_next,
                    );
                    cb.require_equal(
                        "section_rlc' == byte'",
                        meta.query_advice(section_rlc, Rotation::next()),
                        meta.query_advice(tx_table.value, Rotation::next()),
                    );
                },
            );

            // Dynamic section transition #2: into access_list
            cb.condition(meta.query_advice(is_access_list, Rotation::next()), |cb| {
                cb.require_equal(
                    "al_idx starts with 1",
                    meta.query_advice(al_idx, Rotation::next()),
                    1.expr(),
                );
                cb.require_zero(
                    "sks_acc starts with 0",
                    meta.query_advice(sks_acc, Rotation::next()),
                );
                cb.require_equal(
                    "section_rlc::cur == field_rlc::cur",
                    meta.query_advice(section_rlc, Rotation::next()),
                    meta.query_advice(field_rlc, Rotation::next()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                sum::expr([
                    meta.query_advice(is_access_list, Rotation::cur()),
                    meta.query_advice(is_calldata, Rotation::cur()),
                ]),
                not::expr(meta.query_advice(is_tx_id_zero, Rotation::cur())),
                not::expr(meta.query_advice(is_tx_id_zero, Rotation::next())),
                is_final_cur,
            ]))
        });

        ////////////////////////////////////////////////////////////////////////
        ///////////  Access List Constraints (if available on tx)  /////////////
        ////////////////////////////////////////////////////////////////////////
        meta.create_gate("tx access list", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_final_cur = meta.query_advice(is_final, Rotation::cur());
            cb.require_boolean("is_final is boolean", is_final_cur.clone());

            // section_rlc accumulation factor, rand^20 for addresses or rand^32 for storage keys
            let r20 = [1, 0, 1, 0, 0]
                .iter()
                .fold(1.expr(), |acc: Expression<F>, bit| {
                    acc.clone()
                        * acc
                        * if *bit > 0 {
                            challenges.keccak_input()
                        } else {
                            1.expr()
                        }
                });
            let r32 = [1, 0, 0, 0, 0, 0]
                .iter()
                .fold(1.expr(), |acc: Expression<F>, bit| {
                    acc.clone()
                        * acc
                        * if *bit > 0 {
                            challenges.keccak_input()
                        } else {
                            1.expr()
                        }
                });

            // current tag is AccessListAddress
            cb.condition(
                and::expr([
                    not::expr(is_final_cur.clone()),
                    meta.query_advice(is_access_list_address, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "index = al_idx",
                        meta.query_advice(al_idx, Rotation::cur()),
                        meta.query_advice(tx_table.index, Rotation::cur()),
                    );
                    cb.require_equal(
                        "access_list_address = value",
                        meta.query_advice(tx_table.value, Rotation::cur()),
                        meta.query_advice(tx_table.access_list_address, Rotation::cur()),
                    );
                    cb.require_zero("sk_idx = 0", meta.query_advice(sk_idx, Rotation::cur()));
                    cb.require_equal(
                        "section_rlc' = section_rlc * r ^ pow(len::next) + field_rlc'",
                        meta.query_advice(section_rlc, Rotation::next()),
                        meta.query_advice(section_rlc, Rotation::cur())
                            * select::expr(
                                meta.query_advice(is_access_list_storage_key, Rotation::next()),
                                r32.clone(),
                                r20.clone(),
                            )
                            + meta.query_advice(field_rlc, Rotation::next()),
                    );
                },
            );

            // current tag is AccessListStorageKey
            cb.condition(
                and::expr([
                    not::expr(is_final_cur.clone()),
                    meta.query_advice(is_access_list_storage_key, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "index = sks_acc",
                        meta.query_advice(sks_acc, Rotation::cur()),
                        meta.query_advice(tx_table.index, Rotation::cur()),
                    );
                    cb.require_equal(
                        "section_rlc' = section_rlc * r ^ pow(len::next) + field_rlc'",
                        meta.query_advice(section_rlc, Rotation::next()),
                        meta.query_advice(section_rlc, Rotation::cur())
                            * select::expr(
                                meta.query_advice(is_access_list_storage_key, Rotation::next()),
                                r32.clone(),
                                r20.clone(),
                            )
                            + meta.query_advice(field_rlc, Rotation::next()),
                    );
                },
            );

            // When is_final_cur is false, tx_id stays the same for either AccessList or
            // AccessListStorageKey
            cb.condition(not::expr(is_final_cur.clone()), |cb| {
                cb.require_equal(
                    "tx_id::next == tx_id::cur",
                    tx_id_unchanged.is_equal_expression.clone(),
                    1.expr(),
                );
            });

            // within same tx, next tag is AccessListAddress
            cb.condition(
                and::expr([
                    not::expr(is_final_cur.clone()),
                    meta.query_advice(is_access_list_address, Rotation::next()),
                ]),
                |cb| {
                    cb.require_equal(
                        "sks_acc' = sks_acc",
                        meta.query_advice(sks_acc, Rotation::cur()),
                        meta.query_advice(sks_acc, Rotation::next()),
                    );
                    cb.require_equal(
                        "al_idx' = al_idx + 1",
                        meta.query_advice(al_idx, Rotation::cur()) + 1.expr(),
                        meta.query_advice(al_idx, Rotation::next()),
                    );
                },
            );

            // within same tx, next tag is AccessListStorageKey
            cb.condition(
                and::expr([
                    not::expr(is_final_cur.clone()),
                    meta.query_advice(is_access_list_storage_key, Rotation::next()),
                ]),
                |cb| {
                    cb.require_equal(
                        "sks_acc' = sks_acc + 1",
                        meta.query_advice(sks_acc, Rotation::cur()) + 1.expr(),
                        meta.query_advice(sks_acc, Rotation::next()),
                    );
                    cb.require_equal(
                        "sk_idx' = sk_idx + 1",
                        meta.query_advice(sk_idx, Rotation::cur()) + 1.expr(),
                        meta.query_advice(sk_idx, Rotation::next()),
                    );
                    cb.require_equal(
                        "al_idx' = al_idx",
                        meta.query_advice(al_idx, Rotation::cur()),
                        meta.query_advice(al_idx, Rotation::next()),
                    );
                    cb.require_equal(
                        "access_list_address' = access_list_address",
                        meta.query_advice(tx_table.access_list_address, Rotation::cur()),
                        meta.query_advice(tx_table.access_list_address, Rotation::next()),
                    );
                },
            );

            // When is_final_cur is true, the tx_id must change for the next dynamic section
            cb.condition(
                and::expr([
                    is_final_cur.clone(),
                    not::expr(tx_id_is_zero.expr(Rotation::next())(meta)),
                ]),
                |cb| {
                    cb.require_zero(
                        "tx_id changes at is_final == 1",
                        tx_id_unchanged.is_equal_expression.clone(),
                    );
                },
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_access_list, Rotation::cur()),
                not::expr(tx_id_is_zero.expr(Rotation::cur())(meta)),
            ]))
        });

        ////////////////////////////////////////////////////////////////////////
        ///////////   SignVerify recover CallerAddress    //////////////////////
        ////////////////////////////////////////////////////////////////////////
        meta.create_gate("tx signature v", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let is_chain_id = meta.query_advice(is_chain_id, Rotation::cur());

            //  1. eip155 tx: v Є {chain_id*2 + 35, chain_id*2 + 36}
            cb.condition(
                and::expr([
                    is_chain_id.expr(),
                    tx_type_bits.value_equals(Eip155, Rotation::cur())(meta),
                ]),
                |cb| {
                    // we rely on the assumption that SigV is on the next of ChainID
                    let v = meta.query_advice(tx_table.value, Rotation::next());
                    let chain_id = meta.query_advice(tx_table.value, Rotation::cur());

                    cb.require_boolean(
                        "V - (chain_id * 2 + 35) Є {0, 1}",
                        v - chain_id * 2.expr() - 35.expr(),
                    );
                },
            );

            //  2. pre-eip155 tx: v Є {27, 28}
            cb.condition(
                and::expr([
                    is_chain_id.expr(),
                    tx_type_bits.value_equals(PreEip155, Rotation::cur())(meta),
                ]),
                |cb| {
                    let v = meta.query_advice(tx_table.value, Rotation::next());
                    cb.require_boolean("V - 27 Є {0, 1}", v - 27.expr());
                },
            );

            //  3. l1 msg: v == 0
            cb.condition(
                and::expr([
                    is_chain_id.expr(),
                    tx_type_bits.value_equals(L1Msg, Rotation::cur())(meta),
                ]),
                |cb| {
                    let v = meta.query_advice(tx_table.value, Rotation::next());
                    cb.require_zero("V == 0", v);
                },
            );

            // 4. EPI1559/2930: v Є {0, 1}
            cb.condition(
                and::expr([
                    is_chain_id.expr(),
                    sum::expr([
                        tx_type_bits.value_equals(Eip1559, Rotation::cur())(meta),
                        tx_type_bits.value_equals(Eip2930, Rotation::cur())(meta),
                    ]),
                ]),
                |cb| {
                    let v = meta.query_advice(tx_table.value, Rotation::next());
                    cb.require_boolean("v Є {0, 1}", v);
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate(
            "caller address == sv_address if it's not zero and tx_type != L1Msg",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.condition(not::expr(value_is_zero.expr(Rotation::cur())(meta)), |cb| {
                    cb.require_equal(
                        "caller address == sv_address",
                        meta.query_advice(tx_table.value, Rotation::cur()),
                        meta.query_advice(sv_address, Rotation::cur()),
                    );
                });

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_caller_address, Rotation::cur()),
                    not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
                ]))
            },
        );

        //////////////////////////////////////////////////////////
        //// EIP4844: Accumulation and Hashing of Chunk Bytes  ///
        //////////////////////////////////////////////////////////
        meta.create_gate("Degree reduction column: is_chunk_bytes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_chunk_bytes = (tx_type != L1Msg && !padding)",
                meta.query_advice(is_chunk_bytes, Rotation::cur()),
                and::expr([
                    not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
                    not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
                ]),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
                not::expr(meta.query_advice(is_calldata, Rotation::cur())),
                not::expr(meta.query_advice(is_access_list, Rotation::cur())),
            ]))
        });

        meta.create_gate("Chunk len acc and hash RLC acc starts at 0", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "chunk_txbytes_len_acc = 0",
                meta.query_advice(chunk_txbytes_len_acc, Rotation::cur()),
            );
            cb.require_zero(
                "chunk_txbytes_rlc = 0",
                meta.query_advice(chunk_txbytes_rlc, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(q_first, Rotation::cur()),
            ]))
        });

        meta.create_gate("Chunk Bytes RLC", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Accumulate hash length
            cb.require_equal(
                "chunk_txbytes_len_acc::cur == chunk_txbytes_len_acc::prev + HashLength",
                meta.query_advice(chunk_txbytes_len_acc, Rotation::cur()),
                meta.query_advice(chunk_txbytes_len_acc, Rotation(-(HASH_RLC_OFFSET as i32)))
                        // the previous row in fixed tx_table is the signed RLP length of current tx
                        + meta.query_advice(tx_table.value, Rotation::prev()),
            );

            // Accumulate chunk bytes RLC
            cb.require_equal(
                "chunk_txbytes_rlc::cur == chunk_txbytes_rlc::prev * pow_of_rand(HashLength) + HashRLC",
                meta.query_advice(chunk_txbytes_rlc, Rotation::cur()),
                meta.query_advice(chunk_txbytes_rlc, Rotation(-(HASH_RLC_OFFSET as i32)))
                        * meta.query_advice(pow_of_rand, Rotation::cur())
                        + meta.query_advice(tx_table.value, Rotation::cur()),
            );

            // The chunk bytes len is the same as the HashLen field in tx_table (in the prev row)
            cb.require_equal(
                "chunk_bytes_len = HashLen",
                meta.query_advice(chunk_bytes_len, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::prev()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                // Only l2 signed bytes are accumulated
                meta.query_advice(is_chunk_bytes, Rotation::cur()),
                is_hash_rlc(meta),
            ]))
        });

        meta.create_gate(
            "Chunk Bytes RLC stays same for l1 msg and padding txs",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // Check hash length is unchanged
                cb.require_equal(
                    "chunk_txbytes_len_acc::cur == chunk_txbytes_len_acc::prev",
                    meta.query_advice(chunk_txbytes_len_acc, Rotation::cur()),
                    meta.query_advice(chunk_txbytes_len_acc, Rotation(-(HASH_RLC_OFFSET as i32))),
                );

                // Check chunk RLC is unchanged
                cb.require_equal(
                    "chunk_txbytes_rlc::cur == chunk_txbytes_rlc::prev",
                    meta.query_advice(chunk_txbytes_rlc, Rotation::cur()),
                    meta.query_advice(chunk_txbytes_rlc, Rotation(-(HASH_RLC_OFFSET as i32))),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_advice(is_chunk_bytes, Rotation::cur())),
                    is_hash_rlc(meta),
                ]))
            },
        );

        meta.lookup_any("Correct pow_of_rand for HashLen", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_row_hash_rlc, Rotation::cur()),
                // A valid chunk txbytes tx is determined by: (tx.tx_type != TxType::L1Msg) &&
                // !tx.caller_address.is_zero()
                not::expr(meta.query_advice(is_l1_msg, Rotation::cur())),
                not::expr(meta.query_advice(is_padding_tx, Rotation::cur())),
            ]);

            vec![
                1.expr(),                                            // q_enable
                meta.query_advice(chunk_bytes_len, Rotation::cur()), // exponent
                meta.query_advice(pow_of_rand, Rotation::cur()),     // pow_of_rand
            ]
            .into_iter()
            .zip(pow_of_rand_table.table_exprs(meta))
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        meta.create_gate("One chunk_txbytes_len_acc, chunk_txbytes_rlc value and pow_of_rand for each tx (in fixed section)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // chunk_txbytes_len_acc, chunk_txbytes_rlc and pow_of_rand stay the same for the same tx
            cb.require_equal(
                "chunk_txbytes_len_acc' == chunk_txbytes_len_acc",
                meta.query_advice(chunk_txbytes_len_acc, Rotation::cur()),
                meta.query_advice(chunk_txbytes_len_acc, Rotation::prev()),
            );
            cb.require_equal(
                "chunk_txbytes_rlc' == chunk_txbytes_rlc",
                meta.query_advice(chunk_txbytes_rlc, Rotation::cur()),
                meta.query_advice(chunk_txbytes_rlc, Rotation::prev()),
            );
            cb.require_equal(
                "pow_of_rand' == pow_of_rand",
                meta.query_advice(pow_of_rand, Rotation::cur()),
                meta.query_advice(pow_of_rand, Rotation::prev()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
                not::expr(is_nonce(meta)),
                not::expr(meta.query_advice(is_calldata, Rotation::cur()))
            ]))
        });

        log_deg("tx_circuit", meta);

        Self {
            minimum_rows: meta.minimum_rows(),
            q_first,
            q_dynamic_first,
            q_dynamic_last,
            tx_tag_bits: tag_bits,
            tx_type,
            tx_type_bits,
            rlp_tag,
            is_none,
            tx_value_rlc,
            tx_value_length,
            u8_table,
            u16_table,
            tx_id_is_zero,
            value_is_zero,
            tx_id_unchanged,
            is_calldata,
            is_tx_id_zero,
            is_caller_address,
            tx_id_cmp_cum_num_txs,
            cum_num_txs,
            is_padding_tx,
            lookup_conditions,
            tx_nonce,
            block_num,
            block_num_unchanged,
            num_all_txs_acc,
            total_l1_popped_before,
            is_l1_msg,
            is_eip2930,
            is_eip1559,
            is_row_hash_rlc,
            is_chain_id,
            is_final,
            calldata_gas_cost_acc,
            section_rlc,
            calldata_byte,
            sv_address,
            sig_table,
            block_table,
            tx_table,
            keccak_table,
            rlp_table,
            pow_of_rand_table,
            is_tag_block_num,
            al_idx,
            sk_idx,
            sks_acc,
            is_access_list,
            is_access_list_address,
            is_access_list_storage_key,
            field_rlc,
            is_chunk_bytes,
            chunk_bytes_len,
            chunk_txbytes_rlc,
            chunk_txbytes_len_acc,
            pow_of_rand,
            tx_rom_table,
            _marker: PhantomData,
            num_txs,
        }
    }
}

type FixedRowsAssignmentResult<F> = (Vec<AssignedCell<F, F>>, Vec<Value<F>>);
impl<F: Field> TxCircuitConfig<F> {
    #[allow(clippy::too_many_arguments)]
    fn configure_lookups(
        meta: &mut ConstraintSystem<F>,
        q_enable: Column<Fixed>,
        q_dynamic_first: Column<Fixed>,
        rlp_tag: Column<Advice>,
        tx_value_rlc: Column<Advice>,
        tx_value_length: Column<Advice>,
        tx_type_bits: BinaryNumberConfig<TxType, 3>,
        tx_id_is_zero: IsZeroConfig<F>,
        is_none: Column<Advice>,
        lookup_conditions: &HashMap<LookupCondition, Column<Advice>>,
        is_final: Column<Advice>,
        is_calldata: Column<Advice>,
        is_chain_id: Column<Advice>,
        is_l1_msg_col: Column<Advice>,
        is_eip2930: Column<Advice>,
        is_eip1559: Column<Advice>,
        sv_address: Column<Advice>,
        calldata_gas_cost_acc: Column<Advice>,
        section_rlc: Column<Advice>,
        field_rlc: Column<Advice>,
        tx_table: TxTable,
        keccak_table: KeccakTable,
        rlp_table: RlpTable,
        sig_table: SigTable,
        is_access_list: Column<Advice>,
        is_access_list_address: Column<Advice>,
        is_access_list_storage_key: Column<Advice>,
        al_idx: Column<Advice>,
        sk_idx: Column<Advice>,
        sks_acc: Column<Advice>,
        chunk_txbytes_rlc: Column<Advice>,
        chunk_txbytes_len_acc: Column<Advice>,
    ) {
        macro_rules! is_tx_type {
            ($var:ident, $type_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tx_type_bits.value_equals(TxType::$type_variant, Rotation::cur())(meta)
                };
            };
        }
        /////////////////////////////////////////////////////////////////
        /////////////////    block table lookups     ////////////////////
        ///////////////// ////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////
        /////////////////    tx table lookups     ///////////////////////
        /////////////////////////////////////////////////////////////////
        // lookup to check CallDataGasCost of the tx's call data.
        meta.lookup_any("tx call data gas cost in TxTable", |meta| {
            // if call data length != 0, then we can lookup the calldata gas cost on the
            // last row of the tx's call data bytes.
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxCalldata],
                    Rotation::cur(),
                ),
            ]);

            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                CallData.expr(),
                meta.query_advice(tx_table.value, Rotation::next()), // calldata_gas_cost
                1.expr(),                                            // is_final = 1
            ]
            .into_iter()
            .zip(vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(calldata_gas_cost_acc, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
            ])
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        // We need to handle the case in which some of the call data bytes is skipped in
        // the tx table. If the call data length is larger than 0, then we will
        // do lookup in the tx table to make sure the last call data byte in tx
        // has index = call_data_length-1.
        meta.lookup_any("is_final call data byte should be present", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxCalldata],
                    Rotation::cur(),
                ),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                CallData.expr(),
                meta.query_advice(tx_table.value, Rotation::cur()) - 1.expr(), /* index starts
                                                                                * from 0 */
                1.expr(), // is_final = true
            ]
            .into_iter()
            .zip(vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.index, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
            ])
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("lookup CallDataRLC in the calldata part", |meta| {
            let is_call_data = meta.query_advice(is_calldata, Rotation::cur());
            let section_rlc = meta.query_advice(section_rlc, Rotation::cur());
            let enable = and::expr([
                meta.query_fixed(tx_table.q_enable, Rotation::cur()),
                is_call_data,
                not::expr(tx_id_is_zero.expr(Rotation::cur())(meta)),
                meta.query_advice(is_final, Rotation::cur()),
            ]);

            let input_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                CallDataRLC.expr(),
                section_rlc.expr(),
            ];
            let table_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enable.expr(), table))
                .collect()
        });

        meta.lookup_any("lookup AccessListAddressLen in the TxTable", |meta| {
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_access_list, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
            ]);

            let input_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                AccessListAddressesLen.expr(),
                meta.query_advice(al_idx, Rotation::cur()),
            ];
            let table_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enable.expr(), table))
                .collect()
        });

        meta.lookup_any("lookup AccessListStorageKeysLen in the TxTable", |meta| {
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_access_list, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
            ]);

            let input_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                AccessListStorageKeysLen.expr(),
                meta.query_advice(sks_acc, Rotation::cur()),
            ];
            let table_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enable.expr(), table))
                .collect()
        });

        meta.lookup_any("lookup AccessListRLC in the TxTable", |meta| {
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_access_list, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
            ]);

            let input_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                AccessListRLC.expr(),
                meta.query_advice(section_rlc, Rotation::cur()),
            ];
            let table_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tag, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enable.expr(), table))
                .collect()
        });

        meta.lookup_any("is_final access list row should be present", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxAccessList],
                    Rotation::cur(),
                ),
            ]);
            let input_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                1.expr(),
                1.expr(),
                meta.query_advice(tx_table.value, Rotation(0)), // al_idx
                meta.query_advice(tx_table.value, Rotation(1)), // sks_acc
                meta.query_advice(tx_table.value, Rotation(2)), // section_rlc for access list
            ];
            let table_exprs = vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(is_access_list, Rotation::cur()),
                meta.query_advice(is_final, Rotation::cur()),
                meta.query_advice(al_idx, Rotation::cur()),
                meta.query_advice(sks_acc, Rotation::cur()),
                meta.query_advice(section_rlc, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enable.expr(), table))
                .collect()
        });

        /////////////////////////////////////////////////////////////////
        /////////////////    RLP table lookups     //////////////////////
        ///////////////// ////////////////////////////////////////////////
        is_tx_type!(is_pre_eip155, PreEip155);
        is_tx_type!(is_eip155, Eip155);
        is_tx_type!(is_l1_msg, L1Msg);

        // lookup tx type in RLP table for L1Msg only
        meta.lookup_any("lookup tx type in RLP table", |meta| {
            let enable = and::expr([meta.query_fixed(q_enable, Rotation::cur()), is_l1_msg(meta)]);
            let hash_format = L1MsgHash.expr();
            let tag_value = 0x7E.expr();
            let tag_bytes_rlc = 0x7E.expr();
            let tag_length = 1.expr();

            let input_exprs = vec![
                1.expr(), // q_enable = true
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                hash_format,
                RLPTxType.expr(),
                tag_value,
                tag_bytes_rlc,
                tag_length,
                1.expr(), // is_output = true
                0.expr(), // is_none = false
                0.expr(), // access_list_idx
                0.expr(), // storage_key_idx
            ];
            assert_eq!(input_exprs.len(), rlp_table.table_exprs(meta).len());

            input_exprs
                .into_iter()
                .zip(rlp_table.table_exprs(meta))
                .map(|(input, table)| (enable.expr() * input, table))
                .collect()
        });

        // lookup tx tag in RLP table for signing.
        meta.lookup_any("lookup tx tag in RLP Table for signing", |meta| {
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpSignTag],
                    Rotation::cur(),
                ),
            ]);
            let rlp_tag = meta.query_advice(rlp_tag, Rotation::cur());
            let is_none = meta.query_advice(is_none, Rotation::cur());
            let sign_format = is_pre_eip155(meta) * TxSignPreEip155.expr()
                + is_eip155(meta) * TxSignEip155.expr()
                + meta.query_advice(is_eip2930, Rotation::cur()) * TxSignEip2930.expr()
                + meta.query_advice(is_eip1559, Rotation::cur()) * TxSignEip1559.expr();

            // q_enable, tx_id, format, rlp_tag, tag_value, is_output, is_none
            vec![
                1.expr(), // q_enable = true
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                sign_format,
                rlp_tag,
                meta.query_advice(tx_table.value, Rotation::cur()),
                meta.query_advice(tx_value_rlc, Rotation::cur()),
                meta.query_advice(tx_value_length, Rotation::cur()),
                1.expr(), // is_output = true
                is_none,
                0.expr(), // access_list_idx
                0.expr(), // storage_key_idx
            ]
            .into_iter()
            .zip_eq(rlp_table.table_exprs(meta))
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx tag in RLP table for hashing
        meta.lookup_any("lookup tx tag in RLP Table for hashing", |meta| {
            let rlp_tag = meta.query_advice(rlp_tag, Rotation::cur());
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                sum::expr([
                    meta.query_advice(
                        lookup_conditions[&LookupCondition::RlpHashTag],
                        Rotation::cur(),
                    ),
                    meta.query_advice(
                        lookup_conditions[&LookupCondition::L1MsgHash],
                        Rotation::cur(),
                    ),
                ]),
            ]);
            let is_none = meta.query_advice(is_none, Rotation::cur());
            let hash_format = is_pre_eip155(meta) * TxHashPreEip155.expr()
                + is_eip155(meta) * TxHashEip155.expr()
                + is_l1_msg(meta) * L1MsgHash.expr()
                + meta.query_advice(is_eip2930, Rotation::cur()) * TxHashEip2930.expr()
                + meta.query_advice(is_eip1559, Rotation::cur()) * TxHashEip1559.expr();

            vec![
                1.expr(), // q_enable = true
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                hash_format,
                rlp_tag,
                meta.query_advice(tx_table.value, Rotation::cur()),
                meta.query_advice(tx_value_rlc, Rotation::cur()),
                meta.query_advice(tx_value_length, Rotation::cur()),
                1.expr(), // is_output = true
                is_none,
                0.expr(), // access_list_idx
                0.expr(), // storage_key_idx
            ]
            .into_iter()
            .zip_eq(rlp_table.table_exprs(meta))
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup access list address in RLP table
        // 1. ensure field_rlc is correct
        // 2. ensure value of address is correct
        meta.lookup_any(
            "Lookup access list address in RLP Table from tx circuit dynamic section (Signing)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_access_list_address, Rotation::cur()),
                ]);

                // only eip2930 and eip1559 contains an access list
                let sign_format = meta.query_advice(is_eip2930, Rotation::cur())
                    * TxSignEip2930.expr()
                    + meta.query_advice(is_eip1559, Rotation::cur()) * TxSignEip1559.expr();

                vec![
                    1.expr(), // q_enable = true
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    sign_format,
                    meta.query_advice(rlp_tag, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(field_rlc, Rotation::cur()),
                    20.expr(),                                  // 20 bytes for address
                    1.expr(),                                   // is_output = true
                    0.expr(),                                   // is_none = false. must have value
                    meta.query_advice(al_idx, Rotation::cur()), // access_list_idx
                    meta.query_advice(sk_idx, Rotation::cur()), // storage_key_idx
                ]
                .into_iter()
                .zip_eq(rlp_table.table_exprs(meta))
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "Lookup access list address in RLP Table from tx circuit dynamic section (Hashing)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_access_list_address, Rotation::cur()),
                ]);

                // only eip2930 and eip1559 contains an access list
                let hash_format = meta.query_advice(is_eip2930, Rotation::cur())
                    * TxHashEip2930.expr()
                    + meta.query_advice(is_eip1559, Rotation::cur()) * TxHashEip1559.expr();

                vec![
                    1.expr(), // q_enable = true
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    hash_format,
                    meta.query_advice(rlp_tag, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(field_rlc, Rotation::cur()),
                    20.expr(),                                  // 20 bytes for address
                    1.expr(),                                   // is_output = true
                    0.expr(),                                   // is_none = false. must have value
                    meta.query_advice(al_idx, Rotation::cur()), // access_list_idx
                    meta.query_advice(sk_idx, Rotation::cur()), // storage_key_idx
                ]
                .into_iter()
                .zip_eq(rlp_table.table_exprs(meta))
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );

        // lookup access list storage key in RLP table
        // 1. ensure field_rlc is correct
        // 2. ensure value of storage key is correct
        meta.lookup_any(
            "Lookup access list storage key in RLP Table from tx circuit dynamic section (Signing)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_access_list_storage_key, Rotation::cur()),
                ]);

                // only eip2930 and eip1559 contains an access list
                let sign_format = meta.query_advice(is_eip2930, Rotation::cur())
                    * TxSignEip2930.expr()
                    + meta.query_advice(is_eip1559, Rotation::cur()) * TxSignEip1559.expr();

                vec![
                    1.expr(), // q_enable = true
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    sign_format,
                    meta.query_advice(rlp_tag, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(field_rlc, Rotation::cur()),
                    32.expr(),                                  // 32 bytes for storage keys
                    1.expr(),                                   // is_output = true
                    0.expr(),                                   // is_none = false. must have value
                    meta.query_advice(al_idx, Rotation::cur()), // access_list_idx
                    meta.query_advice(sk_idx, Rotation::cur()), // storage_key_idx
                ]
                .into_iter()
                .zip_eq(rlp_table.table_exprs(meta))
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );

        meta.lookup_any(
            "Lookup access list storage key in RLP Table from tx circuit dynamic section (Hashing)",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_access_list_storage_key, Rotation::cur()),
                ]);

                // only eip2930 and eip1559 contains an access list
                let hash_format = meta.query_advice(is_eip2930, Rotation::cur())
                    * TxHashEip2930.expr()
                    + meta.query_advice(is_eip1559, Rotation::cur()) * TxHashEip1559.expr();

                vec![
                    1.expr(), // q_enable = true
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    hash_format,
                    meta.query_advice(rlp_tag, Rotation::cur()),
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(field_rlc, Rotation::cur()),
                    32.expr(),                                  // 32 bytes for storage keys
                    1.expr(),                                   // is_output = true
                    0.expr(),                                   // is_none = false. must have value
                    meta.query_advice(al_idx, Rotation::cur()), // access_list_idx
                    meta.query_advice(sk_idx, Rotation::cur()), // storage_key_idx
                ]
                .into_iter()
                .zip_eq(rlp_table.table_exprs(meta))
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );

        ////////////////////////////////////////////////////////////////////
        /////////////////    Sig table lookups     //////////////////////
        ///////////////// //////////////////////////////////////////////////
        meta.lookup_any("Sig table lookup", |meta| {
            let enabled = and::expr([
                // use is_l1_msg_col instead of is_l1_msg(meta) because it has lower degree
                not::expr(meta.query_advice(is_l1_msg_col, Rotation::cur())),
                // lookup to sig table on the ChainID row because we have an indicator of degree 1
                // for ChainID and ChainID is not far from (msg_hash_rlc, sig_v,
                // ...)
                meta.query_advice(is_chain_id, Rotation::cur()),
            ]);

            let msg_hash_rlc = meta.query_advice(tx_table.value, Rotation(6));
            let chain_id = meta.query_advice(tx_table.value, Rotation::cur());
            let sig_v = meta.query_advice(tx_table.value, Rotation(1));
            let sig_r = meta.query_advice(tx_table.value, Rotation(2));
            let sig_s = meta.query_advice(tx_table.value, Rotation(3));
            let sv_address = meta.query_advice(sv_address, Rotation::cur());

            let v = is_eip155(meta) * (sig_v.expr() - 2.expr() * chain_id - 35.expr())
                + is_pre_eip155(meta) * (sig_v.expr() - 27.expr());

            let input_exprs = vec![
                1.expr(),     // q_enable = true
                msg_hash_rlc, // msg_hash_rlc
                v,            // sig_v
                sig_r,        // sig_r
                sig_s,        // sig_s
                sv_address,
                1.expr(), // is_valid
            ];

            // LookupTable::table_exprs is not used here since `is_valid` not used by evm circuit.
            let table_exprs = vec![
                meta.query_fixed(sig_table.q_enable, Rotation::cur()),
                // msg_hash_rlc not needed to be looked up for tx circuit?
                meta.query_advice(sig_table.msg_hash_rlc, Rotation::cur()),
                meta.query_advice(sig_table.sig_v, Rotation::cur()),
                meta.query_advice(sig_table.sig_r_rlc, Rotation::cur()),
                meta.query_advice(sig_table.sig_s_rlc, Rotation::cur()),
                meta.query_advice(sig_table.recovered_addr, Rotation::cur()),
                meta.query_advice(sig_table.is_valid, Rotation::cur()),
            ];

            input_exprs
                .into_iter()
                .zip(table_exprs)
                .map(|(input, table)| (input * enabled.expr(), table))
                .collect()
        });

        ////////////////////////////////////////////////////////////////////
        /////////////////    Keccak table lookups     //////////////////////
        ///////////////// //////////////////////////////////////////////////
        // lookup Keccak table for tx sign data hash, i.e. the sighash that has to be
        // signed.
        // lookup Keccak table for tx hash too.
        meta.lookup_any("Keccak table lookup for TxSign and L1 TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(lookup_conditions[&LookupCondition::Keccak], Rotation::cur()),
            ]);

            vec![
                1.expr(),                                            // q_enable
                1.expr(),                                            // is_final
                meta.query_advice(tx_table.value, Rotation::next()), // input_rlc
                meta.query_advice(tx_table.value, Rotation::cur()),  // input_len
                meta.query_advice(tx_table.value, Rotation(2)),      // output_rlc
            ]
            .into_iter()
            .zip(keccak_table.table_exprs(meta))
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        ////////////////////////////////////////////////////////////////////
        /////////////    4844: Chunk bytes RLC lookups     /////////////////
        ///////////////// //////////////////////////////////////////////////
        meta.lookup_any("Keccak table lookup for ChunkHash", |meta| {
            // Isolate the last row in the fixed section, which belongs to the last tx in the chunk
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(q_dynamic_first, Rotation::cur()),
            ]);

            vec![
                1.expr(),                                                             // q_enable
                1.expr(),                                                             // is_final
                meta.query_advice(chunk_txbytes_rlc, Rotation::prev()),               // input_rlc
                meta.query_advice(chunk_txbytes_len_acc, Rotation::prev()),           // input_len
                meta.query_advice(tx_table.chunk_txbytes_hash_rlc, Rotation::prev()), // output_rlc
            ]
            .into_iter()
            .zip(keccak_table.table_exprs(meta))
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
    }

    /// Assign 1st empty row with tag = Null
    fn assign_null_row(&self, region: &mut Region<'_, F>, offset: &mut usize) -> Result<(), Error> {
        self.assign_common_part(
            region,
            *offset,
            None,
            1,
            TxFieldTag::Null,
            0,
            Value::known(F::zero()),
            Value::known(F::zero()),
        )?;
        let (col_anno, col, col_val) = ("rlp_tag", self.rlp_tag, F::from(usize::from(Null) as u64));
        region.assign_advice(|| col_anno, col, *offset, || Value::known(col_val))?;

        *offset += 1;
        Ok(())
    }

    /// Assign TX_LEN rows of each tx where tags are not in { Null, CallData }
    #[allow(clippy::too_many_arguments)]
    fn assign_fixed_rows(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        tx: &Transaction,
        sign_data: &SignData,
        next_tx: Option<&Transaction>,
        total_l1_popped_before: u64,
        num_all_txs_acc: u64,
        num_txs: u64,
        cum_num_txs: u64,
        chunk_txbytes_rlc_acc: Value<F>,
        chunk_txbytes_len_acc: Value<F>,
        chunk_txbytes_hash: Value<F>,
        pows_of_rand: &mut Vec<Value<F>>,
        is_last_tx: bool,
        challenges: &Challenges<Value<F>>,
    ) -> Result<FixedRowsAssignmentResult<F>, Error> {
        let keccak_input = challenges.keccak_input();
        let evm_word = challenges.evm_word();
        let zero_rlc = keccak_input.map(|_| F::zero());
        let sign_hash = keccak256(tx.rlp_unsigned.as_slice());
        let hash = keccak256(tx.rlp_signed.as_slice());
        let sign_hash_rlc = rlc_be_bytes(&sign_hash, evm_word);
        let hash_rlc = if tx.tx_type != L1Msg {
            Value::known(F::zero())
        } else {
            rlc_be_bytes(&hash, evm_word)
        };
        let mut supplemental_data: Vec<Value<F>> = vec![];
        let mut txbytes_hash_assignment: Option<AssignedCell<F, F>> = None;
        let mut tx_value_cells = vec![];
        let rlp_sign_tag_length = if tx.tx_type.is_l1_msg() {
            // l1 msg does not have sign data
            0
        } else {
            get_rlp_len_tag_length(&tx.rlp_unsigned)
        };
        let (access_list_address_size, access_list_storage_key_size) =
            access_list_size(&tx.access_list);

        // Only bytes from L2 txs are accumulated for chunk bytes hash
        let is_chunk_bytes = tx.is_chunk_l2_tx();

        let hash_len = if is_chunk_bytes {
            tx.rlp_signed.len()
        } else {
            0
        };
        let tx_hash_rlc = rlc_be_bytes(&tx.rlp_signed, keccak_input);
        if hash_len >= pows_of_rand.len() {
            for _ in 0..(tx.rlp_signed.len() - pows_of_rand.len() + 1) {
                pows_of_rand.push(pows_of_rand.last().unwrap().mul(keccak_input));
            }
        }
        let pow_of_rand = pows_of_rand[hash_len];
        let chunk_txbytes_rlc = if is_chunk_bytes {
            chunk_txbytes_rlc_acc.mul(pow_of_rand).add(tx_hash_rlc)
        } else {
            chunk_txbytes_rlc_acc
        };
        let chunk_txbytes_len = chunk_txbytes_len_acc.add(Value::known(F::from(hash_len as u64)));
        supplemental_data.push(chunk_txbytes_rlc);
        supplemental_data.push(chunk_txbytes_len);

        let fixed_rows = vec![
            // need to be in same order as that tx table load function uses
            (
                Nonce, // tx field tag
                Some(RlpTableInputValue {
                    tag: Tag::Nonce.into(),
                    is_none: tx.nonce == 0,
                    be_bytes_len: tx.nonce.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.nonce.to_be_bytes(), keccak_input),
                }),
                Value::known(F::from(tx.nonce)),
            ),
            (
                GasPrice,
                Some(RlpTableInputValue {
                    tag: Tag::GasPrice.into(),
                    is_none: tx.gas_price.is_zero(),
                    be_bytes_len: tx.gas_price.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.gas_price.to_be_bytes(), keccak_input),
                }),
                rlc_be_bytes(&tx.gas_price.to_be_bytes(), evm_word),
            ),
            (
                Gas,
                Some(RlpTableInputValue {
                    tag: Tag::Gas.into(),
                    is_none: tx.gas == 0,
                    be_bytes_len: tx.gas.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.gas.to_be_bytes(), keccak_input),
                }),
                Value::known(F::from(tx.gas)),
            ),
            (
                CallerAddress,
                Some(RlpTableInputValue {
                    tag: Tag::Sender.into(),
                    is_none: false,
                    be_bytes_len: tx.caller_address.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.caller_address.to_fixed_bytes(), keccak_input),
                }),
                Value::known(tx.caller_address.to_scalar().expect("tx.from too big")),
            ),
            (
                CalleeAddress,
                Some(RlpTableInputValue {
                    tag: Tag::To.into(),
                    is_none: tx.callee_address.is_none(),
                    be_bytes_len: tx.callee_address.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(
                        tx.callee_address
                            .map_or(vec![], |callee| callee.to_fixed_bytes().to_vec())
                            .as_slice(),
                        keccak_input,
                    ),
                }),
                Value::known(
                    tx.callee_address
                        .unwrap_or(Address::zero())
                        .to_scalar()
                        .expect("tx.to too big"),
                ),
            ),
            (IsCreate, None, Value::known(F::from(tx.is_create as u64))),
            (
                TxFieldTag::Value,
                Some(RlpTableInputValue {
                    tag: Tag::Value.into(),
                    is_none: tx.value.is_zero(),
                    be_bytes_len: tx.value.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.value.to_be_bytes(), keccak_input),
                }),
                rlc_be_bytes(&tx.value.to_be_bytes(), evm_word),
            ),
            (
                CallDataRLC,
                Some(RlpTableInputValue {
                    tag: Tag::Data.into(),
                    is_none: tx.call_data.is_empty(),
                    be_bytes_len: tx.call_data.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.call_data, keccak_input),
                }),
                rlc_be_bytes(&tx.call_data, keccak_input),
            ),
            (
                CallDataLength,
                None,
                Value::known(F::from(tx.call_data.len() as u64)),
            ),
            (
                CallDataGasCost,
                None,
                Value::known(F::from(tx.call_data_gas_cost)),
            ),
            (
                TxDataGasCost,
                Some(RlpTableInputValue {
                    tag: GasCost,
                    is_none: false,
                    be_bytes_len: 0,
                    be_bytes_rlc: zero_rlc,
                }),
                Value::known(F::from(tx.tx_data_gas_cost)),
            ),
            (
                ChainID,
                Some(RlpTableInputValue {
                    tag: Tag::ChainId.into(),
                    is_none: tx.chain_id.is_zero(),
                    be_bytes_len: tx.chain_id.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.chain_id.to_be_bytes(), keccak_input),
                }),
                Value::known(F::from(tx.chain_id)),
            ),
            (
                SigV,
                Some(RlpTableInputValue {
                    tag: Tag::SigV.into(),
                    is_none: tx.v.is_zero(),
                    be_bytes_len: tx.v.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.v.to_be_bytes(), keccak_input),
                }),
                Value::known(F::from(tx.v)),
            ),
            (
                SigR,
                Some(RlpTableInputValue {
                    tag: Tag::SigR.into(),
                    is_none: tx.r.is_zero(),
                    be_bytes_len: tx.r.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.r.to_be_bytes(), keccak_input),
                }),
                rlc_be_bytes(&tx.r.to_be_bytes(), evm_word),
            ),
            (
                SigS,
                Some(RlpTableInputValue {
                    tag: Tag::SigS.into(),
                    is_none: tx.s.is_zero(),
                    be_bytes_len: tx.s.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.s.to_be_bytes(), keccak_input),
                }),
                rlc_be_bytes(&tx.s.to_be_bytes(), evm_word),
            ),
            (
                TxSignLength,
                Some(RlpTableInputValue {
                    tag: Len,
                    is_none: false,
                    be_bytes_len: rlp_sign_tag_length,
                    be_bytes_rlc: zero_rlc,
                }),
                Value::known(F::from(tx.rlp_unsigned.len() as u64)),
            ),
            (
                TxSignRLC,
                Some(RlpTableInputValue {
                    tag: RLC,
                    is_none: false,
                    be_bytes_len: 0,
                    be_bytes_rlc: zero_rlc,
                }),
                rlc_be_bytes(&tx.rlp_unsigned, keccak_input),
            ),
            (TxSignHash, None, sign_hash_rlc),
            (
                TxHashLength,
                Some(RlpTableInputValue {
                    tag: Len,
                    is_none: false,
                    be_bytes_len: get_rlp_len_tag_length(&tx.rlp_signed),
                    be_bytes_rlc: zero_rlc,
                }),
                Value::known(F::from(tx.rlp_signed.len() as u64)),
            ),
            (
                TxHashRLC,
                Some(RlpTableInputValue {
                    tag: RLC,
                    is_none: false,
                    be_bytes_len: 0,
                    be_bytes_rlc: zero_rlc,
                }),
                tx_hash_rlc,
            ),
            (TxFieldTag::TxHash, None, hash_rlc),
            (
                TxFieldTag::TxType,
                None,
                Value::known(F::from(tx.tx_type as u64)),
            ),
            (
                AccessListAddressesLen,
                Some(RlpTableInputValue {
                    tag: Null,
                    is_none: access_list_address_size.is_zero(),
                    be_bytes_len: 0,
                    be_bytes_rlc: zero_rlc,
                }),
                Value::known(F::from(access_list_address_size)),
            ),
            (
                AccessListStorageKeysLen,
                Some(RlpTableInputValue {
                    tag: Null,
                    is_none: access_list_storage_key_size.is_zero(),
                    be_bytes_len: 0,
                    be_bytes_rlc: zero_rlc,
                }),
                Value::known(F::from(access_list_storage_key_size)),
            ),
            (
                AccessListRLC,
                Some(RlpTableInputValue {
                    tag: RLC,
                    is_none: tx.access_list.is_none(),
                    be_bytes_len: access_list_len::<F>(&tx.access_list),
                    be_bytes_rlc: access_list_rlc(&tx.access_list, challenges),
                }),
                access_list_rlc(&tx.access_list, challenges),
            ),
            (
                MaxFeePerGas,
                Some(RlpTableInputValue {
                    tag: Tag::MaxFeePerGas.into(),
                    is_none: tx.max_fee_per_gas.is_zero(),
                    be_bytes_len: tx.max_fee_per_gas.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(&tx.max_fee_per_gas.to_be_bytes(), keccak_input),
                }),
                rlc_be_bytes(&tx.max_fee_per_gas.to_be_bytes(), evm_word),
            ),
            (
                MaxPriorityFeePerGas,
                Some(RlpTableInputValue {
                    tag: Tag::MaxPriorityFeePerGas.into(),
                    is_none: tx.max_priority_fee_per_gas.is_zero(),
                    be_bytes_len: tx.max_priority_fee_per_gas.tag_length(),
                    be_bytes_rlc: rlc_be_bytes(
                        &tx.max_priority_fee_per_gas.to_be_bytes(),
                        keccak_input,
                    ),
                }),
                rlc_be_bytes(&tx.max_priority_fee_per_gas.to_be_bytes(), evm_word),
            ),
            (BlockNumber, None, Value::known(F::from(tx.block_number))),
        ];
        for (tx_tag, rlp_input, tx_value) in fixed_rows {
            let rlp_tag = rlp_input.clone().map_or(Null, |input| input.tag);
            let rlp_is_none = rlp_input.clone().map_or(false, |input| input.is_none);
            let rlp_be_bytes_len = rlp_input.clone().map_or(0, |input| input.be_bytes_len);
            let rlp_be_bytes_rlc = rlp_input
                .clone()
                .map_or(zero_rlc, |input| input.be_bytes_rlc);
            let is_l1_msg = tx.tx_type.is_l1_msg();
            // it's the tx_id of next row
            let tx_id_next = if tx_tag == BlockNumber {
                next_tx.map_or(0, |tx| tx.id)
            } else {
                tx.id
            };

            tx_value_cells.push(self.assign_common_part(
                region,
                *offset,
                Some(tx),
                tx_id_next,
                tx_tag,
                0,
                tx_value,
                Value::known(F::zero()),
            )?);

            // 1st phase columns
            for (col_anno, col, col_val) in [
                // rlp table lookup related assignment
                (
                    "rlp_tag",
                    self.rlp_tag,
                    F::from(usize::from(rlp_tag) as u64),
                ),
                ("is_none", self.is_none, F::from(rlp_is_none as u64)),
                (
                    "tx_value_length",
                    self.tx_value_length,
                    F::from(rlp_be_bytes_len as u64),
                ),
                // num_all_txs, num_txs, cum_num_txs related assignment
                ("tx_nonce", self.tx_nonce, F::from(tx.nonce)),
                ("block_num", self.block_num, F::from(tx.block_number)),
                (
                    "total_l1_popped_before",
                    self.total_l1_popped_before,
                    F::from(total_l1_popped_before),
                ),
                (
                    "num_all_txs_acc",
                    self.num_all_txs_acc,
                    F::from(num_all_txs_acc),
                ),
                ("num_txs", self.num_txs, F::from(num_txs)),
                ("cum_num_txs", self.cum_num_txs, F::from(cum_num_txs)),
                // tx meta info
                (
                    "is_padding_tx",
                    self.is_padding_tx,
                    F::from(tx.caller_address.is_zero() as u64),
                ),
                (
                    "sv_address",
                    self.sv_address,
                    sign_data.get_addr().to_scalar().unwrap(),
                ),
                (
                    "is_tag_calldata",
                    self.is_calldata,
                    F::from((tx_tag == CallData) as u64),
                ),
                // tx_tag related indicator columns
                (
                    "is_tag_block_num",
                    self.is_tag_block_num,
                    F::from((tx_tag == BlockNumber) as u64),
                ),
                (
                    "is_tag_hash_rlc",
                    self.is_row_hash_rlc,
                    F::from((tx_tag == TxHashRLC) as u64),
                ),
                (
                    "is_tag_chain_id",
                    self.is_chain_id,
                    F::from((tx_tag == ChainID) as u64),
                ),
                (
                    "is_tag_caller_addr",
                    self.is_caller_address,
                    F::from((tx_tag == CallerAddress) as u64),
                ),
                (
                    "is_chunk_bytes",
                    self.is_chunk_bytes,
                    F::from(is_chunk_bytes as u64),
                ),
                (
                    "chunk_bytes_len",
                    self.chunk_bytes_len,
                    F::from(hash_len as u64),
                ),
            ] {
                region.assign_advice(|| col_anno, col, *offset, || Value::known(col_val))?;
            }
            region.assign_advice(
                || "chunk_txbytes_len_acc",
                self.chunk_txbytes_len_acc,
                *offset,
                || chunk_txbytes_len,
            )?;
            txbytes_hash_assignment = Some(region.assign_advice(
                || "tx_table.chunk_txbytes_hash_rlc",
                self.tx_table.chunk_txbytes_hash_rlc,
                *offset,
                || chunk_txbytes_hash,
            )?);

            // 2nd phase columns
            for (col_anno, col, col_val) in [
                ("tx_value_rlc", self.tx_value_rlc, rlp_be_bytes_rlc),
                ("pow_of_rand", self.pow_of_rand, pow_of_rand),
                (
                    "chunk_txbytes_rlc",
                    self.chunk_txbytes_rlc,
                    chunk_txbytes_rlc,
                ),
            ] {
                region.assign_advice(|| col_anno, col, *offset, || col_val)?;
            }

            // lookup conditions
            let mut conditions = HashMap::<LookupCondition, F>::new();
            // 1. lookup to Tx table for CallDataLength and CallDataGasCost
            conditions.insert(LookupCondition::TxCalldata, {
                let is_data_length = tx_tag == CallDataLength;
                if is_data_length {
                    F::from(!tx.call_data.is_empty() as u64)
                } else {
                    F::zero()
                }
            });
            // 2. lookup to ensure the final row in the access list dynamic section is present.
            conditions.insert(LookupCondition::TxAccessList, {
                let tag_enable = tx_tag == AccessListAddressesLen;
                if tag_enable
                    && tx.access_list.is_some()
                    && !tx.access_list.as_ref().unwrap().0.is_empty()
                {
                    F::one()
                } else {
                    F::zero()
                }
            });
            // 3. lookup to RLP table for signing (non L1 msg)
            conditions.insert(LookupCondition::RlpSignTag, {
                let sign_set = [
                    Nonce,
                    Gas,
                    CalleeAddress,
                    TxFieldTag::Value,
                    CallDataRLC,
                    TxSignLength,
                    TxSignRLC,
                ];
                let is_tag_in_set = sign_set.into_iter().filter(|tag| tx_tag == *tag).count() == 1;
                let case1 = is_tag_in_set && !is_l1_msg;
                let case2 = !tx.tx_type.is_pre_eip155() && !is_l1_msg && (tx_tag == ChainID);
                let case3 = !tx.tx_type.is_eip1559() && !is_l1_msg && (tx_tag == GasPrice);
                let case4 = tx.tx_type.is_eip1559()
                    && (tx_tag == MaxFeePerGas || tx_tag == MaxPriorityFeePerGas);
                F::from((case1 || case2 || case3 || case4) as u64)
            });
            // 4. lookup to RLP table for hashing (non L1 msg)
            conditions.insert(LookupCondition::RlpHashTag, {
                let hash_set = [
                    Nonce,
                    Gas,
                    CalleeAddress,
                    TxFieldTag::Value,
                    CallDataRLC,
                    TxDataGasCost,
                    SigV,
                    SigR,
                    SigS,
                    TxHashLength,
                    TxHashRLC,
                ];
                let is_tag_in_set = hash_set.into_iter().filter(|tag| tx_tag == *tag).count() == 1;
                let case1 = is_tag_in_set && !is_l1_msg;
                let case2 = !tx.tx_type.is_eip1559() && !is_l1_msg && (tx_tag == GasPrice);
                let case3 = tx.tx_type.is_eip1559()
                    && (tx_tag == MaxFeePerGas || tx_tag == MaxPriorityFeePerGas);
                F::from((case1 || case2 || case3) as u64)
            });
            // 5. lookup to RLP table for hashing (L1 msg)
            conditions.insert(LookupCondition::L1MsgHash, {
                let hash_set = [
                    Nonce,
                    Gas,
                    CalleeAddress,
                    TxFieldTag::Value,
                    CallDataRLC,
                    CallerAddress,
                    TxHashLength,
                    TxHashRLC,
                ];

                let is_tag_in_set = hash_set.into_iter().filter(|tag| tx_tag == *tag).count() == 1;
                F::from((is_l1_msg && is_tag_in_set) as u64)
            });
            // 6. lookup to Keccak table for tx_sign_hash and l1 tx_hash
            conditions.insert(LookupCondition::Keccak, {
                let case1 = (tx_tag == TxSignLength) && !is_l1_msg;
                let case2 = (tx_tag == TxHashLength) && is_l1_msg;
                F::from((case1 || case2) as u64)
            });

            // lookup conditions are 1st phase cols
            for (condition, value) in conditions {
                region.assign_advice(
                    || format!("lookup condition {condition:?}"),
                    self.lookup_conditions[&condition],
                    *offset,
                    || Value::known(value),
                )?;
            }

            // assign chips
            let block_num_unchanged_chip = IsEqualChip::construct(self.block_num_unchanged.clone());
            block_num_unchanged_chip.assign(
                region,
                *offset,
                Value::known(F::from(next_tx.map_or(0, |tx| tx.block_number))),
                Value::known(F::from(tx.block_number)),
            )?;
            let tx_id_cmp_cum_num_txs =
                ComparatorChip::construct(self.tx_id_cmp_cum_num_txs.clone());
            tx_id_cmp_cum_num_txs.assign(
                region,
                *offset,
                F::from(tx.id as u64),
                F::from(cum_num_txs),
            )?;

            *offset += 1;
        }
        if is_last_tx {
            tx_value_cells.push(txbytes_hash_assignment.unwrap());
        }
        Ok((tx_value_cells, supplemental_data))
    }

    /// Assign calldata byte rows of each tx
    fn assign_calldata_rows(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        tx: &Transaction,
        next_tx: Option<&Transaction>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // assign to call_data related columns
        let mut gas_cost_acc = 0;
        let mut rlc = challenges.keccak_input().map(|_| F::zero());
        for (idx, byte) in tx.call_data.iter().enumerate() {
            let is_final = idx == (tx.call_data.len() - 1);
            gas_cost_acc += if *byte == 0 { 4 } else { 16 };
            rlc = rlc
                .zip(challenges.keccak_input())
                .map(|(rlc, keccak_input)| rlc * keccak_input + F::from(*byte as u64));
            // the tx id of next row
            let tx_id_next = if !is_final {
                tx.id
            } else {
                next_tx.map_or(0, |tx| tx.id)
            };

            self.assign_common_part(
                region,
                *offset,
                Some(tx),
                tx_id_next,
                CallData,
                idx as u64,
                Value::known(F::from(*byte as u64)),
                Value::known(F::zero()),
            )?;

            // 1st phase columns
            for (col_anno, col, col_val) in [
                ("block_num", self.block_num, F::from(tx.block_number)),
                ("rlp_tag", self.rlp_tag, F::from(usize::from(Null) as u64)),
                ("is_final", self.is_final, F::from(is_final as u64)),
                (
                    "gas_cost_acc",
                    self.calldata_gas_cost_acc,
                    F::from(gas_cost_acc),
                ),
                ("byte", self.calldata_byte, F::from(*byte as u64)),
                ("is_calldata", self.is_calldata, F::one()),
            ] {
                region.assign_advice(|| col_anno, col, *offset, || Value::known(col_val))?;
            }

            // 2nd phase columns
            region.assign_advice(|| "rlc", self.section_rlc, *offset, || rlc)?;

            *offset += 1;
        }

        Ok(())
    }

    /// Assign access list rows of each tx
    fn assign_access_list_rows(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        tx: &Transaction,
        next_tx: Option<&Transaction>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // assign to access_list related columns
        if tx.access_list.is_some() {
            // storage key len accumulator
            let mut sks_acc: usize = 0;

            // row counting for determining when section ends
            let total_rows: usize = tx
                .access_list
                .as_ref()
                .unwrap()
                .0
                .iter()
                .fold(0, |acc, al| acc + 1 + al.storage_keys.len());
            let mut curr_row: usize = 0;

            // initialize access list section rlc
            let mut section_rlc = challenges.keccak_input().map(|_| F::zero());
            // depending on prev row, the accumulator advances by different magnitude
            let r20 = challenges.keccak_input().map(|f| f.pow([20, 0, 0, 0]));
            let r32 = challenges.keccak_input().map(|f| f.pow([32, 0, 0, 0]));

            for (al_idx, al) in tx.access_list.as_ref().unwrap().0.iter().enumerate() {
                curr_row += 1;
                let is_final = curr_row == total_rows;

                let field_rlc =
                    rlc_be_bytes(&al.address.to_fixed_bytes(), challenges.keccak_input());
                section_rlc = section_rlc * r20 + field_rlc;

                let tx_id_next = if curr_row == total_rows {
                    next_tx.map_or(0, |tx| tx.id)
                } else {
                    tx.id
                };

                self.assign_common_part(
                    region,
                    *offset,
                    Some(tx),
                    tx_id_next,
                    TxFieldTag::AccessListAddress,
                    (al_idx + 1) as u64,
                    Value::known(al.address.to_scalar().unwrap()),
                    Value::known(al.address.to_scalar().unwrap()),
                )?;

                // 1st phase columns
                for (col_anno, col, col_val) in [
                    ("block_num", self.block_num, F::from(tx.block_number)),
                    ("al_idx", self.al_idx, F::from((al_idx + 1) as u64)),
                    ("sk_idx", self.sk_idx, F::from(0u64)),
                    ("sks_acc", self.sks_acc, F::from(sks_acc as u64)),
                    (
                        "rlp_tag",
                        self.rlp_tag,
                        F::from(usize::from(Tag::AccessListAddress) as u64),
                    ),
                    ("is_final", self.is_final, F::from(is_final as u64)),
                    ("is_access_list", self.is_access_list, F::one()),
                    (
                        "is_access_list_address",
                        self.is_access_list_address,
                        F::one(),
                    ),
                ] {
                    region.assign_advice(|| col_anno, col, *offset, || Value::known(col_val))?;
                }

                region.assign_advice(|| "field_rlc", self.field_rlc, *offset, || field_rlc)?;

                // 2nd phase columns
                region.assign_advice(|| "rlc", self.section_rlc, *offset, || section_rlc)?;

                *offset += 1;

                for (sk_idx, sk) in al.storage_keys.iter().enumerate() {
                    curr_row += 1;
                    sks_acc += 1;
                    let is_final = curr_row == total_rows;

                    let field_rlc = rlc_be_bytes(&sk.to_fixed_bytes(), challenges.keccak_input());
                    section_rlc = section_rlc * r32 + field_rlc;

                    let tx_id_next = if curr_row == total_rows {
                        next_tx.map_or(0, |tx| tx.id)
                    } else {
                        tx.id
                    };

                    self.assign_common_part(
                        region,
                        *offset,
                        Some(tx),
                        tx_id_next,
                        TxFieldTag::AccessListStorageKey,
                        sks_acc as u64,
                        rlc_be_bytes(&sk.to_fixed_bytes(), challenges.evm_word()),
                        Value::known(al.address.to_scalar().unwrap()),
                    )?;

                    // 1st phase columns
                    for (col_anno, col, col_val) in [
                        ("block_num", self.block_num, F::from(tx.block_number)),
                        ("al_idx", self.al_idx, F::from((al_idx + 1) as u64)),
                        ("sk_idx", self.sk_idx, F::from((sk_idx + 1) as u64)),
                        ("sks_acc", self.sks_acc, F::from(sks_acc as u64)),
                        (
                            "rlp_tag",
                            self.rlp_tag,
                            F::from(usize::from(Tag::AccessListStorageKey) as u64),
                        ),
                        ("is_final", self.is_final, F::from(is_final as u64)),
                        ("is_access_list", self.is_access_list, F::one()),
                        (
                            "is_access_list_storage_key",
                            self.is_access_list_storage_key,
                            F::one(),
                        ),
                    ] {
                        region.assign_advice(
                            || col_anno,
                            col,
                            *offset,
                            || Value::known(col_val),
                        )?;
                    }

                    // field_rlc to work with section_rlc
                    region.assign_advice(|| "field_rlc", self.field_rlc, *offset, || field_rlc)?;

                    // 2nd phase columns
                    region.assign_advice(|| "rlc", self.section_rlc, *offset, || section_rlc)?;

                    *offset += 1;
                }
            }
        }

        Ok(())
    }

    // Assigns to common columns in different parts of tx circuit
    // 1. 1st all zero row
    // 2. fixed rows of each tx
    // 3. calldata rows of dynamic size
    #[allow(clippy::too_many_arguments)]
    fn assign_common_part(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx: Option<&Transaction>,
        tx_id_next: usize,
        tag: TxFieldTag,
        index: u64,
        value: Value<F>,
        access_list_address: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let (tx_type, tx_id) = if let Some(tx) = tx {
            (tx.tx_type, tx.id)
        } else {
            // tx is None if this row is 1st all-zero row.
            assert_eq!(offset, 0);
            (Default::default(), 0)
        };
        let tag_chip = BinaryNumberChip::construct(self.tx_tag_bits);
        tag_chip.assign(region, offset, &tag)?;
        let tx_type_chip = BinaryNumberChip::construct(self.tx_type_bits);
        tx_type_chip.assign(region, offset, &tx_type)?;

        // assign to is_zero/is_equal chips
        let tx_id_is_zero_chip = IsZeroChip::construct(self.tx_id_is_zero.clone());
        tx_id_is_zero_chip.assign(region, offset, Value::known(F::from(tx_id as u64)))?;

        let value_is_zero_chip = IsZeroChip::construct(self.value_is_zero.clone());
        value_is_zero_chip.assign(region, offset, value)?;

        let tx_id_unchanged_chip = IsEqualChip::construct(self.tx_id_unchanged.clone());
        tx_id_unchanged_chip.assign(
            region,
            offset,
            Value::known(F::from(tx_id as u64)),
            Value::known(F::from(tx_id_next as u64)),
        )?;

        region.assign_fixed(
            || "q_enable",
            self.tx_table.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        region.assign_advice(
            || "tag",
            self.tx_table.tag,
            offset,
            || Value::known(F::from(usize::from(tag) as u64)),
        )?;

        // 1st phase columns
        for (col_anno, col, col_val) in [
            // note that tx_table.index is not assigned in this function
            ("tx_id", self.tx_table.tx_id, F::from(tx_id as u64)),
            ("tx_index", self.tx_table.index, F::from(index)),
            ("tx_type", self.tx_type, F::from(u64::from(tx_type))),
            (
                "is_l1_msg",
                self.is_l1_msg,
                F::from(tx_type.is_l1_msg() as u64),
            ),
            (
                "is_eip2930",
                self.is_eip2930,
                F::from(tx_type.is_eip2930() as u64),
            ),
            (
                "is_eip1559",
                self.is_eip1559,
                F::from(tx_type.is_eip1559() as u64),
            ),
            (
                "is_tx_id_zero",
                self.is_tx_id_zero,
                F::from((tx_id == 0) as u64),
            ),
        ] {
            region.assign_advice(|| col_anno, col, offset, || Value::known(col_val))?;
        }

        region.assign_advice(
            || "access_list_address value",
            self.tx_table.access_list_address,
            offset,
            || access_list_address,
        )?;

        // 2nd phase columns
        let tx_value_cell =
            region.assign_advice(|| "tx_value", self.tx_table.value, offset, || value)?;

        Ok(tx_value_cell)
    }

    fn assign_calldata_zeros(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        end: usize,
    ) -> Result<(), Error> {
        // let rlp_data = F::from( as u64);
        let tag = F::from(CallData as u64);
        let tx_id_is_zero_chip = IsZeroChip::construct(self.tx_id_is_zero.clone());
        let value_is_zero_chip = IsZeroChip::construct(self.value_is_zero.clone());
        let tx_id_unchanged = IsEqualChip::construct(self.tx_id_unchanged.clone());
        let tag_chip = BinaryNumberChip::construct(self.tx_tag_bits);

        for offset in start..end {
            region.assign_fixed(
                || "q_enable",
                self.tx_table.q_enable,
                offset,
                || Value::known(F::one()),
            )?;
            region.assign_advice(
                || "rlp_tag",
                self.rlp_tag,
                offset,
                || Value::known(F::from(usize::from(Null) as u64)),
            )?;
            region.assign_advice(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
            tag_chip.assign(region, offset, &CallData)?;
            // no need to assign tx_id_is_zero_chip for real prover as tx_id = 0
            tx_id_is_zero_chip.assign(region, offset, Value::known(F::zero()))?;
            // no need to assign value_is_zero_chip for real prover as value = 0
            value_is_zero_chip.assign(region, offset, Value::known(F::zero()))?;
            tx_id_unchanged.assign(
                region,
                offset,
                Value::known(F::zero()),
                Value::known(F::zero()),
            )?;

            for (col, value) in [
                (self.tx_table.tx_id, F::zero()),
                (self.tx_table.index, F::zero()),
                (self.tx_table.value, F::zero()),
                (self.is_final, F::one()),
                (self.is_calldata, F::one()),
                (self.calldata_gas_cost_acc, F::zero()),
                (self.is_tx_id_zero, F::one()),
            ] {
                region.assign_advice(|| "", col, offset, || Value::known(value))?;
            }
            for col in self.lookup_conditions.values() {
                region.assign_advice(
                    || "lookup condition",
                    *col,
                    offset,
                    || Value::known(F::zero()),
                )?;
            }
        }

        Ok(())
    }

    fn assign_paddings(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        end: usize,
    ) -> Result<(), Error> {
        for offset in start..end {
            region.assign_advice(
                || "tag",
                self.tx_table.tag,
                offset,
                || Value::known(F::from(TxFieldTag::Null as u64)),
            )?;
        }

        Ok(())
    }
}

/// Tx Circuit for verifying transaction signatures and tx table.
/// PI circuit ensures that each tx's hash in the tx table is
/// equal to the one in public input. Then we can use RLP circuit to decode each
/// tx field's value from RLP-encoded tx bytes.
#[derive(Clone, Default, Debug)]
pub struct TxCircuit<F: Field> {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// List of Transactions
    pub txs: Vec<Transaction>,
    /// Chain ID
    pub chain_id: u64,
    /// Start L1 Queue Index
    pub start_l1_queue_index: u64,
    /// Size
    pub size: usize,
    /// Tx value cells (exported for PI circuit)
    pub value_cells: RefCell<Option<Vec<AssignedCell<F, F>>>>,
    _marker: PhantomData<F>,
}

impl<F: Field> TxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        chain_id: u64,
        start_l1_queue_index: u64,
        txs: Vec<Transaction>,
    ) -> Self {
        log::info!(
            "TxCircuit::new(max_txs = {}, max_calldata = {}, chain_id = {})",
            max_txs,
            max_calldata,
            chain_id
        );
        debug_assert!(txs.len() <= max_txs);

        TxCircuit::<F> {
            max_txs,
            max_calldata,
            txs,
            size: Self::min_num_rows(max_txs, max_calldata),
            chain_id,
            start_l1_queue_index,
            value_cells: RefCell::new(None),
            _marker: PhantomData,
        }
    }

    /// Returned data contains both the tx hash and sig hash
    fn keccak_inputs(&self) -> Result<Vec<Vec<u8>>, Error> {
        let mut inputs = Vec::new();

        let padding_tx = {
            let mut tx = Transaction::dummy(self.chain_id);
            tx.id = self.txs.len() + 1;
            tx
        };
        let hash_datas = self
            .txs
            .iter()
            .chain(iter::once(&padding_tx))
            .map(|tx| tx.rlp_signed.clone())
            .collect::<Vec<Vec<u8>>>();
        inputs.extend_from_slice(&hash_datas);

        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .chain(iter::once(&padding_tx))
            .enumerate()
            .map(|(_, tx)| {
                if tx.tx_type.is_l1_msg() {
                    Ok(SignData::default())
                } else {
                    tx.sign_data().map_err(|e| {
                        error!("keccak_inputs_tx_circuit error: {:?}", e);
                        Error::Synthesis
                    })
                }
            })
            .collect::<Result<Vec<SignData>, Error>>()?;
        // Keccak inputs from SignVerify Chip
        let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
        inputs.extend_from_slice(&sign_verify_inputs);

        // Keccak input for chunk bytes (only L2 txs are included)
        let chunk_hash_bytes = self
            .txs
            .iter()
            .filter(|&tx| tx.is_chunk_l2_tx())
            .flat_map(|tx| tx.rlp_signed.clone())
            .collect::<Vec<u8>>();
        inputs.extend_from_slice(&[chunk_hash_bytes]);

        Ok(inputs)
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows(txs_len: usize, call_data_len: usize) -> usize {
        txs_len * TX_LEN + call_data_len
    }

    // assign num_txs, cum_num_txs, num_all_txs only as we only lookup into
    // block table for these three fields and this is mainly used for unit-test
    fn assign_dev_block_table(
        &self,
        config: TxCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut total_l1_popped_before = 0;
        let block_nums = self
            .txs
            .iter()
            .map(|tx| tx.block_number)
            .collect::<BTreeSet<u64>>();
        let mut num_txs_in_blocks = BTreeMap::new();
        let mut num_all_txs_in_blocks: BTreeMap<u64, u64> = BTreeMap::new();
        for tx in self.txs.iter() {
            if let Some(num_txs) = num_txs_in_blocks.get_mut(&tx.block_number) {
                *num_txs += 1;
            } else {
                num_txs_in_blocks.insert(tx.block_number, 1_usize);
            }

            if let Some(num_all_txs) = num_all_txs_in_blocks.get_mut(&tx.block_number) {
                if tx.tx_type.is_l1_msg() {
                    *num_all_txs += tx.nonce - total_l1_popped_before + 1;
                    total_l1_popped_before = tx.nonce + 1;
                } else {
                    *num_all_txs += 1;
                }
            } else {
                let num_all_txs = if tx.tx_type.is_l1_msg() {
                    tx.nonce - total_l1_popped_before + 1
                } else {
                    1
                };
                num_all_txs_in_blocks.insert(tx.block_number, num_all_txs);
            }
        }
        log::debug!("block_nums: {:?}", block_nums);
        log::debug!("num_all_txs: {:?}", num_all_txs_in_blocks);

        layouter.assign_region(
            || "dev block table",
            |mut region| {
                for (offset, (block_num, num_txs, cum_num_txs, num_all_txs)) in
                    iter::once((0, 0, 0, 0))
                        .chain(block_nums.iter().scan(0, |cum_num_txs, block_num| {
                            let num_txs = num_txs_in_blocks[block_num];
                            let num_all_txs = num_all_txs_in_blocks[block_num];
                            *cum_num_txs += num_txs;

                            Some((*block_num, num_txs, *cum_num_txs, num_all_txs))
                        }))
                        .enumerate()
                {
                    for (j, (tag, value)) in [
                        (NumTxs, num_txs as u64),
                        (CumNumTxs, cum_num_txs as u64),
                        (NumAllTxs, num_all_txs),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        let row = offset * 3 + j;
                        region.assign_fixed(
                            || "block_table.tag",
                            config.block_table.tag,
                            row,
                            || Value::known(F::from(tag as u64)),
                        )?;
                        region.assign_advice(
                            || "block_table.index",
                            config.block_table.index,
                            row,
                            || Value::known(F::from(block_num)),
                        )?;
                        region.assign_advice(
                            || "block_table.value",
                            config.block_table.value,
                            row,
                            || Value::known(F::from(value)),
                        )?;
                    }
                }
                Ok(())
            },
        )
    }

    fn assign(
        &self,
        config: &TxCircuitConfig<F>,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        start_l1_queue_index: u64,
        sign_datas: Vec<SignData>,
        padding_txs: &[Transaction],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        config.tx_rom_table.load(layouter)?;

        layouter.assign_region(
            || "tx table aux",
            |mut region| {
                let mut offset = 0;

                let sigs = &sign_datas;

                debug_assert_eq!(padding_txs.len() + self.txs.len(), sigs.len());

                let mut cum_num_txs = 0;
                let mut num_txs;
                let mut num_all_txs_acc = 0;
                let mut total_l1_popped_before = start_l1_queue_index;
                let mut total_l1_popped_after = start_l1_queue_index;

                // 1. Empty entry
                region.assign_fixed(|| "q_first", config.q_first, 0, || Value::known(F::one()))?;
                config.assign_null_row(&mut region, &mut offset)?;

                // 2. Assign all tx fields except for call data
                let get_tx = |i: usize| {
                    if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &padding_txs[i - self.txs.len()]
                    }
                };

                let mut chunk_bytes: Vec<u8> = vec![];
                for i in 0..sigs.len() {
                    let tx = get_tx(i);
                    if tx.is_chunk_l2_tx() {
                        chunk_bytes.extend_from_slice(&tx.rlp_signed);
                    }
                }

                let chunk_txbytes_hash = keccak256(chunk_bytes.as_slice());
                let evm_word = challenges.evm_word();
                let chunk_txbytes_hash = rlc_be_bytes(&chunk_txbytes_hash, evm_word);

                let mut tx_value_cells = vec![];
                let mut chunk_txbytes_rlc_acc = Value::known(F::zero());
                let mut chunk_txbytes_len_acc = Value::known(F::zero());
                let mut pows_of_rand: Vec<Value<F>> = vec![Value::known(F::one())];
                for (i, sign_data) in sigs.iter().enumerate() {
                    let tx = get_tx(i);
                    let block_num = tx.block_number;
                    // get each tx's
                    if i < self.txs.len() {
                        cum_num_txs = self
                            .txs
                            .iter()
                            .filter(|tx| tx.block_number <= block_num)
                            .count() as u64;
                        num_txs = self
                            .txs
                            .iter()
                            .filter(|tx| tx.block_number == block_num)
                            .count() as u64;
                        let mut init_new_block = |tx: &Transaction| {
                            if tx.tx_type.is_l1_msg() {
                                let queue_index = tx.nonce;
                                num_all_txs_acc = queue_index - total_l1_popped_before + 1;
                                total_l1_popped_after = queue_index + 1;
                            } else {
                                // next tx's total_l1_popped_before do not change
                                total_l1_popped_after = total_l1_popped_before;
                                num_all_txs_acc = 1;
                            }
                        };
                        // first tx of all or first tx of next block
                        if i == 0 || tx.block_number != self.txs[i - 1].block_number {
                            init_new_block(tx);
                        } else {
                            // same block
                            if tx.tx_type.is_l1_msg() {
                                let queue_index = tx.nonce;
                                num_all_txs_acc += queue_index - total_l1_popped_before + 1;
                                total_l1_popped_after = queue_index + 1;
                            } else {
                                // next tx's total_l1_popped_before do not change
                                total_l1_popped_after = total_l1_popped_before;
                                num_all_txs_acc += 1;
                            }
                        }
                    } else {
                        num_txs = 0_u64;
                        // padding_tx is an l2 tx
                        num_all_txs_acc = (i - self.txs.len() + 1) as u64;
                    }
                    let is_last_tx = i == (sigs.len() - 1);
                    let next_tx = if is_last_tx {
                        self.txs.iter().find(|tx| !tx.call_data.is_empty())
                    } else {
                        Some(get_tx(i+1))
                    };
                    log::debug!(
                        "[block_num: {}, num_txs: {}, cum_num_txs: {}] tx_id: {}, num_all_txs_acc: {}",
                        tx.block_number,
                        num_txs,
                        cum_num_txs,
                        i,
                        num_all_txs_acc,
                    );
                    let (assigned_cells, supplemental_data) = config.assign_fixed_rows(
                        &mut region,
                        &mut offset,
                        tx,
                        sign_data,
                        next_tx,
                        total_l1_popped_before,
                        num_all_txs_acc,
                        num_txs,
                        cum_num_txs,
                        chunk_txbytes_rlc_acc,
                        chunk_txbytes_len_acc,
                        chunk_txbytes_hash,
                        &mut pows_of_rand,
                        is_last_tx,
                        challenges,
                    )?;

                    tx_value_cells.extend_from_slice(
                        assigned_cells.as_slice()
                    );

                    chunk_txbytes_rlc_acc = supplemental_data[0];
                    chunk_txbytes_len_acc = supplemental_data[1];

                    // set next tx's total_l1_popped_before
                    total_l1_popped_before = total_l1_popped_after;
                }
                assert_eq!(offset, self.max_txs * TX_LEN + 1);

                let calldata_first_row = self.max_txs * TX_LEN + 1;
                let calldata_last_row = calldata_first_row + self.max_calldata;
                // 3. Assign call data of txs
                // 3.1 padding txs have no calldata bytes
                for (i, tx) in self.txs.iter().enumerate() {
                    let next_tx = self
                        .txs
                        .iter()
                        .skip(i + 1)
                        .find(|tx| !tx.call_data.is_empty());
                    config.assign_calldata_rows(
                        &mut region,
                        &mut offset,
                        tx,
                        next_tx,
                        challenges,
                    )?;
                    config.assign_access_list_rows(
                        &mut region,
                        &mut offset,
                        tx,
                        next_tx,
                        challenges,
                    )?;
                }
                assert!(offset <= calldata_last_row, "{offset}, {calldata_last_row}");
                // 3.2 pad calldata with zeros
                config.assign_calldata_zeros(
                    &mut region,
                    offset,
                    calldata_last_row,
                )?;
                // 3.3. assign first and last indicators
                for (col_anno, col, row) in [
                    ("q_dynamic_first", config.q_dynamic_first, calldata_first_row),
                    ("q_dynamic_last", config.q_dynamic_last, calldata_last_row-1),
                ] {
                    region.assign_fixed(|| col_anno, col, row, || Value::known(F::one()))?;
                }

                Ok(tx_value_cells)
            },
        )
    }
}

impl<F: Field> SubCircuit<F> for TxCircuit<F> {
    type Config = TxCircuitConfig<F>;

    fn unusable_rows() -> usize {
        9
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        for tx in &block.txs {
            if tx.chain_id != block.chain_id {
                panic!(
                    "inconsistent chain id, block chain id {}, tx {:?}",
                    block.chain_id, tx.chain_id
                );
            }
        }
        Self::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.chain_id,
            block.start_l1_queue_index,
            block.txs.clone(),
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        // Since each call data byte at least takes one row in RLP circuit.
        // For L2 tx, each call data byte takes two row in RLP circuit.
        assert!(block.circuits_params.max_calldata < block.circuits_params.max_rlp_rows);

        // Calculate blob capacity usage
        let chunk_txbytes_len = block
            .txs
            .iter()
            .map(|tx| {
                if tx.is_chunk_l2_tx() {
                    tx.rlp_signed.len()
                } else {
                    0
                }
            })
            .sum::<usize>();
        let blob_usage: f32 = chunk_txbytes_len as f32 / CHUNK_TXBYTES_BLOB_LIMIT as f32;

        // Calculate tx circuit dynamic section usage
        let sum_calldata_len = block.txs.iter().map(|tx| tx.call_data.len()).sum::<usize>();
        let sum_access_list_len = block
            .txs
            .iter()
            .map(|tx| {
                if tx.access_list.is_some() {
                    let access_list = tx.access_list.clone().unwrap().0;
                    access_list.len()
                        + access_list
                            .iter()
                            .map(|al| al.storage_keys.len())
                            .sum::<usize>()
                } else {
                    0usize
                }
            })
            .sum::<usize>();

        // With the introduction of access list, the max_calldata circuit parameter now has to share
        // capacity between calldata and access list rows TODO: The max_calldata parameter
        // should be renamed later to max_dynamic
        let max_dynamic_data = if block.circuits_params.max_calldata == 0 {
            // input-specific max_dynamic
            sum_calldata_len + sum_access_list_len
        } else {
            block.circuits_params.max_calldata
        };
        let dynamic_usage =
            (sum_calldata_len + sum_access_list_len) as f32 / max_dynamic_data as f32;

        // Get the highest usage fraction out of all capacities
        let highest_usage = ([blob_usage, dynamic_usage])
            .iter()
            .cloned()
            .fold(0_f32, f32::max);

        // Return the highest usage percentage
        (
            (highest_usage * block.circuits_params.max_vertical_circuit_rows as f32).ceil()
                as usize,
            Self::min_num_rows(
                block.circuits_params.max_txs,
                block.circuits_params.max_calldata,
            ),
        )
    }

    /// Make the assignments to the TxCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        assert!(self.txs.len() <= self.max_txs);

        let padding_txs = (self.txs.len()..self.max_txs)
            .map(|i| {
                let mut tx = Transaction::dummy(self.chain_id);
                tx.id = i + 1;
                tx
            })
            .collect::<Vec<Transaction>>();
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .chain(padding_txs.iter())
            .map(|tx| {
                if tx.tx_type.is_l1_msg() {
                    Ok(SignData::default())
                } else {
                    tx.sign_data().map_err(|e| {
                        error!("tx_to_sign_data error for tx {:?}", e);
                        Error::Synthesis
                    })
                }
            })
            .collect::<Result<Vec<SignData>, Error>>()?;

        // check if tx.caller_address == recovered_pk
        let recovered_pks = keccak_inputs_sign_verify(&sign_datas)
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| {
                // each sign_data produce two inputs for hashing
                // pk -> pk_hash, msg -> msg_hash
                idx % 2 == 0
            })
            .map(|(_, input)| input)
            .collect::<Vec<_>>();

        for (pk, tx) in recovered_pks.into_iter().zip(self.txs.iter()) {
            let pk_hash = keccak(&pk);
            let address = pk_hash.to_address();
            // L1 Msg does not have signature
            if !tx.tx_type.is_l1_msg() && address != tx.caller_address {
                log::error!(
                    "pk address from sign data {:?} does not match the one from tx address {:?}",
                    address,
                    tx.caller_address
                )
            }
        }

        let tx_value_cells = self.assign(
            config,
            challenges,
            layouter,
            self.start_l1_queue_index,
            sign_datas,
            &padding_txs,
        )?;
        // export tx value cells
        *self.value_cells.borrow_mut() = Some(tx_value_cells);

        Ok(())
    }
}

pub(crate) fn get_sign_data(
    txs: &[Transaction],
    max_txs: usize,
    chain_id: usize,
) -> Result<Vec<SignData>, halo2_proofs::plonk::Error> {
    let padding_txs = (txs.len()..max_txs)
        .map(|i| {
            let mut tx = Transaction::dummy(chain_id as u64);
            tx.id = i + 1;
            tx
        })
        .collect::<Vec<Transaction>>();
    let signatures: Vec<SignData> = txs
        .iter()
        .chain(padding_txs.iter())
        .map(|tx| {
            if tx.tx_type.is_l1_msg() {
                // dummy signature
                Ok(SignData::default())
            } else {
                // TODO: map err or still use bus_mapping::err?
                tx.sign_data().map_err(|e| {
                    log::error!("tx_to_sign_data error for tx {:?}", e);
                    halo2_proofs::plonk::Error::Synthesis
                })
            }
        })
        .collect::<Result<Vec<SignData>, halo2_proofs::plonk::Error>>()?;
    Ok(signatures)
}

/// Returns the RLC of the access list including addresses and storage keys
/// This function provides an alternative routine to calculate access_list_rlc
/// to ascertain the correctness of assignment in witness generation.
pub fn access_list_rlc<F: Field>(
    access_list: &Option<AccessList>,
    challenges: &Challenges<Value<F>>,
) -> Value<F> {
    if access_list.is_some() {
        let mut section_rlc = challenges.keccak_input().map(|_| F::zero());
        let r20 = challenges.keccak_input().map(|f| f.pow([20, 0, 0, 0]));
        let r32 = challenges.keccak_input().map(|f| f.pow([32, 0, 0, 0]));

        for al in access_list.as_ref().unwrap().0.iter() {
            let field_rlc = rlc_be_bytes(&al.address.to_fixed_bytes(), challenges.keccak_input());
            section_rlc = section_rlc * r20 + field_rlc;

            for sk in al.storage_keys.iter() {
                let field_rlc = rlc_be_bytes(&sk.to_fixed_bytes(), challenges.keccak_input());
                section_rlc = section_rlc * r32 + field_rlc;
            }
        }

        section_rlc
    } else {
        Value::known(F::zero())
    }
}

/// Returns the length of the access list including addresses and storage keys
pub fn access_list_len<F: Field>(access_list: &Option<AccessList>) -> u32 {
    if access_list.is_some() {
        let mut len = 0;
        for al in access_list.as_ref().unwrap().0.iter() {
            len += 20;
            len += 32 * (al.storage_keys.len() as u32);
        }
        len
    } else {
        0
    }
}
