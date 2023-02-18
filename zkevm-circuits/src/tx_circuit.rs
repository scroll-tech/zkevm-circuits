//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

pub mod sign_verify;

use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::table::{KeccakTable, LookupTable, RlpTable, TxFieldTag, TxTable};
#[cfg(not(feature = "enable-sign-verify"))]
use crate::tx_circuit::sign_verify::pub_key_hash_to_address;
use crate::util::{random_linear_combine_word as rlc, SubCircuit, SubCircuitConfig};
use crate::witness;
use crate::witness::{RlpDataType, RlpTxTag, Transaction};
use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
#[cfg(not(feature = "enable-sign-verify"))]
use eth_types::sign_types::{pk_bytes_le, pk_bytes_swap_endianness};
use eth_types::{
    sign_types::SignData,
    {Field, ToLittleEndian, ToScalar},
};
#[cfg(not(feature = "enable-sign-verify"))]
use ethers_core::utils::keccak256;
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction};
use gadgets::util::{and, not, select, sum, Expr};
#[cfg(feature = "enable-sign-verify")]
use halo2_proofs::circuit::{Cell, RegionIndex};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
};
use log::error;
use num::Zero;
use sign_verify::{AssignedSignatureVerify, SignVerifyChip, SignVerifyConfig};
use std::collections::HashMap;
use std::iter;
use std::marker::PhantomData;

use crate::table::TxFieldTag::{
    CallData, CallDataGasCost, CallDataLength, CalleeAddress, CallerAddress, Gas, GasPrice,
    IsCreate, Nonce, SigR, SigS, SigV, TxHashLength, TxHashRLC, TxSignHash, TxSignLength,
    TxSignRLC,
};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};
use halo2_proofs::plonk::Fixed;

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

/// Number of rows of one tx occupies in the fixed part of tx table
pub const TX_LEN: usize = 19;
/// Offset of TxHash tag in the tx table
pub const TX_HASH_OFFSET: usize = 18;

#[derive(Clone, Debug)]
struct TagTable {
    tx_tag: Column<Fixed>,
    rlp_tag: Column<Fixed>,
}

impl TagTable {
    fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tx_tag: meta.fixed_column(),
            rlp_tag: meta.fixed_column(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum LookupCondition {
    // lookup into tx table
    TxCalldata,
    // lookup into tag table
    Tag,
    // lookup into rlp table
    RlpCalldata,
    RlpSignTag,
    RlpHashTag,
    // lookup into keccak table
    Keccak,
}

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    minimum_rows: usize,

    q_enable: Column<Fixed>,

    /// TxFieldTag assigned to the row.
    tag: BinaryNumberConfig<TxFieldTag, 5>,
    rlp_tag: Column<Advice>,
    tag_table: TagTable,

    tx_id_is_zero: IsEqualConfig<F>,
    /// Primarily used to verify if the `CallDataLength` is zero or non-zero.
    value_is_zero: IsZeroConfig<F>,
    /// We use an equality gadget to know whether the tx id changes between
    /// subsequent rows or not.
    tx_id_unchanged: IsEqualConfig<F>,
    is_calldata: Column<Advice>,

    lookup_conditions: HashMap<LookupCondition, Column<Advice>>,
    /// A boolean advice column, which is turned on only for the last byte in
    /// call data.
    is_final: Column<Advice>,
    /// A dedicated column that holds the calldata's length. We use this column
    /// only for the TxFieldTag::CallData tag.
    calldata_length: Column<Advice>,
    /// An accumulator value used to correctly calculate the calldata gas cost
    /// for a tx.
    calldata_gas_cost_acc: Column<Advice>,
    /// Chain ID.
    chain_id: Column<Advice>,

    /// Address recovered by SignVerifyChip
    sv_address: Column<Advice>,
    sign_verify: SignVerifyConfig<F>,

    // External tables
    tx_table: TxTable,
    rlp_table: RlpTable,
    keccak_table: KeccakTable,

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct TxCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// RlpTable
    pub rlp_table: RlpTable,
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
            keccak_table,
            rlp_table,
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let tag = BinaryNumberChip::configure(meta, q_enable, None);
        let rlp_tag = meta.advice_column();
        let value_inv = meta.advice_column_in(SecondPhase);
        let is_calldata = meta.advice_column(); // to reduce degree
        let lookup_conditions = [
            LookupCondition::TxCalldata,
            LookupCondition::Tag,
            LookupCondition::RlpCalldata,
            LookupCondition::RlpSignTag,
            LookupCondition::RlpHashTag,
            LookupCondition::Keccak,
        ]
        .into_iter()
        .map(|condition| (condition, meta.advice_column()))
        .collect::<HashMap<LookupCondition, Column<Advice>>>();

        let tag_table = TagTable::construct(meta);
        let sv_address = meta.advice_column();
        meta.enable_equality(tx_table.value);
        meta.enable_equality(sv_address);

        let log_deg = |s: &'static str, meta: &mut ConstraintSystem<F>| {
            log::info!("after {}, meta.degree: {}", s, meta.degree());
        };

        macro_rules! is_tx_tag {
            ($var:ident, $tag_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    tag.value_equals(TxFieldTag::$tag_variant, Rotation::cur())(meta)
                };
            };
        }
        is_tx_tag!(is_nonce, Nonce);
        is_tx_tag!(is_gas_price, GasPrice);
        is_tx_tag!(is_gas, Gas);
        is_tx_tag!(is_to, CalleeAddress);
        is_tx_tag!(is_value, Value);
        is_tx_tag!(is_data, CallData);
        is_tx_tag!(is_data_length, CallDataLength);
        is_tx_tag!(is_sig_v, SigV);
        is_tx_tag!(is_sig_r, SigR);
        is_tx_tag!(is_sig_s, SigS);
        is_tx_tag!(is_sign_length, TxSignLength);
        is_tx_tag!(is_sign_rlc, TxSignRLC);
        is_tx_tag!(is_hash_length, TxHashLength);
        is_tx_tag!(is_hash_rlc, TxHashRLC);
        // is_tx_tag!(is_sign_hash, TxSignHash);
        // is_tx_tag!(is_hash, TxHash);
        // is_tx_tag!(is_padding, Padding);

        let tx_id_is_zero = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            |_| 0.expr(),
        );
        let value_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    sum::expr(vec![
                        // if caller_address is zero, then skip the sig verify.
                        tag.value_equals(CallerAddress, Rotation::cur())(meta),
                        // if callee_address is zero, then IsCreate = false.
                        tag.value_equals(CalleeAddress, Rotation::cur())(meta),
                        // if call_data_length is zero, then skip lookup to tx table for call data
                        tag.value_equals(CallDataLength, Rotation::cur())(meta),
                        // if call data byte is zero, then gas_cost = 4 (16 otherwise)
                        tag.value_equals(CallData, Rotation::cur())(meta),
                    ]),
                ])
            },
            |meta| meta.query_advice(tx_table.value, Rotation::cur()),
            value_inv,
        );
        log_deg("value_is_zero", meta);

        let tx_id_unchanged = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::next()),
        );

        let is_final = meta.advice_column();
        let calldata_length = meta.advice_column();
        let calldata_gas_cost_acc = meta.advice_column();
        let chain_id = meta.advice_column();

        meta.create_gate("calldata lookup into tx table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "condition",
                and::expr([
                    is_data_length(meta),
                    not::expr(value_is_zero.is_zero_expression.expr()),
                ]),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::TxCalldata],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("lookup into tag table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_in_set = sum::expr([
                is_nonce(meta),
                is_gas_price(meta),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_data_length(meta),
                is_sig_v(meta),
                is_sig_r(meta),
                is_sig_s(meta),
                is_sign_length(meta),
                is_sign_rlc(meta),
                is_hash_length(meta),
                is_hash_rlc(meta),
            ]);
            cb.require_equal(
                "condition",
                is_tag_in_set,
                meta.query_advice(lookup_conditions[&LookupCondition::Tag], Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("calldata lookup into rlp table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "condition",
                and::expr([
                    is_data(meta),
                    not::expr(tx_id_is_zero.is_equal_expression.expr()),
                ]),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpCalldata],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("sign tag lookup into rlp table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_in_tx_sign = sum::expr([
                is_nonce(meta),
                is_gas_price(meta),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_data_length(meta), // call data length in DataPrefix
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

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("hash tag lookup into rlp table condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_in_tx_hash = sum::expr([
                is_nonce(meta),
                is_gas_price(meta),
                is_gas(meta),
                is_to(meta),
                is_value(meta),
                is_data_length(meta),
                is_sig_v(meta),
                is_sig_r(meta),
                is_sig_s(meta),
                is_hash_length(meta),
                is_hash_rlc(meta),
            ]);

            cb.require_equal(
                "condition",
                is_tag_in_tx_hash,
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpHashTag],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("calldata length lookup condition", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_tag_sign_or_hash = sum::expr([is_sign_length(meta), is_hash_length(meta)]);
            cb.require_equal(
                "condition",
                is_tag_sign_or_hash,
                meta.query_advice(lookup_conditions[&LookupCondition::Keccak], Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        Self::configure_lookups(
            meta,
            q_enable,
            rlp_tag,
            &lookup_conditions,
            &tag_table,
            is_final,
            calldata_length,
            calldata_gas_cost_acc,
            // chain_id,
            tx_table.clone(),
            keccak_table.clone(),
            rlp_table,
        );

        let sign_verify = SignVerifyConfig::new(meta, keccak_table.clone());

        meta.create_gate("is_calldata", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "is_calldata",
                tag.value_equals(CallData, Rotation::cur())(meta),
                meta.query_advice(is_calldata, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

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
                cb.require_equal(
                    "calldata_length::cur == calldata_length::next",
                    meta.query_advice(calldata_length, Rotation::cur()),
                    meta.query_advice(calldata_length, Rotation::next()),
                );

                let value_next_is_not_zero = meta.query_advice(value_inv, Rotation::next())
                    * meta.query_advice(tx_table.value, Rotation::next());
                let gas_cost_next = select::expr(value_next_is_not_zero, 16.expr(), 4.expr());
                // call data gas cost accumulator check.
                cb.require_equal(
                    "calldata_gas_cost_acc::next == calldata_gas_cost::cur + gas_cost_next",
                    meta.query_advice(calldata_gas_cost_acc, Rotation::next()),
                    meta.query_advice(calldata_gas_cost_acc, Rotation::cur()) + gas_cost_next,
                );
            });

            // on the final call data byte, tx_id must change.
            // FIXME: tx id change is not sufficient as tx id can change from 4 -> 5 -> 4
            //  instead we need to ensure that tx_id_next > tx_id if tx_id_next != 0
            cb.condition(is_final_cur, |cb| {
                cb.require_zero(
                    "tx_id changes at is_final == 1",
                    tx_id_unchanged.is_equal_expression.clone(),
                );
                cb.require_equal(
                    "calldata_length == index::cur + 1",
                    meta.query_advice(calldata_length, Rotation::cur()),
                    meta.query_advice(tx_table.index, Rotation::cur()) + 1.expr(),
                );
            });

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_calldata, Rotation::cur()),
                not::expr(tx_id_is_zero.is_equal_expression.expr()),
            ]))
        });

        /*
        meta.create_gate("tx id change at nonce row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tx_id::cur == tx_id::prev + 1",
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tx_id, Rotation::prev()) + 1.expr(),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                // meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]))
        });
        */

        meta.create_gate("tx is_create", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(value_is_zero.is_zero_expression.clone(), |cb| {
                cb.require_equal(
                    "if callee_address == 0 then is_create == 1",
                    meta.query_advice(tx_table.value, Rotation::next()),
                    1.expr(),
                );
            });
            cb.condition(not::expr(value_is_zero.is_zero_expression.clone()), |cb| {
                cb.require_zero(
                    "if callee_address != 0 then is_create == 0",
                    meta.query_advice(tx_table.value, Rotation::next()),
                );
            });

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(CalleeAddress, Rotation::cur())(meta),
            ]))
        });

        /*
        meta.create_gate("tx signature v", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let chain_id_expr = meta.query_advice(chain_id, Rotation::cur());
            cb.require_boolean(
                "V - (chain_id * 2 + 35) Є {0, 1}",
                meta.query_advice(tx_table.value, Rotation::cur())
                    - (chain_id_expr.clone() + chain_id_expr + 35.expr()),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(SigV, Rotation::cur())(meta),
            ]))
        });
         */

        #[cfg(feature = "reject-eip2718")]
        meta.create_gate("caller address == sv_address if it's not zero", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(not::expr(value_is_zero.is_zero_expression.expr()), |cb| {
                cb.require_equal(
                    "caller address == sv_address",
                    meta.query_advice(tx_table.value, Rotation::cur()),
                    meta.query_advice(sv_address, Rotation::cur()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(CallerAddress, Rotation::cur())(meta),
            ]))
        });

        meta.create_gate("tag equality", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag equality (fixed tag == binary number config's tag",
                meta.query_fixed(tx_table.tag, Rotation::cur()),
                tag.value(Rotation::cur())(meta),
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        Self {
            minimum_rows: meta.minimum_rows(),
            q_enable,
            tag,
            rlp_tag,
            tag_table,
            tx_id_is_zero,
            value_is_zero,
            tx_id_unchanged,
            is_calldata,
            lookup_conditions,
            is_final,
            calldata_length,
            calldata_gas_cost_acc,
            chain_id,
            sv_address,
            sign_verify,
            tx_table,
            keccak_table,
            rlp_table,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> TxCircuitConfig<F> {
    /// Load ECDSA RangeChip table.
    pub fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "tag table region",
            |mut region| {
                for (i, (tag, rlp_tag)) in [
                    (Nonce, RlpTxTag::Nonce),
                    (GasPrice, RlpTxTag::GasPrice),
                    (Gas, RlpTxTag::Gas),
                    (CalleeAddress, RlpTxTag::To),
                    (TxFieldTag::Value, RlpTxTag::Value),
                    (CallDataLength, RlpTxTag::DataPrefix),
                    (SigV, RlpTxTag::SigV),
                    (SigR, RlpTxTag::SigR),
                    (SigS, RlpTxTag::SigS),
                    (TxSignLength, RlpTxTag::RlpLength),
                    (TxHashLength, RlpTxTag::RlpLength),
                    (TxSignRLC, RlpTxTag::Rlp),
                    (TxHashRLC, RlpTxTag::Rlp),
                ]
                .into_iter()
                .enumerate()
                {
                    region.assign_fixed(
                        || "tx tag",
                        self.tag_table.tx_tag,
                        i,
                        || Value::known(F::from(tag as u64)),
                    )?;
                    region.assign_fixed(
                        || "rlp tag",
                        self.tag_table.rlp_tag,
                        i,
                        || Value::known(F::from(rlp_tag as u64)),
                    )?;
                }

                Ok(())
            },
        )?;
        #[cfg(feature = "enable-sign-verify")]
        self.sign_verify.load_range(layouter)?;

        Ok(())
    }

    /// Assigns a tx circuit row and returns the assigned cell of the value in
    /// the row.
    #[allow(clippy::too_many_arguments)]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        tx_id: usize,
        tx_id_next: usize,
        tag: TxFieldTag,
        rlp_tag: RlpTxTag,
        value: Value<F>,
        is_final: bool,
        calldata_length: Option<u64>,
        calldata_gas_cost_acc: Option<u64>,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "q_enable",
            self.q_enable,
            *offset,
            || Value::known(F::one()),
        )?;

        let tag_chip = BinaryNumberChip::construct(self.tag);
        tag_chip.assign(region, *offset, &tag)?;

        let tx_id_is_zero_chip = IsEqualChip::construct(self.tx_id_is_zero.clone());
        tx_id_is_zero_chip.assign(
            region,
            *offset,
            Value::known(F::from(tx_id as u64)),
            Value::known(F::zero()),
        )?;

        let is_zero_chip = IsZeroChip::construct(self.value_is_zero.clone());
        is_zero_chip.assign(region, *offset, value)?;

        let tx_id_unchanged_chip = IsEqualChip::construct(self.tx_id_unchanged.clone());
        tx_id_unchanged_chip.assign(
            region,
            *offset,
            Value::known(F::from(tx_id as u64)),
            Value::known(F::from(tx_id_next as u64)),
        )?;

        /*
        region.assign_fixed(
            || "tx_table.tag",
            self.tx_table.tag,
            *offset,
            || Value::known(F::from(tag as u64)),
        )?;
        region.assign_advice(
            || "tx_table.tx_id",
            self.tx_table.tx_id,
            *offset,
            || Value::known(F::from(tx_id as u64)),
        )?;
        region.assign_advice(
            || "tx_table.index",
            self.tx_table.index,
            *offset,
            || Value::known(F::from())
        )?;
        region.assign_advice(
            || "tx_table.value",
            self.tx_table.value,
            *offset,
            value,
        )?;
        */

        region.assign_advice(
            || "rlp tag",
            self.rlp_tag,
            *offset,
            || Value::known(F::from(rlp_tag as u64)),
        )?;
        region.assign_advice(
            || "is_final",
            self.is_final,
            *offset,
            || Value::known(F::from(is_final as u64)),
        )?;
        region.assign_advice(
            || "calldata_length",
            self.calldata_length,
            *offset,
            || Value::known(F::from(calldata_length.unwrap_or_default())),
        )?;
        region.assign_advice(
            || "calldata_gas_cost_acc",
            self.calldata_gas_cost_acc,
            *offset,
            || Value::known(F::from(calldata_gas_cost_acc.unwrap_or_default())),
        )?;

        region.assign_advice(
            || "chain_id",
            self.chain_id,
            *offset,
            || Value::known(F::zero()),
        )?;

        let mut conditions = HashMap::<LookupCondition, Value<F>>::new();
        conditions.insert(LookupCondition::TxCalldata, {
            let is_data_length = tag == CallDataLength;
            if is_data_length {
                value.map(|value| F::from(!value.is_zero_vartime() as u64))
            } else {
                Value::known(F::zero())
            }
        });
        conditions.insert(LookupCondition::Tag, {
            let set = [
                Nonce,
                GasPrice,
                Gas,
                CalleeAddress,
                TxFieldTag::Value,
                CallDataLength,
                SigV,
                SigR,
                SigS,
                TxSignLength,
                TxSignRLC,
                TxHashLength,
                TxHashRLC,
            ];
            let is_tag_in_set = set.into_iter().filter(|_tag| tag == *_tag).count();
            Value::known(F::from(is_tag_in_set as u64))
        });
        conditions.insert(LookupCondition::RlpCalldata, {
            let is_data = tag == CallData;
            Value::known(F::from((is_data && tx_id != 0) as u64))
        });
        conditions.insert(LookupCondition::RlpSignTag, {
            let sign_set = [
                Nonce,
                GasPrice,
                Gas,
                CalleeAddress,
                TxFieldTag::Value,
                CallDataLength,
                TxSignLength,
                TxSignRLC,
            ];
            let is_tag_in_set = sign_set.into_iter().filter(|_tag| tag == *_tag).count();
            Value::known(F::from(is_tag_in_set as u64))
        });
        conditions.insert(LookupCondition::RlpHashTag, {
            let hash_set = [
                Nonce,
                GasPrice,
                Gas,
                CalleeAddress,
                TxFieldTag::Value,
                CallDataLength,
                SigV,
                SigR,
                SigS,
                TxHashLength,
                TxHashRLC,
            ];
            let is_tag_in_set = hash_set.into_iter().filter(|_tag| tag == *_tag).count();
            Value::known(F::from(is_tag_in_set as u64))
        });
        conditions.insert(LookupCondition::Keccak, {
            let set = [TxSignLength, TxHashLength];
            let is_tag_in_set = set.into_iter().filter(|_tag| tag == *_tag).count();
            Value::known(F::from(is_tag_in_set as u64))
        });

        for (condition, value) in conditions {
            region.assign_advice(
                || format!("lookup condition {:?}", condition),
                self.lookup_conditions[&condition],
                *offset,
                || value,
            )?;
        }
        region.assign_advice(
            || "is_calldata",
            self.is_calldata,
            *offset,
            || Value::known(F::from((tag == CallData) as u64)),
        )?;

        *offset += 1;

        Ok(())
    }

    fn assign_calldata_zeros(
        &self,
        region: &mut Region<'_, F>,
        start: usize,
        end: usize,
    ) -> Result<(), Error> {
        let rlp_data = F::from(RlpTxTag::Data as u64);
        let tag = F::from(CallData as u64);
        let tx_id_is_zero_chip = IsEqualChip::construct(self.tx_id_is_zero.clone());
        let value_is_zero_chip = IsZeroChip::construct(self.value_is_zero.clone());
        let tx_id_unchanged = IsEqualChip::construct(self.tx_id_unchanged.clone());
        let tag_chip = BinaryNumberChip::construct(self.tag);

        for offset in start..end {
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                offset,
                || Value::known(F::one()),
            )?;
            region.assign_fixed(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
            tag_chip.assign(region, offset, &CallData)?;
            // no need to assign tx_id_is_zero_chip for real prover as tx_id = 0
            tx_id_is_zero_chip.assign(
                region,
                offset,
                Value::known(F::zero()),
                Value::known(F::zero()),
            )?;
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
                (self.rlp_tag, rlp_data),
                (self.is_final, F::one()),
                (self.is_calldata, F::one()),
                (self.calldata_length, F::zero()),
                (self.calldata_gas_cost_acc, F::zero()),
                (self.chain_id, F::zero()),
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
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                offset,
                || Value::known(F::zero()),
            )?;
            region.assign_fixed(
                || "tag",
                self.tx_table.tag,
                offset,
                || Value::known(F::from(TxFieldTag::Null as u64)),
            )?;
        }

        Ok(())
    }

    /// Get number of rows required.
    pub fn get_num_rows_required(num_tx: usize) -> usize {
        let num_rows_range_table = 1 << 18;
        // Number of rows required to verify a transaction.
        let num_rows_per_tx = 140436;
        (num_tx * num_rows_per_tx).max(num_rows_range_table)
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_lookups(
        meta: &mut ConstraintSystem<F>,
        q_enable: Column<Fixed>,
        rlp_tag: Column<Advice>,
        lookup_conditions: &HashMap<LookupCondition, Column<Advice>>,
        tag_table: &TagTable,
        is_final: Column<Advice>,
        calldata_length: Column<Advice>,
        calldata_gas_cost_acc: Column<Advice>,
        // chain_id: Column<Advice>,
        tx_table: TxTable,
        keccak_table: KeccakTable,
        rlp_table: RlpTable,
    ) {
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
            .zip(
                vec![
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    meta.query_fixed(tx_table.tag, Rotation::cur()),
                    meta.query_advice(calldata_gas_cost_acc, Rotation::cur()),
                    meta.query_advice(is_final, Rotation::cur()),
                ]
                .into_iter(),
            )
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
                meta.query_advice(tx_table.value, Rotation::cur()) - 1.expr(), // index
                1.expr(),                                                      // is_final
            ]
            .into_iter()
            .zip(
                vec![
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    meta.query_fixed(tx_table.tag, Rotation::cur()),
                    meta.query_advice(tx_table.index, Rotation::cur()),
                    meta.query_advice(is_final, Rotation::cur()),
                ]
                .into_iter(),
            )
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        /////////////////////////////////////////////////////////////////
        /////////////////    RLP table lookups     //////////////////////
        /////////////////////////////////////////////////////////////////

        // lookup to tag table to make sure rlp_tag is correct
        meta.lookup_any("(tag, rlp_tag) in tag table", |meta| {
            // nonce -> nonce
            // gas_price -> gas_price
            // gas -> gas
            // callee_address -> to
            // value -> value
            // call_data_length -> data_prefix
            // sig_v -> sig_v
            // sig_r -> sig_r
            // sig_s -> sig_s
            // sign_length -> rlp_length
            // sign_rlc -> rlp
            // hash_length -> rlp_length
            // hash_rlc -> rlp
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(lookup_conditions[&LookupCondition::Tag], Rotation::cur()),
            ]);
            let tx_tag = meta.query_fixed(tx_table.tag, Rotation::cur());
            let rlp_tag = meta.query_advice(rlp_tag, Rotation::cur());
            let tx_tag_table = meta.query_fixed(tag_table.tx_tag, Rotation::cur());
            let rlp_tag_table = meta.query_fixed(tag_table.rlp_tag, Rotation::cur());

            vec![
                (enable.expr() * tx_tag, tx_tag_table),
                (enable.expr() * rlp_tag, rlp_tag_table),
            ]
        });

        // lookup tx tag in rlp table for TxSign.
        meta.lookup_any("tx tag in RLP Table::TxSign", |meta| {
            let enable = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpSignTag],
                    Rotation::cur(),
                ),
            ]);
            let rlp_tag = meta.query_advice(rlp_tag, Rotation::cur());

            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                rlp_tag,
                1.expr(), // tag_rindex == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx tag in rlp table for TxHash
        meta.lookup_any("tx tag in RLP Table::TxHash", |meta| {
            let rlp_tag = meta.query_advice(rlp_tag, Rotation::cur());
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpHashTag],
                    Rotation::cur(),
                ),
            ]);

            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                rlp_tag,
                1.expr(), // tag_rindex == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        /*
        // lookup RLP table to check Chain ID.
        meta.lookup_any("rlp table Chain ID", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                // meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::SigV, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::ChainId.expr(), // tag
                1.expr(),                 // tag_index == 1
                meta.query_advice(chain_id, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
         */

        // lookup tx calldata bytes in RLP table for TxSign.
        meta.lookup_any("tx calldata::index in RLP Table::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpCalldata],
                    Rotation::cur(),
                ),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Data.expr(),
                meta.query_advice(calldata_length, Rotation::cur())
                    - meta.query_advice(tx_table.index, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx calldata bytes in RLP table for TxSign.
        meta.lookup_any("tx calldata::index in RLP Table::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(
                    lookup_conditions[&LookupCondition::RlpCalldata],
                    Rotation::cur(),
                ),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Data.expr(),
                meta.query_advice(calldata_length, Rotation::cur())
                    - meta.query_advice(tx_table.index, Rotation::cur()),
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        /////////////////////////////////////////////////////////////////
        /////////////////    Keccak table lookups     //////////////////////
        /////////////////////////////////////////////////////////////////
        // lookup Keccak table for tx sign data hash, i.e. the sighash that has to be
        // signed.
        // lookup Keccak table for tx hash too.
        meta.lookup_any("Keccak table lookup for TxSignHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(lookup_conditions[&LookupCondition::Keccak], Rotation::cur()),
            ]);

            vec![
                1.expr(),                                            // is_enabled
                meta.query_advice(tx_table.value, Rotation::next()), // input_rlc
                meta.query_advice(tx_table.value, Rotation::cur()),  // input_len
                meta.query_advice(tx_table.value, Rotation(2)),      // output_rlc
            ]
            .into_iter()
            .zip(keccak_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
    }
}

/// Tx Circuit for verifying transaction signatures and tx table. (**legacy tx
/// only right now**) PI circuit ensures that each tx's hash in the tx table is
/// equal to the one in public input. Then we can use RLP circuit to decode each
/// tx field's value from RLP-encoded tx bytes.
#[derive(Clone, Default, Debug)]
pub struct TxCircuit<F: Field> {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// SignVerify chip
    pub sign_verify: SignVerifyChip<F>,
    /// List of Transactions
    pub txs: Vec<Transaction>,
    /// Chain ID
    pub chain_id: u64,
    /// Size
    pub size: usize,
}

impl<F: Field> TxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(max_txs: usize, max_calldata: usize, chain_id: u64, txs: Vec<Transaction>) -> Self {
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
            sign_verify: SignVerifyChip::new(max_txs),
            txs,
            size: Self::min_num_rows(max_txs, max_calldata),
            chain_id,
        }
    }

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
            .filter(|(_, tx)| {
                if tx.v == 0 && tx.r.is_zero() && tx.s.is_zero() {
                    log::warn!(
                        "tx {} is not signed, skipping tx circuit keccak input",
                        tx.id
                    );
                    false
                } else {
                    true
                }
            })
            .map(|(_, tx)| {
                tx.sign_data().map_err(|e| {
                    error!("keccak_inputs_tx_circuit error: {:?}", e);
                    Error::Synthesis
                })
            })
            .collect::<Result<Vec<SignData>, Error>>()?;
        // Keccak inputs from SignVerify Chip
        let sign_verify_inputs = keccak_inputs_sign_verify(&sign_datas);
        inputs.extend_from_slice(&sign_verify_inputs);

        Ok(inputs)
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows(txs_len: usize, call_data_len: usize) -> usize {
        let tx_table_len = txs_len * TX_LEN + call_data_len;
        #[cfg(feature = "enable-sign-verify")]
        let min_rows = std::cmp::max(tx_table_len, SignVerifyChip::<F>::min_num_rows(txs_len));
        #[cfg(not(feature = "enable-sign-verify"))]
        let min_rows = tx_table_len;
        min_rows
    }

    fn assign(
        &self,
        config: &TxCircuitConfig<F>,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        assigned_sig_verifs: Vec<AssignedSignatureVerify<F>>,
        sign_datas: Vec<SignData>,
        padding_txs: &[Transaction],
    ) -> Result<(), Error> {
        let last_off = layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                #[cfg(feature = "enable-sign-verify")]
                let sigs = &assigned_sig_verifs;
                #[cfg(not(feature = "enable-sign-verify"))]
                let sigs = &sign_datas;

                debug_assert_eq!(assigned_sig_verifs.len() + sign_datas.len(), sigs.len());
                debug_assert_eq!(padding_txs.len() + self.txs.len(), sigs.len());

                // Empty entry
                config.assign_row(
                    &mut region,
                    &mut offset,
                    0,                         // tx_id
                    !sigs.is_empty() as usize, // tx_id_next
                    TxFieldTag::Null,
                    RlpTxTag::Padding,
                    Value::known(F::zero()),
                    false,
                    None,
                    None,
                )?;

                // Assign all tx fields except for call data
                for (i, assigned_sig_verif) in sigs.iter().enumerate() {
                    let tx = if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &padding_txs[i - self.txs.len()]
                    };
                    let rlp_unsigned_tx_be_bytes = tx.rlp_unsigned.clone();
                    let rlp_signed_tx_be_bytes = tx.rlp_signed.clone();

                    #[cfg(feature = "enable-sign-verify")]
                    let tx_sign_hash = assigned_sig_verif.msg_hash_rlc.value().copied();
                    #[cfg(not(feature = "enable-sign-verify"))]
                    let tx_sign_hash = {
                        challenges.evm_word().map(|rand| {
                            assigned_sig_verif
                                .msg
                                .to_vec()
                                .into_iter()
                                .fold(F::zero(), |acc, byte| acc * rand + F::from(byte as u64))
                        })
                    };
                    for (tag, rlp_tag, value) in [
                        // need to be in same order as that tx table load function uses
                        (Nonce, RlpTxTag::Nonce, Value::known(F::from(tx.nonce))),
                        (Gas, RlpTxTag::Gas, Value::known(F::from(tx.gas))),
                        (
                            GasPrice,
                            RlpTxTag::GasPrice,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.gas_price.to_le_bytes(), challenge)),
                        ),
                        (
                            CallerAddress,
                            RlpTxTag::Padding, // FIXME
                            Value::known(tx.caller_address.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            CalleeAddress,
                            RlpTxTag::To,
                            Value::known(tx.callee_address.to_scalar().expect("tx.to too big")),
                        ),
                        (
                            IsCreate,
                            RlpTxTag::Padding, // FIXME
                            Value::known(F::from(tx.is_create as u64)),
                        ),
                        (
                            TxFieldTag::Value,
                            RlpTxTag::Value,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.value.to_le_bytes(), challenge)),
                        ),
                        (
                            CallDataLength,
                            RlpTxTag::DataPrefix,
                            Value::known(F::from(tx.call_data.len() as u64)),
                        ),
                        (
                            CallDataGasCost,
                            RlpTxTag::Padding, // FIXME
                            Value::known(F::from(tx.call_data_gas_cost)),
                        ),
                        (SigV, RlpTxTag::SigV, Value::known(F::from(tx.v))),
                        (
                            SigR,
                            RlpTxTag::SigR,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.r.to_le_bytes(), challenge)),
                        ),
                        (
                            SigS,
                            RlpTxTag::SigS,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.s.to_le_bytes(), challenge)),
                        ),
                        (
                            TxSignLength,
                            RlpTxTag::RlpLength,
                            Value::known(F::from(rlp_unsigned_tx_be_bytes.len() as u64)),
                        ),
                        (
                            TxSignRLC,
                            RlpTxTag::Rlp,
                            challenges.keccak_input().map(|rand| {
                                rlp_unsigned_tx_be_bytes
                                    .iter()
                                    .fold(F::zero(), |acc, byte| acc * rand + F::from(*byte as u64))
                            }),
                        ),
                        (
                            TxSignHash,
                            RlpTxTag::Padding, // FIXME
                            tx_sign_hash,
                        ),
                        (
                            TxHashLength,
                            RlpTxTag::RlpLength,
                            Value::known(F::from(rlp_signed_tx_be_bytes.len() as u64)),
                        ),
                        (
                            TxHashRLC,
                            RlpTxTag::Rlp,
                            challenges.keccak_input().map(|rand| {
                                rlp_signed_tx_be_bytes
                                    .iter()
                                    .fold(F::zero(), |acc, byte| acc * rand + F::from(*byte as u64))
                            }),
                        ),
                        (
                            TxFieldTag::TxHash,
                            RlpTxTag::Padding, // FIXME
                            challenges.evm_word().map(|challenge| {
                                tx.hash
                                    .to_fixed_bytes()
                                    .into_iter()
                                    .fold(F::zero(), |acc, byte| {
                                        acc * challenge + F::from(byte as u64)
                                    })
                            }),
                        ),
                        (
                            TxFieldTag::BlockNumber,
                            RlpTxTag::Padding,       // FIXME
                            Value::known(F::zero()), // FIXME
                        ),
                    ] {
                        let tx_id_next = match tag {
                            TxFieldTag::BlockNumber => {
                                if i == sigs.len() - 1 {
                                    self.txs
                                        .iter()
                                        .enumerate()
                                        .find(|(_i, tx)| !tx.call_data.is_empty())
                                        .map(|(i, _tx)| i + 1)
                                        .unwrap_or_else(|| 0)
                                } else {
                                    i + 2
                                }
                            }
                            _ => i + 1,
                        };
                        config.assign_row(
                            &mut region,
                            &mut offset,
                            i + 1,      // tx_id
                            tx_id_next, // tx_id_next
                            tag,
                            rlp_tag,
                            value,
                            false,
                            None,
                            None,
                        )?;
                        // Ref. spec 0. Copy constraints using fixed offsets
                        // between the tx rows and the SignVerifyChip
                        match tag {
                            CallerAddress => {
                                #[cfg(feature = "enable-sign-verify")]
                                {
                                    assigned_sig_verif.address.copy_advice(
                                        || "sv_address == SignVerify.address",
                                        &mut region,
                                        config.sv_address,
                                        offset - 1,
                                    )?;
                                }
                                #[cfg(not(feature = "enable-sign-verify"))]
                                {
                                    let pk_le = pk_bytes_le(&assigned_sig_verif.pk);
                                    let pk_be = pk_bytes_swap_endianness(&pk_le);
                                    let pk_hash = keccak256(pk_be);
                                    let address =
                                        Value::known(pub_key_hash_to_address::<F>(&pk_hash));
                                    region.assign_advice(
                                        || "sv_address",
                                        config.sv_address,
                                        offset - 1,
                                        || address,
                                    )?;
                                }
                            }
                            TxSignHash => {
                                #[cfg(feature = "enable-sign-verify")]
                                {
                                    region.constrain_equal(
                                        assigned_sig_verif.msg_hash_rlc.cell(),
                                        Cell {
                                            // FIXME
                                            region_index: RegionIndex(1),
                                            row_offset: offset - 1, /* offset is increased by 1
                                                                     * inside assign_row */
                                            column: config.tx_table.value.into(),
                                        },
                                    )?;
                                }
                            }
                            SigV => {
                                region.assign_advice(
                                    || "chain id",
                                    config.chain_id,
                                    offset,
                                    || Value::known(F::from(self.chain_id)),
                                )?;
                            }
                            // TODO: connect r, s to SignVerifyChip
                            _ => (),
                        }
                    }
                }

                log::debug!("assigning calldata, offset {}", offset);

                // Assign call data
                let mut calldata_count = 0;
                for (i, tx) in self.txs.iter().enumerate() {
                    let mut calldata_gas_cost = 0;
                    let calldata_length = tx.call_data.len();
                    calldata_count += calldata_length;
                    for (index, byte) in tx.call_data.iter().enumerate() {
                        assert!(calldata_count < self.max_calldata);
                        let (tx_id_next, is_final) = if index == calldata_length - 1 {
                            if i == self.txs.len() - 1 {
                                (0, true)
                            } else {
                                (
                                    self.txs
                                        .iter()
                                        .enumerate()
                                        .skip(i + 1)
                                        .find(|(_, tx)| !tx.call_data.is_empty())
                                        .map(|(j, _)| j + 1)
                                        .unwrap_or_else(|| 0),
                                    true,
                                )
                            }
                        } else {
                            (i + 1, false)
                        };
                        calldata_gas_cost += if byte.is_zero() { 4 } else { 16 };
                        config.assign_row(
                            &mut region,
                            &mut offset,
                            i + 1,      // tx_id
                            tx_id_next, // tx_id_next
                            CallData,
                            RlpTxTag::Data,
                            Value::known(F::from(*byte as u64)),
                            is_final,
                            Some(calldata_length as u64),
                            Some(calldata_gas_cost),
                        )?;
                    }
                }

                debug_assert_eq!(offset, self.max_txs * TX_LEN + 1 + calldata_count);

                Ok(offset)
            },
        )?;
        if last_off + config.minimum_rows > self.size {
            log::error!(
                "circuit size not enough, last offset {}, minimum_rows {}, self.size {}",
                last_off,
                config.minimum_rows,
                self.size
            );
        }
        layouter.assign_region(
            || "tx table (calldata zeros and paddings)",
            |mut region| {
                config.assign_calldata_zeros(
                    &mut region,
                    0,
                    self.max_calldata + self.max_txs * TX_LEN + 1 - last_off,
                )?;
                config.assign_paddings(
                    &mut region,
                    self.max_calldata + self.max_txs * TX_LEN + 1 - last_off,
                    self.size - config.minimum_rows - last_off,
                )?;

                Ok(())
            },
        )
    }
}

impl<F: Field> SubCircuit<F> for TxCircuit<F> {
    type Config = TxCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        debug_assert_eq!(block.chain_id, block.context.chain_id());
        for tx in &block.txs {
            if tx.chain_id != block.chain_id.as_u64() {
                panic!(
                    "inconsistent chain id, block chain id {}, tx {:?}",
                    block.chain_id, tx.chain_id
                );
            }
        }
        Self::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.context.chain_id().as_u64(),
            block.txs.clone(),
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            Self::min_num_rows(
                block.txs.len(),
                block.txs.iter().map(|tx| tx.call_data.len()).sum(),
            ),
            std::cmp::max(
                1 << 18,
                Self::min_num_rows(
                    block.circuits_params.max_txs,
                    block.circuits_params.max_calldata,
                ),
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
            .into_iter()
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
                tx.sign_data().map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", e);
                    Error::Synthesis
                })
            })
            .collect::<Result<Vec<SignData>, Error>>()?;

        config.load_aux_tables(layouter)?;
        #[cfg(feature = "enable-sign-verify")]
        {
            let assigned_sig_verifs =
                self.sign_verify
                    .assign(&config.sign_verify, layouter, &sign_datas, challenges)?;
            self.sign_verify.assert_sig_is_valid(
                &config.sign_verify,
                layouter,
                assigned_sig_verifs.as_slice(),
            )?;
            self.assign(
                config,
                challenges,
                layouter,
                assigned_sig_verifs,
                Vec::new(),
                &padding_txs,
            )?;
        }
        #[cfg(not(feature = "enable-sign-verify"))]
        {
            self.assign(
                config,
                challenges,
                layouter,
                Vec::new(),
                sign_datas,
                &padding_txs,
            )?;
        }
        Ok(())
    }

    fn instance(&self) -> Vec<Vec<F>> {
        // The maingate expects an instance column, but we don't use it, so we return an
        // "empty" instance column
        vec![vec![]]
    }
}

#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
#[cfg(feature = "onephase")]
use crate::util::MockChallenges as Challenges;

impl<F: Field> Circuit<F> for TxCircuit<F> {
    type Config = (TxCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let rlp_table = RlpTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            TxCircuitConfig::new(
                meta,
                TxCircuitConfigArgs {
                    tx_table,
                    keccak_table,
                    rlp_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        let padding_txs = (self.txs.len()..self.max_txs)
            .into_iter()
            .map(|i| {
                let mut tx = Transaction::dummy(self.chain_id);
                tx.id = i + 1;
                tx
            })
            .collect::<Vec<Transaction>>();

        config
            .keccak_table
            .dev_load(&mut layouter, &self.keccak_inputs()?, &challenges)?;
        config.tx_table.load(
            &mut layouter,
            &self.txs,
            self.max_txs,
            self.max_calldata,
            self.chain_id,
            &challenges,
        )?;
        config.rlp_table.dev_load(
            &mut layouter,
            self.txs
                .iter()
                .chain(padding_txs.iter())
                .map(|tx| tx.into())
                .collect(),
            &challenges,
        )?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod tx_circuit_tests {
    use super::*;
    use crate::util::log2_ceil;
    #[cfg(feature = "reject-eip2718")]
    use eth_types::address;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    #[cfg(feature = "reject-eip2718")]
    use mock::AddrOrWallet;
    use pretty_assertions::assert_eq;
    use std::cmp::max;

    const NUM_BLINDING_ROWS: usize = 64;

    fn run<F: Field>(
        txs: Vec<Transaction>,
        chain_id: u64,
        max_txs: usize,
        max_calldata: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        let k = max(
            18,
            log2_ceil(TxCircuit::<F>::min_num_rows(max_txs, max_calldata)),
        );
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let circuit = TxCircuit::<F>::new(max_txs, max_calldata, chain_id, txs);

        let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn tx_circuit_2tx_2max_tx() {
        const NUM_TXS: usize = 2;
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 32;

        assert_eq!(
            run::<Fr>(
                [
                    mock::CORRECT_MOCK_TXS[1].clone(),
                    mock::CORRECT_MOCK_TXS[3].clone()
                ]
                .iter()
                .enumerate()
                .map(|(i, tx)| {
                    let mut mock_tx = tx.clone();
                    mock_tx.transaction_idx((i + 1) as u64);
                    mock_tx.into()
                })
                .collect(),
                mock::MOCK_CHAIN_ID.as_u64(),
                MAX_TXS,
                MAX_CALLDATA
            ),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_0tx_1max_tx() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        assert_eq!(run::<Fr>(vec![], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
    }

    #[test]
    fn tx_circuit_1tx_1max_tx() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
    }

    #[test]
    fn tx_circuit_1tx_2max_tx() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
    }

    #[cfg(feature = "reject-eip2718")]
    #[test]
    fn tx_circuit_bad_address() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
        // This address doesn't correspond to the account that signed this tx.
        tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

        assert!(run::<Fr>(
            vec![tx.into()],
            mock::MOCK_CHAIN_ID.as_u64(),
            MAX_TXS,
            MAX_CALLDATA
        )
        .is_err(),);
    }
}
