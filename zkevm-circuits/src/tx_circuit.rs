//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

pub mod sign_verify;

use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::table::{KeccakTable, LookupTable, RlpTable, TxFieldTag, TxTable};
use crate::util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness;
use crate::witness::{signed_tx_from_geth_tx, RlpDataType, RlpTxTag};
use bus_mapping::circuit_input_builder::keccak_inputs_tx_circuit;
use eth_types::{
    sign_types::SignData,
    {geth_types::Transaction, Address, Field, ToLittleEndian, ToScalar},
};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction};
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use log::error;
use num::Zero;
use sign_verify::{AssignedSignatureVerify, SignVerifyChip, SignVerifyConfig};
use std::marker::PhantomData;

pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};
use halo2_proofs::plonk::Fixed;

/// Number of static fields per tx: [nonce, gas, gas_price,
/// caller_address, callee_address, is_create, value, call_data_length,
/// call_data_gas_cost, tx_sign_hash].
/// Note that call data bytes are layed out in the TxTable after all the static
/// fields arranged by txs.
pub(crate) const TX_LEN: usize = 10;

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    q_enable: Column<Fixed>,
    is_usable: Column<Advice>,

    /// TxFieldTag assigned to the row.
    tag: BinaryNumberConfig<TxFieldTag, 4>,
    /// Primarily used to verify if the `CallDataLength` is zero or non-zero.
    value_is_zero: IsEqualConfig<F>,
    /// We use an equality gadget to know whether the tx id changes between
    /// subsequent rows or not.
    tx_id_unchanged: IsEqualConfig<F>,
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

    /// Length of the RLP-encoded unsigned tx.
    tx_sign_data_len: Column<Advice>,
    /// RLC-encoded RLP-encoding of unsigned tx.
    tx_sign_data_rlc: Column<Advice>,

    sign_verify: SignVerifyConfig,
    tx_table: TxTable,
    rlp_table: RlpTable,
    _marker: PhantomData<F>,
    // External tables
    keccak_table: KeccakTable,
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
    pub challenges: Challenges<Expression<F>>,
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
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let is_usable = meta.advice_column();
        let tag = BinaryNumberChip::configure(meta, q_enable, None);
        meta.enable_equality(tx_table.value);

        let value_is_zero = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_usable, Rotation::cur()),
                    or::expr(vec![
                        tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
                        tag.value_equals(TxFieldTag::CallDataLength, Rotation::cur())(meta),
                        tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
                    ]),
                ])
            },
            |meta| meta.query_advice(tx_table.value, Rotation::cur()),
            |_| 0.expr(),
        );
        let tx_id_unchanged = IsEqualChip::configure(
            meta,
            |meta| {
                and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_usable, Rotation::cur()),
                ])
            },
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::next()),
        );

        let is_final = meta.advice_column();
        let calldata_length = meta.advice_column();
        let calldata_gas_cost_acc = meta.advice_column();
        let chain_id = meta.advice_column();

        let tx_sign_data_len = meta.advice_column();
        let tx_sign_data_rlc = meta.advice_column();

        Self::configure_lookups(
            meta,
            q_enable,
            is_usable,
            tag,
            is_final,
            calldata_length,
            calldata_gas_cost_acc,
            chain_id,
            tx_sign_data_len,
            tx_sign_data_rlc,
            &value_is_zero,
            tx_table.clone(),
            keccak_table.clone(),
            rlp_table,
        );

        let sign_verify = SignVerifyConfig::new(meta, keccak_table.clone(), challenges);

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
            });

            // call data gas cost accumulator check.
            cb.condition(
                and::expr(vec![
                    not::expr(is_final_cur.clone()),
                    value_is_zero.is_equal_expression.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "calldata_gas_cost_acc::next == calldata_gas_cost::cur + 4",
                        meta.query_advice(calldata_gas_cost_acc, Rotation::next()),
                        meta.query_advice(calldata_gas_cost_acc, Rotation::cur()) + 4.expr(),
                    );
                },
            );
            cb.condition(
                not::expr(or::expr(vec![
                    is_final_cur.clone(),
                    value_is_zero.is_equal_expression.clone(),
                ])),
                |cb| {
                    cb.require_equal(
                        "calldata_gas_cost_acc::next == calldata_gas_cost::cur + 16",
                        meta.query_advice(calldata_gas_cost_acc, Rotation::next()),
                        meta.query_advice(calldata_gas_cost_acc, Rotation::cur()) + 16.expr(),
                    );
                },
            );

            // on the final call data byte, tx_id must change.
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
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
            ]))
        });

        meta.create_gate("tx id change at nonce row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tx_id::cur == tx_id::prev + 1",
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                meta.query_advice(tx_table.tx_id, Rotation::prev()) + 1.expr(),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]))
        });

        meta.create_gate("tx is_create", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(value_is_zero.is_equal_expression.clone(), |cb| {
                cb.require_equal(
                    "if callee_address == 0 then is_create == 1",
                    meta.query_advice(tx_table.value, Rotation::next()),
                    1.expr(),
                );
            });
            cb.condition(not::expr(value_is_zero.is_equal_expression.clone()), |cb| {
                cb.require_zero(
                    "if callee_address != 0 then is_create == 0",
                    meta.query_advice(tx_table.value, Rotation::next()),
                );
            });

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
            ]))
        });

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
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::SigV, Rotation::cur())(meta),
            ]))
        });

        meta.create_gate("tag equality", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "tag equality (fixed tag == binary number config's tag",
                meta.query_advice(tx_table.tag, Rotation::cur()),
                tag.value(Rotation::cur())(meta),
            );

            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
            ]))
        });

        Self {
            q_enable,
            is_usable,
            tag,
            value_is_zero,
            tx_id_unchanged,
            is_final,
            calldata_length,
            calldata_gas_cost_acc,
            chain_id,
            tx_sign_data_len,
            tx_sign_data_rlc,
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
        self.sign_verify.load_range(layouter)
    }

    /// Assigns a tx circuit row and returns the assigned cell of the value in
    /// the row.
    #[allow(clippy::too_many_arguments)]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        usable: bool,
        tx_id: usize,
        tx_id_next: usize,
        tag: TxFieldTag,
        index: usize,
        value: Value<F>,
        is_final: bool,
        calldata_length: Option<u64>,
        calldata_gas_cost_acc: Option<u64>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_fixed(
            || "q_enable",
            self.q_enable,
            offset,
            || Value::known(F::one()),
        )?;
        region.assign_advice(
            || "is_usable",
            self.is_usable,
            offset,
            || Value::known(F::from(usable as u64)),
        )?;
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(F::from(tx_id as u64)),
        )?;
        region.assign_advice(
            || "tag",
            self.tx_table.tag,
            offset,
            || Value::known(F::from(tag as u64)),
        )?;

        let tag_chip = BinaryNumberChip::construct(self.tag);
        tag_chip.assign(region, offset, &tag)?;

        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(F::from(index as u64)),
        )?;

        let is_zero_chip = IsEqualChip::construct(self.value_is_zero.clone());
        is_zero_chip.assign(region, offset, value, Value::known(F::zero()))?;

        let tx_id_unchanged_chip = IsEqualChip::construct(self.tx_id_unchanged.clone());
        tx_id_unchanged_chip.assign(
            region,
            offset,
            Value::known(F::from(tx_id as u64)),
            Value::known(F::from(tx_id_next as u64)),
        )?;

        region.assign_advice(
            || "is_final",
            self.is_final,
            offset,
            || Value::known(F::from(is_final as u64)),
        )?;
        region.assign_advice(
            || "calldata_length",
            self.calldata_length,
            offset,
            || Value::known(F::from(calldata_length.unwrap_or_default())),
        )?;
        region.assign_advice(
            || "calldata_gas_cost_acc",
            self.calldata_gas_cost_acc,
            offset,
            || Value::known(F::from(calldata_gas_cost_acc.unwrap_or_default())),
        )?;
        region.assign_advice(
            || "tx_sign_data_len",
            self.tx_sign_data_len,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_sign_data_rlc",
            self.tx_sign_data_rlc,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "chain_id",
            self.chain_id,
            offset,
            || Value::known(F::zero()),
        )?;

        region.assign_advice(|| "value", self.tx_table.value, offset, || value)
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
        is_usable: Column<Advice>,
        tag: BinaryNumberConfig<TxFieldTag, 4>,
        is_final: Column<Advice>,
        calldata_length: Column<Advice>,
        calldata_gas_cost_acc: Column<Advice>,
        chain_id: Column<Advice>,
        tx_sign_data_len: Column<Advice>,
        tx_sign_data_rlc: Column<Advice>,
        value_is_zero: &IsEqualConfig<F>,
        tx_table: TxTable,
        keccak_table: KeccakTable,
        rlp_table: RlpTable,
    ) {
        // lookup tx nonce.
        meta.lookup_any("tx nonce in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Nonce.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx nonce in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Nonce, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Nonce.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx rlc(gasprice).
        meta.lookup_any("tx rlc(gasprice) in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::GasPrice, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::GasPrice.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx rlc(gasprice) in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::GasPrice, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::GasPrice.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx gas.
        meta.lookup_any("tx gas in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Gas, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Gas.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx gas in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Gas, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Gas.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx callee address.
        meta.lookup_any("tx callee address in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::To.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx callee address in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CalleeAddress, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::To.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx rlc(value).
        meta.lookup_any("tx rlc(value) in RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Value, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Value.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("tx rlc(value) in RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                tag.value_equals(TxFieldTag::Value, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Value.expr(),
                1.expr(), // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup to check CallDataLength of the tx's call data.
        meta.lookup_any("tx calldatalength in TxTable", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
                meta.query_advice(is_final, Rotation::cur()),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CallDataLength.expr(),
                0.expr(),
                meta.query_advice(tx_table.index, Rotation::cur()) + 1.expr(),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup to check CallDataGasCost of the tx's call data.
        meta.lookup_any("tx calldatagascost in TxTable", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
                meta.query_advice(is_final, Rotation::cur()),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CallDataGasCost.expr(),
                0.expr(),
                meta.query_advice(calldata_gas_cost_acc, Rotation::cur()),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup RLP table to check SigV and Chain ID.
        meta.lookup_any("rlp table Chain ID", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
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
        meta.lookup_any("rlp table SigV", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::SigV, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::SigV.expr(), // tag
                1.expr(),              // tag_index == 1
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup RLP table for SigR and SigS.
        meta.lookup_any("rlp table SigR", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::SigR, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::SigR.expr(),
                1.expr(),
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        meta.lookup_any("rlp table SigS", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::SigS, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::SigS.expr(),
                1.expr(),
                meta.query_advice(tx_table.value, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup tx calldata bytes in RLP table.
        meta.lookup_any(
            "tx calldata::index in RLPTable::TxSign where len(calldata) > 0",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_usable, Rotation::cur()),
                    tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
                    not::expr(value_is_zero.is_equal_expression.clone()),
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
            },
        );
        meta.lookup_any(
            "tx calldata::index in RLPTable::TxHash where len(calldata) > 0",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_usable, Rotation::cur()),
                    tag.value_equals(TxFieldTag::CallData, Rotation::cur())(meta),
                    not::expr(value_is_zero.is_equal_expression.clone()),
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
            },
        );

        // lookup tx's DataPrefix if call_data_length == 0.
        meta.lookup_any(
            "tx DataPrefix in RLPTable::TxSign where len(calldata) == 0",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    tag.value_equals(TxFieldTag::CallDataLength, Rotation::cur())(meta),
                    value_is_zero.is_equal_expression.clone(),
                ]);
                vec![
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    RlpTxTag::DataPrefix.expr(),
                    1.expr(),   // tag_index == 1
                    128.expr(), // len == 0 => RLP == 128
                    RlpDataType::TxSign.expr(),
                ]
                .into_iter()
                .zip(rlp_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );
        meta.lookup_any(
            "tx DataPrefix in RLPTable::TxHash where len(calldata) == 0",
            |meta| {
                let enable = and::expr(vec![
                    meta.query_fixed(q_enable, Rotation::cur()),
                    tag.value_equals(TxFieldTag::CallDataLength, Rotation::cur())(meta),
                    value_is_zero.is_equal_expression.clone(),
                ]);
                vec![
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    RlpTxTag::DataPrefix.expr(),
                    1.expr(),   // tag_index == 1
                    128.expr(), // len == 0 => RLP == 128
                    RlpDataType::TxHash.expr(),
                ]
                .into_iter()
                .zip(rlp_table.table_exprs(meta).into_iter())
                .map(|(arg, table)| (enable.clone() * arg, table))
                .collect()
            },
        );

        // lookup tx table to ensure call data bytes are populated if call_data_length >
        // 0.
        meta.lookup_any("is_final call data byte should be present", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::CallDataLength, Rotation::cur())(meta),
                not::expr(value_is_zero.is_equal_expression.clone()),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                TxFieldTag::CallData.expr(),
                meta.query_advice(tx_table.value, Rotation::cur()) - 1.expr(), // index
                1.expr(),                                                      // is_final
            ]
            .into_iter()
            .zip(
                vec![
                    meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    meta.query_advice(tx_table.tag, Rotation::cur()),
                    meta.query_advice(tx_table.index, Rotation::cur()),
                    meta.query_advice(is_final, Rotation::cur()),
                ]
                .into_iter(),
            )
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup RLP table for length of RLP-encoding of unsigned tx.
        meta.lookup_any("Length of RLP-encoding for RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxSignHash, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::RlpLength.expr(),
                1.expr(), // tag_index
                meta.query_advice(tx_sign_data_len, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup RLP table for RLC of RLP-encoding of unsigned tx.
        meta.lookup_any("RLC of RLP-encoding for RLPTable::TxSign", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxSignHash, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Rlp.expr(),
                1.expr(), // tag_index
                meta.query_advice(tx_sign_data_rlc, Rotation::cur()),
                RlpDataType::TxSign.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup Keccak table for tx sign data hash, i.e. the sighash that has to be
        // signed.
        meta.lookup_any("Keccak table lookup for TxSignHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxSignHash, Rotation::cur())(meta),
            ]);
            vec![
                1.expr(),                                             // is_enabled
                meta.query_advice(tx_sign_data_rlc, Rotation::cur()), // input_rlc
                meta.query_advice(tx_sign_data_len, Rotation::cur()), // input_len
                meta.query_advice(tx_table.value, Rotation::cur()),   // output_rlc
            ]
            .into_iter()
            .zip(keccak_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup RLP table for length of RLP-encoding of signed tx.
        meta.lookup_any("Length of RLP-encoding for RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxHash, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::RlpLength.expr(),
                1.expr(), // tag_index
                meta.query_advice(tx_sign_data_len, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
        // lookup RLP table for RLC of RLP-encoding of signed tx.
        meta.lookup_any("RLC of RLP-encoding for RLPTable::TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxHash, Rotation::cur())(meta),
            ]);
            vec![
                meta.query_advice(tx_table.tx_id, Rotation::cur()),
                RlpTxTag::Rlp.expr(),
                1.expr(), // tag_index
                meta.query_advice(tx_sign_data_rlc, Rotation::cur()),
                RlpDataType::TxHash.expr(),
            ]
            .into_iter()
            .zip(rlp_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });

        // lookup Keccak table for tx hash
        meta.lookup_any("Keccak table lookup for TxHash", |meta| {
            let enable = and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_usable, Rotation::cur()),
                tag.value_equals(TxFieldTag::TxHash, Rotation::cur())(meta),
            ]);
            vec![
                1.expr(),                                             // is_enabled
                meta.query_advice(tx_sign_data_rlc, Rotation::cur()), // input_rlc
                meta.query_advice(tx_sign_data_len, Rotation::cur()), // input_len
                meta.query_advice(tx_table.value, Rotation::cur()),   // output_rlc
            ]
            .into_iter()
            .zip(keccak_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (enable.clone() * arg, table))
            .collect()
        });
    }
}

/// Tx Circuit for verifying transaction signatures
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
}

impl<F: Field> TxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(max_txs: usize, max_calldata: usize, chain_id: u64, txs: Vec<Transaction>) -> Self {
        TxCircuit::<F> {
            max_txs,
            max_calldata,
            sign_verify: SignVerifyChip::new(max_txs),
            txs,
            chain_id,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows(txs_len: usize, call_data_len: usize) -> usize {
        let tx_table_len = txs_len * TX_LEN + call_data_len;
        std::cmp::max(tx_table_len, SignVerifyChip::<F>::min_num_rows(txs_len))
    }

    fn assign_tx_table(
        &self,
        config: &TxCircuitConfig<F>,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        assigned_sig_verifs: Vec<AssignedSignatureVerify<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                // Empty entry
                config.assign_row(
                    &mut region,
                    offset,
                    true,
                    0,                                        // tx_id
                    !assigned_sig_verifs.is_empty() as usize, // tx_id_next
                    TxFieldTag::Null,
                    0,
                    Value::known(F::zero()),
                    false,
                    None,
                    None,
                )?;
                offset += 1;
                // Assign al Tx fields except for call data
                let tx_default = Transaction::default();
                for (i, assigned_sig_verif) in assigned_sig_verifs.iter().enumerate() {
                    let tx = if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &tx_default
                    };
                    let signed_tx: ethers_core::types::Transaction = tx.into();
                    let rlp_signed_tx_be_bytes = signed_tx.rlp().to_vec();

                    for (tag, value) in [
                        (TxFieldTag::Nonce, Value::known(F::from(tx.nonce.as_u64()))),
                        (
                            TxFieldTag::GasPrice,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.gas_price.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::Gas,
                            Value::known(F::from(tx.gas_limit.as_u64())),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            Value::known(tx.from.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            Value::known(
                                tx.to
                                    .unwrap_or_else(Address::zero)
                                    .to_scalar()
                                    .expect("tx.to too big"),
                            ),
                        ),
                        (
                            TxFieldTag::IsCreate,
                            Value::known(F::from(tx.to.is_none() as u64)),
                        ),
                        (
                            TxFieldTag::Value,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.value.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            Value::known(F::from(tx.call_data.0.len() as u64)),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            Value::known(F::from(
                                tx.call_data
                                    .0
                                    .iter()
                                    .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                            )),
                        ),
                        (TxFieldTag::SigV, Value::known(F::from(tx.v))),
                        (
                            TxFieldTag::SigR,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.r.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::SigS,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.s.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            assigned_sig_verif.msg_hash_rlc.value().copied(),
                        ),
                        (
                            TxFieldTag::TxHash,
                            challenges.evm_word().map(|challenge| {
                                tx.hash
                                    .to_fixed_bytes()
                                    .into_iter()
                                    .fold(F::zero(), |acc, byte| {
                                        acc * challenge + F::from(byte as u64)
                                    })
                            }),
                        ),
                    ] {
                        let tx_id_next = match tag {
                            TxFieldTag::TxHash => {
                                if i == assigned_sig_verifs.len() - 1 {
                                    self.txs
                                        .iter()
                                        .enumerate()
                                        .find(|(_i, tx)| tx.call_data.len() > 0)
                                        .map(|(i, _tx)| i + 1)
                                        .unwrap_or_else(|| 0)
                                } else {
                                    i + 2
                                }
                            }
                            _ => i + 1,
                        };
                        let assigned_cell = config.assign_row(
                            &mut region,
                            offset,
                            true,
                            i + 1,      // tx_id
                            tx_id_next, // tx_id_next
                            tag,
                            0,
                            value,
                            false,
                            None,
                            None,
                        )?;
                        // Ref. spec 0. Copy constraints using fixed offsets between the tx rows and
                        // the SignVerifyChip
                        match tag {
                            TxFieldTag::CallerAddress => region.constrain_equal(
                                assigned_cell.cell(),
                                assigned_sig_verif.address.cell(),
                            )?,
                            TxFieldTag::TxSignHash => {
                                region.constrain_equal(
                                    assigned_cell.cell(),
                                    assigned_sig_verif.msg_hash_rlc.cell(),
                                )?;
                                region.assign_advice(
                                    || "tx_sign_data_len",
                                    config.tx_sign_data_len,
                                    offset,
                                    || Value::known(F::from(assigned_sig_verif.msg_len as u64)),
                                )?;
                                region.assign_advice(
                                    || "tx_sign_data_rlc",
                                    config.tx_sign_data_rlc,
                                    offset,
                                    || assigned_sig_verif.msg_rlc,
                                )?;
                            }
                            TxFieldTag::TxHash => {
                                region.assign_advice(
                                    || "tx_hash_data_len",
                                    config.tx_sign_data_len,
                                    offset,
                                    || Value::known(F::from(rlp_signed_tx_be_bytes.len() as u64)),
                                )?;
                                region.assign_advice(
                                    || "tx_hash_data_rlc",
                                    config.tx_sign_data_rlc,
                                    offset,
                                    || {
                                        challenges.keccak_input().map(|challenge| {
                                            rlp_signed_tx_be_bytes
                                                .iter()
                                                .fold(F::zero(), |acc, byte| {
                                                    acc * challenge + F::from(*byte as u64)
                                                })
                                        })
                                    },
                                )?;
                            }
                            TxFieldTag::SigV => {
                                region.assign_advice(
                                    || "chain id",
                                    config.chain_id,
                                    offset,
                                    || Value::known(F::from(self.chain_id)),
                                )?;
                            }
                            _ => (),
                        }

                        offset += 1;
                    }
                }

                // Assign call data
                let mut calldata_count = 0;
                for (i, tx) in self.txs.iter().enumerate() {
                    let mut calldata_gas_cost = 0;
                    let calldata_length = tx.call_data.len();
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < self.max_calldata);
                        let (tx_id_next, is_final) = if index == calldata_length - 1 {
                            if i == self.txs.len() - 1 {
                                (0, true)
                            } else {
                                (
                                    self.txs
                                        .iter()
                                        .skip(i + 1)
                                        .enumerate()
                                        .find(|(_, tx)| tx.call_data.len() > 0)
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
                            offset,
                            true,
                            i + 1,      // tx_id
                            tx_id_next, // tx_id_next
                            TxFieldTag::CallData,
                            index,
                            Value::known(F::from(*byte as u64)),
                            is_final,
                            Some(calldata_length as u64),
                            Some(calldata_gas_cost),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..self.max_calldata {
                    config.assign_row(
                        &mut region,
                        offset,
                        false,
                        0, // tx_id
                        0, // tx_id_next
                        TxFieldTag::CallData,
                        0,
                        Value::known(F::zero()),
                        false,
                        None,
                        None,
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> SubCircuit<F> for TxCircuit<F> {
    type Config = TxCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.context.chain_id().as_u64(),
            block
                .context
                .first()
                .eth_block
                .transactions
                .iter()
                .map(|tx| tx.into())
                .collect(),
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> usize {
        Self::min_num_rows(
            block.txs.len(),
            block.txs.iter().map(|tx| tx.call_data.len()).sum(),
        )
    }

    /// Make the assignments to the TxCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        assert!(self.txs.len() <= self.max_txs);
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_data(self.chain_id).map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", e);
                    Error::Synthesis
                })
            })
            .try_collect()?;

        config.load_aux_tables(layouter)?;
        let assigned_sig_verifs =
            self.sign_verify
                .assign(&config.sign_verify, layouter, &sign_datas, challenges)?;
        self.assign_tx_table(config, challenges, layouter, assigned_sig_verifs)?;
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
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
        let challenges = challenges.values(&mut layouter);

        config.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_tx_circuit(&self.txs[..], self.chain_id).map_err(|e| {
                error!("keccak_inputs_tx_circuit error: {:?}", e);
                Error::Synthesis
            })?,
            &challenges,
        )?;
        config.rlp_table.dev_load(
            &mut layouter,
            signed_tx_from_geth_tx(self.txs.as_slice(), self.chain_id),
            &challenges,
        )?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod tx_circuit_tests {
    use super::*;
    use crate::util::log2_ceil;
    use eth_types::address;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use mock::AddrOrWallet;
    use pretty_assertions::assert_eq;

    const NUM_BLINDING_ROWS: usize = 64;

    fn run<F: Field>(
        txs: Vec<Transaction>,
        chain_id: u64,
        max_txs: usize,
        max_calldata: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        let k = log2_ceil(NUM_BLINDING_ROWS + TxCircuit::<Fr>::min_num_rows(max_txs, max_calldata));
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
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        assert_eq!(
            run::<Fr>(
                [
                    mock::CORRECT_MOCK_TXS[1].clone(),
                    mock::CORRECT_MOCK_TXS[3].clone()
                ]
                .iter()
                .map(|tx| Transaction::from(tx.clone()))
                .collect_vec(),
                mock::MOCK_CHAIN_ID.as_u64(),
                MAX_TXS,
                MAX_CALLDATA
            ),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_1tx_1max_tx() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
    }

    #[ignore]
    #[test]
    fn tx_circuit_1tx_2max_tx() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
    }

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
