use crate::{
    evm_circuit::table::{Lookup, MsgExpr, MsgF, RwValues},
    table::{
        BlockTable, BytecodeTable, CopyTable, DualByteTable, EccTable, ExpTable, FixedTable,
        KeccakTable, ModExpTable, PowOfRandTable, RwTable, SHA256Table, SigTable, TxTable,
    },
    util::{assign_global, query_expression},
};
use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_lookup::BusLookupChip,
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

/// EVMBusLookups makes all lookup tables available on the bus.
#[derive(Clone, Debug)]
pub struct EVMBusLookups<F> {
    bus_tables: [BusTable<F>; 14],
}

impl<F: Field> EVMBusLookups<F> {
    /// Connect all tables to the bus.
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        dual_byte_table: &DualByteTable,
        fixed_table: &FixedTable,
        rw_table: &RwTable,
        tx_table: &TxTable,
        bytecode_table: &BytecodeTable,
        block_table: &BlockTable,
        copy_table: &CopyTable,
        keccak_table: &KeccakTable,
        sha256_table: &SHA256Table,
        exp_table: &ExpTable,
        sig_table: &SigTable,
        modexp_table: &ModExpTable,
        ecc_table: &EccTable,
        pow_of_rand_table: &PowOfRandTable,
    ) -> Self {
        let tables: [&dyn QueryTable<F>; 14] = [
            dual_byte_table,
            fixed_table,
            rw_table,
            tx_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            sha256_table,
            exp_table,
            sig_table,
            modexp_table,
            ecc_table,
            pow_of_rand_table,
        ];
        Self {
            bus_tables: tables.map(|table| BusTable::configure(meta, bus_builder, table)),
        }
    }

    /// Assign the answers to all lookups on the bus.
    ///
    /// This must be called after all other circuits. The lookup queries and the content of the
    /// tables must have been assigned already.
    ///
    /// This function reads the content of the tables, it detects how many times each entry has been
    /// looked up, and it assigns the bus operations from the tables to balance these lookups.
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "EVM Bus Tables",
            |mut region| {
                for table in &self.bus_tables {
                    table.assign(&mut region, bus_assigner)?;
                }

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug)]
struct BusTable<F> {
    enabled: Expression<F>,
    message: MsgExpr<F>,
    chip: BusLookupChip<F>,
}

impl<F: Field> BusTable<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        table: &dyn QueryTable<F>,
    ) -> Self {
        let (enabled, message) =
            query_expression(meta, |meta| (table.enabled(meta), table.message(meta)));
        BusTable {
            enabled: enabled.clone(),
            message: message.clone(),
            chip: BusLookupChip::connect(meta, bus_builder, enabled, message),
        }
    }

    fn assign(
        &self,
        region: &mut Region<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
    ) -> Result<(), Error> {
        for offset in 0..bus_assigner.n_rows() {
            let enabled = eval(region, offset, self.enabled.clone());
            if enabled.is_zero_vartime() {
                continue;
            }

            let message = self
                .message
                .clone()
                .map_values(|expr| eval(region, offset, expr));

            self.chip
                .assign(region, bus_assigner, offset, message.clone())?;
        }
        Ok(())
    }
}

fn eval<F: Field>(region: &Region<F>, offset: usize, expr: Expression<F>) -> F {
    // TODO: error handling.
    let value = expr.evaluate(
        &|scalar| Value::known(scalar),
        &|_| unimplemented!("selector column"),
        &|fixed_query| {
            Value::known(
                region
                    .query_fixed(
                        fixed_query.column(),
                        (offset as i32 + fixed_query.rotation().0) as usize,
                    )
                    .unwrap(),
            )
        },
        &|advice_query| {
            Value::known(
                region
                    .query_advice(
                        advice_query.column(),
                        (offset as i32 + advice_query.rotation().0) as usize,
                    )
                    .unwrap(),
            )
        },
        &|_| unimplemented!("instance column"),
        &|_| unimplemented!("challenge"),
        &|a| -a,
        &|a, b| a + b,
        &|a, b| a * b,
        &|a, scalar| a * Value::known(scalar),
    );
    let mut f = F::zero();
    value.map(|v| f = v);
    f
}

trait QueryTable<F: Field> {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F>;
    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F>;
}

impl<F: Field> QueryTable<F> for DualByteTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::bytes(self.bytes.map(|col| meta.query_fixed(col, Rotation::cur())))
    }
}

impl<F: Field> QueryTable<F> for FixedTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        let mut query = |col| meta.query_fixed(col, Rotation::cur());

        MsgExpr::lookup(Lookup::Fixed {
            tag: query(self.tag),
            values: self.values.map(query),
        })
    }
}

impl<F: Field> QueryTable<F> for RwTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        let mut query = |col| meta.query_advice(col, Rotation::cur());

        MsgExpr::lookup(Lookup::Rw {
            counter: query(self.rw_counter),
            is_write: query(self.is_write),
            tag: query(self.tag),
            values: RwValues {
                id: query(self.id),
                address: query(self.address),
                field_tag: query(self.field_tag),
                storage_key: query(self.storage_key),
                value: query(self.value),
                value_prev: query(self.value_prev),
                aux1: query(self.aux1),
                aux2: query(self.aux2),
            },
        })
    }
}

impl<F: Field> QueryTable<F> for TxTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::Tx {
            id: meta.query_advice(self.tx_id, Rotation::cur()),
            field_tag: meta.query_fixed(self.tag, Rotation::cur()),
            index: meta.query_advice(self.index, Rotation::cur()),
            value: meta.query_advice(self.value, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for BytecodeTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        let mut query = |col| meta.query_advice(col, Rotation::cur());

        MsgExpr::lookup(Lookup::Bytecode {
            hash: query(self.code_hash),
            tag: query(self.tag),
            index: query(self.index),
            is_code: query(self.is_code),
            value: query(self.value),
            push_rlc: query(self.push_rlc),
        })
    }
}

impl<F: Field> QueryTable<F> for BlockTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::Block {
            field_tag: meta.query_fixed(self.tag, Rotation::cur()),
            number: meta.query_advice(self.index, Rotation::cur()),
            value: meta.query_advice(self.value, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for CopyTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::CopyTable {
            is_first: meta.query_advice(self.is_first, Rotation::cur()),
            src_id: meta.query_advice(self.id, Rotation::cur()),
            src_tag: self.tag.value(Rotation::cur())(meta),
            dst_id: meta.query_advice(self.id, Rotation::next()),
            dst_tag: self.tag.value(Rotation::next())(meta),
            src_addr: meta.query_advice(self.addr, Rotation::cur()),
            src_addr_end: meta.query_advice(self.src_addr_end, Rotation::cur()),
            dst_addr: meta.query_advice(self.addr, Rotation::next()),
            length: meta.query_advice(self.real_bytes_left, Rotation::cur()),
            rlc_acc: meta.query_advice(self.rlc_acc, Rotation::cur()),
            rw_counter: meta.query_advice(self.rw_counter, Rotation::cur()),
            rwc_inc: meta.query_advice(self.rwc_inc_left, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for KeccakTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        // This is a boolean because of constraint "boolean is_final".
        meta.query_fixed(self.q_enable, Rotation::cur())
            * meta.query_advice(self.is_final, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::KeccakTable {
            input_rlc: meta.query_advice(self.input_rlc, Rotation::cur()),
            input_len: meta.query_advice(self.input_len, Rotation::cur()),
            output_rlc: meta.query_advice(self.output_rlc, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for SHA256Table {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        // This is a boolean because of constraint "final_is_bool".
        meta.query_fixed(self.q_enable, Rotation::cur())
            * meta.query_advice(self.is_final, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::Sha256Table {
            input_rlc: meta.query_advice(self.input_rlc, Rotation::cur()),
            input_len: meta.query_advice(self.input_len, Rotation::cur()),
            output_rlc: meta.query_advice(self.output_rlc, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for ExpTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        // is_step implies q_enable by fixed assignment.
        meta.query_fixed(self.is_step, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::ExpTable {
            base_limbs: [
                meta.query_advice(self.base_limb, Rotation::cur()),
                meta.query_advice(self.base_limb, Rotation::next()),
                meta.query_advice(self.base_limb, Rotation(2)),
                meta.query_advice(self.base_limb, Rotation(3)),
            ],
            exponent_lo_hi: [
                meta.query_advice(self.exponent_lo_hi, Rotation::cur()),
                meta.query_advice(self.exponent_lo_hi, Rotation::next()),
            ],
            exponentiation_lo_hi: [
                meta.query_advice(self.exponentiation_lo_hi, Rotation::cur()),
                meta.query_advice(self.exponentiation_lo_hi, Rotation::next()),
            ],
        })
    }
}

impl<F: Field> QueryTable<F> for SigTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        let mut query = |col| meta.query_advice(col, Rotation::cur());

        MsgExpr::lookup(Lookup::SigTable {
            msg_hash_rlc: query(self.msg_hash_rlc),
            sig_v: query(self.sig_v),
            sig_r_rlc: query(self.sig_r_rlc),
            sig_s_rlc: query(self.sig_s_rlc),
            recovered_addr: query(self.recovered_addr),
            is_valid: query(self.is_valid),
        })
    }
}

impl<F: Field> QueryTable<F> for ModExpTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_head, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::ModExpTable {
            base_limbs: [
                meta.query_advice(self.base, Rotation::cur()),
                meta.query_advice(self.base, Rotation::next()),
                meta.query_advice(self.base, Rotation(2)),
            ],
            exp_limbs: [
                meta.query_advice(self.exp, Rotation::cur()),
                meta.query_advice(self.exp, Rotation::next()),
                meta.query_advice(self.exp, Rotation(2)),
            ],
            modulus_limbs: [
                meta.query_advice(self.modulus, Rotation::cur()),
                meta.query_advice(self.modulus, Rotation::next()),
                meta.query_advice(self.modulus, Rotation(2)),
            ],
            result_limbs: [
                meta.query_advice(self.result, Rotation::cur()),
                meta.query_advice(self.result, Rotation::next()),
                meta.query_advice(self.result, Rotation(2)),
            ],
        })
    }
}

impl<F: Field> QueryTable<F> for EccTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::EccTable {
            op_type: meta.query_fixed(self.op_type, Rotation::cur()),
            is_valid: meta.query_advice(self.is_valid, Rotation::cur()),
            arg1_rlc: meta.query_advice(self.arg1_rlc, Rotation::cur()),
            arg2_rlc: meta.query_advice(self.arg2_rlc, Rotation::cur()),
            arg3_rlc: meta.query_advice(self.arg3_rlc, Rotation::cur()),
            arg4_rlc: meta.query_advice(self.arg4_rlc, Rotation::cur()),
            input_rlc: meta.query_advice(self.input_rlc, Rotation::cur()),
            output1_rlc: meta.query_advice(self.output1_rlc, Rotation::cur()),
            output2_rlc: meta.query_advice(self.output2_rlc, Rotation::cur()),
        })
    }
}

impl<F: Field> QueryTable<F> for PowOfRandTable {
    fn enabled(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.q_enable, Rotation::cur())
    }

    fn message(&self, meta: &mut VirtualCells<F>) -> MsgExpr<F> {
        MsgExpr::lookup(Lookup::PowOfRandTable {
            exponent: meta.query_fixed(self.exponent, Rotation::cur()),
            pow_of_rand: meta.query_advice(self.pow_of_rand, Rotation::cur()),
        })
    }
}
