use eth_types::Field;
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_lookup::BusLookupChip,
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
    poly::Rotation,
};
use itertools::Itertools;

use crate::{
    evm_circuit::table::{Lookup, MsgExpr, MsgF, RwValues},
    table::{RwTable, TxTable},
    util::{assign_global, query_expression},
};

#[derive(Clone, Debug)]
pub struct EVMBusLookups<F> {
    rw_lookup: BusLookupChip<F>,
    tx_lookup: BusLookupChip<F>,
}

impl<F: Field> EVMBusLookups<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        rw_table: &RwTable,
        tx_table: &TxTable,
    ) -> Self {
        let rw_lookup = {
            let rw_enabled = query_expression(meta, |meta| {
                meta.query_fixed(rw_table.q_enable, Rotation::cur())
            });

            let message = query_expression(meta, |meta| {
                let mut query = |col| meta.query_advice(col, Rotation::cur());

                MsgExpr::lookup(Lookup::Rw {
                    counter: query(rw_table.rw_counter),
                    is_write: query(rw_table.is_write),
                    tag: query(rw_table.tag),
                    values: RwValues {
                        id: query(rw_table.id),
                        address: query(rw_table.address),
                        field_tag: query(rw_table.field_tag),
                        storage_key: query(rw_table.storage_key),
                        value: query(rw_table.value),
                        value_prev: query(rw_table.value_prev),
                        aux1: query(rw_table.aux1),
                        aux2: query(rw_table.aux2),
                    },
                })
            });
            BusLookupChip::connect(meta, bus_builder, rw_enabled, message)
        };

        let tx_lookup = {
            let tx_enabled = query_expression(meta, |meta| {
                meta.query_fixed(tx_table.q_enable, Rotation::cur())
            });
            let message = query_expression(meta, |meta| {
                MsgExpr::lookup(Lookup::Tx {
                    id: meta.query_advice(tx_table.tx_id, Rotation::cur()),
                    field_tag: meta.query_fixed(tx_table.tag, Rotation::cur()),
                    index: meta.query_advice(tx_table.index, Rotation::cur()),
                    value: meta.query_advice(tx_table.value, Rotation::cur()),
                })
            });
            BusLookupChip::connect(meta, bus_builder, tx_enabled, message)
        };

        Self {
            rw_lookup,
            tx_lookup,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
        rw_messages: Vec<(usize, MsgF<F>)>,
        tx_messages: Vec<(usize, MsgF<F>)>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "EVM Bus Tables",
            |mut region| {
                // RW table.
                for (offset, message) in rw_messages.iter().unique_by(|(o, _)| *o) {
                    self.rw_lookup
                        .assign(&mut region, bus_assigner, *offset, message.clone())?;
                }

                // TX table.
                for (offset, message) in tx_messages.iter().unique_by(|(o, _)| *o) {
                    self.tx_lookup
                        .assign(&mut region, bus_assigner, *offset, message.clone())?;
                }

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )
    }
}
