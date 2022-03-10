use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::evm_circuit::util::math_gadget::generate_lagrange_base_polynomial;
use crate::{
    evm_circuit::{
        // step::{Preset, Step},
        table::{
            AccountFieldTag, CallContextFieldTag, FixedTableTag, Lookup, RwTableTag,
            TxContextFieldTag,
        },
        util::{Cell, RandomLinearCombination, Word},
    },
    util::Expr,
};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
use std::convert::TryInto;
use strum::IntoEnumIterator;

// TODO(mason) set these correctly
const MAX_DEGREE: usize = 15;
const LOOKUP_DEGREE: usize = 2;
const WIDTH: usize = 10;

pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    To(T),
}

#[derive(Clone, Debug, Default)]
struct RowUsage {
    next_idx: usize,
    is_byte_lookup_enabled: bool,
}

#[derive(Clone, Debug)]
struct Row<F> {
    pub(crate) qs_byte_lookup: Cell<F>,
    pub(crate) cells: [Cell<F>; WIDTH],
}

// rename this to RWTableRow?
#[derive(Clone, Debug)]
pub(crate) struct Step<F> {
    rows: Vec<Row<F>>,
}

impl<F> Default for Transition<F> {
    fn default() -> Self {
        Self::Same
    }
}

// Maybe this should be QueryBuilder?
pub(crate) struct ConstraintBuilder<F: FieldExt> {
    cb: BaseConstraintBuilder<F>,
    rw_counter: Column<Advice>,
    s_enable: Column<Fixed>,
    is_write: Column<Advice>,
    keys: [Column<Advice>; 5],
    keys_diff_inv: [Column<Advice>; 5],
    key2_limbs: [Column<Advice>; 8],
    key4_bytes: [Column<Advice>; 32],
    value: Column<Advice>,
    auxs: [Column<Advice>; 2],
    rw_counter_table: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    memory_value_table: Column<Fixed>,
}

impl<'a, F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn new(meta: &'a mut ConstraintSystem<F>, keys: [Column<Advice>; 5]) -> Self {
        Self {
            cb: BaseConstraintBuilder::new(MAX_DEGREE),
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            keys,
            keys_diff_inv: [(); 5].map(|_| meta.advice_column()),
            key2_limbs: [(); 8].map(|_| meta.advice_column()),
            key4_bytes: [(); 32].map(|_| meta.advice_column()),
            auxs: [(); 2].map(|_| meta.advice_column()),
            s_enable: meta.fixed_column(),
            value: meta.advice_column(),
            rw_counter_table: meta.fixed_column(),
            memory_address_table_zero: meta.fixed_column(),
            stack_address_table_zero: meta.fixed_column(),
            memory_value_table: meta.fixed_column(),
        }
    }

    fn tag(&self) -> Column<Advice> {
        self.keys[0]
    }
    fn account_addr(&self) -> Column<Advice> {
        self.keys[2]
    }
    fn address(&self) -> Column<Advice> {
        self.keys[3]
    }
    fn storage_key(&self) -> Column<Advice> {
        self.keys[4]
    }

    pub(super) fn q_tag_is(&self, meta: &mut VirtualCells<F>, tag: RwTableTag) -> Expression<F> {
        generate_lagrange_base_polynomial(
            meta.query_advice(self.tag(), Rotation::cur()),
            tag as usize,
            RwTableTag::iter().map(|x| x as usize),
        )
    }
    // let q_stack = |meta: &mut VirtualCells<F>| q_tag_is(meta, STACK_TAG);
    // let q_storage = |meta: &mut VirtualCells<F>| q_tag_is(meta, STORAGE_TAG);

    // #[allow(clippy::type_complexity)]
    // pub(crate) fn build(self) -> Vec<(&'static str, Expression<F>)> {
    //     let mut constraints = self.cb.constraints;
    //     for (row, usage) in
    // self.curr.rows.iter().zip(self.curr_row_usages.iter()) {         if
    // usage.is_byte_lookup_enabled {             constraints.push(("Enable byte
    // lookup", row.qs_byte_lookup.expr() - 1.expr()));         }
    //     }
    //     constraints
    // }
    //
    // pub(crate) fn query_bool(&mut self) -> Cell<F> {
    //     let [cell] = self.query_cells::<1>(false);
    //     self.require_boolean("Constrain cell to be a bool", cell.expr());
    //     cell
    // }
    //
    // pub(crate) fn query_byte(&mut self) -> Cell<F> {
    //     let [cell] = self.query_cells::<1>(true);
    //     cell
    // }
    //
    // pub(crate) fn query_cell(&mut self) -> Cell<F> {
    //     let [cell] = self.query_cells::<1>(false);
    //     cell
    // }
    //
    // pub(crate) fn query_word(&mut self) -> Word<F> {
    //     self.query_rlc()
    // }
    //
    // pub(crate) fn query_rlc<const N: usize>(&mut self) ->
    // RandomLinearCombination<F, N> {     RandomLinearCombination::<F,
    // N>::new(self.query_bytes(), self.power_of_randomness) }
    //
    // pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
    //     self.query_cells::<N>(true)
    // }
    //
    // fn query_cells<const N: usize>(&mut self, is_byte: bool) -> [Cell<F>; N] {
    //     let mut cells = Vec::with_capacity(N);
    //     let rows = &self.curr.rows;
    //     let row_usages = &mut self.curr_row_usages;
    //
    //     // Iterate rows to find cell that matches the is_byte requirement.
    //     for (row, usage) in rows.iter().zip(row_usages.iter_mut()) {
    //         // If this row doesn't match the is_byte requirement and is already
    //         // used, skip this row.
    //         if usage.is_byte_lookup_enabled != is_byte && usage.next_idx > 0 {
    //             continue;
    //         }
    //
    //         // Enable the byte range lookup for this row if queried cells are
    //         // required to be bytes.
    //         if usage.next_idx == 0 && is_byte {
    //             usage.is_byte_lookup_enabled = true;
    //         }
    //
    //         let n = row.cells.len().min(usage.next_idx + N - cells.len());
    //         cells.extend(row.cells[usage.next_idx..n].iter().cloned());
    //         usage.next_idx = n;
    //
    //         if cells.len() == N {
    //             return cells.try_into().unwrap();
    //         }
    //     }
    //
    //     unreachable!("not enough cells for query")
    // }
    //
    // // Common
    //
    // pub(crate) fn require_zero(&mut self, name: &'static str, constraint:
    // Expression<F>) {     self.cb.require_zero(name, constraint);
    // }
    //
    // pub(crate) fn require_equal(
    //     &mut self,
    //     name: &'static str,
    //     lhs: Expression<F>,
    //     rhs: Expression<F>,
    // ) {
    //     self.cb.require_equal(name, lhs, rhs);
    // }
    //
    // pub(crate) fn require_boolean(&mut self, name: &'static str, value:
    // Expression<F>) {     self.cb.require_boolean(name, value);
    // }
    //
    // pub(crate) fn require_in_set(
    //     &mut self,
    //     name: &'static str,
    //     value: Expression<F>,
    //     set: Vec<Expression<F>>,
    // ) {
    //     self.cb.require_in_set(name, value, set);
    // }
}
