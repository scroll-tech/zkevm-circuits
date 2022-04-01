use super::{
    lookups::Queries as LookupsQueries, multiple_precision_integer::Queries as MpiQueries,
    random_linear_combination::Queries as RlcQueries, N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_RW_COUNTER,
};
use crate::evm_circuit::{param::N_BYTES_WORD, util::constraint_builder::BaseConstraintBuilder};
use eth_types::{Address, Field};
use halo2_proofs::plonk::Expression;

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub selector: Expression<F>,
    pub rw_counter: MpiQueries<F, u32, N_LIMBS_RW_COUNTER>,
    pub is_write: Expression<F>,
    pub tag: Expression<F>,
    pub id: Expression<F>,
    pub address: MpiQueries<F, Address, N_LIMBS_ACCOUNT_ADDRESS>,
    pub field_tag: Expression<F>,
    pub storage_key: RlcQueries<F, N_BYTES_WORD>,
    pub value: Expression<F>,
    pub lookups: LookupsQueries<F>,
    pub power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    // lexicographic_ordering expressions, etc.
}

pub struct ConstraintBuilder<F: Field> {
    pub base_constraint_builder: BaseConstraintBuilder<F>,
    pub lookups: Vec<(&'static str, (Expression<F>, Expression<F>))>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            base_constraint_builder: BaseConstraintBuilder::new(20), // TODO: pick this reasonably
            lookups: vec![],
        }
    }
    pub fn build(&mut self, _q: &Queries<F>) {}

    pub fn gate(
        &self,
        condition: Expression<F>,
    ) -> Vec<(&'static str, halo2_proofs::plonk::Expression<F>)> {
        self.base_constraint_builder.gate(condition)
    }
}

// pub fn matches_constraints(tag: RwTableTag) -> Expression<F> {
//     generate_lagrange_base_polynomial(
//         self.tag.cur(),
//         tag as usize,
//         RwTableTag::iter().map(|x| x as usize),
//     )
// }
//
// pub fn add_general_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     cb.require_in_set(
//         "tag in RwTableTag range",
//         self.tag.cur.clone(),
//         RwTableTag::iter().map(|x| x.expr()).collect(),
//     );
// }
//
// fn add_start_constraints<F: Field>(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     cb.require_zero("rw_counter starts at 0", self.rw_counter.value.cur());
//     cb.require_zero("tag is 0 at start", self.tag.cur())
// }
//
// fn add_memory_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     cb.require_zero("field_tag is 0 for MemoryOp", self.field_tag.cur());
//     cb.require_zero(
//         "storage_key is 0 for MemoryOp",
//         self.storage_key.encoded.cur(),
//     );
//     // # 1. First access for a set of all keys
//     //  #
//     //  # When the set of all keys changes (first access of an address in a
// call)     //  # - If READ, value must be 0
//     for i in 2..N_LIMBS_ACCOUNT_ADDRESS {
//         cb.require_zero(
//             "memory address is at most 2 limbs",
//             self.address.limbs[i].cur(),
//         )
//     }
//     // lookup self.value.cur is in u8 range.
// }
//
// fn add_stack_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     cb.require_zero("field_tag is 0 for StackOp",
// self.field_tag.cur.clone());     cb.require_zero(
//         "storage_key is 0 for StackOp",
//         self.storage_key.encoded.cur.clone(),
//     );
//     // # 1. First access for a set of all keys
//     //  #
//     //  # When the set of all keys changes (first access of an address in a
// call)     //  # - If READ, value must be 0
//     for i in 2..N_LIMBS_ACCOUNT_ADDRESS {
//         cb.require_zero(
//             "memory address is at most 2 limbs",
//             self.address.limbs[i].cur.clone(),
//         )
//     }
//     // lookup self.address.cur is in u10 range.
//
//     cb.require_boolean(
//         "stack pointer change is 0 or 1",
//         self.address.value.change(),
//     );
// }
//
// fn add_account_storage_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         // Moved tx_id from aux to id column, so this no longer is true.
//         // ("0 id for Storage ", self.id.cur()),
//         ("0 field_tag for Storage", self.field_tag.cur()),
//     ] {
//         cb.require_zero(name, expression);
//     }
// }
//
// fn add_call_context_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         ("0 address for Account ", self.address.value.cur()),
//         ("0 storage_key for Account", self.storage_key.encoded.cur()),
//     ] {
//         cb.require_zero(name, expression);
//     }
// }
//
// fn add_account_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         ("0 id for Account ", self.id.cur()),
//         ("0 storage_key for Account", self.storage_key.encoded.cur()),
//     ] {
//         cb.require_zero(name, expression);
//     }
// }
//
// fn add_tx_refund_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         ("0 address for TxRefund ", self.address.value.cur()),
//         ("0 field_tag for TxRefund", self.field_tag.cur()),
//         ("0 storage_key for TxRefund", self.storage_key.encoded.cur()),
//     ] {
//         cb.require_zero(name, expression);
//     }
//     // TODO: add more constraints in state spec.
// }
//
// fn add_tx_access_list_account_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         ("0 field_tag for TxAccessListAccount", self.field_tag.cur()),
//         (
//             "0 storage_key for TxAccessListAccount",
//             self.storage_key.encoded.cur(),
//         ),
//     ] {
//         cb.require_zero(name, expression);
//     }
//     // TODO: add more constraints in state spec.
// }
//
// fn add_tx_access_list_account_storage_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused key is 0
//     cb.require_zero(
//         "0 field_tag for TxAccessListAccountStorage",
//         self.storage_key.encoded.cur(),
//     );
//     // TODO: add more constraints in state spec.
// }
//
// fn add_account_destructed_constraints(
//     cb: &mut BaseConstraintBuilder<F>,
//     lookups: &mut Vec<Lookup<F>>,
//     &e: StateExpressions,
// ) {
//     // Unused keys are 0
//     for (name, expression) in [
//         ("0 id for AccountDestructed", self.id.cur()),
//         ("0 address for AccountDestructed", self.address.value.cur()),
//         (
//             "0 storage_key for AccountDestructed",
//             self.storage_key.encoded.cur(),
//         ),
//     ] {
//         cb.require_zero(name, expression);
//     }
//     // TODO: add more constraints in state spec.
// }
