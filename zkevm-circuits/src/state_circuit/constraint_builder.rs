use super::{
    lookups::Queries as LookupsQueries, multiple_precision_integer::Queries as MpiQueries,
    random_linear_combination::Queries as RlcQueries, N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_ID,
    N_LIMBS_RW_COUNTER,
};
use crate::util::Expr;
use crate::{
    evm_circuit::{param::N_BYTES_WORD, util::not},
    table::{AccountFieldTag, RwTableTag},
};
use eth_types::Field;
use gadgets::binary_number::BinaryNumberConfig;
use halo2_proofs::plonk::Expression;
use strum::IntoEnumIterator;

#[derive(Clone)]
pub struct RwTableQueries<F: Field> {
    pub rw_counter: Expression<F>,
    pub prev_rw_counter: Expression<F>,
    pub is_write: Expression<F>,
    pub tag: Expression<F>,
    pub id: Expression<F>,
    pub prev_id: Expression<F>,
    pub address: Expression<F>,
    pub prev_address: Expression<F>,
    pub field_tag: Expression<F>,
    pub storage_key: Expression<F>,
    pub value: Expression<F>,
    pub value_prev: Expression<F>,
    // TODO: aux1 and aux2
}

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub selector: Expression<F>,
    pub rw_table: RwTableQueries<F>,
    pub lexicographic_ordering_selector: Expression<F>,
    pub rw_counter: MpiQueries<F, N_LIMBS_RW_COUNTER>,
    pub tag_bits: [Expression<F>; 4],
    pub id: MpiQueries<F, N_LIMBS_ID>,
    pub is_tag_and_id_unchanged: Expression<F>,
    pub address: MpiQueries<F, N_LIMBS_ACCOUNT_ADDRESS>,
    pub storage_key: RlcQueries<F, N_BYTES_WORD>,
    pub initial_value: Expression<F>,
    pub value_prev_col: Expression<F>,
    pub initial_value_prev: Expression<F>,
    pub lookups: LookupsQueries<F>,
    pub power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    pub first_access: Expression<F>,
    pub not_first_access: Expression<F>,
}

type Constraint<F> = (&'static str, Expression<F>);
type Lookup<F> = (&'static str, (Expression<F>, Expression<F>));

pub struct ConstraintBuilder<F: Field> {
    pub constraints: Vec<Constraint<F>>,
    lookups: Vec<Lookup<F>>,
    condition: Expression<F>,
}

impl<F: Field> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
            condition: 1.expr(),
        }
    }

    pub fn gate(&self, condition: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .iter()
            .cloned()
            .map(|(name, expression)| (name, condition.clone() * expression))
            .collect()
    }

    pub fn lookups(&self) -> Vec<Lookup<F>> {
        self.lookups.clone()
    }

    pub fn build(&mut self, q: &Queries<F>) {
        self.build_general_constraints(q);
        self.condition(q.tag_matches(RwTableTag::Start), |cb| {
            cb.build_start_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::Memory), |cb| {
            cb.build_memory_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::Stack), |cb| {
            cb.build_stack_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::AccountStorage), |cb| {
            cb.build_account_storage_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::TxAccessListAccount), |cb| {
            cb.build_tx_access_list_account_constraints(q)
        });
        self.condition(
            q.tag_matches(RwTableTag::TxAccessListAccountStorage),
            |cb| cb.build_tx_access_list_account_storage_constraints(q),
        );
        self.condition(q.tag_matches(RwTableTag::TxRefund), |cb| {
            cb.build_tx_refund_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::Account), |cb| {
            cb.build_account_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::AccountDestructed), |cb| {
            cb.build_account_destructed_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::CallContext), |cb| {
            cb.build_call_context_constraints(q)
        });
        self.condition(q.tag_matches(RwTableTag::TxLog), |cb| {
            cb.build_tx_log_constraints(q)
        });
    }

    fn build_general_constraints(&mut self, q: &Queries<F>) {
        // tag value in RwTableTag range is enforced in BinaryNumberChip
        self.require_boolean("is_write is boolean", q.is_write());

        // When at least one of the keys (tag, id, address, field_tag, or storage_key)
        // in the current row differs from the previous row.
        self.condition(q.first_access(), |cb| {
            cb.require_zero(
                "first access reads don't change value",
                q.is_read() * (q.rw_table.value.clone() - q.initial_value()),
            );
        });

        // When all the keys in the current row and previous row are equal.
        self.condition(q.not_first_access.clone(), |cb| {
            cb.require_zero(
                "non-first access reads don't change value",
                q.is_read() * (q.rw_table.value.clone() - q.rw_table.value_prev.clone()),
            );
            cb.require_zero(
                "initial value doesn't change in an access group",
                q.initial_value.clone() - q.initial_value_prev(),
            );
        });

        // Only reversible rws have `value_prev`.
        // There is no need to constain MemoryRw and StackRw since the 'read
        // consistency' part of the constaints are enough for them to behave
        // correctly.
        // For these 6 Rws whose `value_prev` need to be
        // constrained:
        // (1) `AccountStorage` and `Account`: they are related to storage
        // and they should be connected to MPT cricuit later to check the
        // `value_prev`.
        // (2)`TxAccessListAccount` and
        // `TxAccessListAccountStorage`:  Default values of them should be
        // `false` indicating "not accessed yet".
        // (3) `AccountDestructed`: Since we probably
        // will not support this feature, it is skipped now.
        // (4) `TxRefund`: Default values should be '0'. BTW it may be moved out of rw table in the future. See https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/395
        // for more details.

        // FIXME: For RwTableTag::Account, this is a dummy placeholder to pass
        // constraints It should be aux2/committed_value.
        // We should fix this after the committed_value field of Rw::Account in
        // both bus-mapping and evm-circuits are implemented.
        /*
        self.condition(q.first_access(), |cb| {
            cb.require_equal(
                "prev value when first access",
                q.value_prev_col.clone(),
                (q.tag_matches(RwTableTag::TxAccessListAccount)
                    + q.tag_matches(RwTableTag::TxAccessListAccountStorage)
                    + q.tag_matches(RwTableTag::AccountDestructed)
                    + q.tag_matches(RwTableTag::TxRefund))
                    * 0u64.expr()
                    + q.tag_matches(RwTableTag::Account)
                          *  q.value_prev_col.clone()
                    + q.tag_matches(RwTableTag::AccountStorage)
                       *     q.aux2.clone(), // committed value
            );
        });
        self.condition(q.not_first_access(), |cb| {
            cb.require_equal(
                "prev value when not first acccess",
                q.value_prev_col.clone(),
                (q.tag_matches(RwTableTag::TxAccessListAccount)
                    + q.tag_matches(RwTableTag::TxAccessListAccountStorage)
                    + q.tag_matches(RwTableTag::AccountDestructed)
                    + q.tag_matches(RwTableTag::TxRefund))
                    * q.value_prev.clone()
                    + q.tag_matches(RwTableTag::Account) * q.value_prev_col.clone()
                    + q.tag_matches(RwTableTag::AccountStorage) * q.value_prev.clone(),
            );
        });
        */
        /*
        self.require_equal("rw table rlc", q.rw_rlc.clone(), {
            rlc::expr(
                &[
                    q.rw_counter.value.clone(),
                    q.is_write.clone(),
                    q.tag.clone(),
                    q.id.value.clone(),
                    q.address.value.clone(),
                    q.field_tag.clone(),
                    q.storage_key.encoded.clone(),
                    q.value.clone(),
                    q.value_prev_col.clone(),
                    0u64.expr(), //q.aux1,
                    q.aux2.clone(),
                ],
                &q.power_of_randomness,
            )
        })
        */
    }

    fn build_start_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for Start", q.field_tag());
        self.require_zero("address is 0 for Start", q.rw_table.address.clone());
        self.require_zero("id is 0 for Start", q.id());
        self.require_zero("storage_key is 0 for Start", q.rw_table.storage_key.clone());
        self.require_zero(
            "rw_counter increases by 1 for every non-first row",
            q.lexicographic_ordering_selector.clone() * (q.rw_counter_change() - 1.expr()),
        );
        self.require_zero("Start value is 0", q.value());
        self.require_zero("Start initial_value is 0", q.initial_value());
    }

    fn build_memory_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for Memory", q.field_tag());
        self.require_zero(
            "storage_key is 0 for Memory",
            q.rw_table.storage_key.clone(),
        );
        // could do this more efficiently by just asserting address = limb0 + 2^16 *
        // limb1?
        for limb in &q.address.limbs[2..] {
            self.require_zero("memory address fits into 2 limbs", limb.clone());
        }
        self.add_lookup(
            "memory value is a byte",
            (q.rw_table.value.clone(), q.lookups.u8.clone()),
        );
        self.require_zero("initial Memory value is 0", q.initial_value());
    }

    fn build_stack_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for Stack", q.field_tag());
        self.require_zero("storage_key is 0 for Stack", q.rw_table.storage_key.clone());
        self.require_zero(
            "first access to new stack address is a write",
            q.first_access() * (1.expr() - q.is_write()),
        );
        self.add_lookup(
            "stack address fits into 10 bits",
            (q.rw_table.address.clone(), q.lookups.u10.clone()),
        );
        self.condition(q.is_tag_and_id_unchanged.clone(), |cb| {
            cb.require_boolean(
                "if previous row is also Stack with unchanged call id, address change is 0 or 1",
                q.address_change(),
            )
        });

        self.require_zero("initial Stack value is 0", q.initial_value.clone());
    }

    fn build_account_storage_constraints(&mut self, q: &Queries<F>) {
        // TODO: cold VS warm
        self.require_zero("field_tag is 0 for AccountStorage", q.field_tag());

        // TODO: add mpt lookup for committed value and final value in an access
        // group.
    }
    fn build_tx_access_list_account_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for TxAccessListAccount", q.field_tag());
        self.require_zero(
            "storage_key is 0 for TxAccessListAccount",
            q.rw_table.storage_key.clone(),
        );
        self.require_boolean("TxAccessListAccount value is boolean", q.value());
        self.require_zero(
            "initial TxAccessListAccount value is false",
            q.initial_value(),
        );
    }

    fn build_tx_access_list_account_storage_constraints(&mut self, q: &Queries<F>) {
        self.require_zero(
            "field_tag is 0 for TxAccessListAccountStorage",
            q.field_tag(),
        );
        self.require_boolean("TxAccessListAccountStorage value is boolean", q.value());
        self.require_zero(
            "initial TxAccessListAccountStorage value is false",
            q.initial_value(),
        );
    }

    fn build_tx_refund_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("address is 0 for TxRefund", q.rw_table.address.clone());
        self.require_zero("field_tag is 0 for TxRefund", q.field_tag());
        self.require_zero(
            "storage_key is 0 for TxRefund",
            q.rw_table.storage_key.clone(),
        );
        self.require_zero("initial TxRefund value is 0", q.initial_value());
    }

    fn build_account_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("id is 0 for Account", q.id());
        self.require_zero(
            "storage_key is 0 for Account",
            q.rw_table.storage_key.clone(),
        );
        self.require_in_set(
            "field_tag in AccountFieldTag range",
            q.field_tag(),
            set::<F, AccountFieldTag>(),
        );

        // TODO: add mpt lookup for committed value and final value in an access
        // group.
    }

    fn build_account_destructed_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("id is 0 for AccountDestructed", q.id());
        self.require_zero("field_tag is 0 for AccountDestructed", q.field_tag());
        self.require_zero(
            "storage_key is 0 for AccountDestructed",
            q.rw_table.storage_key.clone(),
        );
        // TODO: Missing constraints
    }

    fn build_call_context_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("address is 0 for CallContext", q.rw_table.address.clone());
        self.require_zero(
            "storage_key is 0 for CallContext",
            q.rw_table.storage_key.clone(),
        );
        self.add_lookup(
            "field_tag in CallContextFieldTag range",
            (q.field_tag(), q.lookups.call_context_field_tag.clone()),
        );
        // TODO: explain why call context doesn't need an initial value.
    }

    fn build_tx_log_constraints(&mut self, q: &Queries<F>) {
        self.require_equal(
            "is_write is always true for TxLog",
            q.rw_table.is_write.clone(),
            1.expr(),
        );
        self.require_zero("initial TxLog value is 0", q.initial_value());

        // Comment out the following field_tag-related constraints as it is
        // duplicated between state circuit and evm circuit. For more information, please refer to https://github.com/privacy-scaling-explorations/zkevm-specs/issues/221
        // cb.require_zero(
        //     "reset log_id to one when tx_id increases",
        //     q.tx_log_id() - 1.expr(),
        // );

        // constrain first field_tag is Address when tx id increases
        // cb.require_equal(
        //     "first field_tag is Address when tx changes",
        //     q.field_tag_matches(TxLogFieldTag::Address),
        //     1.expr(),
        // );

        // increase log_id when tag changes to Address within same tx
        // self.condition(
        //     q.is_id_unchanged.clone()
        //         * q.is_tag_unchanged.clone()
        //         * q.field_tag_matches(TxLogFieldTag::Address),
        //     |cb| {
        //         cb.require_equal(
        //             "log_id = pre_log_id + 1",
        //             q.tx_log_id(),
        //             q.tx_log_id_prev() + 1.expr(),
        //         )
        //     },
        // );

        // within same tx, log_id will not change if field_tag != Address
        // self.condition(
        //     q.is_id_unchanged.clone()
        //         * q.is_tag_unchanged.clone()
        //         * (1.expr() - q.field_tag_matches(TxLogFieldTag::Address)),
        //     |cb| {
        //         cb.require_equal(
        //             "log_id will not change if field_tag != Address within
        // tx",             q.tx_log_id(),
        //             q.tx_log_id_prev(),
        //         )
        //     },
        // );

        // constrain index is increasing by 1 when field_tag stay same
        // self.condition(
        //     q.is_tag_unchanged.clone() * q.is_field_tag_unchanged.clone(),
        //     |cb| {
        //         cb.require_equal(
        //             "index = pre_index + 1",
        //             q.tx_log_index(),
        //             q.tx_log_index_prev() + 1.expr(),
        //         )
        //     },
        // );

        // self.condition(q.field_tag_matches(TxLogFieldTag::Address), |cb| {
        //     cb.require_zero("index is zero for address ", q.tx_log_index())
        // });

        // if tag Topic appear, topic_index in range [0,4)
        // self.condition(q.field_tag_matches(TxLogFieldTag::Topic), |cb| {
        //     let topic_index = q.tx_log_index();
        //     cb.require_zero(
        //         "topic_index in range [0,4) ",
        //         topic_index.clone()
        //             * (1.expr() - topic_index.clone())
        //             * (2.expr() - topic_index.clone())
        //             * (3.expr() - topic_index),
        //     )
        // });
    }

    fn require_zero(&mut self, name: &'static str, e: Expression<F>) {
        self.constraints.push((name, self.condition.clone() * e));
    }

    fn require_equal(&mut self, name: &'static str, left: Expression<F>, right: Expression<F>) {
        self.require_zero(name, left - right)
    }

    fn require_boolean(&mut self, name: &'static str, e: Expression<F>) {
        self.require_zero(name, e.clone() * (1.expr() - e))
    }

    fn require_in_set(&mut self, name: &'static str, item: Expression<F>, set: Vec<Expression<F>>) {
        self.require_zero(
            name,
            set.iter().fold(1.expr(), |acc, element| {
                acc * (item.clone() - element.clone())
            }),
        );
    }

    fn add_lookup(&mut self, name: &'static str, lookup: (Expression<F>, Expression<F>)) {
        let mut lookup = lookup;
        lookup.0 = lookup.0 * self.condition.clone();
        self.lookups.push((name, lookup));
    }

    fn condition(&mut self, condition: Expression<F>, build: impl FnOnce(&mut Self)) {
        let original_condition = self.condition.clone();
        self.condition = self.condition.clone() * condition;
        build(self);
        self.condition = original_condition;
    }
}

impl<F: Field> Queries<F> {
    fn selector(&self) -> Expression<F> {
        self.selector.clone()
    }

    fn is_write(&self) -> Expression<F> {
        self.rw_table.is_write.clone()
    }

    fn is_read(&self) -> Expression<F> {
        not::expr(self.is_write())
    }

    fn tag(&self) -> Expression<F> {
        self.rw_table.tag.clone()
    }

    fn id(&self) -> Expression<F> {
        self.rw_table.id.clone()
    }

    fn id_change(&self) -> Expression<F> {
        self.id() - self.rw_table.prev_id.clone()
    }

    fn field_tag(&self) -> Expression<F> {
        self.rw_table.field_tag.clone()
    }

    fn value(&self) -> Expression<F> {
        self.rw_table.value.clone()
    }

    fn value_prev(&self) -> Expression<F> {
        self.rw_table.value_prev.clone()
    }

    fn initial_value(&self) -> Expression<F> {
        self.initial_value.clone()
    }

    fn initial_value_prev(&self) -> Expression<F> {
        self.initial_value_prev.clone()
    }

    fn tag_matches(&self, tag: RwTableTag) -> Expression<F> {
        BinaryNumberConfig::<RwTableTag, 4>::value_equals_expr(tag, self.tag_bits.clone())
    }

    // be careful! not boolean!!
    fn first_access(&self) -> Expression<F> {
        self.first_access.clone()
    }
    fn not_first_access(&self) -> Expression<F> {
        self.not_first_access.clone()
    }

    fn address_change(&self) -> Expression<F> {
        self.rw_table.address.clone() - self.rw_table.prev_address.clone()
    }

    fn rw_counter_change(&self) -> Expression<F> {
        self.rw_table.rw_counter.clone() - self.rw_table.prev_rw_counter.clone()
    }

    fn tx_log_index(&self) -> Expression<F> {
        from_digits(&self.address.limbs[0..2], (1u64 << 16).expr())
    }

    fn tx_log_index_prev(&self) -> Expression<F> {
        from_digits(&self.address.limbs_prev[0..2], (1u64 << 16).expr())
    }

    fn tx_log_id(&self) -> Expression<F> {
        from_digits(&self.address.limbs[3..5], (1u64 << 16).expr())
    }

    fn tx_log_id_prev(&self) -> Expression<F> {
        from_digits(&self.address.limbs_prev[3..5], (1u64 << 16).expr())
    }
}

fn from_digits<F: Field>(digits: &[Expression<F>], base: Expression<F>) -> Expression<F> {
    digits
        .iter()
        .rev()
        .fold(Expression::Constant(F::zero()), |result, digit| {
            digit.clone() + result * base.clone()
        })
}

fn set<F: Field, T: IntoEnumIterator + Expr<F>>() -> Vec<Expression<F>> {
    T::iter().map(|x| x.expr()).collect() // you don't need this collect if you
                                          // can figure out the return type
                                          // without it.
}
