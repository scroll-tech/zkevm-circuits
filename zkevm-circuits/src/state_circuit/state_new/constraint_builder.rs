use super::super::param::{N_BITS_ADDRESS, N_BITS_FIELD_TAG, N_BITS_ID, N_BITS_TAG};
use super::{
    lookups::Queries as LookupsQueries, multiple_precision_integer::Queries as MpiQueries,
    random_linear_combination::Queries as RlcQueries, N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_ID,
    N_LIMBS_RW_COUNTER,
};
use crate::evm_circuit::{
    param::N_BYTES_WORD,
    table::{AccountFieldTag, RwTableTag},
    util::{math_gadget::generate_lagrange_base_polynomial, not},
};
use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::plonk::Expression;
use strum::IntoEnumIterator;

#[derive(Clone)]
pub struct Queries<F: Field> {
    pub selector: Expression<F>,
    pub rw_counter: MpiQueries<F, N_LIMBS_RW_COUNTER>,
    pub is_write: Expression<F>,
    pub tag: Expression<F>,
    pub id: MpiQueries<F, N_LIMBS_ID>,
    pub address: MpiQueries<F, N_LIMBS_ACCOUNT_ADDRESS>,
    pub field_tag: Expression<F>,
    pub storage_key: RlcQueries<F, N_BYTES_WORD>,
    pub value: Expression<F>,
    pub lookups: LookupsQueries<F>,
    pub power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    // lexicographic_ordering expressions, etc.
}

pub struct ConstraintBuilder<F: Field> {
    constraints: Vec<(&'static str, Expression<F>)>,
    lookups: Vec<(&'static str, (Expression<F>, Expression<F>))>,
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

    pub fn lookups(&self) -> Vec<(&'static str, (Expression<F>, Expression<F>))> {
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
    }

    fn build_general_constraints(&mut self, q: &Queries<F>) {
        self.require_in_set(
            "tag in RwTableTag range",
            q.tag(),
            RwTableTag::iter().map(|x| x.expr()).collect(),
        );
        self.require_boolean("is_write is boolean", q.is_write());
    }

    fn build_start_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("rw_counter is 0 for Start", q.rw_counter.value.clone());
    }

    fn build_memory_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for Memory", q.field_tag());
        self.require_zero("storage_key is 0 for Memory", q.storage_key.encoded.clone());
        self.require_zero(
            "read from a fresh key is 0",
            q.first_access() * q.is_read() * q.value(),
        );
        // could do this more efficiently by just asserting address = limb0 + 2^16 *
        // limb1?
        for limb in &q.address.limbs[2..] {
            self.require_zero("memory address fits into 2 limbs", limb.clone());
        }
        self.add_lookup(
            "memory value is a byte",
            (q.value.clone(), q.lookups.u8.clone()),
        );
    }

    fn build_stack_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for Stack", q.field_tag());
        self.require_zero("storage_key is 0 for Stack", q.storage_key.encoded.clone());
        self.require_zero(
            "first access to new stack address is a write",
            q.first_access() * q.is_write(),
        );
        self.add_lookup(
            "stack address fits into 10 bits",
            (q.address.value.clone(), q.lookups.u10.clone()),
        );
        self.condition(not::expr(q.first_access()), |cb| {
            cb.require_boolean("stack address change is 0 or 1", q.address_change())
        })
    }

    fn build_account_storage_constraints(&mut self, q: &Queries<F>) {
        // TODO: cold VS warm
        // TODO: connection to MPT on first and last access for each (address, key)
        self.require_zero("id is 0 for AccountStorage", q.id());
        self.require_zero("field_tag is 0 for AccountStorage", q.field_tag());
        // for every first access, we add an AccountStorage write to setup the value
        // from the previous block with rw_counter = 0
        self.condition(q.first_access(), |cb| {
            cb.require_zero("first access is a write", q.is_write());
            cb.require_zero("first access rw_counter is 0", q.rw_counter.value.clone());
        })
    }
    fn build_tx_access_list_account_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("field_tag is 0 for TxAccessListAccount", q.field_tag());
        self.require_zero(
            "storage_key is 0 for TxAccessListAccount",
            q.storage_key.encoded.clone(),
        );
        // TODO: Missing constraints
    }

    fn build_tx_access_list_account_storage_constraints(&mut self, q: &Queries<F>) {
        self.require_zero(
            "field_tag is 0 for TxAccessListAccountStorage",
            q.field_tag(),
        );
        // TODO: Missing constraints
    }

    fn build_tx_refund_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("address is 0 for TxRefund", q.address.value.clone());
        self.require_zero("field_tag is 0 for TxRefund", q.field_tag());
        self.require_zero(
            "storage_key is 0 for TxRefund",
            q.storage_key.encoded.clone(),
        );
        // TODO: Missing constraints
    }

    fn build_account_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("id is 0 for Account", q.id());
        self.require_zero(
            "storage_key is 0 for Account",
            q.storage_key.encoded.clone(),
        );
        self.require_in_set(
            "field_tag in AccountFieldTag range",
            q.field_tag(),
            set::<AccountFieldTag>(),
        );
        // for every first access, we add an Account write to setup the value from the
        // previous block with rw_counter = 0
        self.condition(q.first_access(), |cb| {
            cb.require_zero("first access is a write", q.is_write());
            cb.require_zero("first access rw_counter is 0", q.rw_counter.value.clone());
        });
    }

    fn build_account_destructed_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("id is 0 for AccountDestructed", q.id());
        self.require_zero("field_tag is 0 for AccountDestructed", q.field_tag());
        self.require_zero(
            "storage_key is 0 for AccountDestructed",
            q.storage_key.encoded.clone(),
        );
        // TODO: Missing constraints
    }

    fn build_call_context_constraints(&mut self, q: &Queries<F>) {
        self.require_zero("address is 0 for CallContext", q.address.value.clone());
        self.require_zero(
            "storage_key is 0 for CallContext",
            q.storage_key.encoded.clone(),
        );
    }

    fn require_zero(&mut self, name: &'static str, e: Expression<F>) {
        self.constraints.push((name, self.condition.clone() * e));
    }

    fn require_boolean(&mut self, name: &'static str, e: Expression<F>) {
        self.require_zero(name, e.clone() * not::expr(e))
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
        // handle nested conditions?
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
        self.is_write.clone()
    }

    fn is_read(&self) -> Expression<F> {
        not::expr(&self.is_write)
    }

    fn tag(&self) -> Expression<F> {
        self.tag.clone()
    }

    fn id(&self) -> Expression<F> {
        self.id.value.clone()
    }

    fn field_tag(&self) -> Expression<F> {
        self.field_tag.clone()
    }

    fn value(&self) -> Expression<F> {
        self.value.clone()
    }

    fn tag_matches(&self, tag: RwTableTag) -> Expression<F> {
        generate_lagrange_base_polynomial(self.tag.clone(), tag as usize, set::<RwTableTag>())
    }

    fn sort_keys(&self) -> (Expression<F>, Expression<F>) {
        let n_bits_remaining =
            F::CAPACITY - N_BITS_TAG - N_BITS_ID - N_BITS_ADDRESS - N_BITS_FIELD_TAG;
        let n_bytes_remaining = (n_bits_remaining / 8) as usize;

        let mut key_0 = self.tag();
        key_0 = key_0 * (1u64 << N_BITS_ID).expr() + self.id();
        key_0 = key_0 * (1u64 << (N_BITS_ADDRESS / 4)).expr().square().square()
            + self.address.value.clone();
        key_0 = key_0 * (1u64 << N_BITS_FIELD_TAG).expr() + self.field_tag();
        key_0 = key_0 * (1u64 << n_bits_remaining).expr()
            + from_digits(
                &self.storage_key.bytes[..n_bytes_remaining],
                (1u64 << 8).expr(),
            );

        let key_1 = from_digits(
            &self.storage_key.bytes[n_bytes_remaining..],
            (1u64 << 8).expr(),
        );

        (key_0, key_1)
    }

    fn first_access(&self) -> Expression<F> {
        1.expr()
    }

    fn address_change(&self) -> Expression<F> {
        self.address.value.clone() - self.address.value_prev.clone()
    }
}

fn from_digits<F: Field>(digits: &[Expression<F>], base: Expression<F>) -> Expression<F> {
    digits
        .iter()
        .fold(Expression::Constant(F::zero()), |result, digit| {
            digit.clone() + result * base.clone()
        })
}

fn set<F: Field, T: IntoEnumIterator + Expr<F>>() -> Vec<Expression<F>> {
    T::iter().map(|x| x.expr()).collect()
}
