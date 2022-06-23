use super::{lookups, N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_ID, N_LIMBS_RW_COUNTER};
use crate::{
    evm_circuit::{param::N_BYTES_WORD, witness::RwRow},
    util::Expr,
};
use eth_types::{Field, ToBigEndian};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::ops::Mul;

// We use this chip to show that the rows of the rw table are in lexicographic
// order, i.e. ordered by (tag, field_tag, id, address, storage_key, and
// rw_counter). We do this by packing these 6 fields into a 480 bit value X, and
// then showing that X_cur > X_prev. Let A0, A1, ..., A29 be the 30 16-bit limbs
// of X_cur and B0, B1, ..., B29 be 30 16-bit limbs of X_prev, in big endian
// order.

// Let
// C0 = A0 - B0,
// C1 = C0 << 16 + A1 - B1,
// ...
// C14 = C13 << 16 + A14 - B14,
// and
// C15 = A15 - B15,
// C16 = C15 << 16 + A16 - B16,
// ...
// C29 = C28 << 16 + A29 - B29.
// We have to split the 30 limbs into upper and lower halves between C14 and C15
// because a field element can only hold 15 16-bit limbs.

// X_cur > X_prev iff one of the following is true:
// 1. one of C0, ..., C14 is non-zero and fits into 16 bits.
// 2. all of C0, ..., C14 are 0 and one of C15, ..., C29 is non-zero and fits
//    into 16 bits. (note that "all of C0, ..., C14 are 0" is equivalent to
//    "C14 is 0".)

// We show that one of these is true with the following constraints:
//  1. upper_limb_difference is (at least) 1 of the 15 values C0, ..., C14.
//  2. lower_limb_difference is (at least) 1 of the 15 values C15, ..., C29.
//  3. upper_limb_difference fits into 16 bits.
//  4. if upper_limb_difference is 0, then lower_limb_difference fits into 16
//    bits.
//  5. if upper_limb_difference is 0, then C14 is 0.
//  6. at least one of upper_limb_difference or lower_limb_difference is not 0.

// We satisfy these constraints by assigning upper_limb_difference
// to be the first non-zero difference between the first 15 big-endian limbs of
// X_cur and X_prev or 0 if the the limbs are all equal. E.g. if X_curr = (2, 1,
// 6, ...) and X_prev = (2, 1, 2, ...), then upper_limb_difference = C2 = 6 - 2
// = 4. If there is no difference between the first 15 pairs of limbs, then
// lower_limb_difference is assigned to be the first non-zero difference between
// the last 15 pairs of limbs. This non-zero difference will exist because there
// are no duplicate entries in the rw table. If upper_limb_difference has a
// non-zero value, then we assign lower_limb_difference to be the value of C29.

// Packing the field into 480 bits:
//   4 bits for tag,
// + 5 bits for field_tag
// + 23 bits for id
// + 160 bits for address,
// + 256 bits for storage key
// + 32  bits for rw_counter
// -----------------------------------
// = 480 bits

#[derive(Clone)]
pub struct Config<F> {
    pub(crate) selector: Column<Fixed>,
    upper_limb_difference: Column<Advice>,
    pub(crate) upper_limb_difference_is_zero: IsZeroConfig<F>,
    lower_limb_difference: Column<Advice>,
    lower_limb_difference_is_zero: IsZeroConfig<F>,
    // TODO: remove these columns from the config
    tag: Column<Advice>,
    field_tag: Column<Advice>,
    id_limbs: [Column<Advice>; N_LIMBS_ID],
    address_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
    storage_key_bytes: [Column<Advice>; N_BYTES_WORD],
    rw_counter_limbs: [Column<Advice>; N_LIMBS_RW_COUNTER],
}

pub struct Chip<F: Field> {
    config: Config<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config<F>) -> Self {
        Self { config }
    }

    #[allow(clippy::too_many_arguments)]
    // TODO: fix this to not have too many arguments?
    pub fn configure<const QUICK_CHECK: bool>(
        meta: &mut ConstraintSystem<F>,
        tag: Column<Advice>,
        field_tag: Column<Advice>,
        id_limbs: [Column<Advice>; N_LIMBS_ID],
        address_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
        storage_key_bytes: [Column<Advice>; N_BYTES_WORD],
        rw_counter_limbs: [Column<Advice>; N_LIMBS_RW_COUNTER],
        lookup: lookups::Config<QUICK_CHECK>,
    ) -> Config<F> {
        let selector = meta.fixed_column();
        let [upper_limb_difference, upper_limb_difference_inverse, lower_limb_difference, lower_limb_difference_inverse] =
            [0; 4].map(|_| meta.advice_column());
        let [upper_limb_difference_is_zero_config, lower_limb_difference_is_zero_config] = [
            (upper_limb_difference, upper_limb_difference_inverse),
            (lower_limb_difference, lower_limb_difference_inverse),
        ]
        .map(|(value, advice)| {
            IsZeroChip::configure(
                meta,
                |meta| meta.query_fixed(selector, Rotation::cur()),
                |meta| meta.query_advice(value, Rotation::cur()),
                advice,
            )
        });

        let upper_limb_difference_is_zero = upper_limb_difference_is_zero_config
            .is_zero_expression
            .clone();
        let lower_limb_difference_is_zero = lower_limb_difference_is_zero_config
            .is_zero_expression
            .clone();

        let config = Config {
            selector,
            upper_limb_difference,
            upper_limb_difference_is_zero: upper_limb_difference_is_zero_config,
            lower_limb_difference,
            lower_limb_difference_is_zero: lower_limb_difference_is_zero_config,
            tag,
            field_tag,
            id_limbs,
            address_limbs,
            storage_key_bytes,
            rw_counter_limbs,
        };
        meta.create_gate("upper_limb_difference is one of 15 values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, &config, Rotation::cur());
            let prev = Queries::new(meta, &config, Rotation::prev());
            let upper_limb_difference = meta.query_advice(upper_limb_difference, Rotation::cur());
            vec![
                selector
                    * upper_limb_difference_possible_values(cur, prev)
                        .iter()
                        .map(|e| upper_limb_difference.clone() - e.clone())
                        .fold(1.expr(), Expression::mul),
            ]
        });
        assert!(meta.degree() <= 16);
        meta.create_gate(
            "upper_limb_difference is zero iff all 15 possible values are 0",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, &config, Rotation::cur());
                let prev = Queries::new(meta, &config, Rotation::prev());
                vec![
                    // all 15 possible values are 0 iff the final linear combination is 0
                    selector
                        * upper_limb_difference_is_zero.clone()
                        * upper_limb_difference_possible_values(cur, prev)[14].clone(),
                ]
            },
        );
        meta.create_gate("lower_limb_difference is one of 15 values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, &config, Rotation::cur());
            let prev = Queries::new(meta, &config, Rotation::prev());
            let lower_limb_difference = meta.query_advice(lower_limb_difference, Rotation::cur());
            vec![
                selector
                    * lower_limb_difference_possible_values(cur, prev)
                        .iter()
                        .map(|e| lower_limb_difference.clone() - e.clone())
                        .fold(1.expr(), Expression::mul),
            ]
        });
        assert!(meta.degree() <= 16);
        lookup.range_check_u16(meta, "upper_limb_difference fits into u16", |meta| {
            meta.query_advice(upper_limb_difference, Rotation::cur())
        });
        lookup.range_check_u16(
            meta,
            "upper_limb_difference is zero or lower_limb_difference fits into u16",
            |meta| {
                let lower_limb_difference =
                    meta.query_advice(lower_limb_difference, Rotation::cur());
                upper_limb_difference_is_zero * lower_limb_difference
            },
        );

        assert!(meta.degree() <= 16);
        meta.create_gate("lower_limb_difference is not zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            vec![(selector * lower_limb_difference_is_zero)]
        });
        assert!(meta.degree() <= 16);

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: &RwRow<F>,
        prev: &RwRow<F>,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "upper_limb_difference",
            self.config.selector,
            offset,
            || Ok(F::one()),
        )?;

        // this doesn't make sense that we have to "construct" the chip every time we
        // assign?
        let upper_limb_difference_is_zero_chip =
            IsZeroChip::construct(self.config.upper_limb_difference_is_zero.clone());
        let lower_limb_difference_is_zero_chip =
            IsZeroChip::construct(self.config.lower_limb_difference_is_zero.clone());

        let cur_be_limbs = rw_to_be_limbs(cur);
        let prev_be_limbs = rw_to_be_limbs(prev);

        let find_result = cur_be_limbs
            .iter()
            .zip(&prev_be_limbs)
            .enumerate()
            .find(|(_, (a, b))| a != b);
        let (index, (cur_limb, prev_limb)) = if cfg!(test) {
            find_result.unwrap_or((30, (&0, &0)))
        } else {
            find_result.expect("repeated rw counter")
        };

        let mut upper_limb_difference = F::from(*cur_limb as u64) - F::from(*prev_limb as u64);
        let mut lower_limb_difference = lower_limb_difference_value(&cur_be_limbs, &prev_be_limbs);
        if index >= 15 {
            lower_limb_difference = upper_limb_difference;
            upper_limb_difference = F::zero();
        }

        region.assign_advice(
            || "upper_limb_difference",
            self.config.upper_limb_difference,
            offset,
            || Ok(upper_limb_difference),
        )?;
        region.assign_advice(
            || "lower_limb_difference",
            self.config.lower_limb_difference,
            offset,
            || Ok(lower_limb_difference),
        )?;
        upper_limb_difference_is_zero_chip.assign(region, offset, Some(upper_limb_difference))?;
        lower_limb_difference_is_zero_chip.assign(region, offset, Some(lower_limb_difference))?;
        Ok(())
    }
}

struct Queries<F: Field> {
    tag: Expression<F>,       // 4 bits
    field_tag: Expression<F>, // 8 bits, so we can pack tag + field_tag into one limb.
    id_limbs: [Expression<F>; N_LIMBS_ID],
    address_limbs: [Expression<F>; N_LIMBS_ACCOUNT_ADDRESS],
    storage_key_bytes: [Expression<F>; N_BYTES_WORD],
    rw_counter_limbs: [Expression<F>; N_LIMBS_RW_COUNTER],
}

impl<F: Field> Queries<F> {
    fn new(meta: &mut VirtualCells<'_, F>, config: &Config<F>, rotation: Rotation) -> Self {
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            tag: query_advice(config.tag),
            field_tag: query_advice(config.field_tag),
            id_limbs: config.id_limbs.map(&mut query_advice),
            address_limbs: config.address_limbs.map(&mut query_advice),
            storage_key_bytes: config.storage_key_bytes.map(&mut query_advice),
            rw_counter_limbs: config.rw_counter_limbs.map(query_advice),
        }
    }

    fn packed_tags(&self) -> Expression<F> {
        (1u64 << 5).expr() * self.tag.clone() + self.field_tag.clone()
    }

    fn storage_key_be_limbs(&self) -> Vec<Expression<F>> {
        self.storage_key_bytes
            .iter()
            .rev()
            .tuples()
            .map(|(hi, lo)| (1u64 << 8).expr() * hi.clone() + lo.clone())
            .collect()
    }

    fn be_limbs(&self) -> Vec<Expression<F>> {
        let mut limbs: Vec<_> = self
            .id_limbs
            .iter()
            .rev()
            .chain(self.address_limbs.iter().rev())
            .chain(&self.storage_key_be_limbs())
            .chain(self.rw_counter_limbs.iter().rev())
            .cloned()
            .collect();
        // The packed tags are shifted left by 7 bits so that they occupy the most
        // significant 9 bits of the first 16-bit limb.
        limbs[0] = limbs[0].clone() + self.packed_tags() * (1u64 << 7).expr();
        limbs
    }
}

fn rw_to_be_limbs<F: Field>(row: &RwRow<F>) -> Vec<u16> {
    let mut id = row.id as u32;
    assert_eq!(id.to_be_bytes().len(), 4);
    // The max value of `id` is 2^23 - 1, so the 9 most significant bits should be
    // 0. We use these 9 bits to hold value of `tag` and `field_tag`.
    assert!(id < (1 << 23));
    id += (((row.tag as u32) << 5) + (row.field_tag as u32)) << 23;

    let mut be_bytes = vec![];
    be_bytes.extend_from_slice(&id.to_be_bytes());
    be_bytes.extend_from_slice(&(row.address.0));
    be_bytes.extend_from_slice(&(row.storage_key.to_be_bytes()));
    be_bytes.extend_from_slice(&((row.rw_counter as u32).to_be_bytes()));

    be_bytes
        .iter()
        .tuples()
        .map(|(hi, lo)| u16::from_be_bytes([*hi, *lo]))
        .collect()
}

fn upper_limb_difference_possible_values<F: Field>(
    cur: Queries<F>,
    prev: Queries<F>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs()[..15].iter().zip(&prev.be_limbs()[..15]) {
        partial_sum = partial_sum * (1u64 << 16).expr() + cur_limb.clone() - prev_limb.clone();
        result.push(partial_sum.clone())
    }
    assert_eq!(result.len(), 15);
    result
}

fn lower_limb_difference_possible_values<F: Field>(
    cur: Queries<F>,
    prev: Queries<F>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs()[15..].iter().zip(&prev.be_limbs()[15..]) {
        partial_sum = partial_sum * (1u64 << 16).expr() + cur_limb.clone() - prev_limb.clone();
        result.push(partial_sum.clone())
    }
    assert_eq!(result.len(), 15);
    result
}

fn lower_limb_difference_value<F: Field>(cur_limbs: &[u16], prev_limbs: &[u16]) -> F {
    be_limbs_to_value::<F>(&cur_limbs[15..]) - be_limbs_to_value::<F>(&prev_limbs[15..])
}

fn be_limbs_to_value<F: Field>(limbs: &[u16]) -> F {
    limbs.iter().fold(F::zero(), |result, &limb| {
        result * F::from(1u64 << 16) + F::from(limb as u64)
    })
}
