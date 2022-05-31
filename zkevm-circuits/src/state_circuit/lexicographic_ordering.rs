use super::{
    binary_number::{AsBits, Chip as BinaryNumberChip, Config as BinaryNumberConfig},
    SortKeysConfig, N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_ID, N_LIMBS_RW_COUNTER,
};
use crate::{
    evm_circuit::{param::N_BYTES_WORD, witness::Rw},
    util::Expr,
};
use eth_types::{Field, ToBigEndian};
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::iter::once;
use strum::IntoEnumIterator;
use strum_macros::{EnumCount, EnumIter};

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

#[derive(Clone, Copy, Debug, EnumIter, EnumCount)]
// TODO: unpub this
// should call this limb index
pub enum Limb {
    Tag,
    Id1,
    Id0,
    Address9,
    Address8,
    Address7,
    Address6,
    Address5,
    Address4,
    Address3,
    Address2,
    Address1,
    Address0,
    FieldTag,
    StorageKey15,
    StorageKey14,
    StorageKey13,
    StorageKey12,
    StorageKey11,
    StorageKey10,
    StorageKey9,
    StorageKey8,
    StorageKey7,
    StorageKey6,
    StorageKey5,
    StorageKey4,
    StorageKey3,
    StorageKey2,
    StorageKey1,
    StorageKey0,
    RwCounter1,
    RwCounter0,
}

impl AsBits<5> for Limb {
    fn as_bits(&self) -> [bool; 5] {
        let mut bits = [false; 5];
        let mut x = *self as u8;
        for i in 0..5 {
            bits[4 - i] = x % 2 == 1;
            x /= 2;
        }
        bits
    }
}

#[derive(Clone, Copy)]
pub struct Config {
    pub(crate) selector: Column<Fixed>,
    pub first_different_limb: BinaryNumberConfig<Limb, 5>,
    limb_difference: Column<Advice>,
    limb_difference_inverse: Column<Advice>,
}

impl Config {
    pub fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        keys: SortKeysConfig,
        u16_range: Column<Fixed>,
    ) -> Self {
        let selector = meta.fixed_column();
        let first_different_limb = BinaryNumberChip::configure(meta, selector);
        let limb_difference = meta.advice_column();
        let limb_difference_inverse = meta.advice_column();

        let config = Config {
            selector,
            first_different_limb,
            limb_difference,
            limb_difference_inverse,
        };

        meta.lookup_any("limb_difference fits into u16", |meta| {
            vec![(
                meta.query_advice(limb_difference, Rotation::cur()),
                meta.query_fixed(u16_range, Rotation::cur()),
            )]
        });

        meta.create_gate("limb_difference is not zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let limb_difference = meta.query_advice(limb_difference, Rotation::cur());
            let limb_difference_inverse =
                meta.query_advice(limb_difference_inverse, Rotation::cur());
            vec![selector * (1.expr() - limb_difference * limb_difference_inverse)]
        });

        meta.create_gate("limbs match before first_different_limb", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, keys, Rotation::cur());
            let prev = Queries::new(meta, keys, Rotation::prev());

            let mut constraints = vec![];
            for (limb, e) in Limb::iter().zip(limb_difference_possible_values(cur, prev)) {
                constraints.push(
                    selector.clone()
                        * first_different_limb.value_equals(&limb, Rotation::cur())(meta)
                        * e,
                )
            }
            constraints
        });

        meta.create_gate(
            "limb_difference is equal to the difference at claimed limb",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, keys, Rotation::cur());
                let prev = Queries::new(meta, keys, Rotation::prev());
                let limb_difference = meta.query_advice(limb_difference, Rotation::cur());

                let mut constraints = vec![];
                for ((limb, cur_expression), prev_expression) in
                    Limb::iter().zip(cur.be_limbs()).zip(prev.be_limbs())
                {
                    constraints.push(
                        selector.clone()
                            * first_different_limb.value_equals(&limb, Rotation::cur())(meta)
                            * (limb_difference.clone() - cur_expression + prev_expression),
                    );
                }
                constraints
            },
        );

        config
    }

    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: &Rw,
        prev: &Rw,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "upper_limb_difference",
            self.selector,
            offset,
            || Ok(F::one()),
        )?;

        let cur_be_limbs = rw_to_be_limbs(cur);
        let prev_be_limbs = rw_to_be_limbs(prev);

        let find_result = Limb::iter()
            .zip(&cur_be_limbs)
            .zip(&prev_be_limbs)
            .find(|((_, a), b)| a != b);
        let ((index, cur_limb), prev_limb) = if cfg!(test) {
            find_result.unwrap_or(((Limb::RwCounter0, &0), &0))
        } else {
            find_result.expect("repeated rw counter")
        };

        BinaryNumberChip::construct(self.first_different_limb).assign(region, offset, index)?;

        let limb_difference = F::from(*cur_limb as u64) - F::from(*prev_limb as u64);
        region.assign_advice(
            || "limb_difference",
            self.limb_difference,
            offset,
            || Ok(limb_difference),
        )?;
        region.assign_advice(
            || "limb_difference_inverse",
            self.limb_difference_inverse,
            offset,
            || Ok(limb_difference.invert().unwrap()),
        )?;

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
    fn new(meta: &mut VirtualCells<'_, F>, keys: SortKeysConfig, rotation: Rotation) -> Self {
        let tag = keys.tag.value(rotation)(meta);
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            tag,
            id_limbs: keys.id.limbs.map(&mut query_advice),
            address_limbs: keys.address.limbs.map(&mut query_advice),
            field_tag: query_advice(keys.field_tag),
            storage_key_bytes: keys.storage_key.bytes.map(&mut query_advice),
            rw_counter_limbs: keys.rw_counter.limbs.map(query_advice),
        }
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
        once(&self.tag)
            .chain(self.id_limbs.iter().rev())
            .chain(self.address_limbs.iter().rev())
            .chain(once(&self.field_tag))
            .chain(&self.storage_key_be_limbs())
            .chain(self.rw_counter_limbs.iter().rev())
            .cloned()
            .collect()
    }
}

fn rw_to_be_limbs(row: &Rw) -> Vec<u16> {
    let mut be_bytes = vec![0u8];
    be_bytes.push(row.tag() as u8);
    be_bytes.extend_from_slice(&(row.id().unwrap_or_default() as u32).to_be_bytes());
    be_bytes.extend_from_slice(&(row.address().unwrap_or_default().0));
    be_bytes.push(0u8);
    be_bytes.push(row.field_tag().unwrap_or_default() as u8);
    be_bytes.extend_from_slice(&(row.storage_key().unwrap_or_default().to_be_bytes()));
    be_bytes.extend_from_slice(&((row.rw_counter() as u32).to_be_bytes()));

    be_bytes
        .iter()
        .tuples()
        .map(|(hi, lo)| u16::from_be_bytes([*hi, *lo]))
        .collect()
}

fn limb_difference_possible_values<F: Field>(
    cur: Queries<F>,
    prev: Queries<F>,
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs().iter().zip(&prev.be_limbs()) {
        result.push(partial_sum.clone());
        partial_sum = partial_sum * (1u64 << 16).expr() + cur_limb.clone() - prev_limb.clone();
    }
    result
}

#[cfg(test)]
mod test {
    use super::Limb;
    use strum::IntoEnumIterator;

    #[test]
    fn n_limbs() {
        assert_eq!(Limb::iter().len(), 32);
    }
}
