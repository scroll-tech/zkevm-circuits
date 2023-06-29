use super::{lookups, param::*, SortKeysConfig};
use crate::{evm_circuit::param::N_BYTES_WORD, impl_expr, util::Expr, witness::Rw};
use eth_types::{Field, ToBigEndian};
use gadgets::binary_number::{AsBits, BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::iter::once;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// We use this chip to show that the rows of the rw table are in lexicographic
// order, i.e. ordered by (tag, id, address, field_tag, storage_key, and
// rw_counter). We do this by packing these 6 fields into a 512 bit value X, and
// then showing that X_cur > X_prev. Let A0, A1, ..., A31 be the 32 16-bit limbs
// of X_cur and B0, B1, ..., B31 be 32 16-bit limbs of X_prev, in big endian
// order.

// Let
// C0 = A0 - B0,
// C1 = C0 << 16 + A1 - B1,
// ...
// C31 = C30 << 16 + A31 - B21.

// X_cur > X_prev iff one of C0, ..., C31 is non-zero and fits into 16 bits.
// C16, ..., C31 do not necessarily fit into a field element, so to check that
// Cn fits into 16 bits, we use an RLC to check that Cn-1 = 0 and then do a
// lookup for An-Bn.

// We show this with following advice columns and constraints:
// - first_different_limb: first index where the limbs differ. We use a BinaryNumberChip here to
//   reduce the degree of the constraints.
// - limb_difference: the difference between the limbs at first_different_limb.
// - limb_difference_inverse: the inverse of limb_difference

//  1. limb_difference fits into 16 bits.
//  2. limb_difference is not zero because its inverse exists.
//  3. RLC of the pairwise limb differences before the first_different_limb is
//     zero.
//  4. limb_difference equals the difference of the limbs at
//     first_different_limb.

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LimbIndex {
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

impl_expr!(LimbIndex);

impl AsBits<5> for LimbIndex {
    fn as_bits(&self) -> [bool; 5] {
        let mut bits = [false; 5];
        let mut x = *self as u8;
        for i in 0..5 {
            bits[4 - i] = x % 2 == 1;
            x /= 2;
        }
        assert_eq!(x, 0);
        bits
    }
}

#[derive(Clone, Copy)]
pub struct Config {
    pub(crate) selector: Column<Fixed>,
    pub first_different_limb: BinaryNumberConfig<LimbIndex, 5>,
    limb_difference: Column<Advice>,
    limb_difference_inverse: Column<Advice>,
}

impl Config {
    pub fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        keys: SortKeysConfig,
        lookup: lookups::Config,
        powers_of_randomness: [Expression<F>; N_BYTES_WORD - 1],
    ) -> Self {
        let selector = meta.fixed_column();
        let first_different_limb = BinaryNumberChip::configure(meta, selector, None);
        let limb_difference = meta.advice_column();
        let limb_difference_inverse = meta.advice_column();

        let config = Config {
            selector,
            first_different_limb,
            limb_difference,
            limb_difference_inverse,
        };

        lookup.range_check_u16(meta, "limb_difference fits into u16", |meta| {
            meta.query_advice(limb_difference, Rotation::cur())
        });

        meta.create_gate("limb_difference is not zero", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let limb_difference = meta.query_advice(limb_difference, Rotation::cur());
            let limb_difference_inverse =
                meta.query_advice(limb_difference_inverse, Rotation::cur());
            vec![selector * (1.expr() - limb_difference * limb_difference_inverse)]
        });

        meta.create_gate(
            "limb differences before first_different_limb are all 0",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, keys, Rotation::cur());
                let prev = Queries::new(meta, keys, Rotation::prev());

                let mut constraints = vec![];
                for (i, rlc_expression) in
                    LimbIndex::iter().zip(rlc_limb_differences(cur, prev, powers_of_randomness))
                {
                    // E.g. if first_different_limb = 5, four limb differences before need to be 0.
                    // Using RLC, we check that (cur_1 - prev_1) + r(cur_2 - prev_2) + r^2(cur_3 -
                    // prev_3) + r^3(cur_4 - prev_4) = 0.
                    constraints.push(
                        selector.clone()
                            * first_different_limb.value_equals(i, Rotation::cur())(meta)
                            * rlc_expression,
                    )
                }
                constraints
            },
        );

        meta.create_gate(
            "limb_difference equals difference of limbs at index",
            |meta| {
                let selector = meta.query_fixed(selector, Rotation::cur());
                let cur = Queries::new(meta, keys, Rotation::cur());
                let prev = Queries::new(meta, keys, Rotation::prev());
                let limb_difference = meta.query_advice(limb_difference, Rotation::cur());

                let mut constraints = vec![];
                for ((i, cur_limb), prev_limb) in
                    LimbIndex::iter().zip(cur.be_limbs()).zip(prev.be_limbs())
                {
                    constraints.push(
                        selector.clone()
                            * first_different_limb.value_equals(i, Rotation::cur())(meta)
                            * (limb_difference.clone() - cur_limb + prev_limb),
                    );
                }
                constraints
            },
        );

        config
    }

    // Returns true if the `cur` row is a first access to a group (at least one of
    // tag, id, address, field_tag, or storage_key is different from the one in
    // `prev`), and false otherwise.
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: &Rw,
        prev: &Rw,
    ) -> Result<LimbIndex, Error> {
        region.assign_fixed(
            || "upper_limb_difference",
            self.selector,
            offset,
            || Value::known(F::one()),
        )?;

        let cur_be_limbs = rw_to_be_limbs(cur);
        let prev_be_limbs = rw_to_be_limbs(prev);

        let find_result = LimbIndex::iter()
            .zip(&cur_be_limbs)
            .zip(&prev_be_limbs)
            .find(|((_, a), b)| a != b);
        let ((index, cur_limb), prev_limb) = if cfg!(test) {
            find_result.unwrap_or(((LimbIndex::RwCounter0, &0), &0))
        } else {
            find_result.expect("repeated rw counter")
        };

        BinaryNumberChip::construct(self.first_different_limb).assign(region, offset, &index)?;

        let limb_difference = F::from(*cur_limb as u64) - F::from(*prev_limb as u64);
        region.assign_advice(
            || "limb_difference",
            self.limb_difference,
            offset,
            || Value::known(limb_difference),
        )?;
        region.assign_advice(
            || "limb_difference_inverse",
            self.limb_difference_inverse,
            offset,
            || Value::known(limb_difference.invert().unwrap()),
        )?;

        Ok(index)
    }

    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        [
            (self.limb_difference, "LO_limb_difference"),
            (self.limb_difference_inverse, "LO_limb_difference_inverse"),
        ]
        .iter()
        .for_each(|(col, ann)| region.name_column(|| format!("{prefix}_{ann}"), *col));
        // fixed column
        region.name_column(
            || format!("{prefix}_LO_upper_limb_difference"),
            self.selector,
        );
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

// Returns a vector of length 32 with the rlc of the limb differences between
// from 0 to i-l. 0 for i=0,
fn rlc_limb_differences<F: Field>(
    cur: Queries<F>,
    prev: Queries<F>,
    powers_of_randomness: [Expression<F>; 31],
) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    let powers_of_randomness = once(1.expr()).chain(powers_of_randomness.into_iter());
    for ((cur_limb, prev_limb), power_of_randomness) in cur
        .be_limbs()
        .iter()
        .zip(&prev.be_limbs())
        .zip(powers_of_randomness)
    {
        result.push(partial_sum.clone());
        partial_sum = partial_sum + power_of_randomness * (cur_limb.clone() - prev_limb.clone());
    }
    result
}

#[cfg(test)]
mod test {
    use super::LimbIndex;
    use gadgets::binary_number::{from_bits, AsBits};
    use strum::IntoEnumIterator;

    #[test]
    fn enough_bits_for_limb_index() {
        for index in LimbIndex::iter() {
            assert_eq!(from_bits(&index.as_bits()), index as usize);
        }
    }
}
