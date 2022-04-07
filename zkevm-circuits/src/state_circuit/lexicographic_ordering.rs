use super::{N_LIMBS_ACCOUNT_ADDRESS, N_LIMBS_ID, N_LIMBS_RW_COUNTER};
use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::{not, select},
        witness::Rw,
    },
    util::Expr,
};
use eth_types::{Field, ToBigEndian};
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::{marker::PhantomData, ops::Mul};

// 2 limbs for tag, field_tag and id.
// 10 limbs for address,
// 16 limbs for storage key
// 2 limbs for rw_counter
// 30 limbs in total -> can fit into two field elements
#[derive(Clone, Copy)]
pub struct Config {
    diff_1: Column<Advice>,
    diff_2: Column<Advice>,
    diff_inverse: Column<Advice>,
    pub diff_selector: Column<Advice>,
    tag: Column<Advice>,
    field_tag: Column<Advice>,
    id_limbs: [Column<Advice>; N_LIMBS_ID],
    address_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
    storage_key_bytes: [Column<Advice>; N_BYTES_WORD],
    rw_counter_limbs: [Column<Advice>; N_LIMBS_RW_COUNTER],
}

impl Config {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cur: &Rw,
        prev: &Rw,
    ) -> Result<AssignedCell<F, F>, Error> {
        let cur_be_limbs = rw_to_be_limbs(cur);
        let prev_be_limbs = rw_to_be_limbs(prev);
        assert_eq!(cur_be_limbs.len(), 30);
        assert_eq!(prev_be_limbs.len(), 30);

        let find_result = cur_be_limbs
            .iter()
            .zip(&prev_be_limbs)
            .enumerate()
            .find(|(_, (a, b))| a != b);
        let (index, (cur_limb, prev_limb)) = find_result.expect("repeated rw counter");

        let mut diff_1 = F::from((cur_limb - prev_limb).into());
        let mut diff_2 = if cur_be_limbs[15] >= prev_be_limbs[15] {
            F::from((cur_be_limbs[15] - prev_be_limbs[15]).into())
        } else {
            -F::from((prev_be_limbs[15] - cur_be_limbs[15]).into())
        };
        let mut diff_inverse = diff_1.invert().unwrap();
        let mut diff_selector = F::one();
        if index >= 15 {
            diff_1 = F::zero();
            diff_2 = F::from((cur_limb - prev_limb).into());
            diff_inverse = diff_2.invert().unwrap();
            diff_selector = F::zero();
        }

        region.assign_advice(|| "diff_1", self.diff_1, offset, || Ok(diff_1))?;
        region.assign_advice(|| "diff_2", self.diff_2, offset, || Ok(diff_2))?;
        region.assign_advice(
            || "diff_inverse",
            self.diff_inverse,
            offset,
            || Ok(diff_inverse),
        )?;
        region.assign_advice(
            || "diff_selector",
            self.diff_selector,
            offset,
            || Ok(diff_selector),
        )
    }
}

pub struct Chip<F: Field> {
    config: Config,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    // TODO: fix this to not have too many arguments?
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Column<Fixed>,
        tag: Column<Advice>,
        field_tag: Column<Advice>,
        id_limbs: [Column<Advice>; N_LIMBS_ID],
        address_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
        storage_key_bytes: [Column<Advice>; N_BYTES_WORD],
        rw_counter_limbs: [Column<Advice>; N_LIMBS_RW_COUNTER],
        u16_range: Column<Fixed>,
    ) -> Config {
        let diff_1 = meta.advice_column();
        let diff_2 = meta.advice_column();
        let diff_inverse = meta.advice_column();
        let diff_selector = meta.advice_column();
        let config = Config {
            diff_1,
            diff_2,
            diff_inverse,
            diff_selector,
            tag,
            field_tag,
            id_limbs,
            address_limbs,
            storage_key_bytes,
            rw_counter_limbs,
        };
        meta.create_gate("diff_1 is one of 15 values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, config, Rotation::cur());
            let prev = Queries::new(meta, config, Rotation::prev());
            let diff_1 = meta.query_advice(diff_1, Rotation::cur());
            vec![
                selector
                    * diff_1_possible_values(cur, prev)
                        .iter()
                        .map(|e| diff_1.clone() - e.clone())
                        .fold(1.expr(), Expression::mul),
            ]
        });

        meta.create_gate("diff_2 is one of 15 values", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let cur = Queries::new(meta, config, Rotation::cur());
            let prev = Queries::new(meta, config, Rotation::prev());
            let diff_2 = meta.query_advice(diff_2, Rotation::cur());
            vec![
                selector
                    * diff_2_possible_values(cur, prev)
                        .iter()
                        .map(|e| diff_2.clone() - e.clone())
                        .fold(1.expr(), Expression::mul),
            ]
        });

        meta.lookup_any("diff_1 fits into u16", |meta| {
            let diff_selector = meta.query_advice(diff_selector, Rotation::cur());
            let diff_1 = meta.query_advice(diff_1, Rotation::cur());
            vec![(
                diff_selector * diff_1,
                meta.query_fixed(u16_range, Rotation::cur()),
            )]
        });
        meta.lookup_any("diff_2 fits into u16", |meta| {
            let diff_selector = meta.query_advice(diff_selector, Rotation::cur());
            let diff_2 = meta.query_advice(diff_2, Rotation::cur());
            vec![(
                not::expr(diff_selector) * diff_2,
                meta.query_fixed(u16_range, Rotation::cur()),
            )]
        });

        meta.create_gate("diff_selector is boolean", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let diff_selector = meta.query_advice(diff_selector, Rotation::cur());
            vec![selector * diff_selector.clone() * not::expr(diff_selector)]
        });

        meta.create_gate("diff_inverse", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let diff_selector = meta.query_advice(diff_selector, Rotation::cur());
            let diff_inverse = meta.query_advice(diff_inverse, Rotation::cur());
            let diff_1 = meta.query_advice(diff_1, Rotation::cur());
            let diff_2 = meta.query_advice(diff_2, Rotation::cur());
            vec![
                selector
                    * select::expr(
                        diff_selector,
                        diff_inverse.clone() * diff_1 - 1u64.expr(),
                        diff_inverse * diff_2 - 1u64.expr(),
                    ),
            ]
        });

        config
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
    fn new(meta: &mut VirtualCells<'_, F>, config: Config, rotation: Rotation) -> Self {
        let mut query_advice = |column| meta.query_advice(column, rotation);
        Self {
            // witness: query_advice(config.witness),
            tag: query_advice(config.tag),
            field_tag: query_advice(config.field_tag),
            id_limbs: config.id_limbs.map(&mut query_advice),
            address_limbs: config.address_limbs.map(&mut query_advice),
            storage_key_bytes: config.storage_key_bytes.map(&mut query_advice),
            rw_counter_limbs: config.rw_counter_limbs.map(query_advice),
        }
    }

    fn packed_tags(&self) -> Expression<F> {
        (1u64 << 4).expr() * self.tag.clone() + self.field_tag.clone()
    }

    fn storage_key_limbs(&self) -> Vec<Expression<F>> {
        self.storage_key_bytes
            .iter()
            .tuples()
            .map(|(hi, lo)| (1u64 << 16).expr() * hi.clone() + lo.clone())
            .collect()
    }

    fn be_limbs(&self) -> Vec<Expression<F>> {
        let mut limbs: Vec<_> = self
            .id_limbs
            .iter()
            .rev()
            .chain(self.address_limbs.iter().rev())
            .chain(self.storage_key_limbs().iter().rev())
            .chain(self.rw_counter_limbs.iter().rev())
            .cloned()
            .collect();
        // most significant byte of id should be 0, so safe to overwrite it with packed
        // tags.
        limbs[0] = limbs[0].clone() + self.packed_tags() * (1u64 << 8).expr();
        limbs
    }
}

fn rw_to_be_limbs(row: &Rw) -> Vec<u16> {
    let mut be_bytes = vec![];
    be_bytes.extend_from_slice(&(row.id().unwrap_or_default() as u32).to_be_bytes());
    assert_eq!(be_bytes.len(), 4);

    // check that the first byte of id is not used, and overwrites it with packed
    // tags.
    assert_eq!(be_bytes[0], 0);
    be_bytes[0] = row.field_tag().unwrap_or_default() as u8 + ((row.tag() as u8) << 4);
    assert_eq!(be_bytes.len(), 4);

    be_bytes.extend_from_slice(&(row.address().unwrap_or_default().0));
    assert_eq!(be_bytes.len(), 24);
    be_bytes.extend_from_slice(&(row.storage_key().unwrap_or_default().to_be_bytes()));
    assert_eq!(be_bytes.len(), 24 + 32);
    be_bytes.extend_from_slice(&((row.rw_counter() as u32).to_be_bytes()));
    assert_eq!(be_bytes.len(), 24 + 32 + 4);

    be_bytes
        .iter()
        .tuples()
        .map(|(hi, lo)| u16::from_be_bytes([*hi, *lo]))
        .collect()
}

fn diff_1_possible_values<F: Field>(cur: Queries<F>, prev: Queries<F>) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs()[..15].iter().zip(&prev.be_limbs()[..15]) {
        partial_sum = partial_sum * (1u64 << 16).expr() + cur_limb.clone() - prev_limb.clone();
        result.push(partial_sum.clone())
    }
    result
}

fn diff_2_possible_values<F: Field>(cur: Queries<F>, prev: Queries<F>) -> Vec<Expression<F>> {
    let mut result = vec![];
    let mut partial_sum = 0u64.expr();
    for (cur_limb, prev_limb) in cur.be_limbs()[15..].iter().zip(&prev.be_limbs()[15..]) {
        partial_sum = partial_sum * (1u64 << 16).expr() + cur_limb.clone() - prev_limb.clone();
        result.push(partial_sum.clone())
    }
    result
}
