use crate::RlcConfig;
use gadgets::util::Expr;
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    halo2curves::{bn256::Fr, group::ff::PrimeField},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::util::Field;

#[derive(Clone, Copy, Debug)]
pub struct BooleanAdvice {
    pub column: Column<Advice>,
}

impl BooleanAdvice {
    pub fn construct<F: Field>(
        meta: &mut ConstraintSystem<F>,
        enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) -> Self {
        let advice = Self {
            column: meta.advice_column(),
        };
        meta.create_gate("BooleanAdvice: main gate", |meta| {
            let bool_val = meta.query_advice(advice.column, Rotation::cur());
            vec![enable(meta) * bool_val.expr() * (1.expr() - bool_val)]
        });
        advice
    }

    pub fn expr_at<F: Field>(&self, meta: &mut VirtualCells<F>, at: Rotation) -> Expression<F> {
        meta.query_advice(self.column, at)
    }
}

pub fn constrain_crt_equals_bytes(
    region: &mut Region<Fr>,
    rlc_config: &RlcConfig,
    crt: &CRTInteger<Fr>,
    bytes: &[AssignedCell<Fr, Fr>],
    rlc_config_offset: &mut usize,
) -> Result<(), Error> {
    let mut powers_of_256 = vec![];
    for i in 0..11 {
        let assigned_cell =
            rlc_config.load_private(region, &Fr::from_u128(256u128.pow(i)), rlc_config_offset)?;
        let region_index = assigned_cell.cell().region_index;
        let fixed_cell = if i == 0 {
            rlc_config.one_cell(region_index)
        } else {
            rlc_config
                .pow_of_two_hundred_and_fifty_six_cell(region_index, usize::try_from(i).unwrap())
        };
        region.constrain_equal(fixed_cell, assigned_cell.cell())?;
        powers_of_256.push(assigned_cell);
    }

    let limb_from_bytes_lo =
        rlc_config.inner_product(region, &bytes[0..11], &powers_of_256, rlc_config_offset)?;
    let limb_from_bytes_mid =
        rlc_config.inner_product(region, &bytes[11..22], &powers_of_256, rlc_config_offset)?;
    let limb_from_bytes_hi = rlc_config.inner_product(
        region,
        &bytes[22..32],
        &powers_of_256[0..10],
        rlc_config_offset,
    )?;

    for (limb_from_bytes, crt_limb) in [limb_from_bytes_lo, limb_from_bytes_mid, limb_from_bytes_hi]
        .iter()
        .zip_eq(crt.limbs())
    {
        region.constrain_equal(limb_from_bytes.cell(), crt_limb.cell())?
    }

    Ok(())

    // This can just be a collect....
}
