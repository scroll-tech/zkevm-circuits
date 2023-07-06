use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Challenge, Column, ConstraintSystem, Error, Expression, SecondPhase, Selector,
    },
    poly::Rotation,
};
use snark_verifier::system::halo2::Config;
use zkevm_circuits::util::Challenges;

#[cfg(test)]
use halo2_proofs::plonk::FirstPhase;

use crate::constants::LOG_DEGREE;

use super::RlcConfig;

impl RlcConfig {
    pub(crate) fn load_private(
        &self,
        region: &mut Region<Fr>,
        f: &Fr,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let res = region.assign_advice(
            || "load private",
            self.phase_2_column,
            *offset,
            || Value::known(*f),
        );
        *offset += 1;
        res
    }

    /// Enforce the element in f is a zero element.
    pub(crate) fn enforce_zero(
        &self,
        region: &mut Region<Fr>,
        f: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        self.selector.enable(region, *offset)?;

        region.assign_advice(
            || "a",
            self.phase_2_column,
            *offset,
            || Value::known(Fr::zero()),
        )?;
        region.assign_advice(
            || "b",
            self.phase_2_column,
            *offset + 1,
            || Value::known(Fr::zero()),
        )?;
        f.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
        region.assign_advice(
            || "d",
            self.phase_2_column,
            *offset + 3,
            || Value::known(Fr::zero()),
        )?;
        *offset += 4;
        Ok(())
    }

    /// Enforce res = a + b
    pub(crate) fn add(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        self.selector.enable(region, *offset)?;

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        region.assign_advice(
            || "b",
            self.phase_2_column,
            *offset + 1,
            || Value::known(Fr::one()),
        )?;
        b.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
        let d = region.assign_advice(
            || "d",
            self.phase_2_column,
            *offset + 3,
            || a.value() + b.value(),
        )?;
        *offset += 4;

        Ok(d)
    }

    /// Enforce res = a - b
    pub(crate) fn sub(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        self.selector.enable(region, *offset)?;

        let res = region.assign_advice(
            || "a",
            self.phase_2_column,
            *offset,
            || a.value() - b.value(),
        )?;
        region.assign_advice(
            || "b",
            self.phase_2_column,
            *offset + 1,
            || Value::known(Fr::one()),
        )?;
        b.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
        a.copy_advice(|| "d", region, self.phase_2_column, *offset + 3)?;
        *offset += 4;

        Ok(res)
    }

    /// Enforce res = a * b
    pub(crate) fn mul(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        self.selector.enable(region, *offset)?;

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        b.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
        region.assign_advice(
            || "c",
            self.phase_2_column,
            *offset + 2,
            || Value::known(Fr::zero()),
        )?;
        let d = region.assign_advice(
            || "d",
            self.phase_2_column,
            *offset + 3,
            || a.value() * b.value(),
        )?;
        *offset += 4;

        Ok(d)
    }

    /// Enforce res = a * b + c
    pub(crate) fn mul_add(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        c: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        self.selector.enable(region, *offset)?;

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        b.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
        c.copy_advice(|| "b", region, self.phase_2_column, *offset + 2)?;
        let d = region.assign_advice(
            || "d",
            self.phase_2_column,
            *offset + 3,
            || a.value() * b.value() + c.value(),
        )?;
        *offset += 4;

        Ok(d)
    }

    // Returns inputs[0] + challange * inputs[1] + ... + challenge^k * inputs[k]
    pub(crate) fn rlc(
        &self,
        region: &mut Region<Fr>,
        inputs: &[AssignedCell<Fr, Fr>],
        challenge: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let mut acc = inputs[0].clone();
        for input in inputs.iter().skip(1) {
            acc = self.mul_add(region, &acc, &challenge, input, offset)?;
        }
        Ok(acc)
    }

    // padded the columns
    pub(crate) fn pad(&self, region: &mut Region<Fr>, offset: &usize) -> Result<(), Error> {
        for index in *offset..(1 << LOG_DEGREE - 1) {
            region.assign_advice(
                || "pad",
                self.phase_2_column,
                index,
                || Value::known(Fr::zero()),
            )?;
        }
        Ok(())
    }
}
