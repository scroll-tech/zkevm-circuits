use halo2_proofs::{
    circuit::{AssignedCell, Cell, Region, RegionIndex, Value},
    halo2curves::bn256::Fr,
    plonk::{Challenge, Error},
};
use zkevm_circuits::util::Challenges;

use crate::constants::LOG_DEGREE;

use super::RlcConfig;

impl RlcConfig {
    /// initialize the chip with fixed 0 and 1 cells
    pub(crate) fn init(&self, region: &mut Region<Fr>) -> Result<(), Error> {
        region.assign_fixed(|| "const zero", self.fixed, 0, || Value::known(Fr::zero()))?;
        region.assign_fixed(|| "const one", self.fixed, 1, || Value::known(Fr::one()))?;
        Ok(())
    }

    #[inline]
    pub(crate) fn zero_cell(&self, region_index: RegionIndex) -> Cell {
        Cell {
            region_index,
            row_offset: 0,
            column: self.fixed.into(),
        }
    }

    #[inline]
    pub(crate) fn one_cell(&self, region_index: RegionIndex) -> Cell {
        Cell {
            region_index,
            row_offset: 1,
            column: self.fixed.into(),
        }
    }

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

    pub(crate) fn read_challenge(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let challenge_value = challenge_value.keccak_input();
        let challenge_cell = region.assign_advice(
            || "assign challenge",
            self.phase_2_column,
            *offset,
            || challenge_value,
        )?;
        self.enable_challenge.enable(region, *offset)?;
        *offset += 1;
        Ok(challenge_cell)
    }

    /// Enforce the element in f is a zero element.
    pub(crate) fn enforce_zero(
        &self,
        region: &mut Region<Fr>,
        f: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let zero_cell = self.zero_cell(f.cell().region_index);
        region.constrain_equal(f.cell(), zero_cell)
    }

    /// Enforce res = a + b
    #[allow(dead_code)]
    pub(crate) fn add(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        self.selector.enable(region, *offset)?;
        let one_cell = self.one_cell(a.cell().region_index);

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        let one = region.assign_advice(
            || "c",
            self.phase_2_column,
            *offset + 1,
            || Value::known(Fr::one()),
        )?;
        region.constrain_equal(one.cell(), one_cell)?;
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
        let one_cell = self.one_cell(a.cell().region_index);

        let res = region.assign_advice(
            || "a",
            self.phase_2_column,
            *offset,
            || a.value() - b.value(),
        )?;
        let one = region.assign_advice(
            || "b",
            self.phase_2_column,
            *offset + 1,
            || Value::known(Fr::one()),
        )?;
        region.constrain_equal(one.cell(), one_cell)?;
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
        let zero_cell = self.zero_cell(a.cell().region_index);

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        b.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
        let zero = region.assign_advice(
            || "b",
            self.phase_2_column,
            *offset + 2,
            || Value::known(Fr::zero()),
        )?;
        region.constrain_equal(zero.cell(), zero_cell)?;
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
        c.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
        let d = region.assign_advice(
            || "d",
            self.phase_2_column,
            *offset + 3,
            || a.value() * b.value() + c.value(),
        )?;
        *offset += 4;

        Ok(d)
    }

    /// caller need to ensure a is binary
    /// return !a
    pub(crate) fn not(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let one_cell = self.one_cell(a.cell().region_index);
        let one = self.load_private(region, &Fr::one(), offset)?;
        region.constrain_equal(one_cell, one.cell())?;
        self.sub(region, &one, a, offset)
    }

    // if cond = 1 return a, else b
    pub(crate) fn select(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        cond: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        // (cond - 1) * b + cond * a
        let cond_not = self.not(region, cond, offset)?;
        let tmp = self.mul(region, a, cond, offset)?;
        self.mul_add(region, b, &cond_not, &tmp, offset)
    }

    // Returns inputs[0] + challenge * inputs[1] + ... + challenge^k * inputs[k]
    #[allow(dead_code)]
    pub(crate) fn rlc(
        &self,
        region: &mut Region<Fr>,
        inputs: &[AssignedCell<Fr, Fr>],
        challenge: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let mut acc = inputs[0].clone();
        for input in inputs.iter().skip(1) {
            acc = self.mul_add(region, &acc, challenge, input, offset)?;
        }
        Ok(acc)
    }

    // Returns inputs[0] + challenge * inputs[1] + ... + challenge^k * inputs[k]
    pub(crate) fn rlc_with_flag(
        &self,
        region: &mut Region<Fr>,
        inputs: &[AssignedCell<Fr, Fr>],
        challenge: &AssignedCell<Fr, Fr>,
        flags: &[AssignedCell<Fr, Fr>],
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        assert!(flags.len() == inputs.len());

        let mut acc = inputs[0].clone();
        for (input, flag) in inputs.iter().zip(flags.iter()).skip(1) {
            let tmp = self.mul_add(region, &acc, challenge, input, offset)?;
            acc = self.select(region, &tmp, &acc, flag, offset)?;
        }
        Ok(acc)
    }

    // padded the columns
    #[allow(dead_code)]
    pub(crate) fn pad(&self, region: &mut Region<Fr>, offset: &usize) -> Result<(), Error> {
        for index in *offset..(1 << LOG_DEGREE) - 1 {
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
