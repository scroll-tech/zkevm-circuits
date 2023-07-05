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

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone)]
pub struct RlcConfig {
    #[cfg(test)]
    // Test requires a phase 1 column before proceed to phase 2.
    _phase_1_column: Column<Advice>,
    phase_2_column: Column<Advice>,
    selector: Selector,
}

impl RlcConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let selector = meta.complex_selector();

        #[cfg(test)]
        // CS requires existence of at least one phase 1 column if we operate on phase 2 columns.
        // This column is not really used.
        let _phase_1_column = {
            let column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(column);
            column
        };

        let phase_2_column = meta.advice_column_in(SecondPhase);
        meta.enable_equality(phase_2_column);

        // phase_2_column | advice
        // ---------------|-------
        // a              | q
        // b              | 0
        // c              | 0
        // d              | 0
        //
        // constraint: q*(a*b+c-d) = 0

        meta.create_gate("rlc_gate", |meta| {
            let a = meta.query_advice(phase_2_column, Rotation(0));
            let b = meta.query_advice(phase_2_column, Rotation(1));
            let c = meta.query_advice(phase_2_column, Rotation(2));
            let d = meta.query_advice(phase_2_column, Rotation(3));
            let q = meta.query_selector(selector);
            vec![q * (a * b + c - d)]
        });
        Self {
            #[cfg(test)]
            _phase_1_column,
            phase_2_column,
            selector,
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
        let challenge =
            challenge.copy_advice(|| "challenge", region, self.phase_2_column, *offset)?;
        *offset += 1;

        let mut cur_challenge = challenge.clone();

        let mut acc = inputs[0].clone();
        for input in inputs.iter().skip(1) {
            acc = self.mul_add(region, input, &cur_challenge, &acc, offset)?;
            cur_challenge = self.mul(region, &challenge, &cur_challenge, offset)?;
        }
        Ok(acc)
    }

    // padded the columns
    pub(crate) fn pad(&self, region: &mut Region<Fr>, offset: &usize) -> Result<(), Error> {
        for index in *offset..1 << LOG_DEGREE {
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
