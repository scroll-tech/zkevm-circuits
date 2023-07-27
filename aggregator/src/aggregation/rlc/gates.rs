use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    halo2curves::bn256::Fr,
    plonk::Error,
};
use zkevm_circuits::util::Challenges;

use crate::{constants::LOG_DEGREE, util::assert_equal};

use super::RlcConfig;

impl RlcConfig {
    /// initialize the chip with fixed values storing 0, 1, 2, 4, 8, 32
    pub(crate) fn init(&mut self, region: &mut Region<Fr>) -> Result<(), Error> {
        self.fixed_cells.push(region.assign_fixed(
            || "const zero",
            self.fixed,
            0,
            || Value::known(Fr::zero()),
        )?);
        self.fixed_cells.push(region.assign_fixed(
            || "const one",
            self.fixed,
            1,
            || Value::known(Fr::one()),
        )?);
        self.fixed_cells.push(region.assign_fixed(
            || "const two",
            self.fixed,
            2,
            || Value::known(Fr::from(2)),
        )?);
        self.fixed_cells.push(region.assign_fixed(
            || "const four",
            self.fixed,
            3,
            || Value::known(Fr::from(4)),
        )?);
        self.fixed_cells.push(region.assign_fixed(
            || "const eight",
            self.fixed,
            4,
            || Value::known(Fr::from(8)),
        )?);
        self.fixed_cells.push(region.assign_fixed(
            || "const thirty two",
            self.fixed,
            5,
            || Value::known(Fr::from(32)),
        )?);
        Ok(())
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
    ) -> Result<(), Error> {
        let zero_cell = &self.fixed_cells[0];
        region.constrain_equal(f.cell(), zero_cell.cell())
    }

    /// Enforce the element in f is a binary element.
    pub(crate) fn enforce_binary(
        &self,
        region: &mut Region<Fr>,
        f: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let f2 = self.mul(region, f, f, offset)?;
        region.constrain_equal(f.cell(), f2.cell())
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
        let one_cell = &self.fixed_cells[1];

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        one_cell.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
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
        let one_cell = &self.fixed_cells[1];

        let res = region.assign_advice(
            || "a",
            self.phase_2_column,
            *offset,
            || a.value() - b.value(),
        )?;
        one_cell.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
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
        let zero_cell = &self.fixed_cells[0];

        a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
        b.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
        zero_cell.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
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
        let one_cell = &self.fixed_cells[1];
        self.sub(region, one_cell, a, offset)
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

    // decompose a field element into 254 bits of boolean cells
    pub(crate) fn decomposition(
        &self,
        region: &mut Region<Fr>,
        input: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        let mut input_element = Fr::default();
        input.value().map(|&x| input_element = x);

        let bits = input_element
            .to_bytes()
            .iter()
            .flat_map(byte_to_bits_le)
            .collect::<Vec<_>>();
        // sanity check
        {
            let mut reconstructed = Fr::zero();
            bits.iter().rev().for_each(|bit| {
                reconstructed *= Fr::from(2);
                reconstructed += Fr::from(*bit as u64);
            });
            assert_eq!(reconstructed, input_element);
        }

        let bit_cells = bits
            .iter()
            .take(254) // hard coded for BN curve
            .map(|&bit| {
                let cell = self.load_private(region, &Fr::from(bit as u64), offset)?;
                self.enforce_binary(region, &cell, offset)?;
                Ok(cell)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let mut acc = self.fixed_cells[0].clone();
        let two = &self.fixed_cells[2];
        for bit in bit_cells.iter().rev() {
            acc = self.mul_add(region, &acc, two, bit, offset)?;
        }

        // sanity check
        assert_equal(&acc, input);

        region.constrain_equal(acc.cell(), input.cell())?;

        Ok(bit_cells)
    }

    // return a boolean if a is smaller than b
    // requires that both a and b are smallish
    pub(crate) fn is_smaller_than(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        // when a and b are both small (as in our use case)
        // if a < b, (a-b) will under flow and the highest bit of (a-b) be one
        // else,  the highest bit of (a-b) be zero
        let sub = self.sub(region, a, b, offset)?;
        let bits = self.decomposition(region, &sub, offset)?;
        Ok(bits[253].clone())
    }
}
#[inline]
fn byte_to_bits_le(byte: &u8) -> Vec<u8> {
    let mut res = vec![];
    let mut t = *byte;
    for _ in 0..8 {
        res.push(t & 1);
        t >>= 1;
    }
    res
}
