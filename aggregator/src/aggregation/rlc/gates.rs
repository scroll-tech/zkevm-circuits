use ethers_core::utils::keccak256;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Cell, Region, RegionIndex, Value},
    halo2curves::bn256::Fr,
    plonk::Error,
};
use zkevm_circuits::util::Challenges;

// TODO: remove MAX_AGG_SNARKS and make this generic over N_SNARKS
use crate::{DIGEST_LEN, MAX_AGG_SNARKS};

use super::RlcConfig;

const FIXED_OFFSET_32: usize = MAX_AGG_SNARKS + 1;
const FIXED_OFFSET_168: usize = FIXED_OFFSET_32 + 1;
const FIXED_OFFSET_232: usize = FIXED_OFFSET_168 + 1;
const FIXED_OFFSET_2_POW_32: usize = FIXED_OFFSET_232 + 1;
const FIXED_OFFSET_256: usize = FIXED_OFFSET_2_POW_32 + 1;
const FIXED_OFFSET_EMPTY_KECCAK: usize = FIXED_OFFSET_256 + POWS_OF_256;

pub(crate) const POWS_OF_256: usize = 10;

impl RlcConfig {
    /// initialize the chip with fixed cells
    ///
    /// The layout for fixed cells is:
    ///
    /// | Offset                 | Fixed value          |
    /// |------------------------|----------------------|
    /// | 0                      | 0                    |
    /// | 1                      | 1                    |
    /// | i ...                  | i ...                |
    /// | MAX_AGG_SNARKS         | MAX_AGG_SNARKS       |
    /// | MAX_AGG_SNARKS + 1     | 32                   |
    /// | MAX_AGG_SNARKS + 2     | 168                  |
    /// | MAX_AGG_SNARKS + 3     | 232                  |
    /// | MAX_AGG_SNARKS + 4     | 2 ^ 32               |
    /// | MAX_AGG_SNARKS + 5     | 256                  |
    /// | MAX_AGG_SNARKS + 6     | 256 ^ 2              |
    /// | MAX_AGG_SNARKS + 7     | 256 ^ 3              |
    /// | MAX_AGG_SNARKS + j ... | 256 ^ (j - 4)        |
    /// | MAX_AGG_SNARKS + 14    | 256 ^ 10             |
    /// | MAX_AGG_SNARKS + 15    | EMPTY_KECCAK[0]      |
    /// | MAX_AGG_SNARKS + 16    | EMPTY_KECCAK[1]      |
    /// | MAX_AGG_SNARKS + k ... | EMPTY_KECCAK[k - 15] |
    /// | MAX_AGG_SNARKS + 46    | EMPTY_KECCAK[31]     |
    /// |------------------------|----------------------|
    pub(crate) fn init(&self, region: &mut Region<Fr>) -> Result<(), Error> {
        let mut offset = 0;

        // [0, ..., MAX_AGG_SNARKS]
        for const_val in 0..=MAX_AGG_SNARKS {
            region.assign_fixed(
                || format!("const at offset={offset}"),
                self.fixed,
                offset,
                || Value::known(Fr::from(const_val as u64)),
            )?;
            offset += 1;
        }
        assert_eq!(offset, FIXED_OFFSET_32);

        // [32, 168, 232, 1 << 32]
        for const_val in [32, 168, 232, 1 << 32] {
            region.assign_fixed(
                || format!("const at offset={offset}"),
                self.fixed,
                offset,
                || Value::known(Fr::from(const_val)),
            )?;
            offset += 1;
        }
        assert_eq!(offset, FIXED_OFFSET_256);

        // [256, ..., 256 ^ i, ..., 256 ^ 10]
        for const_val in std::iter::successors(Some(Fr::from(256)), |n| Some(n * Fr::from(256)))
            .take(POWS_OF_256)
        {
            region.assign_fixed(
                || format!("const at offset={offset}"),
                self.fixed,
                offset,
                || Value::known(const_val),
            )?;
            offset += 1;
        }
        assert_eq!(offset, FIXED_OFFSET_EMPTY_KECCAK);

        // [EMPTY_KECCAK[0], ..., EMPTY_KECCAK[31]]
        let empty_keccak = keccak256([]);
        for &byte in empty_keccak.iter() {
            region.assign_fixed(
                || format!("const at offset={offset}"),
                self.fixed,
                offset,
                || Value::known(Fr::from(byte as u64)),
            )?;
            offset += 1;
        }
        assert_eq!(offset, FIXED_OFFSET_EMPTY_KECCAK + DIGEST_LEN);

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

    #[inline]
    pub(crate) fn four_cell(&self, region_index: RegionIndex) -> Cell {
        Cell {
            region_index,
            row_offset: 4,
            column: self.fixed.into(),
        }
    }

    #[inline]
    pub(crate) fn fixed_up_to_max_agg_snarks_cell(
        &self,
        region_index: RegionIndex,
        index: usize,
    ) -> Cell {
        assert!(index <= MAX_AGG_SNARKS, "only up to MAX_AGG_SNARKS");
        Cell {
            region_index,
            row_offset: index,
            column: self.fixed.into(),
        }
    }

    #[inline]
    pub(crate) fn pow_of_two_hundred_and_fifty_six_cell(
        &self,
        region_index: RegionIndex,
        exponent: usize,
    ) -> Cell {
        assert!(exponent > 0, "for exponent == 0, fetch the one cell");
        assert!(
            exponent <= POWS_OF_256,
            "only up to 256 ^ 10 in fixed column"
        );
        Cell {
            region_index,
            row_offset: FIXED_OFFSET_256 + exponent - 1,
            column: self.fixed.into(),
        }
    }

    #[inline]
    pub(crate) fn empty_keccak_cell_i(&self, region_index: RegionIndex, index: usize) -> Cell {
        assert!(index <= 31, "keccak digest only has 32 bytes");
        Cell {
            region_index,
            row_offset: FIXED_OFFSET_EMPTY_KECCAK + index,
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

    pub(crate) fn read_challenge1(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let challenge_value = challenge_value.keccak_input();
        let challenge_cell = region.assign_advice(
            || "assign challenge1",
            self.phase_2_column,
            *offset,
            || challenge_value,
        )?;
        self.enable_challenge1.enable(region, *offset)?;
        *offset += 1;
        Ok(challenge_cell)
    }

    pub(crate) fn read_challenge2(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let challenge_value = challenge_value.evm_word();
        let challenge_cell = region.assign_advice(
            || "assign challenge2",
            self.phase_2_column,
            *offset,
            || challenge_value,
        )?;
        self.enable_challenge2.enable(region, *offset)?;
        *offset += 1;
        Ok(challenge_cell)
    }

    /// Enforce the element in f is a zero element.
    pub(crate) fn enforce_zero(
        &self,
        region: &mut Region<Fr>,
        f: &AssignedCell<Fr, Fr>,
    ) -> Result<(), Error> {
        let zero_cell = self.zero_cell(f.cell().region_index);
        region.constrain_equal(f.cell(), zero_cell)
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
            || "b",
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
        // (1 - cond) * b + cond * a
        let cond_not = self.not(region, cond, offset)?;
        let tmp = self.mul(region, a, cond, offset)?;
        self.mul_add(region, b, &cond_not, &tmp, offset)
    }

    // if cond = 1, enforce a==b
    // caller need to ensure cond is binary
    pub(crate) fn conditional_enforce_equal(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        b: &AssignedCell<Fr, Fr>,
        cond: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        let diff = self.sub(region, a, b, offset)?;
        let res = self.mul(region, &diff, cond, offset)?;
        self.enforce_zero(region, &res)
    }

    // Returns inputs[0] + challenge * inputs[1] + ... + challenge^k * inputs[k]
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

    // Returns challenge^k * inputs[0] * flag[0] + ... + challenge * inputs[k-1] * flag[k-1]] +
    // inputs[k]* flag[k]
    pub(crate) fn rlc_with_flag(
        &self,
        region: &mut Region<Fr>,
        inputs: &[AssignedCell<Fr, Fr>],
        challenge: &AssignedCell<Fr, Fr>,
        flags: &[AssignedCell<Fr, Fr>],
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        assert!(flags.len() == inputs.len());
        let mut acc = self.mul(region, &inputs[0], &flags[0], offset)?;
        for (input, flag) in inputs.iter().zip(flags.iter()).skip(1) {
            let tmp = self.mul_add(region, &acc, challenge, input, offset)?;
            acc = self.select(region, &tmp, &acc, flag, offset)?;
        }
        Ok(acc)
    }

    pub(crate) fn inner_product(
        &self,
        region: &mut Region<Fr>,
        a: &[AssignedCell<Fr, Fr>],
        b: &[AssignedCell<Fr, Fr>],
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        assert_eq!(a.len(), b.len());
        assert!(!a.is_empty());

        let mut acc = self.mul(region, &a[0], &b[0], offset)?;
        for (a_next, b_next) in a.iter().zip(b.iter()).skip(1) {
            acc = self.mul_add(region, a_next, b_next, &acc, offset)?;
        }

        Ok(acc)
    }

    // return a boolean if a ?= 0
    pub(crate) fn is_zero(
        &self,
        region: &mut Region<Fr>,
        a: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        // constraints
        // - res + a * a_inv = 1
        // - res * a = 0
        // for some witness a_inv where
        // a_inv = 0 if a = 0
        // a_inv = 1/a if a != 0
        let mut a_tmp = Fr::default();
        a.value().map(|&v| a_tmp = v);
        let res = a_tmp == Fr::zero();
        let res_cell = self.load_private(region, &Fr::from(res as u64), offset)?;
        let a_inv = a_tmp.invert().unwrap_or(Fr::zero());
        let a_inv_cell = self.load_private(region, &a_inv, offset)?;
        {
            // - res + a * a_inv = 1
            self.selector.enable(region, *offset)?;
            a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
            a_inv_cell.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
            res_cell.copy_advice(|| "c", region, self.phase_2_column, *offset + 2)?;
            let d = region.assign_advice(
                || "d",
                self.phase_2_column,
                *offset + 3,
                || Value::known(Fr::one()),
            )?;
            region.constrain_equal(d.cell(), self.one_cell(d.cell().region_index))?;
            *offset += 4;
        }
        {
            // - res * a = 0
            self.selector.enable(region, *offset)?;
            a.copy_advice(|| "a", region, self.phase_2_column, *offset)?;
            res_cell.copy_advice(|| "b", region, self.phase_2_column, *offset + 1)?;
            let c = region.assign_advice(
                || "c",
                self.phase_2_column,
                *offset + 2,
                || Value::known(Fr::zero()),
            )?;
            let d = region.assign_advice(
                || "d",
                self.phase_2_column,
                *offset + 3,
                || Value::known(Fr::zero()),
            )?;
            region.constrain_equal(c.cell(), self.zero_cell(c.cell().region_index))?;
            region.constrain_equal(d.cell(), self.zero_cell(d.cell().region_index))?;
            *offset += 4;
        }
        Ok(res_cell)
    }

    // lookup the input and output rlcs from the lookup table
    pub(crate) fn lookup_keccak_rlcs(
        &self,
        region: &mut Region<Fr>,
        input_rlcs: &AssignedCell<Fr, Fr>,
        output_rlcs: &AssignedCell<Fr, Fr>,
        data_len: &AssignedCell<Fr, Fr>,
        offset: &mut usize,
    ) -> Result<(), Error> {
        self.lookup_gate_selector.enable(region, *offset)?;
        let _input_rlcs_copied =
            input_rlcs.copy_advice(|| "lookup input rlc", region, self.phase_2_column, *offset)?;
        let _output_rlcs_copied = output_rlcs.copy_advice(
            || "lookup output rlc",
            region,
            self.phase_2_column,
            *offset + 1,
        )?;
        let _data_len = data_len.copy_advice(
            || "lookup data len",
            region,
            self.phase_2_column,
            *offset + 2,
        )?;

        *offset += 3;

        Ok(())
    }
}
