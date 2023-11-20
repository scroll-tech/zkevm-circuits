use super::{
    super::{AssignedBits, RoundWordDense, SpreadVar, SpreadWord, STATE},
    compression_util::*,
    CompressionConfig, State,
};
use crate::{
    table16::util::{i2lebsp, sum_with_carry},
    Field,
};
use halo2_proofs::{circuit::Region, plonk::Error};

impl CompressionConfig {
    // #[allow(clippy::many_single_char_names)]
    // pub fn assign_digest<F: Field>(
    //     &self,
    //     region: &mut Region<'_, F>,
    //     state: State<F>,
    // ) -> Result<[BlockWord; DIGEST_SIZE], Error> {
    //     let a_3 = self.extras[0];
    //     let a_4 = self.extras[1];
    //     let a_5 = self.message_schedule;
    //     let a_6 = self.extras[2];
    //     let a_7 = self.extras[3];
    //     let a_8 = self.extras[4];

    //     let (a, b, c, d, e, f, g, h) = match_state(state);

    //     let abcd_row = 0;
    //     self.s_digest.enable(region, abcd_row)?;
    //     let efgh_row = abcd_row + 2;
    //     self.s_digest.enable(region, efgh_row)?;

    //     // Assign digest for A, B, C, D
    //     a.dense_halves
    //         .0
    //         .copy_advice(|| "a_lo", region, a_3, abcd_row)?;
    //     a.dense_halves
    //         .1
    //         .copy_advice(|| "a_hi", region, a_4, abcd_row)?;
    //     let a = a.dense_halves.value();
    //     region.assign_advice(|| "a", a_5, abcd_row, || a.map(|a| F::from(a as u64)))?;

    //     let b = self.assign_digest_word(region, abcd_row, a_6, a_7, a_8, b.dense_halves)?;
    //     let c = self.assign_digest_word(region, abcd_row + 1, a_3, a_4, a_5, c.dense_halves)?;
    //     let d = self.assign_digest_word(region, abcd_row + 1, a_6, a_7, a_8, d)?;

    //     // Assign digest for E, F, G, H
    //     e.dense_halves
    //         .0
    //         .copy_advice(|| "e_lo", region, a_3, efgh_row)?;
    //     e.dense_halves
    //         .1
    //         .copy_advice(|| "e_hi", region, a_4, efgh_row)?;
    //     let e = e.dense_halves.value();
    //     region.assign_advice(|| "e", a_5, efgh_row, || e.map(|e| F::from(e as u64)))?;

    //     let f = self.assign_digest_word(region, efgh_row, a_6, a_7, a_8, f.dense_halves)?;
    //     let g = self.assign_digest_word(region, efgh_row + 1, a_3, a_4, a_5, g.dense_halves)?;
    //     let h = self.assign_digest_word(region, efgh_row + 1, a_6, a_7, a_8, h)?;

    //     Ok([
    //         BlockWord(a),
    //         BlockWord(b),
    //         BlockWord(c),
    //         BlockWord(d),
    //         BlockWord(e),
    //         BlockWord(f),
    //         BlockWord(g),
    //         BlockWord(h),
    //     ])
    // }

    // fn assign_digest_word<F: Field>(
    //     &self,
    //     region: &mut Region<'_, F>,
    //     row: usize,
    //     lo_col: Column<Advice>,
    //     hi_col: Column<Advice>,
    //     word_col: Column<Advice>,
    //     dense_halves: RoundWordDense<F>,
    // ) -> Result<Value<u32>, Error> {
    //     dense_halves.0.copy_advice(|| "lo", region, lo_col, row)?;
    //     dense_halves.1.copy_advice(|| "hi", region, hi_col, row)?;

    //     let val = dense_halves.value();
    //     region.assign_advice(
    //         || "word",
    //         word_col,
    //         row,
    //         || val.map(|val| F::from(val as u64)),
    //     )?;

    //     Ok(val)
    // }

    #[allow(clippy::many_single_char_names)]
    pub fn complete_digest<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        last_compress_state: State<F>,
        initial_state: State<F>,
    ) -> Result<[RoundWordDense<F>; STATE], Error> {
        let a_3 = self.extras[0];
        let a_5 = self.message_schedule;
        let a_6 = self.extras[2];
        let a_8 = self.extras[4];

        let (a, b, c, d, e, f, g, h) = match_state(last_compress_state);
        let (a_i, b_i, c_i, d_i, e_i, f_i, g_i, h_i) = match_state(initial_state);

        let mut digest_dense = Vec::new();
        for (i, (final_dense, init_dense)) in [
            a.dense_halves,
            b.dense_halves,
            c.dense_halves,
            d,
            e.dense_halves,
            f.dense_halves,
            g.dense_halves,
            h,
        ]
        .into_iter()
        .zip([
            a_i.dense_halves,
            b_i.dense_halves,
            c_i.dense_halves,
            d_i,
            e_i.dense_halves,
            f_i.dense_halves,
            g_i.dense_halves,
            h_i,
        ])
        .enumerate()
        {
            let row = i * 2;
            self.s_digest.enable(region, row)?;
            let (final_lo, final_hi) = final_dense.decompose();
            let (init_lo, init_hi) = init_dense.decompose();

            let (digest, carry) = sum_with_carry(vec![
                (final_lo.value_u16(), final_hi.value_u16()),
                (init_lo.value_u16(), init_hi.value_u16()),
            ]);

            region.assign_advice(|| "digest carry", a_8, row, || carry.map(F::from))?;
            region.assign_advice(
                || "digest word",
                a_5,
                row,
                || digest.map(|v| F::from(v as u64)),
            )?;

            final_lo.copy_advice(|| "final lo", region, a_3, row)?;
            final_hi.copy_advice(|| "final hi", region, a_3, row + 1)?;
            init_lo.copy_advice(|| "init lo", region, a_6, row)?;
            init_hi.copy_advice(|| "init hi", region, a_6, row + 1)?;

            let word = digest.map(|w| i2lebsp(w.into()));
            let digest_lo = word.map(|w: [bool; 32]| w[..16].try_into().unwrap());
            let digest_hi = word.map(|w| w[16..].try_into().unwrap());

            let digest_lo = SpreadVar::with_lookup(
                region,
                &self.lookup,
                row,
                digest_lo.map(SpreadWord::<16, 32>::new),
            )?
            .dense;
            let digest_hi = SpreadVar::with_lookup(
                region,
                &self.lookup,
                row + 1,
                digest_hi.map(SpreadWord::<16, 32>::new),
            )?
            .dense;
            digest_dense.push((digest_lo, digest_hi))
        }

        let ret: [(AssignedBits<F, 16>, AssignedBits<F, 16>); STATE] =
            digest_dense.try_into().unwrap();
        Ok(ret.map(RoundWordDense::from))
    }
}
