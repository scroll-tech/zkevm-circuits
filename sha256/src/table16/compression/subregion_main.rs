use super::{
    super::{AssignedBits, RoundWord, RoundWordA, RoundWordE, RoundWordDense,
        StateWord, SpreadVar, SpreadWord, ROUND_CONSTANTS, STATE},
    compression_util::*,
    CompressionConfig, State,
};
use crate::{Field, table16::util::{i2lebsp, sum_with_carry}};
use halo2_proofs::{circuit::Region, plonk::Error};

impl CompressionConfig {
    #[allow(clippy::many_single_char_names)]
    pub fn assign_round<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        round_idx: MainRoundIdx,
        state: State<F>,
        schedule_word: &(AssignedBits<F, 16>, AssignedBits<F, 16>),
    ) -> Result<State<F>, Error> {
        let a_7 = self.extras[3];

        let (a, b, c, d, e, f, g, h) = match_state(state);

        // s_upper_sigma_1(E)
        let sigma_1 = self.assign_upper_sigma_1(region, round_idx, e.pieces.clone().unwrap())?;

        // Ch(E, F, G)
        let ch = self.assign_ch(
            region,
            round_idx,
            e.spread_halves.clone().unwrap(),
            f.spread_halves.clone(),
        )?;
        let ch_neg = self.assign_ch_neg(
            region,
            round_idx,
            e.spread_halves.clone().unwrap(),
            g.spread_halves.clone(),
        )?;

        // s_upper_sigma_0(A)
        let sigma_0 = self.assign_upper_sigma_0(region, round_idx, a.pieces.clone().unwrap())?;

        // Maj(A, B, C)
        let maj = self.assign_maj(
            region,
            round_idx,
            a.spread_halves.clone().unwrap(),
            b.spread_halves.clone(),
            c.spread_halves.clone(),
        )?;

        // H' = H + Ch(E, F, G) + s_upper_sigma_1(E) + K + W
        let h_prime = self.assign_h_prime(
            region,
            round_idx,
            h,
            ch,
            ch_neg,
            sigma_1,
            ROUND_CONSTANTS[round_idx.as_usize()],
            schedule_word,
        )?;

        // E_new = H' + D
        let e_new_dense = self.assign_e_new(region, round_idx, &d, &h_prime)?;
        let e_new_val = e_new_dense.value();

        // A_new = H' + Maj(A, B, C) + sigma_0(A)
        let a_new_dense = self.assign_a_new(region, round_idx, maj, sigma_0, h_prime)?;
        let a_new_val = a_new_dense.value();

        if round_idx < 63.into() {
            // Assign and copy A_new
            let a_new_row = get_decompose_a_row((round_idx + 1).into());
            a_new_dense
                .0
                .copy_advice(|| "a_new_lo", region, a_7, a_new_row)?;
            a_new_dense
                .1
                .copy_advice(|| "a_new_hi", region, a_7, a_new_row + 1)?;

            // Assign and copy E_new
            let e_new_row = get_decompose_e_row((round_idx + 1).into());
            e_new_dense
                .0
                .copy_advice(|| "e_new_lo", region, a_7, e_new_row)?;
            e_new_dense
                .1
                .copy_advice(|| "e_new_hi", region, a_7, e_new_row + 1)?;

            // Decompose A into (2, 11, 9, 10)-bit chunks
            let a_new = self.decompose_a(region, (round_idx + 1).into(), a_new_val)?;

            // Decompose E into (6, 5, 14, 7)-bit chunks
            let e_new = self.decompose_e(region, (round_idx + 1).into(), e_new_val)?;

            Ok(State::new(
                StateWord::A(a_new),
                StateWord::B(RoundWord::new(a.dense_halves, a.spread_halves.unwrap())),
                StateWord::C(b),
                StateWord::D(c.dense_halves),
                StateWord::E(e_new),
                StateWord::F(RoundWord::new(e.dense_halves, e.spread_halves.unwrap())),
                StateWord::G(f),
                StateWord::H(g.dense_halves),
            ))
        } else {
            Ok(State::new(
                StateWord::A(RoundWordA::new_dense(a_new_dense)),
                StateWord::B(RoundWord::new(a.dense_halves, a.spread_halves.unwrap())),
                StateWord::C(b),
                StateWord::D(c.dense_halves),
                StateWord::E(RoundWordE::new_dense(e_new_dense)),
                StateWord::F(RoundWord::new(e.dense_halves, e.spread_halves.unwrap())),
                StateWord::G(f),
                StateWord::H(g.dense_halves),
            ))
        }
    }

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
            a.dense_halves,b.dense_halves,c.dense_halves,d,
            e.dense_halves,f.dense_halves,g.dense_halves,h,
            ].into_iter().zip([
                a_i.dense_halves, b_i.dense_halves, c_i.dense_halves, d_i, 
                e_i.dense_halves, f_i.dense_halves, g_i.dense_halves, h_i
            ]).enumerate()
        {
            let row = get_digest_first_row() + i*2;
            self.s_digest.enable(region, row)?;
            let (final_lo, final_hi) = final_dense.decompose();
            let (init_lo, init_hi) = init_dense.decompose();

            let (digest, carry) = sum_with_carry(vec![
                    (final_lo.value_u16(), final_hi.value_u16()), 
                    (init_lo.value_u16(), init_hi.value_u16()),
                ]);

            region.assign_advice(||"digest carry", a_8, row, ||carry.map(F::from))?;
            region.assign_advice(||"digest word", a_5, row, ||digest.map(|v|F::from(v as u64)))?;

            final_lo.copy_advice(||"final lo", region, a_3, row)?;
            final_hi.copy_advice(||"final hi", region, a_3, row+1)?;
            init_lo.copy_advice(||"init lo", region, a_6, row)?;
            init_hi.copy_advice(||"init hi", region, a_6, row+1)?;

            let word  = digest.map(|w| i2lebsp(w.into()));
            let digest_lo = word.map(|w: [bool;32]| w[..16].try_into().unwrap());
            let digest_hi = word.map(|w| w[16..].try_into().unwrap());

            let digest_lo = SpreadVar::with_lookup(
                region,
                &self.lookup,
                row,
                digest_lo.map(SpreadWord::<16, 32>::new),
            )?.dense;
            let digest_hi = SpreadVar::with_lookup(
                region,
                &self.lookup,
                row+1,
                digest_hi.map(SpreadWord::<16, 32>::new),
            )?.dense;
            digest_dense.push((digest_lo, digest_hi))
        }

        let ret : [(AssignedBits<F, 16>, AssignedBits<F, 16>); STATE] = digest_dense.try_into().unwrap();
        Ok(ret.map(RoundWordDense::from))
    }

}
