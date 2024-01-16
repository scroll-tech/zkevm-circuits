use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Expression};

use super::{
    constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
    math_gadget::IsZeroGadget,
    CachedRegion, Cell,
};

#[derive(Clone, Debug)]
pub struct PaddingGadget<F> {
    is_cd_len_zero: IsZeroGadget<F>,
    padded_rlc: Cell<F>,
    power_of_rand: Cell<F>,
}

impl<F: Field> PaddingGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        input_rlc: Expression<F>,
        cd_len: Expression<F>,
        input_len: Expression<F>,
    ) -> Self {
        let is_cd_len_zero = IsZeroGadget::construct(cb, cd_len.expr());
        let padded_rlc = cb.query_cell_phase2();
        let power_of_rand = cb.query_cell_phase2();

        // for calldata length == 0, we expect the input RLC and padded RLC to be the same, i.e. 0.
        cb.condition(is_cd_len_zero.expr(), |cb| {
            cb.require_equal(
                "padded RLC == input RLC",
                padded_rlc.expr(),
                input_rlc.expr(),
            );
            cb.require_zero("input RLC == 0", input_rlc.expr());
        });

        // for calldata length > 0 && calldata length < required input length.
        cb.condition(not::expr(is_cd_len_zero.expr()), |cb| {
            // No. of right padded zeroes is the difference between the required input length and
            // the length of the provided input bytes. We only support right-padding by
            // up to 191 bytes, as that's the maximum we ever require considering all
            // cases (modexp, ecrecover, ecAdd, ecMul).
            let n_padded_zeroes = input_len.expr() - cd_len.expr();
            cb.range_lookup(n_padded_zeroes.expr(), 192);

            // Power of randomness we are interested in, i.e. r ^ n_padded_zeroes.
            cb.pow_of_rand_lookup(n_padded_zeroes.expr(), power_of_rand.expr());

            // Validate value of padded RLC.
            cb.require_equal(
                "padded RLC == input RLC * pow_of_r",
                padded_rlc.expr(),
                input_rlc * power_of_rand.expr(),
            );
        });

        Self {
            is_cd_len_zero,
            padded_rlc,
            power_of_rand,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        precompile: PrecompileCalls,
        input_rlc: Value<F>,
        cd_len: u64,
        keccak_rand: Value<F>,
    ) -> Result<u64, halo2_proofs::plonk::Error> {
        let (input_len, padded_rlc, power_of_rand) =
            if let Some(required_input_len) = precompile.input_len() {
                // skip padding if calldata length == 0.
                if cd_len == 0 {
                    (required_input_len as u64, input_rlc, Value::known(F::one()))
                } else {
                    // pad only if calldata length is less than the required input length.
                    let n_padded_zeroes = if cd_len < required_input_len as u64 {
                        (required_input_len as u64) - cd_len
                    } else {
                        0
                    };
                    assert!(required_input_len <= 192);
                    assert!(n_padded_zeroes < 192);
                    let power_of_rand = keccak_rand.map(|r| r.pow([n_padded_zeroes, 0, 0, 0]));
                    (
                        required_input_len as u64,
                        input_rlc * power_of_rand,
                        power_of_rand,
                    )
                }
            } else {
                (cd_len, input_rlc, Value::known(F::one()))
            };

        self.is_cd_len_zero.assign(region, offset, cd_len.into())?;
        self.padded_rlc.assign(region, offset, padded_rlc)?;
        self.power_of_rand.assign(region, offset, power_of_rand)?;

        Ok(input_len)
    }

    pub(crate) fn padded_rlc(&self) -> Expression<F> {
        self.padded_rlc.expr()
    }
}
