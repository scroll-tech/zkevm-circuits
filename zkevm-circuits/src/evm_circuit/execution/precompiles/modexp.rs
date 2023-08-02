use eth_types::{Field, ToScalar, U256};
use gadgets::util::{self, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{BinaryNumberGadget, IsZeroGadget, LtGadget},
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::precompile::{PrecompileAuxData, MODEXP_INPUT_LIMIT, MODEXP_SIZE_LIMIT};

#[derive(Clone, Debug)]
struct RandPowRepresent<F, const BIT_LIMIT: usize> {
    bits: BinaryNumberGadget<F, BIT_LIMIT>,
    pow_lookup: Cell<F>,
    cache_for_degree: Option<Cell<F>>,
    pow: Expression<F>,
}

impl<F: Field, const BIT_LIMIT: usize> RandPowRepresent<F, BIT_LIMIT> {
    const BIT_EXP_MAX_DEGREE: usize = 4;

    /// build randomness r, r**2, ... r**(2**BIT_LIMIT)
    pub fn base_pows_expr(randomness: Expression<F>) -> [Expression<F>; BIT_LIMIT] {
        std::iter::successors(Some(randomness), |r| Some(r.clone() * r.clone()))
            .take(BIT_LIMIT)
            .collect::<Vec<_>>()
            .try_into()
            .expect("same length")
    }

    /// refere to a binary represent of exponent (like BinaryNumberGadget), can
    /// link another expression so the expr is linked_val * r ** exponent
    pub fn configure(
        cb: &mut EVMConstraintBuilder<F>,
        _randomness: Expression<F>,
        exponent: Expression<F>,
        linked_val: Option<Expression<F>>,
    ) -> Self {
        let bits = BinaryNumberGadget::construct(cb, exponent);
        let pow_lookup = cb.query_cell_phase2();
        cb.pow_of_rand_lookup(bits.value(), pow_lookup.expr());

        let pow = linked_val.unwrap_or_else(|| 1.expr()) * pow_lookup.expr();
        // we would cache the pow expression in case degree is too larget
        let cache_for_degree = if pow.degree() > Self::BIT_EXP_MAX_DEGREE {
            let cached_cell = cb.query_cell_phase2();
            cb.require_equal(
                "pow_assemble cached current expression",
                cached_cell.expr(),
                pow.clone(),
            );
            Some(cached_cell)
        } else {
            None
        };

        Self {
            pow_lookup,
            bits,
            pow,
            cache_for_degree,
        }
    }

    pub fn expr(&self) -> Expression<F> {
        self.pow.clone()
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        exponent: usize,
        linked_value: Option<Value<F>>,
    ) -> Result<Value<F>, Error> {
        assert!(
            2usize.pow(BIT_LIMIT as u32) > exponent,
            "exponent ({exponent}) can not exceed bit limit (2**{BIT_LIMIT}-1)"
        );
        self.bits.assign(region, offset, exponent)?;

        let pow_of_rand = region
            .challenges()
            .keccak_input()
            .map(|v| v.pow(&[exponent as u64, 0, 0, 0]));
        let value_should_assigned =
            linked_value.unwrap_or_else(|| Value::known(F::one())) * pow_of_rand;

        self.pow_lookup.assign(region, offset, pow_of_rand)?;

        if let Some(cell) = &self.cache_for_degree {
            cell.assign(region, offset, value_should_assigned)?;
        }

        Ok(value_should_assigned)
    }
}

const SIZE_LIMIT: usize = MODEXP_SIZE_LIMIT;
const SIZE_REPRESENT_BITS: usize = 6;
const SIZE_REPRESENT_BYTES: usize = SIZE_LIMIT / 256 + 1;
const INPUT_LIMIT: usize = 32 * 6;
const INPUT_REPRESENT_BYTES: usize = MODEXP_INPUT_LIMIT / 256 + 1;
const INPUT_REPRESENT_BITS: usize = 8;

type Word<F> = [Cell<F>; 32];

fn assign_word<F: Field, const N: usize>(
    region: &mut CachedRegion<'_, '_, F>,
    offset: usize,
    cells: &[Cell<F>; N],
    bytes: [u8; N],
) -> Result<(), Error> {
    for (cell, byte) in cells.iter().zip(bytes) {
        cell.assign(region, offset, Value::known(F::from(byte as u64)))?;
    }

    Ok(())
}

// rlc cells array, in the reversed byte order
fn rlc_rev<F: Field, const N: usize>(
    cells: &[Cell<F>; N],
    randomness: Expression<F>,
) -> Expression<F> {
    cells
        .iter()
        .map(|cell| cell.expr())
        .reduce(|acc, value| acc * randomness.clone() + value)
        .expect("values should not be empty")
}

// rlc word, in the reversed byte order
fn rlc_word_rev<F: Field>(cells: &[Cell<F>; 32], randomness: Expression<F>) -> Expression<F> {
    rlc_rev(cells, randomness)
}

// calc for big-endian (notice util::expr_from_bytes calc for little-endian)
fn expr_from_bytes<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    bytes
        .iter()
        .fold(0.expr(), |acc, byte| acc * F::from(256) + byte.expr())
}

#[derive(Clone, Debug)]
struct SizeRepresent<F> {
    len_bytes: Word<F>,
    expression: Expression<F>,
    is_rest_field_zero: IsZeroGadget<F>,
    is_not_exceed_limit: LtGadget<F, SIZE_REPRESENT_BYTES>,
}

impl<F: Field> SizeRepresent<F> {
    pub fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let len_bytes = cb.query_bytes();
        let expression = rlc_word_rev(&len_bytes, cb.challenges().keccak_input());
        // we calculate at most 31 bytes so it can be fit into a field
        let len_blank_bytes = len_bytes[..(32 - SIZE_REPRESENT_BYTES)]
            .iter()
            .map(Cell::expr)
            .collect::<Vec<_>>();
        let is_rest_field_zero = IsZeroGadget::construct(
            cb,
            "if length field exceed 1 byte",
            expr_from_bytes(&len_blank_bytes),
        );
        let len_effect_bytes = len_bytes[(32 - SIZE_REPRESENT_BYTES)..]
            .iter()
            .map(Cell::expr)
            .collect::<Vec<_>>();
        let is_not_exceed_limit = LtGadget::construct(
            cb,
            expr_from_bytes(&len_effect_bytes),
            (SIZE_LIMIT + 1).expr(),
        );
        Self {
            len_bytes,
            expression,
            is_rest_field_zero,
            is_not_exceed_limit,
        }
    }

    /// the rlc of size memory, in reversed byte order
    pub fn memory_rlc(&self) -> Expression<F> {
        self.expression.clone()
    }

    /// the value of size
    pub fn value(&self) -> Expression<F> {
        let len_effect_bytes = self.len_bytes[(32 - SIZE_REPRESENT_BYTES)..]
            .iter()
            .map(Cell::expr)
            .collect::<Vec<_>>();
        expr_from_bytes(&len_effect_bytes)
    }

    pub fn is_valid(&self) -> Expression<F> {
        util::and::expr([
            self.is_rest_field_zero.expr(),
            self.is_not_exceed_limit.expr(),
        ])
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        size: &U256,
    ) -> Result<(), Error> {
        let mut bytes = [0u8; 32];
        size.to_big_endian(&mut bytes);

        assign_word(region, offset, &self.len_bytes, bytes)?;

        let rest_field = U256::from_big_endian(&bytes[..(32 - SIZE_REPRESENT_BYTES)]);
        let effect_field = U256::from_big_endian(&bytes[(32 - SIZE_REPRESENT_BYTES)..]);

        self.is_rest_field_zero
            .assign(region, offset, rest_field.to_scalar().unwrap())?;
        self.is_not_exceed_limit.assign(
            region,
            offset,
            effect_field.to_scalar().unwrap(),
            F::from((SIZE_LIMIT + 1) as u64),
        )?;
        Ok(())
    }
}

type RandPow<F> = RandPowRepresent<F, SIZE_REPRESENT_BITS>;

// parse as (valid, len, value: [base, exp, modulus])
type InputParsedResult = (bool, [U256; 3], [[u8; SIZE_LIMIT]; 3]);
type OutputParsedResult = (usize, [u8; SIZE_LIMIT]);

#[derive(Clone, Debug)]
struct ModExpInputs<F> {
    base_len: SizeRepresent<F>,
    modulus_len: SizeRepresent<F>,
    exp_len: SizeRepresent<F>,
    base_pow: RandPow<F>,
    base: Word<F>,
    modulus_pow: RandPow<F>,
    modulus: Word<F>,
    exp_pow: RandPow<F>,
    exp: Word<F>,
    input_valid: Cell<F>,
    input_bytes_rlc: Expression<F>,
    input_len_expected: Expression<F>,
    pub base_limbs: Limbs<F>,
    pub exp_limbs: Limbs<F>,
    pub modulus_limbs: Limbs<F>,
}

impl<F: Field> ModExpInputs<F> {
    pub fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let base_len = SizeRepresent::configure(cb);
        let modulus_len = SizeRepresent::configure(cb);
        let exp_len = SizeRepresent::configure(cb);

        let r_pow_32 =
            RandPowRepresent::<_, 6>::base_pows_expr(cb.challenges().keccak_input())[5].clone(); //r**32
        let r_pow_64 = r_pow_32.clone().square();

        let base = cb.query_bytes();
        let modulus = cb.query_bytes();
        let exp = cb.query_bytes();

        let base_limbs = Limbs::configure(cb, &base);
        let exp_limbs = Limbs::configure(cb, &exp);
        let modulus_limbs = Limbs::configure(cb, &modulus);

        let input_valid = cb.query_bool();
        cb.require_equal(
            "mark input valid by checking 3 lens is valid",
            input_valid.expr(),
            util::and::expr([
                base_len.is_valid(),
                exp_len.is_valid(),
                modulus_len.is_valid(),
            ]),
        );

        let base_len_expected = util::select::expr(input_valid.expr(), base_len.value(), 0.expr());

        let exp_len_expected = util::select::expr(input_valid.expr(), exp_len.value(), 0.expr());

        let modulus_len_expected =
            util::select::expr(input_valid.expr(), modulus_len.value(), 0.expr());

        let input_len_expected = 96.expr()
            + base_len_expected.clone()
            + exp_len_expected.clone()
            + modulus_len_expected.clone();

        // we put correct size in each input word if input is valid
        // else we just put as most as possible bytes (32) into it
        // so we finally handle the memory in limited sized (32*3)
        let modulus_pow = RandPow::configure(
            cb,
            cb.challenges().keccak_input(),
            modulus_len_expected,
            None,
        );

        // exp_pow = r**(modulus_len + exp_len)
        let exp_pow = RandPow::configure(
            cb,
            cb.challenges().keccak_input(),
            exp_len_expected,
            Some(modulus_pow.expr()),
        );

        // base_pow = r**(modulus_len + exp_len + base_len)
        let base_pow = RandPow::configure(
            cb,
            cb.challenges().keccak_input(),
            base_len_expected,
            Some(exp_pow.expr()),
        );

        let input_bytes_rlc = rlc_word_rev(&modulus, cb.challenges().keccak_input()) //rlc of base
            + modulus_pow.expr() * rlc_word_rev(&exp, cb.challenges().keccak_input()) //rlc of exp plus r**base_len
            + exp_pow.expr() * rlc_word_rev(&base, cb.challenges().keccak_input()) //rlc of exp plus r**(base_len + exp_len)
            + base_pow.expr() * modulus_len.memory_rlc()
            + base_pow.expr() * r_pow_32 * exp_len.memory_rlc()
            + base_pow.expr() * r_pow_64 * base_len.memory_rlc();

        // println!("phase 2 cell used {}",
        //     padding_pow.phase2_cell_cost() + [&modulus_pow, &exp_pow,
        // &base_pow].iter().map(|pw|pw.phase2_cell_cost()).sum::<usize>() );

        Self {
            base_len,
            modulus_len,
            exp_len,
            base_pow,
            base,
            modulus_pow,
            modulus,
            exp_pow,
            exp,
            input_valid,
            input_bytes_rlc,
            input_len_expected,
            base_limbs,
            exp_limbs,
            modulus_limbs,
        }
    }

    pub fn modulus_len(&self) -> Expression<F> {
        self.modulus_len.value()
    }
    pub fn is_valid(&self) -> Expression<F> {
        self.input_valid.expr()
    }
    pub fn len_expected(&self) -> Expression<F> {
        self.input_len_expected.clone()
    }
    pub fn bytes_rlc(&self) -> Expression<F> {
        self.input_bytes_rlc.clone()
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (input_valid, lens, values): InputParsedResult,
    ) -> Result<(), Error> {
        self.input_valid.assign(
            region,
            offset,
            Value::known(if input_valid { F::one() } else { F::zero() }),
        )?;

        for (len, len_represent) in
            lens.iter()
                .zip([&self.base_len, &self.exp_len, &self.modulus_len])
        {
            len_represent.assign(region, offset, len)?;
        }

        let mut linked_v = None;
        for (len, pow) in lens
            .iter()
            .zip([&self.base_pow, &self.exp_pow, &self.modulus_pow])
            .rev()
        {
            let assigned = pow.assign(
                region,
                offset,
                if input_valid { len.as_usize() } else { 0 },
                linked_v,
            )?;

            linked_v = Some(assigned);
        }

        for (val_r, input_limbs) in
            values
                .iter()
                .zip([&self.base_limbs, &self.exp_limbs, &self.modulus_limbs])
        {
            input_limbs.assign(region, offset, val_r)?;
        }

        for (val, input_bytes) in values.zip([&self.base, &self.exp, &self.modulus]) {
            assign_word(region, offset, input_bytes, val)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ModExpOutputs<F> {
    result: Word<F>,
    is_result_zero: IsZeroGadget<F>,
    output_bytes_rlc: Expression<F>,
    pub result_limbs: Limbs<F>,
}

impl<F: Field> ModExpOutputs<F> {
    fn configure(
        cb: &mut EVMConstraintBuilder<F>,
        inner_success: Expression<F>,
        modulus_len: Expression<F>,
    ) -> Self {
        let output_len = inner_success * modulus_len;
        let is_result_zero = IsZeroGadget::construct(cb, "if output len is nil", output_len);

        let result = cb.query_bytes();
        let result_limbs = Limbs::configure(cb, &result);

        let output_bytes_rlc = util::select::expr(
            is_result_zero.expr(),
            0.expr(),
            rlc_word_rev(&result, cb.challenges().keccak_input()),
        );

        Self {
            result,
            is_result_zero,
            output_bytes_rlc,
            result_limbs,
        }
    }

    pub fn is_nil(&self) -> Expression<F> {
        self.is_result_zero.expr()
    }

    pub fn bytes_rlc(&self) -> Expression<F> {
        self.output_bytes_rlc.clone()
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (output_len, data): OutputParsedResult,
    ) -> Result<(), Error> {
        self.is_result_zero
            .assign(region, offset, F::from(output_len as u64))?;
        self.result_limbs.assign(region, offset, &data)?;
        assign_word(region, offset, &self.result, data)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Limbs<F> {
    byte14_split_lo: Cell<F>,
    byte14_split_hi: Cell<F>,
    limbs: [Expression<F>; 3],
}

impl<F: Field> Limbs<F> {
    pub fn configure(cb: &mut EVMConstraintBuilder<F>, word: &Word<F>) -> Self {
        let byte14_split_lo = cb.query_byte();
        let byte14_split_hi = cb.query_byte();

        cb.require_equal(
            "split 14th byte in word into half",
            word[MODEXP_SIZE_LIMIT - 14].expr(),
            byte14_split_lo.expr() + byte14_split_hi.expr(),
        );

        let inv_16 = Expression::Constant(F::from(16u64).invert().unwrap());

        let limbs = [
            expr_from_bytes(
                &std::iter::once(&byte14_split_lo)
                    .chain(&word[MODEXP_SIZE_LIMIT - 13..])
                    .collect::<Vec<_>>(),
            ),
            expr_from_bytes(
                &word[MODEXP_SIZE_LIMIT - 27..MODEXP_SIZE_LIMIT - 14]
                    .iter()
                    .chain(std::iter::once(&byte14_split_hi))
                    .collect::<Vec<_>>(),
            ) * inv_16,
            expr_from_bytes(&word[..MODEXP_SIZE_LIMIT - 27]),
        ];

        Self {
            byte14_split_hi,
            byte14_split_lo,
            limbs,
        }
    }

    pub fn limbs(&self) -> [Expression<F>; 3] {
        self.limbs.clone()
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        big_int: &[u8; MODEXP_SIZE_LIMIT],
    ) -> Result<(), Error> {
        let byte14_lo = big_int[MODEXP_SIZE_LIMIT - 14] & 0xf;
        let byte14_hi = big_int[MODEXP_SIZE_LIMIT - 14] & 0xf0;

        self.byte14_split_lo
            .assign(region, offset, Value::known(F::from(byte14_lo as u64)))?;
        self.byte14_split_hi
            .assign(region, offset, Value::known(F::from(byte14_hi as u64)))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ModExpGadget<F> {
    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,

    input: ModExpInputs<F>,
    padding_zero: RandPowRepresent<F, INPUT_REPRESENT_BITS>,
    output: ModExpOutputs<F>,

    input_bytes_acc: Cell<F>,
    output_bytes_acc: Cell<F>,
    garbage_bytes_holder: [Cell<F>; INPUT_LIMIT - 96],
}

impl<F: Field> ExecutionGadget<F> for ModExpGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBigModExp;

    const NAME: &'static str = "MODEXP";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // we 'copy' the acc_bytes cell inside call_op step, so it must be the first query cells
        let input_bytes_acc = cb.query_cell_phase2();
        let output_bytes_acc = cb.query_cell_phase2();

        let [is_success, callee_address, caller_id, call_data_offset, call_data_length, return_data_offset, return_data_length] =
            [
                CallContextFieldTag::IsSuccess,
                CallContextFieldTag::CalleeAddress,
                CallContextFieldTag::CallerId,
                CallContextFieldTag::CallDataOffset,
                CallContextFieldTag::CallDataLength,
                CallContextFieldTag::ReturnDataOffset,
                CallContextFieldTag::ReturnDataLength,
            ]
            .map(|tag| cb.call_context(None, tag));

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        let input = ModExpInputs::configure(cb);
        let padding_zero = RandPowRepresent::configure(
            cb,
            cb.challenges().keccak_input(),
            MODEXP_INPUT_LIMIT.expr() - input.len_expected(),
            None,
        );

        let call_success = util::and::expr([
            input.is_valid(),
            //TODO: replace this constants when gas gadget is ready
            1.expr(),
        ]);

        cb.require_equal(
            "call success if valid input and enough gas",
            is_success.expr(),
            call_success.clone(),
        );

        let output = ModExpOutputs::configure(
            cb,
            //FIXME: there may be still some edge cases lead to nil output (even modulus_len is
            // not 0)
            call_success,
            input.modulus_len(),
        );

        cb.condition(util::not::expr(output.is_nil()), |cb| {
            cb.modexp_table_lookup(
                input.base_limbs.limbs(),
                input.exp_limbs.limbs(),
                input.modulus_limbs.limbs(),
                output.result_limbs.limbs(),
            );
        });

        let garbage_bytes_holder = cb.query_bytes();

        cb.require_equal(
            "input acc bytes with padding must equal",
            input_bytes_acc.expr(),
            padding_zero.expr() * input.bytes_rlc()
                + rlc_rev(&garbage_bytes_holder, cb.challenges().keccak_input()),
        );

        cb.require_equal(
            "output acc bytes must equal",
            output_bytes_acc.expr(),
            output.bytes_rlc(),
        );

        Self {
            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            input,
            padding_zero,
            output,
            input_bytes_acc,
            output_bytes_acc,
            garbage_bytes_holder,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        _block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        if let Some(PrecompileAuxData::Modexp(data)) = &step.aux_data {
            //println!("exp data: {:?}", data);

            self.input
                .assign(region, offset, (data.valid, data.input_lens, data.inputs))?;

            let input_expected_len = 96
                + if data.valid {
                    data.input_lens.iter().map(U256::as_usize).sum::<usize>()
                } else {
                    0
                };

            let garbage_bytes = if call.call_data_length as usize > input_expected_len {
                let mut bts = Vec::new();
                bts.resize(input_expected_len - 96, 0); //front prefix zero
                bts.append(&mut Vec::from(&data.input_memory[input_expected_len..]));
                bts.resize(96, 0); //padding zero
                bts
            } else {
                Vec::from([0u8; 96])
            };

            //println!("garbage bytes {:?}", garbage_bytes);

            self.padding_zero
                .assign(region, offset, INPUT_LIMIT - input_expected_len, None)?;

            for (cell, bt) in self.garbage_bytes_holder.iter().zip(garbage_bytes) {
                cell.assign(region, offset, Value::known(F::from(bt as u64)))?;
            }

            self.output
                .assign(region, offset, (data.output_len, data.output))?;

            let input_rlc = region
                .challenges()
                .keccak_input()
                .map(|randomness| rlc::value(data.input_memory.iter().rev(), randomness));

            let n_padded_zeroes_pow = region
                .challenges()
                .keccak_input()
                .map(|r| r.pow(&[INPUT_LIMIT as u64 - call.call_data_length, 0, 0, 0]));

            let output_rlc = region
                .challenges()
                .keccak_input()
                .map(|randomness| rlc::value(data.output_memory.iter().rev(), randomness));

            self.input_bytes_acc
                .assign(region, offset, n_padded_zeroes_pow * input_rlc)?;
            self.output_bytes_acc.assign(region, offset, output_rlc)?;
        } else {
            log::error!("unexpected aux_data {:?} for modexp", step.aux_data);
            return Err(Error::Synthesis);
        }

        //println!("call success {}", call.is_success);
        self.is_success.assign(
            region,
            offset,
            Value::known(F::from(u64::from(call.is_success))),
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(call.code_address.unwrap().to_scalar().unwrap()),
        )?;
        self.caller_id
            .assign(region, offset, Value::known(F::from(call.caller_id as u64)))?;
        self.call_data_offset.assign(
            region,
            offset,
            Value::known(F::from(call.call_data_offset)),
        )?;
        self.call_data_length.assign(
            region,
            offset,
            Value::known(F::from(call.call_data_length)),
        )?;
        self.return_data_offset.assign(
            region,
            offset,
            Value::known(F::from(call.return_data_offset)),
        )?;
        self.return_data_length.assign(
            region,
            offset,
            Value::known(F::from(call.return_data_length)),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bus_mapping::{
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    #[test]
    fn test_limbs() {
        use crate::table::ModExpTable;
        use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
        use misc_precompiled_circuit::circuits::modexp::Number;
        use num_bigint::BigUint;

        // simply take an hash for test
        let bi = BigUint::parse_bytes(
            b"fcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47",
            16,
        )
        .unwrap();
        let n = Number::<Fr>::from_bn(&bi);
        let w = word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47");
        let mut bytes = [0u8; 32];
        w.to_big_endian(&mut bytes);
        assert_eq!(BigUint::from_bytes_be(&bytes), bi);

        let byte14_lo = bytes[MODEXP_SIZE_LIMIT - 14] & 0xf;
        let byte14_hi = bytes[MODEXP_SIZE_LIMIT - 14] & 0xf0;

        let limb0: Fr = U256::from_big_endian(
            &(std::iter::once(byte14_lo))
                .chain(bytes[MODEXP_SIZE_LIMIT - 13..].iter().copied())
                .collect::<Vec<_>>(),
        )
        .to_scalar()
        .unwrap();

        let limb1: Fr = U256::from_big_endian(
            &bytes[MODEXP_SIZE_LIMIT - 27..MODEXP_SIZE_LIMIT - 14]
                .iter()
                .copied()
                .chain(std::iter::once(byte14_hi))
                .collect::<Vec<_>>(),
        )
        .to_scalar()
        .unwrap();

        let limb2: Fr = U256::from_big_endian(&bytes[..MODEXP_SIZE_LIMIT - 27])
            .to_scalar()
            .unwrap();

        assert_eq!(limb0, n.limbs[0].value);
        assert_eq!(limb1, n.limbs[1].value * Fr::from(16_u64));
        assert_eq!(limb2, n.limbs[2].value);

        let nt: Fr = ModExpTable::native_u256(&w);

        let table_split = ModExpTable::split_u256_108bit_limbs(&w);
        assert_eq!(Fr::from_u128(table_split[0]), n.limbs[0].value);
        assert_eq!(Fr::from_u128(table_split[1]), n.limbs[1].value);
        assert_eq!(Fr::from_u128(table_split[2]), n.limbs[2].value);
        assert_eq!(nt, n.limbs[3].value);
        //Limb::new(None, value)
    }

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "modexp success",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x1)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x1)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x63.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp success",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x3)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x2)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x66.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp success with padding 0",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x3)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x2)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x65.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp no input",
                    setup_code: bytecode! {
                        // just put something in memory
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x0.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp success with garbage bytes",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x3)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x2)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000009"))
                        PUSH1(0x80)
                        MSTORE
                        PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                        PUSH1(0xA0)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0xc0.into(),
                    ret_offset: 0xe0.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp zero modulus",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x2)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x0)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0800090000000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x63.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
            ]
        };

        static ref TEST_U256_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "modexp length in u256",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x20)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x20)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x20)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000008"))
                        PUSH1(0x60)
                        MSTORE
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000009"))
                        PUSH1(0x80)
                        MSTORE
                        PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                        PUSH1(0xA0)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0xc0.into(),
                    ret_offset: 0xe0.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "modexp length in u256 and result wrapped",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x20)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x20)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x20)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000008"))
                        PUSH1(0x60)
                        MSTORE
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000064"))
                        PUSH1(0x80)
                        MSTORE
                        PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                        PUSH1(0xA0)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0xc0.into(),
                    ret_offset: 0xe0.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    ..Default::default()
                },
            ]
        };

        static ref TEST_INVALID_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "modexp length too large invalid",
                    setup_code: bytecode! {
                        // Base size
                        PUSH1(0x1)
                        PUSH1(0x00)
                        MSTORE
                        // Esize
                        PUSH1(0x1)
                        PUSH1(0x20)
                        MSTORE
                        // Msize
                        PUSH1(0x21)
                        PUSH1(0x40)
                        MSTORE
                        // B, E and M
                        PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x0.into(),
                    call_data_length: 0x63.into(),
                    ret_offset: 0x9f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Modexp.address().to_word(),
                    gas: 100000.into(),
                    ..Default::default()
                },
            ]
        };
    }

    #[ignore]
    #[test]
    fn precompile_modexp_test_fast() {
        let bytecode = TEST_VECTOR[4].with_call_op(OpcodeId::STATICCALL);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn precompile_modexp_test_basic() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        for (test_vector, &call_kind) in TEST_VECTOR.iter().cartesian_product(&call_kinds) {
            let bytecode = test_vector.with_call_op(call_kind);

            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .run();
        }
    }

    #[test]
    fn precompile_modexp_test_u256() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        for (test_vector, &call_kind) in TEST_U256_VECTOR.iter().cartesian_product(&call_kinds) {
            let bytecode = test_vector.with_call_op(call_kind);

            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .run();
        }
    }

    // notice, "invalid" test would not work until bus-mapping put calling fail case being handle
    // in normal CallOp, i.e. return None in
    // bus_mapping::circuit_input_builder::input_state_ref::CircuitInputStateRef::get_step_err
    // for unsuccess (call.is_success is false) call
    #[ignore]
    #[test]
    fn precompile_modexp_test_invalid() {
        use eth_types::evm_types::Gas;

        for test_vector in TEST_INVALID_VECTOR.iter() {
            let bytecode = test_vector.with_call_op(OpcodeId::STATICCALL);

            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .geth_data_modifier(Box::new(|block| {
                let steps = &mut block.geth_traces[0].struct_logs;
                let step_len = steps.len();
                let call_step = &mut steps[step_len - 3];
                assert_eq!(call_step.op, OpcodeId::STATICCALL);
                call_step.refund.0 = 0;
                let next_gas = Gas(call_step.gas.0 - call_step.gas_cost.0);

                let pop_step = &mut steps[step_len - 2];
                assert_eq!(pop_step.op, OpcodeId::POP);
                pop_step.gas = next_gas;
                pop_step.stack.0[0] = 0.into();
                let next_gas = Gas(pop_step.gas.0 - pop_step.gas_cost.0);
                let final_step = &mut steps[step_len - 1];
                assert_eq!(final_step.op, OpcodeId::STOP);
                final_step.gas = next_gas;

                // println!("trace {:?}", block.geth_traces);
            }))
            .run();
        }
    }
}
