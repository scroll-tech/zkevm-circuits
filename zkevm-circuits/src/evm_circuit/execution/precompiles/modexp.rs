use eth_types::{Field, ToScalar, U256};
use gadgets::{binary_number::AsBits, util::{self, Expr}};
use halo2_proofs::{circuit::Value, plonk::{Expression, Error}};

use bus_mapping::precompile::{PrecompileAuxData, MODEXP_SIZE_LIMIT};
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{constraint_builder::{EVMConstraintBuilder, ConstrainBuilderCommon}, 
            CachedRegion, Cell,Word,
            math_gadget::{BinaryNumberGadget, IsZeroGadget, LtGadget},
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
struct RandPowRepresent<F, const BIT_LIMIT: usize> {
    bits: BinaryNumberGadget<F, BIT_LIMIT>,
    pow_assembles: [Cell<F>;BIT_LIMIT],
}

impl<F: Field, const BIT_LIMIT: usize> RandPowRepresent<F, BIT_LIMIT> {

    /// build randomness r, r**2, ... r**(2**BIT_LIMIT)
    pub fn base_pows_expr(randomness: Expression<F>) -> [Expression<F>;BIT_LIMIT] {
        std::iter::successors(
            Some(randomness.clone()), 
            |r| Some(r.clone() * r.clone())
        ).take(BIT_LIMIT)
        .collect::<Vec<_>>()
        .try_into()
        .expect("same length")
    }

    /// build r**EXP (EXP can be represented by BIT_LIMIT bits)
    pub fn pows_expr<const EXP: usize>(randomness: Expression<F>) -> Expression<F> {
        assert!(2usize.pow(BIT_LIMIT as u32) > EXP, "EXP ({EXP}) can not exceed bit limit (2**{BIT_LIMIT}-1)");
        let bits : [bool; BIT_LIMIT]= EXP.as_bits();
        let base_pows = Self::base_pows_expr(randomness);
        bits.as_slice().iter().rev().zip(&base_pows).fold(
            1.expr(),
            |calc, (&bit, base_pow)|if bit {calc * base_pow.clone()} else {calc}
        )
    }

    /// refere to a binary represent of exponent (like BinaryNumberGadget)
    pub fn configure(
        cb: &mut EVMConstraintBuilder<F>,
        randomness: Expression<F>,
        exponent: Expression<F>,
    ) -> Self {
        let bits = BinaryNumberGadget::construct(cb, exponent);
        let base_pows = Self::base_pows_expr(randomness);
        let pow_assembles = [0; BIT_LIMIT].map(|_|cb.query_cell_phase2());
        let mut last_pow_assemble = 1.expr();
        for ((pow_assemble, exp_bit), base_pow) in 
            pow_assembles
            .as_slice()
            .iter()
            .zip(bits.bits.as_slice().iter().rev())
            .zip(&base_pows) {
            cb.require_equal(
                "pow_assemble = if exp_bit {pow_assemble.last} else {pow_assemble.last*base_pow}  ",
                pow_assemble.expr(),
                util::select::expr(exp_bit.expr(), last_pow_assemble.clone() * base_pow.clone(), last_pow_assemble.clone()),
            );
            last_pow_assemble = pow_assemble.expr();
        }

        Self {
            pow_assembles,
            bits,
        }
    }

    pub fn pow(&self) -> Expression<F> {self.pow_assembles.last().expect("BIT_LIMIT is not zero").expr()}

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        exponent: usize,
    ) -> Result<(), Error> {
        assert!(2usize.pow(BIT_LIMIT as u32) > exponent, "exponent ({exponent}) can not exceed bit limit (2**{BIT_LIMIT}-1)");
        self.bits.assign(region, offset, exponent)?;
        let bits : [bool; BIT_LIMIT]= exponent.as_bits();
        let base_pows = std::iter::successors(
            Some(region
            .challenges()
            .keccak_input()), 
            |val| Some(val.map(|v|v.square()))
        ).take(BIT_LIMIT);

        let mut last_assigned_assemble = Value::known(F::one());
        for ((column, &bit), base_pow) in 
            self.pow_assembles
            .as_slice()
            .iter()
            .zip(bits.as_slice().iter().rev())
            .zip(base_pows) {
            
            let assigned_v = if bit {
                last_assigned_assemble*base_pow
            }else {
                last_assigned_assemble
            };
            column.assign(region, offset, assigned_v)?;
            last_assigned_assemble = assigned_v;
        }

        Ok(())
    }
}


#[derive(Clone, Debug)]
struct FixedRandPowRepresent<F, const EXP: usize, const BIT_LIMIT: usize> (RandPowRepresent<F, BIT_LIMIT>);

impl<F: Field, const EXP: usize, const BIT_LIMIT: usize> AsRef<RandPowRepresent<F, BIT_LIMIT>> for FixedRandPowRepresent<F, EXP, BIT_LIMIT>{
    fn as_ref(&self) -> &RandPowRepresent<F, BIT_LIMIT>{&self.0}
}

const SIZE_LIMIT: usize = MODEXP_SIZE_LIMIT;
const SIZE_REPRESENT_BITS: usize = 6;
const SIZE_REPRESENT_BYTES: usize = SIZE_LIMIT/256 + 1;
const INPUT_LIMIT: usize = 32*6;

#[derive(Clone, Debug)]
struct SizeRepresent<F> {
    len_bytes: Word<F>,
    is_rest_field_zero: IsZeroGadget<F>,
    is_exceed_limit: LtGadget<F, SIZE_REPRESENT_BYTES>,
}

impl<F: Field> SizeRepresent<F> {
    pub fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let len_bytes = cb.query_keccak_rlc();
        // we calculate at most 31 bytes so it can be fit into a field
        let len_blank_bytes = len_bytes.cells[..(32-SIZE_REPRESENT_BYTES)]
            .iter().map(Cell::expr).collect::<Vec<_>>();
        let is_rest_field_zero = IsZeroGadget::construct(cb, 
                util::expr_from_bytes(&len_blank_bytes),
            );
        let len_effect_bytes = len_bytes.cells[(32-SIZE_REPRESENT_BYTES)..]
            .iter().map(Cell::expr).collect::<Vec<_>>();            
        let is_exceed_limit = LtGadget::construct(cb, 
            util::expr_from_bytes(&len_effect_bytes),
            SIZE_LIMIT.expr(),
        );
        Self {
            len_bytes,
            is_rest_field_zero,
            is_exceed_limit,
        }
    }

    /// the rlc of size memory
    pub fn memory_value(&self) -> Expression<F> {
        self.len_bytes.expr()
    }

    pub fn is_valid(&self) -> Expression<F> {
        util::and::expr(
            [
                self.is_rest_field_zero.expr(),
                util::not::expr(self.is_exceed_limit.expr()),
            ]
        )
    }

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        size: &U256,
    ) -> Result<(), Error> {
        let mut bytes = [0u8; 32];
        size.to_big_endian(&mut bytes);
        self.len_bytes.assign(region, offset, Some(bytes))?;
        Ok(())
    }



}

type RandPow<F> = RandPowRepresent<F, SIZE_REPRESENT_BITS>;

// parse as (valid, len, value: [base, exp, modulus])
type InputParsedResult = (bool, [U256;3], [[u8;SIZE_LIMIT];3]);
type OutputParsedResult = (usize, [u8;SIZE_LIMIT]);

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
}

impl<F: Field> ModExpInputs<F> {
    pub fn configure(
        cb: &mut EVMConstraintBuilder<F>,
        input_bytes_acc: Expression<F>,
    ) -> Self {
        let base_len = SizeRepresent::configure(cb);
        let modulus_len = SizeRepresent::configure(cb);
        let exp_len = SizeRepresent::configure(cb);

        let r_pow_32 = RandPowRepresent::<_, 5>::base_pows_expr(
            cb.challenges().keccak_input())[4].clone(); //r**32
        let r_pow_64 = r_pow_32.clone().square();

        let base = cb.query_keccak_rlc();
        let modulus = cb.query_keccak_rlc();
        let exp = cb.query_keccak_rlc();

        let input_valid = cb.query_cell();
        cb.require_equal("mark input valid by checking 3 lens is valid", 
            input_valid.expr(),
            util::and::expr([
                base_len.is_valid(),
                exp_len.is_valid(),
                modulus_len.is_valid(),
            ]),
        );

        // we put correct size in each input word if input is valid
        // else we just put as most as possible bytes (32) into it
        // so we finally handle the memory in limited sized (32*3)
        let base_pow = RandPow::configure(cb, 
            cb.challenges().keccak_input(),
            util::select::expr(input_valid.expr(), 
                base_len.memory_value(), 
                32.expr(),
            ),
        );
        let exp_pow = RandPow::configure(cb, 
            cb.challenges().keccak_input(),
            util::select::expr(input_valid.expr(), 
                exp_len.memory_value(), 
                32.expr(),
            ),
        );
        let modulus_pow = RandPow::configure(cb,
            cb.challenges().keccak_input(),
            util::select::expr(input_valid.expr(), 
                modulus_len.memory_value(), 
                32.expr(),
            ),       
        );

        let r_pow_base = r_pow_64.clone() * base_pow.pow();
        let r_pow_exp = r_pow_base.clone() * exp_pow.pow();
        let r_pow_modulus = r_pow_exp.clone() * modulus_pow.pow();

        cb.require_equal("acc bytes must equal", 
            input_bytes_acc, 
            base_len.memory_value() + 
            r_pow_32 * exp_len.memory_value() +
            r_pow_64 * modulus_len.memory_value() +
            r_pow_base * base.expr() + //rlc of base plus r**(64+base_len)"
            r_pow_exp * exp.expr() + //rlc of exp plus r**(64+base_len+exp_len)
            r_pow_modulus * modulus.expr() //rlc of modulus plus r**(64+base_len+exp_len+modulus_len)
        );

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
        }
    }

    pub fn modulus_len(&self) -> Expression<F> {self.modulus_len.memory_value()}
    pub fn is_valid(&self) -> Expression<F> {self.input_valid.expr()}

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (input_valid, lens, values): InputParsedResult,
    ) -> Result<(), Error> {
        self.input_valid.assign(region, offset, Value::known(if input_valid {F::one()} else {F::zero()}))?;

        for (len, len_represent) in lens.iter().zip([&self.base_len, &self.exp_len, &self.modulus_len]){
            len_represent.assign(region, offset, len)?;
        }

        for (len, pow) in lens.iter().zip([&self.base_pow, &self.exp_pow, &self.modulus_pow]){
            pow.assign(region, offset, if input_valid {len.as_usize()} else {SIZE_LIMIT})?;
        }

        for (val, input_bytes) in values.zip([&self.base, &self.exp, &self.modulus]){
            input_bytes.assign(region, offset, Some(val))?;
        }

        Ok(())
    }

}


#[derive(Clone, Debug)]
struct ModExpOutputs<F> {
    result_pow: RandPow<F>,
    result_pow_prefix: Cell<F>,
    result: Word<F>,
    is_result_zero: IsZeroGadget<F>,
}

impl<F: Field> ModExpOutputs<F> {
    fn configure(
        cb: &mut EVMConstraintBuilder<F>,
        output_bytes_acc: Expression<F>,
        inner_success: Expression<F>,
        modulus_len: Expression<F>,
    ) -> Self {

        let output_len = inner_success * modulus_len;
        let is_result_zero = IsZeroGadget::construct(cb, output_len.clone());

        let result_pow = RandPow::configure(cb, 
            cb.challenges().keccak_input(),
            output_len,
        );
        let result_pow_prefix = cb.query_cell_phase2();        
        let result = cb.query_keccak_rlc();

        let r_pow_32 = RandPowRepresent::<_, 5>::base_pows_expr(
            cb.challenges().keccak_input())[4].clone(); //r**32

        cb.require_equal("use pow prefix as 1/r**32", 
            result_pow_prefix.expr() * r_pow_32, 
            1.expr(),
        );

        cb.condition(is_result_zero.expr(), |cb|{
            cb.require_equal("acc bytes must equal", 
                output_bytes_acc, 
                result_pow_prefix.expr() * result_pow.pow() * result.expr(), 
            );
        });

        Self {
            result_pow,
            result_pow_prefix,
            result,
            is_result_zero,
        }
    }

    pub fn is_output_nil(&self) -> Expression<F> {self.is_result_zero.expr()}

    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        (output_len, data): OutputParsedResult,
    ) -> Result<(), Error> {
        self.result_pow_prefix.assign(region, offset, 
            region.challenges().keccak_input().map(
                |rand|rand.pow_vartime(&[32]).invert().unwrap()
            ))?;
        self.is_result_zero.assign(region, offset, F::from(output_len as u64))?;
        self.result_pow.assign(region, offset, output_len)?;
        self.result.assign(region, offset, Some(data))?;
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
    output: ModExpOutputs<F>,
}

impl<F: Field> ExecutionGadget<F> for ModExpGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBigModExp;

    const NAME: &'static str = "MODEXP";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {

        // we 'copy' the acc_bytes cell inside call_op step, so it must be the first query cells
        let input_bytes_acc = cb.query_copy_cell_phase2();
        let output_bytes_acc = cb.query_copy_cell_phase2();

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

        let input = ModExpInputs::configure(cb, input_bytes_acc.expr());

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

        let output = ModExpOutputs::configure(cb, 
            output_bytes_acc.expr(),
            //FIXME: there may be still some edge cases lead to nil output (even modulus_len is not 0)
            call_success,
            input.modulus_len(),
        );

        cb.condition(util::not::expr(output.is_output_nil()), |_cb|{
            //TODO: config modexp circuit
        });

        Self {
            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            input,
            output,
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

            self.input.assign(region, offset, (
                data.valid,
                data.input_lens,
                data.inputs,
            ))?;

            self.output.assign(region, offset, (
                data.output_len,
                data.output,
            ))?;

        } else {
            log::error!("unexpected aux_data {:?} for modexp", step.aux_data);
            return Err(Error::Synthesis);
        }

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
    use bus_mapping::{
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

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
            ]
        };
    }

    #[test]
    fn precompile_modexp_test() {
        let call_kinds = vec![
//            OpcodeId::CALL,
            OpcodeId::STATICCALL,
//            OpcodeId::DELEGATECALL,
//            OpcodeId::CALLCODE,
        ];

        for (test_vector, &call_kind) in TEST_VECTOR.iter().cartesian_product(&call_kinds) {
            let bytecode = test_vector.with_call_op(call_kind);

            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .run();
        }
    }
}
