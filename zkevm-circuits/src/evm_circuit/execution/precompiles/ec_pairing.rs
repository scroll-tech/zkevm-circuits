use bus_mapping::{
    circuit_input_builder::{N_BYTES_PER_PAIR, N_PAIRING_PER_OP},
    precompile::{EcPairingError, PrecompileAuxData, PrecompileCalls},
};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{and, not, or, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{BinaryNumberGadget, IsZeroGadget, LtGadget},
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

/// Note: input_len ∈ { 0, 192, 384, 576, 768 } if valid.
///
/// Note: input bytes are padded to 768 bytes within our zkEVM implementation to standardise a
/// pairing operation, such that each pairing op has 4 pairs: [(G1, G2); 4].
#[derive(Clone, Debug)]
pub struct EcPairingGadget<F> {
    // Random linear combination of input bytes to the precompile ecPairing call.
    input_bytes_rlc: Cell<F>,
    // output bytes from ecpairing call.
    output_bytes_rlc: Cell<F>,
    // return bytes
    return_bytes_rlc: Cell<F>,

    // Boolean output from the ecPairing call, denoting whether or not the pairing check was
    // successful.
    output: Cell<F>,

    // Verify invalidity of input bytes. We basically check `or(1, 2)` where:
    // 1. input_len > 4 * 192
    // 2. input_len % 192 != 0
    input_is_zero: IsZeroGadget<F>,

    // call_data_len must less than 2^32.
    input_lt_769: LtGadget<F, 4>,
    input_mod_192: Cell<F>,
    input_div_192: Cell<F>,
    input_mod_192_lt: LtGadget<F, 1>,
    input_mod_192_is_zero: IsZeroGadget<F>,

    /// Number of pairs provided through EVM input. Since a maximum of 4 pairs can be supplied from
    /// EVM, we need 3 binary bits for a max value of [1, 0, 0].
    n_pairs: Cell<F>,
    n_pairs_cmp: BinaryNumberGadget<F, 3>,
    rand_pow_64: Cell<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcPairingGadget<F> {
    const NAME: &'static str = "EC_PAIRING";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBn256Pairing;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (input_bytes_rlc, output_bytes_rlc, return_bytes_rlc, output) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_bool(),
        );

        let n_pairs = cb.query_cell();
        let n_pairs_cmp = BinaryNumberGadget::construct(cb, n_pairs.expr());

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

        // all gas sent to this call will be consumed if `is_success == false`.
        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_BN256PAIRING.expr()
                + n_pairs.expr() * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.expr(),
            cb.curr.state.gas_left.expr(),
        );

        // if the precompile call was unsuccessful, the output (pairing check) MUST BE 0.
        // `is_success` and `output` both are booleans, so:
        cb.require_boolean(
            "if the precompile call was unsuccessful, pairing check == 0",
            is_success.expr() - output.expr(),
        );

        //////////////////////////////// INVALID BEGIN ////////////////////////////////
        let input_is_zero = IsZeroGadget::construct(cb, call_data_length.expr());
        let input_lt_769 = LtGadget::construct(cb, call_data_length.expr(), 769.expr());
        let (input_mod_192, input_div_192, input_mod_192_lt, input_mod_192_is_zero) = cb.condition(
            and::expr([not::expr(input_is_zero.expr()), input_lt_769.expr()]),
            |cb| {
                // r == len(input) % 192
                let input_mod_192 = cb.query_byte();
                // r < 192
                let input_mod_192_lt = LtGadget::construct(cb, input_mod_192.expr(), 192.expr());
                cb.require_equal("len(input) % 192 < 192", input_mod_192_lt.expr(), 1.expr());
                // q == len(input) // 192
                let input_div_192 = cb.query_cell();
                cb.require_in_set(
                    "len(input) // 192 ∈ { 0, 1, 2, 3, 4 }",
                    input_div_192.expr(),
                    vec![0.expr(), 1.expr(), 2.expr(), 3.expr(), 4.expr()],
                );
                // q * 192 + r == call_data_length
                cb.require_equal(
                    "q * 192 + r == len(input)",
                    input_div_192.expr() * 192.expr() + input_mod_192.expr(),
                    call_data_length.expr(),
                );
                let input_mod_192_is_zero = IsZeroGadget::construct(cb, input_mod_192.expr());
                (
                    input_mod_192,
                    input_div_192,
                    input_mod_192_lt,
                    input_mod_192_is_zero,
                )
            },
        );
        cb.condition(
            // (len(input) > 768) || (len(input) % 192 != 0)
            or::expr([
                not::expr(input_lt_769.expr()),
                not::expr(input_mod_192_is_zero.expr()),
            ]),
            |cb| {
                cb.require_equal(
                    "len(input) is invalid => is_success == false",
                    is_success.expr(),
                    false.expr(),
                );
                cb.require_zero("pairing check == 0", output.expr());
            },
        );
        //////////////////////////////// INVALID END //////////////////////////////////

        ///////////////////////////////// VALID BEGIN /////////////////////////////////
        let rand_pow_64 = cb.condition(
            // (len(input) == 0) || ((len(input) <= 768) && (len(input) % 192 == 0))
            or::expr([
                input_is_zero.expr(),
                and::expr([input_lt_769.expr(), input_mod_192_is_zero.expr()]),
            ]),
            |cb| {
                let rand_pow_64 = cb.query_cell_phase2();
                let (rand_pow_192, rand_pow_384, rand_pow_576) = {
                    let rand_pow_128 = rand_pow_64.expr() * rand_pow_64.expr();
                    let rand_pow_192 = rand_pow_128.expr() * rand_pow_64.expr();
                    let rand_pow_384 = rand_pow_192.expr() * rand_pow_192.expr();
                    let rand_pow_576 = rand_pow_384.expr() * rand_pow_192.expr();
                    (rand_pow_192, rand_pow_384, rand_pow_576)
                };
                cb.pow_of_rand_lookup(64.expr(), rand_pow_64.expr());

                // RLC(inputs) that was processed in the ECC Circuit.
                let ecc_circuit_input_rlc = select::expr(
                    n_pairs_cmp.value_equals(0usize),
                    0.expr(),
                    select::expr(
                        n_pairs_cmp.value_equals(1usize),
                        input_bytes_rlc.expr() * rand_pow_576.expr(), /* 576 bytes padded */
                        select::expr(
                            n_pairs_cmp.value_equals(2usize),
                            input_bytes_rlc.expr() * rand_pow_384.expr(), /* 384 bytes padded */
                            select::expr(
                                n_pairs_cmp.value_equals(3usize),
                                input_bytes_rlc.expr() * rand_pow_192.expr(), /* 192 bytes padded */
                                input_bytes_rlc.expr(),                       /* 0 bytes padded */
                            ),
                        ),
                    ),
                );
                cb.condition(n_pairs_cmp.value_equals(0usize), |cb| {
                    cb.require_zero(
                        "ecPairing: n_pairs == 0 => evm input == 0",
                        input_bytes_rlc.expr(),
                    );
                });

                // Covers the following cases:
                // 1. pairing == 1 (where input_rlc == 0, i.e. len(input) == 0).
                // 2. pairing == 1 (where input_rlc != 0, i.e. len(input) != 0).
                // 3. pairing == 0 (both valid and invalid inputs)
                //     - G1 point not on curve
                //     - G2 point not on curve
                //     - G1 co-ord is not in canonical form
                //     - G2 co-ord is not in canonical form
                //     - G1, G2 both valid
                cb.ecc_table_lookup(
                    u64::from(PrecompileCalls::Bn128Pairing).expr(),
                    is_success.expr(),
                    0.expr(),
                    0.expr(),
                    0.expr(),
                    0.expr(),
                    ecc_circuit_input_rlc.expr(),
                    output.expr(),
                    0.expr(),
                );

                // since len(input) was valid, we know that we are left with 3 scenarios:
                // 1. pairing check == true
                // 2. pairing check == false
                // 3. invalid inputs:
                //      - invalid field element
                //      - point not on G1
                //      - point not on G2
                //
                // In all the above, we know that len(input) % 192 == 0 and len(input) <= 768
                cb.require_equal(
                    "ecPairing: n_pairs * N_BYTES_PER_PAIR == call_data_length",
                    n_pairs.expr() * N_BYTES_PER_PAIR.expr(),
                    call_data_length.expr(),
                );
                cb.require_in_set(
                    "ecPairing: input_len ∈ { 0, 192, 384, 576, 768 }",
                    call_data_length.expr(),
                    vec![0.expr(), 192.expr(), 384.expr(), 576.expr(), 768.expr()],
                );

                rand_pow_64
            },
        );
        ///////////////////////////////// VALID END ///////////////////////////////////

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(),                                               // ReturnDataOffset
            select::expr(is_success.expr(), 0x20.expr(), 0x00.expr()), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,

            output,

            input_is_zero,
            input_lt_769,
            input_mod_192,
            input_div_192,
            input_mod_192_lt,
            input_mod_192_is_zero,

            n_pairs,
            n_pairs_cmp,
            rand_pow_64,

            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        if let Some(PrecompileAuxData::EcPairing(res_aux_data)) = step.aux_data.clone() {
            let keccak_rand = region.challenges().keccak_input();

            // len(input) related assignment.
            self.input_is_zero
                .assign(region, offset, F::from(call.call_data_length))?;
            log::trace!(
                "assign ec pairing exec step: calldata_len = {}",
                call.call_data_length
            );
            self.input_lt_769.assign(
                region,
                offset,
                F::from(call.call_data_length),
                F::from(769),
            )?;
            let (input_div_192, input_mod_192) = (
                call.call_data_length / (N_BYTES_PER_PAIR as u64),
                call.call_data_length % (N_BYTES_PER_PAIR as u64),
            );
            self.input_div_192
                .assign(region, offset, Value::known(F::from(input_div_192)))?;
            self.input_mod_192
                .assign(region, offset, Value::known(F::from(input_mod_192)))?;
            self.input_mod_192_lt
                .assign(region, offset, F::from(input_mod_192), F::from(192))?;
            self.input_mod_192_is_zero
                .assign(region, offset, F::from(input_mod_192))?;

            match *res_aux_data {
                Ok(aux_data) => {
                    debug_assert!(
                        call.call_data_length <= (N_PAIRING_PER_OP * N_BYTES_PER_PAIR) as u64,
                        "len(input) > 768"
                    );
                    debug_assert!(
                        call.call_data_length % (N_BYTES_PER_PAIR as u64) == 0,
                        "len(input) % 192 != 0"
                    );
                    // Consider only call_data_length bytes for EVM input.
                    self.input_bytes_rlc.assign(
                        region,
                        offset,
                        keccak_rand.map(|r| {
                            rlc::value(
                                aux_data
                                    .0
                                    .to_bytes_be()
                                    .iter()
                                    .take(call.call_data_length as usize)
                                    .rev(),
                                r,
                            )
                        }),
                    )?;
                    self.output_bytes_rlc.assign(
                        region,
                        offset,
                        keccak_rand.map(|r| rlc::value(aux_data.0.output_bytes.iter().rev(), r)),
                    )?;
                    self.return_bytes_rlc.assign(
                        region,
                        offset,
                        keccak_rand.map(|r| rlc::value(aux_data.0.return_bytes.iter().rev(), r)),
                    )?;
                    // Pairing check output from ecPairing call.
                    self.output.assign(
                        region,
                        offset,
                        Value::known(
                            aux_data
                                .0
                                .output
                                .to_scalar()
                                .expect("ecPairing: output in {0, 1}"),
                        ),
                    )?;
                    // Number of pairs provided in the EVM call.
                    let n_pairs = (call.call_data_length as usize) / N_BYTES_PER_PAIR;
                    self.n_pairs
                        .assign(region, offset, Value::known(F::from(n_pairs as u64)))?;
                    self.n_pairs_cmp.assign(region, offset, n_pairs)?;
                    self.rand_pow_64.assign(
                        region,
                        offset,
                        keccak_rand.map(|r| r.pow([64, 0, 0, 0])),
                    )?;
                }
                Err(EcPairingError::InvalidInputLen(input_bytes)) => {
                    debug_assert_eq!(
                        input_bytes.len(),
                        call.call_data_length as usize,
                        "len(input) != call_data_length"
                    );
                    debug_assert!(
                        (call.call_data_length > (N_PAIRING_PER_OP * N_BYTES_PER_PAIR) as u64)
                            || (call.call_data_length % (N_BYTES_PER_PAIR as u64) != 0),
                        "len(input) is expected to be invalid",
                    );
                    // Consider only call_data_length bytes for EVM input.
                    self.input_bytes_rlc.assign(
                        region,
                        offset,
                        keccak_rand.map(|r| rlc::value(input_bytes.iter().rev(), r)),
                    )?;
                    self.return_bytes_rlc
                        .assign(region, offset, Value::known(F::zero()))?;
                    // Pairing check output from ecPairing call.
                    self.output
                        .assign(region, offset, Value::known(F::zero()))?;
                }
            }
        } else {
            log::error!("unexpected aux_data {:?} for ecPairing", step.aux_data);
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
        self.restore_context
            .assign(region, offset, block, call, step, 7)
    }
}

#[cfg(test)]
mod test {
    use bus_mapping::{
        circuit_input_builder::CircuitsParams,
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, evm_types::GasCost, word, ToWord, Word};
    use halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
    use itertools::Itertools;
    use mock::{test_ctx::helpers::account_0_code_wallet_0_no_code, TestContext, MOCK_WALLETS};
    use rayon::iter::{ParallelBridge, ParallelIterator};
    use std::sync::LazyLock;

    use crate::test_util::CircuitTestBuilder;

    static TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        let mut rng = rand::thread_rng();
        vec![
            PrecompileCallArgs {
                name: "ecPairing (valid): empty calldata",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0x00.into(),
                ret_offset: 0x00.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (valid): zero bytes",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0xC0.into(),
                ret_offset: 0xC0.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            #[cfg(feature = "scroll")]
            PrecompileCallArgs {
                name: "ecPairing (invalid): all zero bytes, len(input) == 5 * 192",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0x3C0.into(),
                ret_offset: 0x3C0.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (pairing true): 2 pairs",
                setup_code: bytecode! {
                    // G1_x1
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x180.into(),
                ret_offset: 0x180.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (pairing true): 4 pairs with random G1s",
                setup_code: {
                    let mut setup_code = bytecode! {
                        // G1_x1
                        PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                        PUSH1(0x00)
                        MSTORE
                        // G1_y1
                        PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                        PUSH1(0x20)
                        MSTORE
                        // G2_x11
                        PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                        PUSH1(0x40)
                        MSTORE
                        // G2_x12
                        PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                        PUSH1(0x60)
                        MSTORE
                        // G2_y11
                        PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                        PUSH1(0x80)
                        MSTORE
                        // G2_y12
                        PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                        PUSH1(0xA0)
                        MSTORE
                        // G1_x2
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                        PUSH1(0xC0)
                        MSTORE
                        // G1_y2
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                        PUSH1(0xE0)
                        MSTORE
                        // G2_x21
                        PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                        PUSH2(0x100)
                        MSTORE
                        // G2_x22
                        PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                        PUSH2(0x120)
                        MSTORE
                        // G2_y21
                        PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                        PUSH2(0x140)
                        MSTORE
                        // G2_y22
                        PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                        PUSH2(0x160)
                        MSTORE
                    };
                    let mut memory_addr = 0x180;
                    for _ in 0..2 {
                        // G1::random
                        let g1 = G1Affine::random(&mut rng);
                        setup_code.push(32, Word::from_little_endian(&g1.x.to_bytes()));
                        setup_code.push(2, memory_addr);
                        memory_addr += 0x20;
                        setup_code.write_op(OpcodeId::MSTORE);
                        setup_code.push(32, Word::from_little_endian(&g1.y.to_bytes()));
                        setup_code.push(2, memory_addr);
                        memory_addr += 0x20;
                        setup_code.write_op(OpcodeId::MSTORE);
                        // G2::identity
                        for _ in 0..4 {
                            setup_code.push(1, 0x00);
                            setup_code.push(2, memory_addr);
                            memory_addr += 0x20;
                            setup_code.write_op(OpcodeId::MSTORE);
                        }
                    }
                    setup_code
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x300.into(),
                ret_offset: 0x300.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (pairing true): 4 pairs with random G2s",
                setup_code: {
                    let mut setup_code = bytecode! {
                        // G1_x1
                        PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                        PUSH1(0x00)
                        MSTORE
                        // G1_y1
                        PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                        PUSH1(0x20)
                        MSTORE
                        // G2_x11
                        PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                        PUSH1(0x40)
                        MSTORE
                        // G2_x12
                        PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                        PUSH1(0x60)
                        MSTORE
                        // G2_y11
                        PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                        PUSH1(0x80)
                        MSTORE
                        // G2_y12
                        PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                        PUSH1(0xA0)
                        MSTORE
                        // G1_x2
                        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                        PUSH1(0xC0)
                        MSTORE
                        // G1_y2
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                        PUSH1(0xE0)
                        MSTORE
                        // G2_x21
                        PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                        PUSH2(0x100)
                        MSTORE
                        // G2_x22
                        PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                        PUSH2(0x120)
                        MSTORE
                        // G2_y21
                        PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                        PUSH2(0x140)
                        MSTORE
                        // G2_y22
                        PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                        PUSH2(0x160)
                        MSTORE
                    };
                    let mut memory_addr = 0x180;
                    for _ in 0..2 {
                        // G1::identity
                        for _ in 0..2 {
                            setup_code.push(1, 0x00);
                            setup_code.push(2, memory_addr);
                            memory_addr += 0x20;
                            setup_code.write_op(OpcodeId::MSTORE);
                        }
                        // G2::random
                        let g2 = G2Affine::random(&mut rng);
                        for fq in [g2.x.c1, g2.x.c0, g2.y.c1, g2.y.c0].iter() {
                            setup_code.push(32, Word::from_little_endian(&fq.to_bytes()));
                            setup_code.push(2, memory_addr);
                            memory_addr += 0x20;
                            setup_code.write_op(OpcodeId::MSTORE);
                        }
                    }
                    setup_code
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x300.into(),
                ret_offset: 0x300.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            #[cfg(feature = "scroll")]
            PrecompileCallArgs {
                name: "ecPairing (invalid): len(input) > 768",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 769.into(),
                ret_offset: 0xC0.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): len(input) % 192 != 0",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 191.into(),
                ret_offset: 191.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): len(input) % 192 != 0",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 193.into(),
                ret_offset: 193.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): invalid field element, mod p is valid",
                setup_code: bytecode! {
                    // G1_x1
                    PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48")) // p + 1
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49")) // p + 2
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x180.into(),
                ret_offset: 0x180.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): G1 point not on curve",
                setup_code: bytecode! {
                    // G1_x1
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18d0"))
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x180.into(),
                ret_offset: 0x180.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): G2 point not on curve",
                setup_code: bytecode! {
                    // G1_x1
                    PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                    PUSH1(0x00)
                    MSTORE
                    // G1_y1
                    PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                    PUSH1(0x20)
                    MSTORE
                    // G2_x11
                    PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebb"))
                    PUSH1(0x40)
                    MSTORE
                    // G2_x12
                    PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                    PUSH1(0x60)
                    MSTORE
                    // G2_y11
                    PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                    PUSH1(0x80)
                    MSTORE
                    // G2_y12
                    PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                    PUSH1(0xA0)
                    MSTORE
                    // G1_x2
                    PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                    PUSH1(0xC0)
                    MSTORE
                    // G1_y2
                    PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                    PUSH1(0xE0)
                    MSTORE
                    // G2_x21
                    PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                    PUSH2(0x100)
                    MSTORE
                    // G2_x22
                    PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                    PUSH2(0x120)
                    MSTORE
                    // G2_y21
                    PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                    PUSH2(0x140)
                    MSTORE
                    // G2_y22
                    PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                    PUSH2(0x160)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x180.into(),
                ret_offset: 0x180.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): G1: (0, 0), G2: not on curve",
                setup_code: bytecode! {
                    // G1_x
                    PUSH32(0x00)
                    PUSH1(0x00)
                    MSTORE
                    // G1_y
                    PUSH32(0x00)
                    PUSH1(0x20)
                    MSTORE
                    // G2_x1
                    PUSH32(0x01)
                    PUSH1(0x40)
                    MSTORE
                    // G2_x2
                    PUSH32(0x02)
                    PUSH1(0x60)
                    MSTORE
                    // G2_y1
                    PUSH32(0x03)
                    PUSH1(0x80)
                    MSTORE
                    // G2_y2
                    PUSH32(0x04)
                    PUSH1(0xA0)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0xC0.into(),
                ret_offset: 0xC0.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecPairing (invalid): G1: not on curve, G2: (0, 0, 0, 0)",
                setup_code: bytecode! {
                    // G1_x
                    PUSH32(0x04)
                    PUSH1(0x00)
                    MSTORE
                    // G1_y
                    PUSH32(0x04)
                    PUSH1(0x20)
                    MSTORE
                    // G2_x1
                    PUSH32(0x00)
                    PUSH1(0x40)
                    MSTORE
                    // G2_x2
                    PUSH32(0x00)
                    PUSH1(0x60)
                    MSTORE
                    // G2_y1
                    PUSH32(0x00)
                    PUSH1(0x80)
                    MSTORE
                    // G2_y2
                    PUSH32(0x00)
                    PUSH1(0xA0)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0xC0.into(),
                ret_offset: 0xC0.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                ..Default::default()
            },
        ]
    });

    static OOG_TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![PrecompileCallArgs {
            name: "ecPairing (pairing true): 2 pairs",
            setup_code: bytecode! {
                // G1_x1
                PUSH32(word!("0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da"))
                PUSH1(0x00)
                MSTORE
                // G1_y1
                PUSH32(word!("0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6"))
                PUSH1(0x20)
                MSTORE
                // G2_x11
                PUSH32(word!("0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc"))
                PUSH1(0x40)
                MSTORE
                // G2_x12
                PUSH32(word!("0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9"))
                PUSH1(0x60)
                MSTORE
                // G2_y11
                PUSH32(word!("0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90"))
                PUSH1(0x80)
                MSTORE
                // G2_y12
                PUSH32(word!("0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e"))
                PUSH1(0xA0)
                MSTORE
                // G1_x2
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000001"))
                PUSH1(0xC0)
                MSTORE
                // G1_y2
                PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                PUSH1(0xE0)
                MSTORE
                // G2_x21
                PUSH32(word!("0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4"))
                PUSH2(0x100)
                MSTORE
                // G2_x22
                PUSH32(word!("0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7"))
                PUSH2(0x120)
                MSTORE
                // G2_y21
                PUSH32(word!("0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2"))
                PUSH2(0x140)
                MSTORE
                // G2_y22
                PUSH32(word!("0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"))
                PUSH2(0x160)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x180.into(),
            ret_offset: 0x180.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Bn128Pairing.address().to_word(),
            value: 1.into(),
            gas: (PrecompileCalls::Bn128Pairing.base_gas_cost().as_u64()
                + 2 * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.as_u64()
                - 1)
            .to_word(),
            ..Default::default()
        }]
    });

    static INVALID_LEN_TEST: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![
            #[cfg(feature = "scroll")]
            PrecompileCallArgs {
                name: "ecPairing (invalid): len(input) > 768",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0x10340.into(),
                ret_offset: 0xC0.into(),
                ret_size: 0x20.into(),
                value: 1.into(),
                address: PrecompileCalls::Bn128Pairing.address().to_word(),
                gas: 12_000_000.into(),
                ..Default::default()
            },
        ]
    });

    #[test]
    fn precompile_ec_pairing_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        TEST_VECTOR
            .iter()
            .cartesian_product(&call_kinds)
            .par_bridge()
            .for_each(|(test_vector, &call_kind)| {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            })
    }

    #[test]
    fn precompile_ec_pairing_oog_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        OOG_TEST_VECTOR
            .iter()
            .cartesian_product(&call_kinds)
            .par_bridge()
            .for_each(|(test_vector, &call_kind)| {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            })
    }

    #[test]
    fn precompile_ec_pairing_invalid_len_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        INVALID_LEN_TEST
            .iter()
            .cartesian_product(&call_kinds)
            .par_bridge()
            .for_each(|(test_vector, &call_kind)| {
                let bytecode = test_vector.with_call_op(call_kind);

                let test_ctx: TestContext<2, 1> = TestContext::new(
                    None,
                    account_0_code_wallet_0_no_code(bytecode),
                    |mut txs, accs| {
                        txs[0]
                            .from(MOCK_WALLETS[0].clone())
                            .to(accs[0].address)
                            .gas(0x1200_0000.into());
                    },
                    |block, _txs| block.number(0xcafeu64),
                )
                .unwrap();
                CircuitTestBuilder::new_from_test_ctx(test_ctx)
                    .params(CircuitsParams {
                        max_rws: 100_000,
                        max_copy_rows: 140_000,
                        ..CircuitsParams::default()
                    })
                    .run()
            })
    }
}
