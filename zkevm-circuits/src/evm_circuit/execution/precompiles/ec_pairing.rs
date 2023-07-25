use bus_mapping::{
    circuit_input_builder::{EcPairingOp, N_BYTES_PER_PAIR, N_PAIRING_PER_OP},
    precompile::{PrecompileAuxData, PrecompileCalls},
};
use eth_types::{Field, ToScalar};
use gadgets::util::{not, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::BinaryNumberGadget,
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
    evm_input_rlc: Cell<F>,
    // Boolean output from the ecPairing call, denoting whether or not the pairing check was
    // successful.
    output: Cell<F>,
    /// Random linear combination of input bytes from the EcPairingOp operation.
    input_rlc: Cell<F>,
    /// Number of pairs provided through EVM input. Since a maximum of 4 pairs can be supplied from
    /// EVM, we need 3 binary bits for a max value of [1, 0, 0].
    n_pairs: Cell<F>,
    n_pairs_cmp: BinaryNumberGadget<F, 3>,
    /// Power of keccak randomness: r ^ k, where k == 768 - call_data_length.
    pow_of_rand: Cell<F>,

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
        let (evm_input_rlc, output, input_rlc, n_pairs) = (
            cb.query_cell_phase2(),
            cb.query_bool(),
            cb.query_cell_phase2(),
            cb.query_cell(),
        );
        let n_pairs_cmp = BinaryNumberGadget::construct(cb, n_pairs.expr());
        let pow_of_rand = cb.query_cell_phase2();

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

        // validate successful call to the precompile ecPairing.
        cb.condition(is_success.expr(), |cb| {
            // Covers the following cases:
            // 1. successful pairing check (where input_rlc == 0).
            // 2. successful pairing check (where input_rlc != 0).
            // 3. unsuccessful pairing check.
            cb.ecc_table_lookup(
                u64::from(PrecompileCalls::Bn128Pairing).expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                input_rlc.expr(),
                output.expr(),
                0.expr(),
            );

            let rlc_pad4 = rlc::expr(
                &EcPairingOp::padded_pairs_exprs::<F, 4>(),
                cb.challenges().keccak_input(),
            );
            let rlc_pad3 = rlc::expr(
                &EcPairingOp::padded_pairs_exprs::<F, 3>(),
                cb.challenges().keccak_input(),
            );
            let rlc_pad2 = rlc::expr(
                &EcPairingOp::padded_pairs_exprs::<F, 2>(),
                cb.challenges().keccak_input(),
            );
            let rlc_pad1 = rlc::expr(
                &EcPairingOp::padded_pairs_exprs::<F, 1>(),
                cb.challenges().keccak_input(),
            );
            let rlc_pad0 = 0.expr();
            let exponent = select::expr(
                n_pairs_cmp.value_equals(0usize),
                768.expr(),
                select::expr(
                    n_pairs_cmp.value_equals(1usize),
                    576.expr(),
                    select::expr(
                        n_pairs_cmp.value_equals(2usize),
                        384.expr(),
                        select::expr(n_pairs_cmp.value_equals(3usize), 192.expr(), 0.expr()),
                    ),
                ),
            );
            let padding = select::expr(
                n_pairs_cmp.value_equals(0usize),
                rlc_pad4,
                select::expr(
                    n_pairs_cmp.value_equals(1usize),
                    rlc_pad3,
                    select::expr(
                        n_pairs_cmp.value_equals(2usize),
                        rlc_pad2,
                        select::expr(n_pairs_cmp.value_equals(3usize), rlc_pad1, rlc_pad0),
                    ),
                ),
            );
            // r ^ exp == pow_of_rand, where exp == 768 - call_data_length.
            // Note: check only if exp < 768.
            cb.condition(not::expr(n_pairs_cmp.value_equals(0usize)), |cb| {
                cb.pow_of_rand_lookup(exponent, pow_of_rand.expr());
            });
            cb.condition(n_pairs_cmp.value_equals(0usize), |cb| {
                cb.require_zero("ecPairing: evm_input_rlc == 0", evm_input_rlc.expr());
            });

            cb.require_equal(
                "ecPairing: evm_input_rlc * pow_of_rand + padding == input_rlc",
                evm_input_rlc.expr() * pow_of_rand.expr() + padding,
                input_rlc.expr(),
            );
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
        });

        let restore_context = RestoreContextGadget::construct(
            cb,
            is_success.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        );

        Self {
            evm_input_rlc,
            output,
            input_rlc,
            n_pairs,
            n_pairs_cmp,
            pow_of_rand,

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
        if let Some(PrecompileAuxData::EcPairing(aux_data)) = &step.aux_data {
            let keccak_rand = region.challenges().keccak_input();
            self.evm_input_rlc.assign(
                region,
                offset,
                keccak_rand.map(|r| rlc::value(aux_data.0.to_evm_bytes_be().iter().rev(), r)),
            )?;
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
            self.input_rlc.assign(
                region,
                offset,
                keccak_rand.map(|r| rlc::value(aux_data.0.to_bytes_be().iter().rev(), r)),
            )?;
            let n_pairs = aux_data.0.n_evm_pairs();
            self.n_pairs
                .assign(region, offset, Value::known(F::from(n_pairs as u64)))?;
            self.n_pairs_cmp.assign(region, offset, n_pairs)?;
            let n_padded_bytes = (N_PAIRING_PER_OP - n_pairs) * N_BYTES_PER_PAIR;
            let pow_of_rand = if n_padded_bytes > 0 {
                keccak_rand.map(|r| r.pow(&[n_padded_bytes as u64, 0, 0, 0]))
            } else {
                Value::known(F::one())
            };
            self.pow_of_rand.assign(region, offset, pow_of_rand)?;
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
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;
    use rayon::iter::{ParallelBridge, ParallelIterator};

    use crate::test_util::CircuitTestBuilder;

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
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
            ]
        };
    }

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
}
