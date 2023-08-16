use bus_mapping::{
    circuit_input_builder::{EcPairingPair, N_BYTES_PER_PAIR, N_PAIRING_PER_OP},
    precompile::{PrecompileAuxData, PrecompileCalls},
};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{or, select, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{BinaryNumberGadget, IsZeroGadget},
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
    /// Gas cost for the precompile call.
    gas_cost: Cell<F>,

    /// Number of pairs provided through EVM input. Since a maximum of 4 pairs can be supplied from
    /// EVM, we need 3 binary bits for a max value of [1, 0, 0].
    n_pairs: Cell<F>,
    n_pairs_cmp: BinaryNumberGadget<F, 3>,
    /// keccak_rand ^ 64.
    rand_pow_64: Cell<F>,

    evm_input_g1_rlc: [Cell<F>; N_PAIRING_PER_OP],
    evm_input_g2_rlc: [Cell<F>; N_PAIRING_PER_OP],
    is_g1_identity: [IsZeroGadget<F>; N_PAIRING_PER_OP],
    is_g2_identity: [IsZeroGadget<F>; N_PAIRING_PER_OP],

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
        let (evm_input_rlc, output) = (cb.query_cell_phase2(), cb.query_bool());
        let gas_cost = cb.query_cell();
        let n_pairs = cb.query_cell();
        let n_pairs_cmp = BinaryNumberGadget::construct(cb, n_pairs.expr());
        let rand_pow_64 = cb.query_cell_phase2();
        let (rand_pow_128, rand_pow_192, rand_pow_384, rand_pow_576) = {
            let rand_pow_128 = rand_pow_64.expr() * rand_pow_64.expr();
            let rand_pow_192 = rand_pow_128.expr() * rand_pow_64.expr();
            let rand_pow_384 = rand_pow_192.expr() * rand_pow_192.expr();
            let rand_pow_576 = rand_pow_384.expr() * rand_pow_192.expr();
            (rand_pow_128, rand_pow_192, rand_pow_384, rand_pow_576)
        };
        cb.pow_of_rand_lookup(64.expr(), rand_pow_64.expr());

        cb.require_equal(
            "gas cost",
            gas_cost.expr(),
            GasCost::PRECOMPILE_BN256PAIRING.expr()
                + n_pairs.expr() * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.expr(),
        );

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

        let evm_input_g1_rlc = array_init::array_init(|_| cb.query_cell_phase2());
        let evm_input_g2_rlc = array_init::array_init(|_| cb.query_cell_phase2());
        let is_g1_identity = evm_input_g1_rlc.clone().map(|g1_rlc| {
            cb.annotation("is G1 zero", |cb| {
                IsZeroGadget::construct(cb, g1_rlc.expr())
            })
        });
        let is_g2_identity = evm_input_g2_rlc.clone().map(|g2_rlc| {
            cb.annotation("is G2 zero", |cb| {
                IsZeroGadget::construct(cb, g2_rlc.expr())
            })
        });

        let padding_g1_g2_rlc = rlc::expr(
            &EcPairingPair::ecc_padding()
                .to_bytes_be()
                .iter()
                .rev()
                .map(|i| i.expr())
                .collect::<Vec<Expression<F>>>(),
            cb.challenges().keccak_input(),
        );
        let ecc_circuit_input_rlcs = evm_input_g1_rlc
            .clone()
            .zip(is_g1_identity.clone())
            .zip(evm_input_g2_rlc.clone().zip(is_g2_identity.clone()))
            .map(|((g1_rlc, is_g1_identity), (g2_rlc, is_g2_identity))| {
                select::expr(
                    or::expr([is_g1_identity.expr(), is_g2_identity.expr()]),
                    // rlc([G1::identity, G2::generator])
                    padding_g1_g2_rlc.expr(),
                    // rlc([g1, g2])
                    g1_rlc.expr() * rand_pow_128.expr() + g2_rlc.expr(),
                )
            });
        let ecc_circuit_input_rlc = ecc_circuit_input_rlcs[0].expr() * rand_pow_576.expr()
            + ecc_circuit_input_rlcs[1].expr() * rand_pow_384.expr()
            + ecc_circuit_input_rlcs[2].expr() * rand_pow_192.expr()
            + ecc_circuit_input_rlcs[3].expr();

        // Equality checks for EVM input bytes to ecPairing call.
        cb.condition(n_pairs_cmp.value_equals(0usize), |cb| {
            cb.require_zero("ecPairing: evm_input_rlc == 0", evm_input_rlc.expr());
        });
        cb.condition(n_pairs_cmp.value_equals(1usize), |cb| {
            cb.require_equal(
                "ecPairing: evm_input_rlc for 1 pair",
                evm_input_rlc.expr(),
                evm_input_g1_rlc[0].expr() * rand_pow_128.expr() + evm_input_g2_rlc[0].expr(),
            );
        });
        cb.condition(n_pairs_cmp.value_equals(2usize), |cb| {
            cb.require_equal(
                "ecPairing: evm_input_rlc for 2 pairs",
                evm_input_rlc.expr(),
                (evm_input_g1_rlc[0].expr() * rand_pow_128.expr() + evm_input_g2_rlc[0].expr())
                    * rand_pow_192.expr()
                    + evm_input_g1_rlc[1].expr() * rand_pow_128.expr()
                    + evm_input_g2_rlc[1].expr(),
            );
        });
        cb.condition(n_pairs_cmp.value_equals(3usize), |cb| {
            cb.require_equal(
                "ecPairing: evm_input_rlc for 3 pairs",
                evm_input_rlc.expr(),
                (evm_input_g1_rlc[0].expr() * rand_pow_128.expr() + evm_input_g2_rlc[0].expr())
                    * rand_pow_384.expr()
                    + (evm_input_g1_rlc[1].expr() * rand_pow_128.expr()
                        + evm_input_g2_rlc[1].expr())
                        * rand_pow_192.expr()
                    + evm_input_g1_rlc[2].expr() * rand_pow_128.expr()
                    + evm_input_g2_rlc[2].expr(),
            );
        });
        cb.condition(n_pairs_cmp.value_equals(4usize), |cb| {
            cb.require_equal(
                "ecPairing: evm_input_rlc for 4 pairs",
                evm_input_rlc.expr(),
                (evm_input_g1_rlc[0].expr() * rand_pow_128.expr() + evm_input_g2_rlc[0].expr())
                    * rand_pow_576.expr()
                    + (evm_input_g1_rlc[1].expr() * rand_pow_128.expr()
                        + evm_input_g2_rlc[1].expr())
                        * rand_pow_384.expr()
                    + (evm_input_g1_rlc[2].expr() * rand_pow_128.expr()
                        + evm_input_g2_rlc[2].expr())
                        * rand_pow_192.expr()
                    + evm_input_g1_rlc[3].expr() * rand_pow_128.expr()
                    + evm_input_g2_rlc[3].expr(),
            );
        });

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
                ecc_circuit_input_rlc.expr(),
                output.expr(),
                0.expr(),
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

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(), // ReturnDataOffset
            0x20.expr(), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            evm_input_rlc,
            output,
            gas_cost,

            n_pairs,
            n_pairs_cmp,
            rand_pow_64,

            evm_input_g1_rlc,
            evm_input_g2_rlc,
            is_g1_identity,
            is_g2_identity,

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
            let n_pairs = (call.call_data_length as usize) / N_BYTES_PER_PAIR;
            let keccak_rand = region.challenges().keccak_input();

            // Consider only call_data_length bytes for EVM input.
            self.evm_input_rlc.assign(
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
            self.n_pairs
                .assign(region, offset, Value::known(F::from(n_pairs as u64)))?;
            self.n_pairs_cmp.assign(region, offset, n_pairs)?;
            // keccak_rand ^ 64.
            self.rand_pow_64
                .assign(region, offset, keccak_rand.map(|r| r.pow(&[64, 0, 0, 0])))?;
            // G1, G2 points from EVM.
            for i in 0..N_PAIRING_PER_OP {
                let g1_bytes = aux_data.0.pairs[i].g1_bytes_be();
                let g2_bytes = aux_data.0.pairs[i].g2_bytes_be();
                let g1_rlc = keccak_rand.map(|r| rlc::value(g1_bytes.iter().rev(), r));
                let g2_rlc = keccak_rand.map(|r| rlc::value(g2_bytes.iter().rev(), r));
                self.evm_input_g1_rlc[i].assign(region, offset, g1_rlc)?;
                self.is_g1_identity[i].assign_value(region, offset, g1_rlc)?;
                self.evm_input_g2_rlc[i].assign(region, offset, g2_rlc)?;
                self.is_g2_identity[i].assign_value(region, offset, g2_rlc)?;
            }
            self.gas_cost.assign(
                region,
                offset,
                Value::known(F::from(
                    GasCost::PRECOMPILE_BN256PAIRING.0
                        + (n_pairs as u64 * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.0),
                )),
            )?;
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
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord, Word};
    use halo2_proofs::halo2curves::bn256::{G1Affine, G2Affine};
    use itertools::Itertools;
    use mock::TestContext;
    use rayon::iter::{ParallelBridge, ParallelIterator};

    use crate::test_util::CircuitTestBuilder;

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
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
                            for fq in [g2.x.c0, g2.x.c1, g2.y.c0, g2.y.c1].iter() {
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
