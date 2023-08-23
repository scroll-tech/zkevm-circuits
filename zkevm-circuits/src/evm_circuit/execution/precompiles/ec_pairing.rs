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
