use bus_mapping::precompile::PrecompileAuxData;
use eth_types::{Field, ToLittleEndian, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes, rlc, CachedRegion, Cell, RandomLinearCombination,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct EcrecoverGadget<F> {
    recovered: Cell<F>,
    msg_hash_rlc: Cell<F>,
    sig_v_rlc: Cell<F>,
    sig_r_rlc: Cell<F>,
    sig_s_rlc: Cell<F>,
    recovered_addr_rlc: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcrecoverGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileEcrecover;

    const NAME: &'static str = "ECRECOVER";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (recovered, msg_hash_rlc, sig_v_rlc, sig_r_rlc, sig_s_rlc, recovered_addr_rlc) = (
            cb.query_bool(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_keccak_rlc(),
        );

        cb.condition(recovered.expr(), |cb| {
            // if address was recovered, the sig_v (recovery ID) was correct.
            cb.require_zero(
                "sig_v == 27 or 28",
                (sig_v_rlc.expr() - 27.expr()) * (sig_v_rlc.expr() - 28.expr()),
            );

            // lookup to the sign_verify table
            // || v | r | s | msg_hash | recovered_addr ||
            cb.sig_table_lookup(
                msg_hash_rlc.expr(),
                sig_v_rlc.expr() - 27.expr(),
                sig_r_rlc.expr(),
                sig_s_rlc.expr(),
                from_bytes::expr(&recovered_addr_rlc.cells),
            );
        });

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
            recovered,
            msg_hash_rlc,
            sig_v_rlc,
            sig_r_rlc,
            sig_s_rlc,
            recovered_addr_rlc,
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
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        if let Some(PrecompileAuxData::Ecrecover(aux_data)) = &step.aux_data {
            let recovered = !aux_data.recovered_addr.is_zero();
            self.recovered
                .assign(region, offset, Value::known(F::from(recovered as u64)))?;
            self.msg_hash_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.msg_hash.to_le_bytes(), r)),
            )?;
            self.sig_v_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_v.to_le_bytes(), r)),
            )?;
            self.sig_r_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_r.to_le_bytes(), r)),
            )?;
            self.sig_s_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_s.to_le_bytes(), r)),
            )?;
            self.recovered_addr_rlc.assign(
                region,
                offset,
                Some({
                    let mut recovered_addr = aux_data.recovered_addr.to_fixed_bytes();
                    recovered_addr.reverse();
                    recovered_addr
                }),
            )?;
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
                    name: "ecrecover (invalid sig, addr not recovered)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 96 bytes from memory addr 0. This is insufficient to recover an
                    // address, and so the return data length from the precompile call will be 0.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (invalid sig, addr recovered)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 101 bytes from memory addr 0. This should be sufficient to recover an
                    // address, but the signature is invalid (ecrecover does not care about this
                    // though)
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x65.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (valid sig, addr recovered)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 128 bytes from memory addr 0. Address is recovered and the signature is
                    // valid.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (valid sig, addr recovered, extra input bytes)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 133 bytes from memory addr 0. Address is recovered and the signature is
                    // valid. The 5 bytes after the first 128 bytes are ignored.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x85.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
            ]
        };
    }

    #[test]
    fn precompile_ecrecover_test() {
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
