use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::{IsZeroGadget, LtGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryCopierGasGadget, MemoryExpandedAddressGadget,
                MemoryExpansionGadget,
            },
            or, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToLittleEndian, U256,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::CALLDATACOPY`], [`OpcodeId::CODECOPY`],
/// [`OpcodeId::EXTCODECOPY`] and [`OpcodeId::RETURNDATACOPY`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGMemoryCopyGadget<F> {
    opcode: Cell<F>,
    /// Check if `EXTCODECOPY` external address is warm
    is_warm: Cell<F>,
    tx_id: Cell<F>,
    /// Extra stack pop for `EXTCODECOPY`
    external_address: Word<F>,
    /// Source offset
    src_offset: Word<F>,
    /// Destination offset and size to copy
    dst_memory_addr: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    is_extcodecopy: IsZeroGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGMemoryCopyGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasMemoryCopy";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasMemoryCopy;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasMemoryCopy opcode must be CALLDATACOPY, CODECOPY, EXTCODECOPY or RETURNDATACOPY",
            opcode.expr(),
            vec![
                OpcodeId::CALLDATACOPY.expr(),
                OpcodeId::CODECOPY.expr(),
                OpcodeId::EXTCODECOPY.expr(),
                OpcodeId::RETURNDATACOPY.expr(),
            ],
        );

        let src_offset = cb.query_word_rlc();
        let external_address = cb.query_word_rlc();
        let is_warm = cb.query_bool();
        let tx_id = cb.query_cell();

        let is_extcodecopy =
            IsZeroGadget::construct(cb, "", opcode.expr() - OpcodeId::EXTCODECOPY.expr());

        cb.condition(is_extcodecopy.expr(), |cb| {
            cb.call_context_lookup(false.expr(), None, CallContextFieldTag::TxId, tx_id.expr());

            // Check if EXTCODECOPY external address is warm.
            cb.account_access_list_read(
                tx_id.expr(),
                from_bytes::expr(&external_address.cells[..N_BYTES_ACCOUNT_ADDRESS]),
                is_warm.expr(),
            );

            // EXTCODECOPY has an extra stack pop for external address.
            cb.stack_pop(external_address.expr());
        });

        let dst_memory_addr = MemoryExpandedAddressGadget::construct_self(cb);

        cb.stack_pop(dst_memory_addr.offset_rlc());
        cb.stack_pop(src_offset.expr());
        cb.stack_pop(dst_memory_addr.length_rlc());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [dst_memory_addr.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        let constant_gas_cost = select::expr(
            is_extcodecopy.expr(),
            // According to EIP-2929, EXTCODECOPY constant gas cost is different for cold and warm
            // accounts.
            select::expr(
                is_warm.expr(),
                GasCost::WARM_ACCESS.expr(),
                GasCost::COLD_ACCOUNT_ACCESS.expr(),
            ),
            // Constant gas cost is same for CALLDATACOPY, CODECOPY and RETURNDATACOPY.
            OpcodeId::CALLDATACOPY.constant_gas_cost().expr(),
        );

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            constant_gas_cost + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            "Memory address is overflow or gas left is less than cost",
            or::expr([dst_memory_addr.overflow(), insufficient_gas.expr()]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            // EXTCODECOPY has extra 1 call context lookup (tx_id), 1 account access list
            // read (is_warm), and 1 stack pop (external_address).
            5.expr() + 3.expr() * is_extcodecopy.expr(),
        );

        Self {
            opcode,
            is_warm,
            tx_id,
            external_address,
            src_offset,
            dst_memory_addr,
            memory_expansion,
            memory_copier_gas,
            insufficient_gas,
            is_extcodecopy,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let is_extcodecopy = opcode == OpcodeId::EXTCODECOPY;

        log::debug!(
            "ErrorOutOfGasMemoryCopy: opcode = {}, gas_left = {}, gas_cost = {}",
            opcode,
            step.gas_left,
            step.gas_cost,
        );

        let (is_warm, external_address) = if is_extcodecopy {
            (
                block.rws[step.rw_indices[1]].tx_access_list_value_pair().0,
                block.rws[step.rw_indices[2]].stack_value(),
            )
        } else {
            (false, U256::zero())
        };

        let rw_offset = if is_extcodecopy { 3 } else { 0 };
        let [dst_offset, src_offset, copy_size] = [rw_offset, rw_offset + 1, rw_offset + 2]
            .map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(u64::from(is_warm))))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(transaction.id as u64)))?;
        self.external_address
            .assign(region, offset, Some(external_address.to_le_bytes()))?;
        self.src_offset
            .assign(region, offset, Some(src_offset.to_le_bytes()))?;
        let memory_addr = self
            .dst_memory_addr
            .assign(region, offset, dst_offset, copy_size)?;
        let (_, memory_expansion_cost) =
            self.memory_expansion
                .assign(region, offset, step.memory_word_size(), [memory_addr])?;
        let memory_copier_gas = self.memory_copier_gas.assign(
            region,
            offset,
            MemoryExpandedAddressGadget::<F>::length_value(dst_offset, copy_size),
            memory_expansion_cost,
        )?;
        let constant_gas_cost = if is_extcodecopy {
            if is_warm {
                GasCost::WARM_ACCESS
            } else {
                GasCost::COLD_ACCOUNT_ACCESS
            }
        } else {
            GasCost::FASTEST
        };
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(memory_copier_gas + constant_gas_cost.0)),
        )?;
        self.is_extcodecopy.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::EXTCODECOPY.as_u64()),
        )?;
        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            // EXTCODECOPY has extra 1 call context lookup (tx_id), 1 account access list
            // read (is_warm), and 1 stack pop (external_address).
            5 + if is_extcodecopy { 3 } else { 0 },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evm_circuit::test::{rand_bytes, rand_word},
        test_util::CircuitTestBuilder,
    };
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        bytecode, evm_types::gas_utils::memory_copier_gas_cost, Bytecode, ToWord, U256,
    };
    use itertools::Itertools;
    use mock::{
        eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
        MOCK_BLOCK_GAS_LIMIT,
    };

    const TESTING_COMMON_OPCODES: &[OpcodeId] = &[
        OpcodeId::CALLDATACOPY,
        OpcodeId::CODECOPY,
        OpcodeId::RETURNDATACOPY,
    ];

    const TESTING_DST_OFFSET_COPY_SIZE_PAIRS: &[(u64, u64)] =
        &[(0x20, 0), (0x40, 20), (0x2000, 0x200)];

    #[test]
    fn test_oog_memory_copy_for_common_opcodes() {
        for (opcode, (dst_offset, copy_size)) in TESTING_COMMON_OPCODES
            .iter()
            .cartesian_product(TESTING_DST_OFFSET_COPY_SIZE_PAIRS.iter())
        {
            let testing_data =
                TestingData::new_for_common_opcode(*opcode, *dst_offset, *copy_size, None);

            test_root(&testing_data);
            test_internal(&testing_data);
        }
    }

    #[test]
    fn test_oog_memory_copy_for_extcodecopy() {
        for (is_warm, (dst_offset, copy_size)) in [false, true]
            .iter()
            .cartesian_product(TESTING_DST_OFFSET_COPY_SIZE_PAIRS.iter())
        {
            let testing_data =
                TestingData::new_for_extcodecopy(*is_warm, *dst_offset, *copy_size, None);

            test_root(&testing_data);
            test_internal(&testing_data);
        }
    }

    #[test]
    fn test_oog_memory_copy_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        test_for_edge_memory_size(0xffffffff1, 0xffffffff0);
    }

    #[test]
    fn test_oog_memory_copy_max_u64_address() {
        test_for_edge_memory_size(u64::MAX, u64::MAX);
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new_for_common_opcode(
            opcode: OpcodeId,
            dst_offset: u64,
            copy_size: u64,
            gas_cost: Option<u64>,
        ) -> Self {
            let bytecode = bytecode! {
                PUSH32(copy_size)
                PUSH32(rand_word())
                PUSH32(dst_offset)
                .write_op(opcode)
            };

            let gas_cost = gas_cost.unwrap_or_else(|| {
                let memory_word_size = (dst_offset + copy_size + 31) / 32;

                OpcodeId::PUSH32.constant_gas_cost().0 * 3
                    + opcode.constant_gas_cost().0
                    + memory_copier_gas_cost(0, memory_word_size, copy_size, GasCost::COPY.as_u64())
            });

            Self { bytecode, gas_cost }
        }

        pub fn new_for_extcodecopy(
            is_warm: bool,
            dst_offset: u64,
            copy_size: u64,
            gas_cost: Option<u64>,
        ) -> Self {
            let external_address = MOCK_ACCOUNTS[4];

            let mut bytecode = bytecode! {
                PUSH32(copy_size)
                PUSH32(U256::zero())
                PUSH32(dst_offset)
                PUSH32(external_address.to_word())
                EXTCODECOPY
            };

            if is_warm {
                bytecode.append(&bytecode! {
                    PUSH32(copy_size)
                    PUSH32(rand_word())
                    PUSH32(dst_offset)
                    PUSH32(external_address.to_word())
                    EXTCODECOPY
                });
            }

            let gas_cost = gas_cost.unwrap_or_else(|| {
                let memory_word_size = (dst_offset + copy_size + 31) / 32;

                let gas_cost = OpcodeId::PUSH32.constant_gas_cost().0 * 4
                    + GasCost::COLD_ACCOUNT_ACCESS.0
                    + memory_copier_gas_cost(
                        0,
                        memory_word_size,
                        copy_size,
                        GasCost::COPY.as_u64(),
                    );

                if is_warm {
                    gas_cost
                        + OpcodeId::PUSH32.constant_gas_cost().0 * 4
                        + GasCost::WARM_ACCESS.0
                        + memory_copier_gas_cost(
                            memory_word_size,
                            memory_word_size,
                            copy_size,
                            GasCost::COPY.as_u64(),
                        )
                } else {
                    gas_cost
                }
            });

            Self { bytecode, gas_cost }
        }
    }

    fn test_root(testing_data: &TestingData) {
        let gas_cost = GasCost::TX
            .0
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            .checked_add(testing_data.gas_cost - 1)
            .unwrap_or(MOCK_BLOCK_GAS_LIMIT);
        let gas_cost = if gas_cost > MOCK_BLOCK_GAS_LIMIT {
            MOCK_BLOCK_GAS_LIMIT
        } else {
            gas_cost
        };

        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(testing_data.bytecode.clone()),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(gas_cost.into());
            },
            |block, _tx| block.number(0xcafe_u64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_copy_rows: 1750,
                ..Default::default()
            })
            .run();
    }

    fn test_internal(testing_data: &TestingData) {
        let (addr_a, addr_b) = (MOCK_ACCOUNTS[0], MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = testing_data.bytecode.clone();
        let gas_cost_b = testing_data.gas_cost;

        // Code A calls code B.
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(U256::from_big_endian(&rand_bytes(8)))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x20) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(gas_cost_b - 1) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_copy_rows: 1750,
                ..Default::default()
            })
            .run();
    }

    fn test_for_edge_memory_size(dst_offset: u64, copy_size: u64) {
        TESTING_COMMON_OPCODES.iter().for_each(|opcode| {
            let testing_data = TestingData::new_for_common_opcode(
                *opcode,
                dst_offset,
                copy_size,
                Some(MOCK_BLOCK_GAS_LIMIT),
            );

            test_root(&testing_data);
            test_internal(&testing_data);
        });

        [false, true].into_iter().for_each(|is_warm| {
            let testing_data = TestingData::new_for_extcodecopy(
                is_warm,
                dst_offset,
                copy_size,
                Some(MOCK_BLOCK_GAS_LIMIT),
            );

            test_root(&testing_data);
            test_internal(&testing_data);
        });
    }
}
