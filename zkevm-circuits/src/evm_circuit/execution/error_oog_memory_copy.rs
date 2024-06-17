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
            not, or, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{Expr, Field},
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    ToLittleEndian, U256,
};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

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

    addr_expansion_gadget: MemoryAddrExpandGadget<F>,
    // other kind(CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY) expansion
    memory_expansion_normal: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    is_extcodecopy: IsZeroGadget<F>,
    is_mcopy: IsZeroGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGMemoryCopyGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasMemoryCopy";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasMemoryCopy;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasMemoryCopy opcode must be CALLDATACOPY, CODECOPY, EXTCODECOPY, MCOPY or RETURNDATACOPY",
            opcode.expr(),
            vec![
                OpcodeId::CALLDATACOPY.expr(),
                OpcodeId::CODECOPY.expr(),
                OpcodeId::EXTCODECOPY.expr(),
                OpcodeId::RETURNDATACOPY.expr(),
                OpcodeId::MCOPY.expr(),
            ],
        );

        let external_address = cb.query_word_rlc();
        let is_warm = cb.query_bool();
        let tx_id = cb.query_cell();

        let is_extcodecopy =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::EXTCODECOPY.expr());
        let is_mcopy = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::MCOPY.expr());

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

        let addr_expansion_gadget = MemoryAddrExpandGadget::construct(cb, is_mcopy.expr());

        cb.stack_pop(addr_expansion_gadget.dst_memory_addr.offset_rlc());
        cb.stack_pop(addr_expansion_gadget.src_memory_addr.offset_rlc());
        cb.stack_pop(addr_expansion_gadget.dst_memory_addr.length_rlc());

        // for others (CALLDATACOPY, CODECOPY, EXTCODECOPY, RETURNDATACOPY)
        let memory_expansion_normal = cb.condition(not::expr(is_mcopy.expr()), |cb| {
            MemoryExpansionGadget::construct(
                cb,
                [addr_expansion_gadget.dst_memory_addr.end_offset()],
            )
        });

        let memory_expansion_cost = select::expr(
            is_mcopy.expr(),
            addr_expansion_gadget.memory_expansion_mcopy.gas_cost(),
            memory_expansion_normal.gas_cost(),
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            addr_expansion_gadget.dst_memory_addr.length(),
            memory_expansion_cost,
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
            // Constant gas cost is same for CALLDATACOPY, CODECOPY，RETURNDATACOPY and mcopy.
            OpcodeId::CALLDATACOPY.constant_gas_cost().expr(),
        );

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            constant_gas_cost + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            // for mcopy, both dst_memory_addr and dst_memory_addr likely overflow.
            "Memory address is overflow or gas left is less than cost",
            or::expr([
                addr_expansion_gadget.dst_memory_addr.overflow(),
                addr_expansion_gadget.src_memory_addr.overflow(),
                insufficient_gas.expr(),
            ]),
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
            addr_expansion_gadget,
            memory_expansion_normal,
            memory_copier_gas,
            insufficient_gas,
            is_extcodecopy,
            is_mcopy,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let is_extcodecopy = opcode == OpcodeId::EXTCODECOPY;
        let is_mcopy = opcode == OpcodeId::MCOPY;

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

        let src_memory_addr = self
            .addr_expansion_gadget
            .src_memory_addr
            .assign(region, offset, src_offset, copy_size)?;
        let dst_memory_addr = self
            .addr_expansion_gadget
            .dst_memory_addr
            .assign(region, offset, dst_offset, copy_size)?;
        let (_, memory_expansion_cost) = self.memory_expansion_normal.assign(
            region,
            offset,
            step.memory_word_size(),
            [dst_memory_addr],
        )?;

        // assign memory_expansion_mcopy
        let (_, memory_expansion_cost_mcopy) =
            self.addr_expansion_gadget.memory_expansion_mcopy.assign(
                region,
                offset,
                step.memory_word_size(),
                [src_memory_addr, dst_memory_addr],
            )?;

        let memory_copier_gas = self.memory_copier_gas.assign(
            region,
            offset,
            MemoryExpandedAddressGadget::<F>::length_value(dst_offset, copy_size),
            if is_mcopy {
                memory_expansion_cost_mcopy
            } else {
                memory_expansion_cost
            },
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
        self.is_mcopy.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::MCOPY.as_u64()),
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

#[derive(Clone, Debug)]
pub(crate) struct MemoryAddrExpandGadget<F> {
    /// Source offset and size to copy
    src_memory_addr: MemoryExpandedAddressGadget<F>,
    /// Destination offset and size to copy
    dst_memory_addr: MemoryExpandedAddressGadget<F>,
    // mcopy expansion
    memory_expansion_mcopy: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,
}

// construct src_memory_addr, dst_memory_addr and memory_expansion_mcopy.
impl<F: Field> MemoryAddrExpandGadget<F> {
    fn construct(cb: &mut EVMConstraintBuilder<F>, is_mcopy: Expression<F>) -> Self {
        let dst_memory_addr = MemoryExpandedAddressGadget::construct_self(cb);
        // src can also be possible to overflow for mcopy.
        let src_memory_addr = MemoryExpandedAddressGadget::construct_self(cb);
        // for mcopy
        let memory_expansion_mcopy = cb.condition(is_mcopy.expr(), |cb| {
            cb.require_equal(
                "mcopy src_address length == dst_address length",
                src_memory_addr.length_rlc(),
                dst_memory_addr.length_rlc(),
            );
            MemoryExpansionGadget::construct(
                cb,
                [src_memory_addr.end_offset(), dst_memory_addr.end_offset()],
            )
        });
        Self {
            src_memory_addr,
            dst_memory_addr,
            memory_expansion_mcopy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        evm_circuit::test::{rand_bytes, rand_word},
        evm_circuit::util::math_gadget::test_util::{
            assert_error_matches, MathGadgetContainer, UnitTestMathGadgetBaseCircuit,
        },
        test_util::CircuitTestBuilder,
    };

    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        bytecode, evm_types::gas_utils::memory_copier_gas_cost, Bytecode, ToWord, U256,
    };
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::bn256::Fr};
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

    // pair type (src_offset, dest_offset, copy_size)
    const TESTING_MCOPY_PARIS: &[(u64, u64, u64)] = &[
        (0x20, 80, 2),
        (0x80, 0x60, 20),
        (0x80, 100, 20),
        (0xa0, 80, 99),
    ];

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
    fn test_oog_memory_copy_for_mcopy() {
        for (src_offset, dest_offset, copy_size) in TESTING_MCOPY_PARIS {
            let testing_data =
                TestingData::new_for_mcopy(*src_offset, *dest_offset, *copy_size, None);
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

    // add expand address to max case.
    #[test]
    fn test_oog_mcopy_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        let copy_size = 0xffffffff0;

        for is_src_max_expand in [false, true] {
            // src_offset (or dest_offset) + copy_size > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
            let (src_offset, dest_offset) = if is_src_max_expand {
                (0xffffffff1, 0x20e0)
            } else {
                (0x20e0, 0xffffffff1)
            };

            let testing_data = TestingData::new_for_mcopy(
                src_offset,
                dest_offset,
                copy_size,
                Some(MOCK_BLOCK_GAS_LIMIT),
            );

            test_root(&testing_data);
            test_internal(&testing_data);
        }
    }

    // this test added by auditing fix memory expansion case https://github.com/scroll-tech/zkevm-circuits/pull/1321
    #[test]
    fn test_oog_mcopy_src_larger_dst_addr() {
        let copy_size = 0xff;
        let src_offset = 0x20e0;
        let dest_offset = 0x20;
        let testing_data = TestingData::new_for_mcopy(src_offset, dest_offset, copy_size, None);

        test_root(&testing_data);
        test_internal(&testing_data);
    }

    // test src_offset or dest_offset is u64::MAX
    #[test]
    fn test_oog_mcopy_max_u64_address() {
        let copy_size = 0xff;
        for is_src_u64_max in [false, true] {
            // assign src_offset or dest_offset to u64::MAX
            let (src_offset, dest_offset) = if is_src_u64_max {
                (u64::MAX, 0x20e0)
            } else {
                (0x20e0, u64::MAX)
            };

            let testing_data = TestingData::new_for_mcopy(
                src_offset,
                dest_offset,
                copy_size,
                Some(MOCK_BLOCK_GAS_LIMIT),
            );

            test_root(&testing_data);
            test_internal(&testing_data);
        }
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

        pub fn new_for_mcopy(
            src_offset: u64,
            dst_offset: u64,
            copy_size: u64,
            gas_cost: Option<u64>,
        ) -> Self {
            let bytecode = bytecode! {
                PUSH32(copy_size)
                PUSH32(src_offset)
                PUSH32(dst_offset)
                MCOPY
            };

            let gas_cost = gas_cost.unwrap_or_else(|| {
                // no memory operation before mcopy
                let cur_memory_word_size = 0;
                let next_memory_word_size = if copy_size == 0 {
                    cur_memory_word_size
                } else {
                    let max_addr = std::cmp::max(src_offset, dst_offset);
                    (max_addr + copy_size + 31) / 32
                };

                OpcodeId::PUSH32.constant_gas_cost().0 * 3
                    + OpcodeId::MCOPY.constant_gas_cost().0
                    + memory_copier_gas_cost(
                        cur_memory_word_size,
                        next_memory_word_size,
                        copy_size,
                        GasCost::COPY.as_u64(),
                    )
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

    // negative test zone: construct wrong witness(src_addr length) in assign stage, thus cause
    // expected constraint error.
    #[derive(Clone)]
    struct ErrOOGMemoryCopyGadgetTestContainer<F> {
        gadget: MemoryAddrExpandGadget<F>,
        is_mcopy: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for ErrOOGMemoryCopyGadgetTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let is_mcopy = cb.query_cell();
            cb.require_boolean("is_mcopy is bool", is_mcopy.expr());
            let gadget = MemoryAddrExpandGadget::<F>::construct(cb, is_mcopy.expr());

            ErrOOGMemoryCopyGadgetTestContainer { gadget, is_mcopy }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[U256],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let [is_mcopy, src_offset, dst_offset, copy_size] =
                [0, 1, 2, 3].map(|i| witnesses[i].as_u64());
            self.is_mcopy
                .assign(region, 0, Value::known(F::from(is_mcopy)))?;

            let src_memory_addr = self.gadget.src_memory_addr.assign(
                region,
                0,
                src_offset.into(),
                // set length = copy_size + 1 which cause constraint not be satisfied.
                (copy_size + 1).into(),
            )?;
            let dst_memory_addr = self.gadget.dst_memory_addr.assign(
                region,
                0,
                dst_offset.into(),
                copy_size.into(),
            )?;
            // assign memory_expansion_mcopy
            self.gadget.memory_expansion_mcopy.assign(
                region,
                0,
                0,
                [src_memory_addr, dst_memory_addr],
            )?;
            Ok(())
        }
    }

    // test for mcopy case, do constrain: src_address length == dst_address length
    // so expect specified error.
    #[test]
    fn test_invalid_src_offset_length() {
        // test is_mcopy = true
        let witnesses = [0x1, 0x20, 0x30, 0x10].map(U256::from);

        const K: usize = 12;
        let circuit = UnitTestMathGadgetBaseCircuit::<ErrOOGMemoryCopyGadgetTestContainer<Fr>>::new(
            K,
            witnesses.into(),
        );

        let prover = MockProver::<Fr>::run(K as u32, &circuit, vec![]).unwrap();
        let result = prover.verify();

        // when mcopy, should encounter constraint error.
        assert_error_matches(result, "mcopy src_address length == dst_address length");
    }

    // test for non mcopy case, do not constrain: src_address length == dst_address length
    // so expect test pass.
    #[test]
    fn test_invalid_src_offset_length_nonmcopy() {
        // test is_mcopy = false
        let witnesses = [0x0, 0x20, 0x30, 0x10].map(U256::from);

        const K: usize = 12;
        let circuit = UnitTestMathGadgetBaseCircuit::<ErrOOGMemoryCopyGadgetTestContainer<Fr>>::new(
            K,
            witnesses.into(),
        );

        let prover = MockProver::<Fr>::run(K as u32, &circuit, vec![]).unwrap();
        let result = prover.verify();
        // when not mcopy, should pass.
        assert!(result.is_ok());
    }
}
