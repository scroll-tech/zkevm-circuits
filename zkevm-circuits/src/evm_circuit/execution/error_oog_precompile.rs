use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_EC_PAIR, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{BinaryNumberGadget, ConstantDivisionGadget, LtGadget},
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::precompile::PrecompileCalls;
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{sum, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGPrecompileGadget<F> {
    precompile_addr: Cell<F>,
    addr_bits: BinaryNumberGadget<F, 4>,
    call_data_length: Cell<F>,
    is_root: Cell<F>,
    n_pairs: ConstantDivisionGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
    n_words: ConstantDivisionGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
    required_gas: Cell<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGPrecompileGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasPrecompile";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasPrecompile;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let required_gas = cb.query_cell();

        // read callee_address
        let precompile_addr = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let addr_bits = BinaryNumberGadget::construct(cb, precompile_addr.expr());

        // read call data length
        let call_data_length = cb.call_context(None, CallContextFieldTag::CallDataLength);
        // read is root
        let is_root = cb.call_context(None, CallContextFieldTag::IsRoot);

        let n_pairs = cb.condition(
            addr_bits.value_equals(PrecompileCalls::Bn128Pairing),
            |cb| {
                ConstantDivisionGadget::construct(
                    cb,
                    call_data_length.expr(),
                    N_BYTES_EC_PAIR as u64,
                )
            },
        );
        let n_words = cb.condition(addr_bits.value_equals(PrecompileCalls::Identity), |cb| {
            ConstantDivisionGadget::construct(
                cb,
                call_data_length.expr() + (N_BYTES_WORD - 1).expr(),
                N_BYTES_WORD as u64,
            )
        });

        // calculate required gas for precompile
        let precompiles_required_gas = vec![
            (
                addr_bits.value_equals(PrecompileCalls::Ecrecover),
                GasCost::PRECOMPILE_ECRECOVER_BASE.expr(),
            ),
            // These are handled in PrecompileFailedGadget
            (
                addr_bits.value_equals(PrecompileCalls::Sha256),
                GasCost::PRECOMPILE_SHA256_BASE.expr()
                    + n_words.quotient() * GasCost::PRECOMPILE_SHA256_PER_WORD.expr(),
            ),
            // addr_bits.value_equals(PrecompileCalls::Ripemd160),
            // addr_bits.value_equals(PrecompileCalls::Blake2F),
            (
                addr_bits.value_equals(PrecompileCalls::Identity),
                GasCost::PRECOMPILE_IDENTITY_BASE.expr()
                    + n_words.quotient() * GasCost::PRECOMPILE_IDENTITY_PER_WORD.expr(),
            ),
            // modexp is handled in ModExpGadget
            (
                addr_bits.value_equals(PrecompileCalls::Bn128Add),
                GasCost::PRECOMPILE_BN256ADD.as_u64().expr(),
            ),
            (
                addr_bits.value_equals(PrecompileCalls::Bn128Mul),
                GasCost::PRECOMPILE_BN256MUL.as_u64().expr(),
            ),
            (
                addr_bits.value_equals(PrecompileCalls::Bn128Pairing),
                GasCost::PRECOMPILE_BN256PAIRING.expr()
                    + n_pairs.quotient() * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.expr(),
            ),
        ];

        cb.require_equal(
            "precompile_addr must belong to precompile calls' set",
            sum::expr(
                precompiles_required_gas
                    .iter()
                    .map(|(cond, _)| cond)
                    .cloned(),
            ),
            1.expr(),
        );

        cb.require_equal(
            "require_gas == sum(is_precompile[addr] * required_gas[addr])",
            required_gas.expr(),
            precompiles_required_gas
                .iter()
                .fold(0.expr(), |acc, (condition, required_gas)| {
                    acc + condition.expr() * required_gas.expr()
                }),
        );

        // gas_left < required_gas
        let insufficient_gas =
            LtGadget::construct(cb, cb.curr.state.gas_left.expr(), required_gas.expr());
        cb.require_equal("gas_left < required_gas", insufficient_gas.expr(), 1.expr());

        let restore_context = super::precompiles::gen_restore_context(
            cb,
            is_root.expr(),
            false.expr(),
            cb.curr.state.gas_left.expr(),
            0.expr(), // ReturnDataLength
        );

        Self {
            precompile_addr,
            required_gas,
            insufficient_gas,
            n_pairs,
            n_words,
            addr_bits,
            is_root,
            call_data_length,
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
        // addr_bits
        let precompile_addr = call.code_address.unwrap();
        self.precompile_addr.assign(
            region,
            offset,
            Value::known(precompile_addr.to_scalar().unwrap()),
        )?;
        self.addr_bits
            .assign(region, offset, precompile_addr.to_fixed_bytes()[19])?;

        // call_data_length
        self.call_data_length.assign(
            region,
            offset,
            Value::known(F::from(call.call_data_length)),
        )?;

        // is_root
        self.is_root
            .assign(region, offset, Value::known(F::from(call.is_root)))?;

        // n_pairs
        let n_pairs = call.call_data_length / 192;
        self.n_pairs
            .assign(region, offset, call.call_data_length as u128)?;

        // n_words
        self.n_words.assign(
            region,
            offset,
            (call.call_data_length + (N_BYTES_WORD as u64) - 1) as u128,
        )?;

        // required_gas
        let precompile_call: PrecompileCalls = precompile_addr.to_fixed_bytes()[19].into();
        let required_gas = match precompile_call {
            PrecompileCalls::Bn128Pairing => {
                precompile_call.base_gas_cost().as_u64()
                    + n_pairs * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.as_u64()
            }
            PrecompileCalls::Identity => {
                let n_words = (call.call_data_length + 31) / 32;
                precompile_call.base_gas_cost().as_u64()
                    + n_words * GasCost::PRECOMPILE_IDENTITY_PER_WORD.as_u64()
            }
            PrecompileCalls::Sha256 => {
                let n_words = (call.call_data_length + 31) / 32;
                precompile_call.base_gas_cost().as_u64()
                    + n_words * GasCost::PRECOMPILE_SHA256_PER_WORD.as_u64()
            }
            PrecompileCalls::Bn128Add | PrecompileCalls::Bn128Mul | PrecompileCalls::Ecrecover => {
                precompile_call.base_gas_cost().as_u64()
            }
            _ => unreachable!(),
        };

        self.required_gas
            .assign(region, offset, Value::known(F::from(required_gas)))?;

        // insufficient_gas
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(required_gas),
        )?;

        self.restore_context
            .assign(region, offset, block, call, step, 3)
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
    use eth_types::{
        bytecode,
        evm_types::{GasCost, OpcodeId},
        word, ToWord,
    };
    use itertools::Itertools;
    use mock::TestContext;
    use std::sync::LazyLock;

    static TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![
            PrecompileCallArgs {
                name: "multi-bytes success (more than 32 bytes)",
                setup_code: bytecode! {
                    // place params in memory
                    PUSH30(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                    PUSH1(0x00) // place from 0x00 in memory
                    MSTORE
                    PUSH30(word!("0xaabbccdd001122331039abcdefefef84"))
                    PUSH1(0x20) // place from 0x20 in memory
                    MSTORE
                },
                // copy 63 bytes from memory addr 0
                call_data_offset: 0x00.into(),
                call_data_length: 0x3f.into(),
                // return only 35 bytes and write from memory addr 72
                ret_offset: 0x48.into(),
                ret_size: 0x23.into(),
                address: PrecompileCalls::Identity.address().to_word(),
                gas: (PrecompileCalls::Identity.base_gas_cost().as_u64()
                    + 2 * GasCost::PRECOMPILE_IDENTITY_PER_WORD.as_u64()
                    - 1)
                .to_word(),
                ..Default::default()
            },
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
                    PUSH32(word!("0x1000000000000000000000000000000000000000000000000000000000000009"))
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
                gas: 20.to_word(),
                ..Default::default()
            },
        ]
    });

    #[test]
    fn precompile_oog_test() {
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
}
