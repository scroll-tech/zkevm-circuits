use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{BinaryNumberGadget, LtGadget},
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::precompile::PrecompileCalls;
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{sum, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
struct NPairsGadget<F> {
    input_mod_192: Cell<F>,
    input_div_192: Cell<F>,
    input_mod_lt_192: LtGadget<F, 1>,
}

impl<F: Field> NPairsGadget<F> {
    fn construct(cb: &mut EVMConstraintBuilder<F>, input_len: Expression<F>) -> Self {
        // r == len(input) % 192
        let input_mod_192 = cb.query_byte();
        // r < 192
        let input_mod_lt_192 = LtGadget::construct(cb, input_mod_192.expr(), 192.expr());
        cb.require_equal("len(input) % 192 < 192", input_mod_lt_192.expr(), 1.expr());
        // q == len(input) // 192
        let input_div_192 = cb.query_cell();
        // q * 192 + r == call_data_length
        cb.require_equal(
            "q * 192 + r == len(input)",
            input_div_192.expr() * 192.expr() + input_mod_192.expr(),
            input_len,
        );

        Self {
            input_mod_192,
            input_div_192,
            input_mod_lt_192,
        }
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        input_len: u64,
    ) -> Result<(), Error> {
        self.input_mod_192
            .assign(region, offset, Value::known(F::from(input_len % 192)))?;
        self.input_div_192
            .assign(region, offset, Value::known(F::from(input_len / 192)))?;
        self.input_mod_lt_192
            .assign(region, offset, F::from(input_len % 192), F::from(192))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGPrecompileGadget<F> {
    precompile_addr: Cell<F>,
    addr_bits: BinaryNumberGadget<F, 4>,
    call_data_length: Cell<F>,
    n_pairs: NPairsGadget<F>,
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
        let n_pairs = NPairsGadget::construct(cb, call_data_length.expr());

        // calculate required gas for precompile
        let precompiles_required_gas = vec![
            (
                addr_bits.value_equals(PrecompileCalls::Ecrecover),
                GasCost::PRECOMPILE_ECRECOVER_BASE.expr(),
            ),
            // addr_bits.value_equals(PrecompileCalls::Sha256),
            // addr_bits.value_equals(PrecompileCalls::Ripemd160),
            // addr_bits.value_equals(PrecompileCalls::Blake2F),

            // TODO: handle identity and modexp
            // (addr_bits.value_equals(PrecompileCalls::Identity), 0.expr()),
            // (addr_bits.value_equals(PrecompileCalls::Modexp),),
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
                    + n_pairs.input_div_192.expr()
                        * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.expr(),
            ),
        ];

        cb.require_equal(
            "precompile_addr must be in precompile calls' set",
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

        let restore_context = RestoreContextGadget::construct2(
            cb,
            false.expr(),
            cb.curr.state.gas_left.expr(),
            0.expr(),
            0.expr(), // ReturnDataOffset
            0.expr(), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            precompile_addr,
            required_gas,
            insufficient_gas,
            n_pairs,
            addr_bits,
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

        // n_pairs
        let n_pairs = call.call_data_length / 192;
        self.n_pairs.assign(region, offset, call.call_data_length)?;

        // required_gas
        let precompile_call: PrecompileCalls = precompile_addr.to_fixed_bytes()[19].into();
        let required_gas = if precompile_call == PrecompileCalls::Bn128Pairing {
            precompile_call.base_gas_cost().as_u64()
                + n_pairs * GasCost::PRECOMPILE_BN256PAIRING_PER_PAIR.as_u64()
        } else {
            precompile_call.base_gas_cost().as_u64()
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

        // restore context
        self.restore_context
            .assign(region, offset, block, call, step, 2)
    }
}
