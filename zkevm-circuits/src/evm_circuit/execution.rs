use super::util::{CachedRegion, CellManager, StoredExpression};
use crate::{
    evm_circuit::{
        param::{MAX_STEP_HEIGHT, STEP_WIDTH},
        step::{ExecutionState, Step},
        table::Table,
        util::{
            constraint_builder::{BaseConstraintBuilder, ConstraintBuilder},
            rlc, CellType,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{LookupTable, RwTableTag, TxReceiptFieldTag},
    util::{query_expression, Expr},
};
use eth_types::Field;
use gadgets::util::not;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use std::{
    collections::{BTreeSet, HashMap},
    iter,
};

use strum::{EnumCount, IntoEnumIterator};

mod add_sub;
mod addmod;
mod address;
mod balance;
mod begin_tx;
mod bitwise;
mod block_ctx;
mod blockhash;
mod byte;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callop;
mod callvalue;
mod chainid;
mod codecopy;
mod codesize;
mod comparator;
mod dummy;
mod dup;
mod end_block;
mod end_inner_block;
mod end_tx;
mod error_invalid_jump;
mod error_oog_call;
mod error_oog_constant;
mod error_oog_static_memory;
mod error_stack;
mod exp;
mod extcodehash;
mod extcodesize;
mod gas;
mod gasprice;
mod is_zero;
mod jump;
mod jumpdest;
mod jumpi;
mod logs;
mod memory;
mod msize;
mod mul_div_mod;
mod mulmod;
#[path = "execution/not.rs"]
mod opcode_not;
mod origin;
mod pc;
mod pop;
mod push;
mod return_revert;
mod returndatacopy;
mod returndatasize;
mod sdiv_smod;
mod selfbalance;
mod sha3;
mod shl_shr;
mod signed_comparator;
mod signextend;
mod sload;
mod sstore;
mod stop;
mod swap;

use self::{logs::LogGadget, sha3::Sha3Gadget};
use add_sub::AddSubGadget;
use addmod::AddModGadget;
use address::AddressGadget;
use balance::BalanceGadget;
use begin_tx::BeginTxGadget;
use bitwise::BitwiseGadget;
use block_ctx::{BlockCtxU160Gadget, BlockCtxU256Gadget, BlockCtxU64Gadget};
use byte::ByteGadget;
use calldatacopy::CallDataCopyGadget;
use calldataload::CallDataLoadGadget;
use calldatasize::CallDataSizeGadget;
use caller::CallerGadget;
use callop::CallOpGadget;
use callvalue::CallValueGadget;
use chainid::ChainIdGadget;
use codecopy::CodeCopyGadget;
use codesize::CodesizeGadget;
use comparator::ComparatorGadget;
use dummy::DummyGadget;
use dup::DupGadget;
use end_block::EndBlockGadget;
use end_inner_block::EndInnerBlockGadget;
use end_tx::EndTxGadget;
use error_invalid_jump::ErrorInvalidJumpGadget;
use error_oog_call::ErrorOOGCallGadget;
use error_oog_constant::ErrorOOGConstantGadget;
use error_stack::ErrorStackGadget;
use exp::ExponentiationGadget;
use extcodehash::ExtcodehashGadget;
use extcodesize::ExtcodesizeGadget;
use gas::GasGadget;
use gasprice::GasPriceGadget;
use is_zero::IsZeroGadget;
use jump::JumpGadget;
use jumpdest::JumpdestGadget;
use jumpi::JumpiGadget;

use memory::MemoryGadget;
use msize::MsizeGadget;
use mul_div_mod::MulDivModGadget;
use mulmod::MulModGadget;
use opcode_not::NotGadget;
use origin::OriginGadget;
use pc::PcGadget;
use pop::PopGadget;
use push::PushGadget;
use return_revert::ReturnRevertGadget;
use returndatacopy::ReturnDataCopyGadget;
use returndatasize::ReturnDataSizeGadget;
use sdiv_smod::SignedDivModGadget;
use selfbalance::SelfbalanceGadget;
use shl_shr::ShlShrGadget;
use signed_comparator::SignedComparatorGadget;
use signextend::SignextendGadget;
use sload::SloadGadget;
use sstore::SstoreGadget;
use stop::StopGadget;
use swap::SwapGadget;

pub(crate) trait ExecutionGadget<F: FieldExt> {
    const NAME: &'static str;

    const EXECUTION_STATE: ExecutionState;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self;

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F> {
    // EVM Circuit selector, which enables all usable rows.  The rows where this selector is
    // disabled won't verify any constraint (they can be unused rows or rows with blinding
    // factors).
    q_usable: Selector,
    // Dynamic selector that is enabled at the rows where each assigned execution step starts (a
    // step has dynamic height).
    q_step: Column<Advice>,
    // Column to hold constant values used for copy constraints
    constants: Column<Fixed>,
    num_rows_until_next_step: Column<Advice>,
    num_rows_inv: Column<Advice>,
    // Selector enabled in the row where the first execution step starts.
    q_step_first: Selector,
    // Selector enabled in the row where the last execution step starts.
    q_step_last: Selector,
    advices: [Column<Advice>; STEP_WIDTH],
    step: Step<F>,
    height_map: HashMap<ExecutionState, usize>,
    stored_expressions_map: HashMap<ExecutionState, Vec<StoredExpression<F>>>,
    // internal state gadgets
    begin_tx_gadget: BeginTxGadget<F>,
    end_block_gadget: EndBlockGadget<F>,
    end_inner_block_gadget: EndInnerBlockGadget<F>,
    end_tx_gadget: EndTxGadget<F>,
    // opcode gadgets
    add_sub_gadget: AddSubGadget<F>,
    addmod_gadget: AddModGadget<F>,
    address_gadget: AddressGadget<F>,
    balance_gadget: BalanceGadget<F>,
    bitwise_gadget: BitwiseGadget<F>,
    byte_gadget: ByteGadget<F>,
    call_op_gadget: CallOpGadget<F>,
    call_value_gadget: CallValueGadget<F>,
    calldatacopy_gadget: CallDataCopyGadget<F>,
    calldataload_gadget: CallDataLoadGadget<F>,
    calldatasize_gadget: CallDataSizeGadget<F>,
    caller_gadget: CallerGadget<F>,
    chainid_gadget: ChainIdGadget<F>,
    codecopy_gadget: CodeCopyGadget<F>,
    codesize_gadget: CodesizeGadget<F>,
    comparator_gadget: ComparatorGadget<F>,
    dup_gadget: DupGadget<F>,
    exp_gadget: ExponentiationGadget<F>,
    extcodehash_gadget: ExtcodehashGadget<F>,
    extcodesize_gadget: ExtcodesizeGadget<F>,
    gas_gadget: GasGadget<F>,
    gasprice_gadget: GasPriceGadget<F>,
    iszero_gadget: IsZeroGadget<F>,
    jump_gadget: JumpGadget<F>,
    jumpdest_gadget: JumpdestGadget<F>,
    jumpi_gadget: JumpiGadget<F>,
    log_gadget: LogGadget<F>,
    memory_gadget: MemoryGadget<F>,
    msize_gadget: MsizeGadget<F>,
    mul_div_mod_gadget: MulDivModGadget<F>,
    mulmod_gadget: MulModGadget<F>,
    not_gadget: NotGadget<F>,
    origin_gadget: OriginGadget<F>,
    pc_gadget: PcGadget<F>,
    pop_gadget: PopGadget<F>,
    push_gadget: PushGadget<F>,
    return_revert_gadget: ReturnRevertGadget<F>,
    sdiv_smod_gadget: SignedDivModGadget<F>,
    selfbalance_gadget: SelfbalanceGadget<F>,
    sha3_gadget: Sha3Gadget<F>,
    shl_shr_gadget: ShlShrGadget<F>,
    sar_gadget: DummyGadget<F, 2, 1, { ExecutionState::SAR }>,
    extcodecopy_gadget: DummyGadget<F, 4, 0, { ExecutionState::EXTCODECOPY }>,
    returndatasize_gadget: ReturnDataSizeGadget<F>,
    returndatacopy_gadget: ReturnDataCopyGadget<F>,
    create_gadget: DummyGadget<F, 3, 1, { ExecutionState::CREATE }>,
    create2_gadget: DummyGadget<F, 4, 1, { ExecutionState::CREATE2 }>,
    selfdestruct_gadget: DummyGadget<F, 1, 0, { ExecutionState::SELFDESTRUCT }>,
    signed_comparator_gadget: SignedComparatorGadget<F>,
    signextend_gadget: SignextendGadget<F>,
    sload_gadget: SloadGadget<F>,
    sstore_gadget: SstoreGadget<F>,
    stop_gadget: StopGadget<F>,
    swap_gadget: SwapGadget<F>,
    blockhash_gadget: DummyGadget<F, 1, 1, { ExecutionState::BLOCKHASH }>,
    block_ctx_u64_gadget: BlockCtxU64Gadget<F>,
    block_ctx_u160_gadget: BlockCtxU160Gadget<F>,
    block_ctx_u256_gadget: BlockCtxU256Gadget<F>,
    // error gadgets
    error_oog_call: ErrorOOGCallGadget<F>,
    error_oog_constant: ErrorOOGConstantGadget<F>,
    error_oog_static_memory_gadget:
        DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasStaticMemoryExpansion }>,
    error_stack: ErrorStackGadget<F>,
    error_oog_dynamic_memory_gadget:
        DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasDynamicMemoryExpansion }>,
    error_oog_log: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasLOG }>,
    error_oog_sload: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSLOAD }>,
    error_oog_sstore: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSSTORE }>,
    error_oog_memory_copy: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasMemoryCopy }>,
    error_oog_account_access: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasAccountAccess }>,
    error_oog_sha3: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSHA3 }>,
    error_oog_ext_codecopy: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasEXTCODECOPY }>,
    error_oog_call_code: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasCALLCODE }>,
    error_oog_delegate_call: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasDELEGATECALL }>,
    error_oog_exp: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasEXP }>,
    error_oog_create2: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasCREATE2 }>,
    error_oog_static_call: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSTATICCALL }>,
    error_oog_self_destruct: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSELFDESTRUCT }>,
    error_oog_code_store: DummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasCodeStore }>,
    error_insufficient_balance: DummyGadget<F, 0, 0, { ExecutionState::ErrorInsufficientBalance }>,
    error_invalid_jump: ErrorInvalidJumpGadget<F>,
    error_depth: DummyGadget<F, 0, 0, { ExecutionState::ErrorDepth }>,
    error_write_protection: DummyGadget<F, 0, 0, { ExecutionState::ErrorWriteProtection }>,
    error_contract_address_collision:
        DummyGadget<F, 0, 0, { ExecutionState::ErrorContractAddressCollision }>,
    error_invalid_creation_code: DummyGadget<F, 0, 0, { ExecutionState::ErrorInvalidCreationCode }>,
    error_return_data_out_of_bound:
        DummyGadget<F, 0, 0, { ExecutionState::ErrorReturnDataOutOfBound }>,
    invalid_opcode_gadget: DummyGadget<F, 0, 0, { ExecutionState::ErrorInvalidOpcode }>,
}

impl<F: Field> ExecutionConfig<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; 31],
        fixed_table: &dyn LookupTable<F>,
        byte_table: &dyn LookupTable<F>,
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
        copy_table: &dyn LookupTable<F>,
        keccak_table: &dyn LookupTable<F>,
        exp_table: &dyn LookupTable<F>,
    ) -> Self {
        let q_usable = meta.complex_selector();
        let q_step = meta.advice_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let num_rows_until_next_step = meta.advice_column();
        let num_rows_inv = meta.advice_column();
        let q_step_first = meta.complex_selector();
        let q_step_last = meta.complex_selector();
        let advices = [(); STEP_WIDTH].map(|_| meta.advice_column());

        let step_curr = Step::new(meta, advices, 0, false);
        let mut height_map = HashMap::new();

        meta.create_gate("Constrain execution state", |meta| {
            let q_usable = meta.query_selector(q_usable);
            let q_step = meta.query_advice(q_step, Rotation::cur());
            let q_step_first = meta.query_selector(q_step_first);
            let q_step_last = meta.query_selector(q_step_last);

            let execution_state_selector_constraints = step_curr.state.execution_state.configure();

            // NEW: Enabled, this will break hand crafted tests, maybe we can remove them?
            let first_step_check = {
                let begin_tx_end_block_selector = step_curr
                    .execution_state_selector([ExecutionState::BeginTx, ExecutionState::EndBlock]);
                iter::once((
                    "First step should be BeginTx or EndBlock",
                    q_step_first * (1.expr() - begin_tx_end_block_selector),
                ))
            };

            let last_step_check = {
                let end_block_selector =
                    step_curr.execution_state_selector([ExecutionState::EndBlock]);
                iter::once((
                    "Last step should be EndBlock",
                    q_step_last * (1.expr() - end_block_selector),
                ))
            };

            execution_state_selector_constraints
                .into_iter()
                .map(move |(name, poly)| (name, q_usable.clone() * q_step.clone() * poly))
                .chain(first_step_check)
                .chain(last_step_check)
        });

        meta.create_gate("q_step", |meta| {
            let q_usable = meta.query_selector(q_usable);
            let q_step_first = meta.query_selector(q_step_first);
            let q_step_last = meta.query_selector(q_step_last);
            let q_step = meta.query_advice(q_step, Rotation::cur());
            let num_rows_left_cur = meta.query_advice(num_rows_until_next_step, Rotation::cur());
            let num_rows_left_next = meta.query_advice(num_rows_until_next_step, Rotation::next());
            let num_rows_left_inverse = meta.query_advice(num_rows_inv, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();
            // q_step needs to be enabled on the first row
            // rw_counter starts at 1
            cb.condition(q_step_first, |cb| {
                cb.require_equal("q_step == 1", q_step.clone(), 1.expr());
                cb.require_equal(
                    "rw_counter is initialized to be 1",
                    step_curr.state.rw_counter.expr(),
                    1.expr(),
                )
            });
            // q_step needs to be enabled on the last row
            cb.condition(q_step_last, |cb| {
                cb.require_equal("q_step == 1", q_step.clone(), 1.expr());
            });
            // Except when step is enabled, the step counter needs to decrease by 1
            cb.condition(1.expr() - q_step.clone(), |cb| {
                cb.require_equal(
                    "num_rows_left_cur := num_rows_left_next + 1",
                    num_rows_left_cur.clone(),
                    num_rows_left_next + 1.expr(),
                );
            });
            // Enforce that q_step := num_rows_until_next_step == 0
            let is_zero = 1.expr() - (num_rows_left_cur.clone() * num_rows_left_inverse.clone());
            cb.require_zero(
                "num_rows_left_cur * is_zero == 0",
                num_rows_left_cur * is_zero.clone(),
            );
            cb.require_zero(
                "num_rows_left_inverse * is_zero == 0",
                num_rows_left_inverse * is_zero.clone(),
            );
            cb.require_equal("q_step == is_zero", q_step, is_zero);
            // On each usable row
            cb.gate(q_usable)
        });

        let mut stored_expressions_map = HashMap::new();
        let step_next = Step::new(meta, advices, MAX_STEP_HEIGHT, true);
        macro_rules! configure_gadget {
            () => {
                Self::configure_gadget(
                    meta,
                    advices,
                    q_usable,
                    q_step,
                    num_rows_until_next_step,
                    q_step_first,
                    q_step_last,
                    &power_of_randomness,
                    &step_curr,
                    &step_next,
                    &mut height_map,
                    &mut stored_expressions_map,
                )
            };
        }

        let cell_manager = step_curr.cell_manager.clone();
        let config = Self {
            q_usable,
            q_step,
            constants,
            num_rows_until_next_step,
            num_rows_inv,
            q_step_first,
            q_step_last,
            advices,
            // internal states
            begin_tx_gadget: configure_gadget!(),
            end_block_gadget: configure_gadget!(),
            end_inner_block_gadget: configure_gadget!(),
            end_tx_gadget: configure_gadget!(),
            // opcode gadgets
            add_sub_gadget: configure_gadget!(),
            addmod_gadget: configure_gadget!(),
            bitwise_gadget: configure_gadget!(),
            byte_gadget: configure_gadget!(),
            call_op_gadget: configure_gadget!(),
            call_value_gadget: configure_gadget!(),
            calldatacopy_gadget: configure_gadget!(),
            calldataload_gadget: configure_gadget!(),
            calldatasize_gadget: configure_gadget!(),
            caller_gadget: configure_gadget!(),
            chainid_gadget: configure_gadget!(),
            codecopy_gadget: configure_gadget!(),
            codesize_gadget: configure_gadget!(),
            comparator_gadget: configure_gadget!(),
            dup_gadget: configure_gadget!(),
            extcodehash_gadget: configure_gadget!(),
            extcodesize_gadget: configure_gadget!(),
            gas_gadget: configure_gadget!(),
            gasprice_gadget: configure_gadget!(),
            iszero_gadget: configure_gadget!(),
            jump_gadget: configure_gadget!(),
            jumpdest_gadget: configure_gadget!(),
            jumpi_gadget: configure_gadget!(),
            log_gadget: configure_gadget!(),
            memory_gadget: configure_gadget!(),
            msize_gadget: configure_gadget!(),
            mul_div_mod_gadget: configure_gadget!(),
            mulmod_gadget: configure_gadget!(),
            not_gadget: configure_gadget!(),
            origin_gadget: configure_gadget!(),
            pc_gadget: configure_gadget!(),
            pop_gadget: configure_gadget!(),
            push_gadget: configure_gadget!(),
            return_revert_gadget: configure_gadget!(),
            sdiv_smod_gadget: configure_gadget!(),
            selfbalance_gadget: configure_gadget!(),
            sha3_gadget: configure_gadget!(),
            address_gadget: configure_gadget!(),
            balance_gadget: configure_gadget!(),
            blockhash_gadget: configure_gadget!(),
            exp_gadget: configure_gadget!(),
            sar_gadget: configure_gadget!(),
            extcodecopy_gadget: configure_gadget!(),
            returndatasize_gadget: configure_gadget!(),
            returndatacopy_gadget: configure_gadget!(),
            create_gadget: configure_gadget!(),
            create2_gadget: configure_gadget!(),
            selfdestruct_gadget: configure_gadget!(),
            shl_shr_gadget: configure_gadget!(),
            signed_comparator_gadget: configure_gadget!(),
            signextend_gadget: configure_gadget!(),
            sload_gadget: configure_gadget!(),
            sstore_gadget: configure_gadget!(),
            stop_gadget: configure_gadget!(),
            swap_gadget: configure_gadget!(),
            block_ctx_u64_gadget: configure_gadget!(),
            block_ctx_u160_gadget: configure_gadget!(),
            block_ctx_u256_gadget: configure_gadget!(),
            // error gadgets
            error_oog_constant: configure_gadget!(),
            error_oog_static_memory_gadget: configure_gadget!(),
            error_stack: configure_gadget!(),
            error_oog_dynamic_memory_gadget: configure_gadget!(),
            error_oog_log: configure_gadget!(),
            error_oog_sload: configure_gadget!(),
            error_oog_sstore: configure_gadget!(),
            error_oog_call: configure_gadget!(),
            error_oog_memory_copy: configure_gadget!(),
            error_oog_account_access: configure_gadget!(),
            error_oog_sha3: configure_gadget!(),
            error_oog_ext_codecopy: configure_gadget!(),
            error_oog_call_code: configure_gadget!(),
            error_oog_delegate_call: configure_gadget!(),
            error_oog_exp: configure_gadget!(),
            error_oog_create2: configure_gadget!(),
            error_oog_static_call: configure_gadget!(),
            error_oog_self_destruct: configure_gadget!(),
            error_oog_code_store: configure_gadget!(),
            error_insufficient_balance: configure_gadget!(),
            error_invalid_jump: configure_gadget!(),
            error_write_protection: configure_gadget!(),
            error_depth: configure_gadget!(),
            error_contract_address_collision: configure_gadget!(),
            error_invalid_creation_code: configure_gadget!(),
            error_return_data_out_of_bound: configure_gadget!(),
            invalid_opcode_gadget: configure_gadget!(),
            // step and presets
            step: step_curr,
            height_map,
            stored_expressions_map,
        };

        Self::configure_lookup(
            meta,
            fixed_table,
            byte_table,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            &power_of_randomness,
            &cell_manager,
        );

        config
    }

    pub fn get_step_height_option(&self, execution_state: ExecutionState) -> Option<usize> {
        self.height_map.get(&execution_state).copied()
    }

    pub fn get_step_height(&self, execution_state: ExecutionState) -> usize {
        self.get_step_height_option(execution_state)
            .unwrap_or_else(|| panic!("Execution state unknown: {:?}", execution_state))
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_gadget<G: ExecutionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_WIDTH],
        q_usable: Selector,
        q_step: Column<Advice>,
        num_rows_until_next_step: Column<Advice>,
        q_step_first: Selector,
        q_step_last: Selector,
        power_of_randomness: &[Expression<F>; 31],
        step_curr: &Step<F>,
        step_next: &Step<F>,
        height_map: &mut HashMap<ExecutionState, usize>,
        stored_expressions_map: &mut HashMap<ExecutionState, Vec<StoredExpression<F>>>,
    ) -> G {
        // Configure the gadget with the max height first so we can find out the actual
        // height
        let height = {
            let mut cb = ConstraintBuilder::new(
                step_curr.clone(),
                step_next.clone(),
                power_of_randomness,
                G::EXECUTION_STATE,
            );
            G::configure(&mut cb);
            let (_, _, height) = cb.build();
            height
        };

        // Now actually configure the gadget with the correct minimal height
        let step_next = &Step::new(meta, advices, height, true);
        let mut cb = ConstraintBuilder::new(
            step_curr.clone(),
            step_next.clone(),
            power_of_randomness,
            G::EXECUTION_STATE,
        );

        let gadget = G::configure(&mut cb);

        // Enforce the step height for this opcode
        let num_rows_until_next_step_next = query_expression(meta, |meta| {
            meta.query_advice(num_rows_until_next_step, Rotation::next())
        });
        cb.require_equal(
            "num_rows_until_next_step_next := height - 1",
            num_rows_until_next_step_next,
            (height - 1).expr(),
        );

        let (constraints, stored_expressions, _) = cb.build();
        debug_assert!(
            !height_map.contains_key(&G::EXECUTION_STATE),
            "execution state already configured"
        );
        height_map.insert(G::EXECUTION_STATE, height);
        debug_assert!(
            !stored_expressions_map.contains_key(&G::EXECUTION_STATE),
            "execution state already configured"
        );
        stored_expressions_map.insert(G::EXECUTION_STATE, stored_expressions);

        // Enforce the logic for this opcode
        let sel_step: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_advice(q_step, Rotation::cur());
        let sel_step_first: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_selector(q_step_first);
        let sel_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_selector(q_step_last);
        let sel_not_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            meta.query_advice(q_step, Rotation::cur()) * not::expr(meta.query_selector(q_step_last))
        };
        for (selector, constraints) in [
            (sel_step, constraints.step),
            (sel_step_first, constraints.step_first),
            (sel_step_last, constraints.step_last),
            (sel_not_step_last, constraints.not_step_last),
        ] {
            if !constraints.is_empty() {
                meta.create_gate(G::NAME, |meta| {
                    let q_usable = meta.query_selector(q_usable);
                    let selector = selector(meta);
                    constraints.into_iter().map(move |(name, constraint)| {
                        (name, q_usable.clone() * selector.clone() * constraint)
                    })
                });
            }
        }

        // Enforce the state transitions for this opcode
        meta.create_gate("Constrain state machine transitions", |meta| {
            let q_usable = meta.query_selector(q_usable);
            let q_step = meta.query_advice(q_step, Rotation::cur());
            let q_step_last = meta.query_selector(q_step_last);

            // ExecutionState transition should be correct.
            iter::empty()
                .chain(
                    IntoIterator::into_iter([
                        (
                            "EndTx can only transit to BeginTx or EndInnerBlock",
                            ExecutionState::EndTx,
                            vec![ExecutionState::BeginTx, ExecutionState::EndInnerBlock],
                        ),
                        (
                            "EndInnerBlock can only transition to BeginTx, EndInnerBlock or EndBlock",
                            ExecutionState::EndInnerBlock,
                            vec![ExecutionState::BeginTx, ExecutionState::EndInnerBlock, ExecutionState::EndBlock],
                        ),
                        (
                            "EndBlock can only transit to EndBlock",
                            ExecutionState::EndBlock,
                            vec![ExecutionState::EndBlock],
                        ),
                    ])
                    .filter(move |(_, from, _)| *from == G::EXECUTION_STATE)
                    .map(|(_, _, to)| 1.expr() - step_next.execution_state_selector(to)),
                )
                .chain(
                    IntoIterator::into_iter([
                        (
                            "Only EndTx or EndInnerBlock can transit to BeginTx",
                            ExecutionState::BeginTx,
                            vec![ExecutionState::EndTx, ExecutionState::EndInnerBlock],
                        ),
                        (
                            "Only ExecutionState which halts or BeginTx can transit to EndTx",
                            ExecutionState::EndTx,
                            ExecutionState::iter()
                                .filter(ExecutionState::halts)
                                .chain(iter::once(ExecutionState::BeginTx))
                                .collect(),
                        ),
                        (
                            "Only EndInnerBlock or EndBlock can transit to EndBlock",
                            ExecutionState::EndBlock,
                            vec![ExecutionState::EndInnerBlock, ExecutionState::EndBlock],
                        ),
                        (
                            "Only EndTx or EndInnerBlock can transit to EndInnerBlock",
                            ExecutionState::EndInnerBlock,
                            vec![ExecutionState::EndTx, ExecutionState::EndInnerBlock],
                        ),
                    ])
                    .filter(move |(_, _, from)| !from.contains(&G::EXECUTION_STATE))
                    .map(|(_, to, _)| step_next.execution_state_selector([to])),
                )
                .chain(
                    IntoIterator::into_iter([
                        (
                            "EndInnerBlock -> BeginTx/EndInnerBlock: block number increases by one",
                            ExecutionState::EndInnerBlock,
                            vec![ExecutionState::BeginTx, ExecutionState::EndInnerBlock],
                            step_next.state.block_number.expr() - step_curr.state.block_number.expr() - 1.expr(),
                        ),
                        (
                            "EndInnerBlock -> EndBlock: block number does not change",
                            ExecutionState::EndInnerBlock,
                            vec![ExecutionState::EndBlock],
                            step_next.state.block_number.expr() - step_curr.state.block_number.expr(),
                        ),
                    ])
                    .filter(move |(_, from, _, _)| *from == G::EXECUTION_STATE)
                    .map(|(_, _, to, expr)| step_next.execution_state_selector(to) * expr)
                )
                .chain(
                    IntoIterator::into_iter([
                        (
                            "step_cur != EndInnerBlock: block number does not change",
                            ExecutionState::EndInnerBlock,
                            step_next.state.block_number.expr() - step_curr.state.block_number.expr(),
                        ),
                    ])
                    .filter(move |(_, from, _)| *from != G::EXECUTION_STATE)
                    .map(|(_, _, expr)| expr)
                )
                // Accumulate all state transition checks.
                // This can be done because all summed values are enforced to be boolean.
                .reduce(|accum, poly| accum + poly)
                .map(move |poly| {
                    q_usable.clone()
                        * q_step.clone()
                        * (1.expr() - q_step_last.clone())
                        * step_curr.execution_state_selector([G::EXECUTION_STATE])
                        * poly
                })
        });

        gadget
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_lookup(
        meta: &mut ConstraintSystem<F>,
        fixed_table: &dyn LookupTable<F>,
        byte_table: &dyn LookupTable<F>,
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
        copy_table: &dyn LookupTable<F>,
        keccak_table: &dyn LookupTable<F>,
        exp_table: &dyn LookupTable<F>,
        power_of_randomness: &[Expression<F>; 31],
        cell_manager: &CellManager<F>,
    ) {
        for column in cell_manager.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                let name = format!("{:?}", table);
                meta.lookup_any(Box::leak(name.into_boxed_str()), |meta| {
                    let table_expressions = match table {
                        Table::Fixed => fixed_table,
                        Table::Tx => tx_table,
                        Table::Rw => rw_table,
                        Table::Bytecode => bytecode_table,
                        Table::Block => block_table,
                        Table::Byte => byte_table,
                        Table::Copy => copy_table,
                        Table::Keccak => keccak_table,
                        Table::Exp => exp_table,
                    }
                    .table_exprs(meta);
                    vec![(
                        column.expr(),
                        rlc::expr(&table_expressions, power_of_randomness),
                    )]
                });
            }
        }
    }

    pub fn get_num_rows_required(&self, block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        let evm_rows = block.evm_circuit_pad_to;
        if evm_rows == 0 {
            for transaction in &block.txs {
                for step in &transaction.steps {
                    num_rows += self.get_step_height(step.execution_state);
                }
            }
            num_rows += 1; // EndBlock
        } else {
            num_rows = block.evm_circuit_pad_to;
        }
        num_rows
    }

    /// Assign columns related to step counter
    fn assign_q_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        height: usize,
    ) -> Result<(), Error> {
        for idx in 0..height {
            let offset = offset + idx;
            self.q_usable.enable(region, offset)?;
            region.assign_advice(
                || "step selector",
                self.q_step,
                offset,
                || Value::known(if idx == 0 { F::one() } else { F::zero() }),
            )?;
            let value = if idx == 0 {
                F::zero()
            } else {
                F::from((height - idx) as u64)
            };
            region.assign_advice(
                || "step height",
                self.num_rows_until_next_step,
                offset,
                || Value::known(value),
            )?;
            region.assign_advice(
                || "step height inv",
                self.num_rows_inv,
                offset,
                || Value::known(value.invert().unwrap_or(F::zero())),
            )?;
        }
        Ok(())
    }

    /// Assign block
    /// When exact is enabled, assign exact steps in block without padding for
    /// unit test purpose
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        let power_of_randomness = (1..32)
            .map(|exp| block.randomness.pow(&[exp, 0, 0, 0]))
            .collect::<Vec<F>>()
            .try_into()
            .unwrap();

        let mut is_first_time = true;

        layouter.assign_region(
            || "Execution step",
            |mut region| {
                log::info!("start execution step assignment");
                if is_first_time {
                    is_first_time = false;
                    region.assign_advice(
                        || "step selector",
                        self.q_step,
                        self.get_num_rows_required(block) - 1,
                        || Value::known(F::zero()),
                    )?;
                    return Ok(());
                }
                let mut offset = 0;

                self.q_step_first.enable(&mut region, offset)?;

                let dummy_tx = Transaction::default();
                let last_call = block
                    .txs
                    .last()
                    .map(|tx| tx.calls[0].clone())
                    .unwrap_or_else(Call::default);
                let end_block_not_last = &block.end_block_not_last;
                let end_block_last = &block.end_block_last;
                // Collect all steps
                let mut steps = block
                    .txs
                    .iter()
                    .flat_map(|tx| {
                        tx.steps
                            .iter()
                            .map(move |step| (tx, &tx.calls[step.call_index], step))
                    })
                    .chain(std::iter::once((&dummy_tx, &last_call, end_block_not_last)))
                    .peekable();

                let evm_rows = block.evm_circuit_pad_to;
                let no_padding = evm_rows == 0;

                // part1: assign real steps
                loop {
                    let (transaction, call, step) = steps.next().expect("should not be empty");
                    let next = steps.peek();
                    if next.is_none() {
                        break;
                    }
                    let height = self.get_step_height(step.execution_state);

                    // Assign the step witness
                    if step.execution_state == ExecutionState::EndTx {
                        let mut tx = transaction.clone();
                        tx.call_data.clear();
                        tx.calls.clear();
                        tx.steps.clear();
                        let total_gas = {
                            let gas_used = tx.gas - step.gas_left;
                            let current_cumulative_gas_used: u64 = if tx.id == 1 {
                                0
                            } else {
                                // first transaction needs TxReceiptFieldTag::COUNT(3) lookups
                                // to tx receipt,
                                // while later transactions need 4 (with one extra cumulative
                                // gas read) lookups
                                let rw = &block.rws[(
                                    RwTableTag::TxReceipt,
                                    (tx.id - 2) * (TxReceiptFieldTag::COUNT + 1) + 2,
                                )];
                                rw.receipt_value()
                            };
                            current_cumulative_gas_used + gas_used
                        };
                        log::info!(
                            "offset {} tx_num {} total_gas {} assign last step {:?} of tx {:?}",
                            offset,
                            tx.id,
                            total_gas,
                            step,
                            tx
                        );
                    }
                    self.assign_exec_step(
                        &mut region,
                        offset,
                        block,
                        transaction,
                        call,
                        step,
                        height,
                        next.copied(),
                        power_of_randomness,
                    )?;

                    // q_step logic
                    self.assign_q_step(&mut region, offset, height)?;

                    offset += height;
                }

                // part2: assign non-last EndBlock steps when padding needed
                if !no_padding {
                    if offset >= evm_rows {
                        log::error!(
                            "evm circuit offset larger than padding: {} > {}",
                            offset,
                            evm_rows
                        );
                        return Err(Error::Synthesis);
                    }
                    let height = self.get_step_height(ExecutionState::EndBlock);
                    debug_assert_eq!(height, 1);
                    let last_row = evm_rows - 1;
                    log::trace!(
                        "assign non-last EndBlock in range [{},{})",
                        offset,
                        last_row
                    );
                    self.assign_same_exec_step_in_range(
                        &mut region,
                        offset,
                        last_row,
                        block,
                        &dummy_tx,
                        &last_call,
                        end_block_not_last,
                        height,
                        power_of_randomness,
                    )?;

                    for row_idx in offset..last_row {
                        self.assign_q_step(&mut region, row_idx, height)?;
                    }
                    offset = last_row;
                }

                // part3: assign the last EndBlock at offset `evm_rows - 1`
                let height = self.get_step_height(ExecutionState::EndBlock);
                debug_assert_eq!(height, 1);
                log::trace!("assign last EndBlock at offset {}", offset);
                self.assign_exec_step(
                    &mut region,
                    offset,
                    block,
                    &dummy_tx,
                    &last_call,
                    end_block_last,
                    height,
                    None,
                    power_of_randomness,
                )?;
                self.assign_q_step(&mut region, offset, height)?;
                // enable q_step_last
                self.q_step_last.enable(&mut region, offset)?;
                offset += height;

                // part4:
                // These are still referenced (but not used) in next rows
                region.assign_advice(
                    || "step height",
                    self.num_rows_until_next_step,
                    offset,
                    || Value::known(F::zero()),
                )?;
                region.assign_advice(
                    || "step height inv",
                    self.q_step,
                    offset,
                    || Value::known(F::zero()),
                )?;

                log::info!("finish execution step assignment");
                log::debug!("assign for region done at offset {}", offset);
                Ok(())
            },
        )?;
        log::debug!("assign_block done");
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_same_exec_step_in_range(
        &self,
        region: &mut Region<'_, F>,
        offset_begin: usize,
        offset_end: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
        height: usize,
        power_of_randomness: [F; 31],
    ) -> Result<(), Error> {
        if offset_end <= offset_begin {
            return Ok(());
        }
        assert_eq!(height, 1);
        assert!(step.rw_indices.is_empty());
        assert!(matches!(step.execution_state, ExecutionState::EndBlock));

        // Disable access to next step deliberately for "repeatable" step
        let region = &mut CachedRegion::<'_, '_, F>::new(
            region,
            power_of_randomness,
            self.advices.to_vec(),
            1,
            offset_begin,
        );
        self.assign_exec_step_int(region, offset_begin, block, transaction, call, step)?;

        region.replicate_assignment_for_range(
            || format!("repeat {:?} rows", step.execution_state),
            offset_begin + 1,
            offset_end,
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
        height: usize,
        next: Option<(&Transaction, &Call, &ExecStep)>,
        power_of_randomness: [F; 31],
    ) -> Result<(), Error> {
        if !(matches!(step.execution_state, ExecutionState::EndBlock) && step.rw_indices.is_empty())
        {
            log::trace!(
                "assign_exec_step offset: {} state {:?} step: {:?} call: {:?}",
                offset,
                step.execution_state,
                step,
                call
            );
        }
        // Make the region large enough for the current step and the next step.
        // The next step's next step may also be accessed, so make the region large
        // enough for 3 steps.
        let region = &mut CachedRegion::<'_, '_, F>::new(
            region,
            power_of_randomness,
            self.advices.to_vec(),
            MAX_STEP_HEIGHT * 3,
            offset,
        );

        // Also set the witness of the next step.
        // These may be used in stored expressions and
        // so their witness values need to be known to be able
        // to correctly calculate the intermediate value.
        if let Some((transaction_next, call_next, step_next)) = next {
            self.assign_exec_step_int(
                region,
                offset + height,
                block,
                transaction_next,
                call_next,
                step_next,
            )?;
        }

        self.assign_exec_step_int(region, offset, block, transaction, call, step)
    }

    fn assign_exec_step_int(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.step
            .assign_exec_step(region, offset, block, transaction, call, step)?;

        macro_rules! assign_exec_step {
            ($gadget:expr) => {
                $gadget.assign_exec_step(region, offset, block, transaction, call, step)?
            };
        }

        match step.execution_state {
            // internal states
            ExecutionState::BeginTx => assign_exec_step!(self.begin_tx_gadget),
            ExecutionState::EndTx => assign_exec_step!(self.end_tx_gadget),
            ExecutionState::EndInnerBlock => assign_exec_step!(self.end_inner_block_gadget),
            ExecutionState::EndBlock => assign_exec_step!(self.end_block_gadget),
            // opcode
            ExecutionState::ADD_SUB => assign_exec_step!(self.add_sub_gadget),
            ExecutionState::ADDMOD => assign_exec_step!(self.addmod_gadget),
            ExecutionState::ADDRESS => assign_exec_step!(self.address_gadget),
            ExecutionState::BALANCE => assign_exec_step!(self.balance_gadget),
            ExecutionState::BITWISE => assign_exec_step!(self.bitwise_gadget),
            ExecutionState::BYTE => assign_exec_step!(self.byte_gadget),
            ExecutionState::CALL_OP => assign_exec_step!(self.call_op_gadget),
            ExecutionState::CALLDATACOPY => assign_exec_step!(self.calldatacopy_gadget),
            ExecutionState::CALLDATALOAD => assign_exec_step!(self.calldataload_gadget),
            ExecutionState::CALLDATASIZE => assign_exec_step!(self.calldatasize_gadget),
            ExecutionState::CALLER => assign_exec_step!(self.caller_gadget),
            ExecutionState::CALLVALUE => assign_exec_step!(self.call_value_gadget),
            ExecutionState::CHAINID => assign_exec_step!(self.chainid_gadget),
            ExecutionState::CODECOPY => assign_exec_step!(self.codecopy_gadget),
            ExecutionState::CODESIZE => assign_exec_step!(self.codesize_gadget),
            ExecutionState::CMP => assign_exec_step!(self.comparator_gadget),
            ExecutionState::DUP => assign_exec_step!(self.dup_gadget),
            ExecutionState::EXP => assign_exec_step!(self.exp_gadget),
            ExecutionState::EXTCODEHASH => assign_exec_step!(self.extcodehash_gadget),
            ExecutionState::EXTCODESIZE => assign_exec_step!(self.extcodesize_gadget),
            ExecutionState::GAS => assign_exec_step!(self.gas_gadget),
            ExecutionState::GASPRICE => assign_exec_step!(self.gasprice_gadget),
            ExecutionState::ISZERO => assign_exec_step!(self.iszero_gadget),
            ExecutionState::JUMP => assign_exec_step!(self.jump_gadget),
            ExecutionState::JUMPDEST => assign_exec_step!(self.jumpdest_gadget),
            ExecutionState::JUMPI => assign_exec_step!(self.jumpi_gadget),
            ExecutionState::LOG => assign_exec_step!(self.log_gadget),
            ExecutionState::MEMORY => assign_exec_step!(self.memory_gadget),
            ExecutionState::MSIZE => assign_exec_step!(self.msize_gadget),
            ExecutionState::MUL_DIV_MOD => assign_exec_step!(self.mul_div_mod_gadget),
            ExecutionState::MULMOD => assign_exec_step!(self.mulmod_gadget),
            ExecutionState::NOT => assign_exec_step!(self.not_gadget),
            ExecutionState::ORIGIN => assign_exec_step!(self.origin_gadget),
            ExecutionState::PC => assign_exec_step!(self.pc_gadget),
            ExecutionState::POP => assign_exec_step!(self.pop_gadget),
            ExecutionState::PUSH => assign_exec_step!(self.push_gadget),
            ExecutionState::RETURN_REVERT => assign_exec_step!(self.return_revert_gadget),
            ExecutionState::RETURNDATASIZE => assign_exec_step!(self.returndatasize_gadget),
            ExecutionState::RETURNDATACOPY => assign_exec_step!(self.returndatacopy_gadget),
            ExecutionState::SCMP => assign_exec_step!(self.signed_comparator_gadget),
            ExecutionState::SDIV_SMOD => assign_exec_step!(self.sdiv_smod_gadget),
            ExecutionState::BLOCKCTXU64 => assign_exec_step!(self.block_ctx_u64_gadget),
            ExecutionState::BLOCKCTXU160 => assign_exec_step!(self.block_ctx_u160_gadget),
            ExecutionState::BLOCKCTXU256 => assign_exec_step!(self.block_ctx_u256_gadget),
            ExecutionState::BLOCKHASH => assign_exec_step!(self.blockhash_gadget),
            ExecutionState::SELFBALANCE => assign_exec_step!(self.selfbalance_gadget),
            // dummy gadgets
            ExecutionState::SAR => assign_exec_step!(self.sar_gadget),
            ExecutionState::EXTCODECOPY => assign_exec_step!(self.extcodecopy_gadget),
            ExecutionState::CREATE => assign_exec_step!(self.create_gadget),
            ExecutionState::CREATE2 => assign_exec_step!(self.create2_gadget),
            ExecutionState::SELFDESTRUCT => assign_exec_step!(self.selfdestruct_gadget),
            // end of dummy gadgets
            ExecutionState::SHA3 => assign_exec_step!(self.sha3_gadget),
            ExecutionState::SHL_SHR => assign_exec_step!(self.shl_shr_gadget),
            ExecutionState::SIGNEXTEND => assign_exec_step!(self.signextend_gadget),
            ExecutionState::SLOAD => assign_exec_step!(self.sload_gadget),
            ExecutionState::SSTORE => assign_exec_step!(self.sstore_gadget),
            ExecutionState::STOP => assign_exec_step!(self.stop_gadget),
            ExecutionState::SWAP => assign_exec_step!(self.swap_gadget),
            // dummy errors
            ExecutionState::ErrorOutOfGasStaticMemoryExpansion => {
                assign_exec_step!(self.error_oog_static_memory_gadget)
            }
            ExecutionState::ErrorOutOfGasConstant => {
                assign_exec_step!(self.error_oog_constant)
            }
            ExecutionState::ErrorOutOfGasCALL => {
                assign_exec_step!(self.error_oog_call)
            }
            ExecutionState::ErrorOutOfGasDynamicMemoryExpansion => {
                assign_exec_step!(self.error_oog_dynamic_memory_gadget)
            }
            ExecutionState::ErrorOutOfGasLOG => {
                assign_exec_step!(self.error_oog_log)
            }
            ExecutionState::ErrorOutOfGasSLOAD => {
                assign_exec_step!(self.error_oog_sload)
            }
            ExecutionState::ErrorOutOfGasSSTORE => {
                assign_exec_step!(self.error_oog_sstore)
            }
            ExecutionState::ErrorOutOfGasMemoryCopy => {
                assign_exec_step!(self.error_oog_memory_copy)
            }
            ExecutionState::ErrorOutOfGasAccountAccess => {
                assign_exec_step!(self.error_oog_account_access)
            }
            ExecutionState::ErrorOutOfGasSHA3 => {
                assign_exec_step!(self.error_oog_sha3)
            }
            ExecutionState::ErrorOutOfGasEXTCODECOPY => {
                assign_exec_step!(self.error_oog_ext_codecopy)
            }
            ExecutionState::ErrorOutOfGasCALLCODE => {
                assign_exec_step!(self.error_oog_call_code)
            }
            ExecutionState::ErrorOutOfGasDELEGATECALL => {
                assign_exec_step!(self.error_oog_delegate_call)
            }
            ExecutionState::ErrorOutOfGasEXP => {
                assign_exec_step!(self.error_oog_exp)
            }
            ExecutionState::ErrorOutOfGasCREATE2 => {
                assign_exec_step!(self.error_oog_create2)
            }
            ExecutionState::ErrorOutOfGasSTATICCALL => {
                assign_exec_step!(self.error_oog_static_call)
            }
            ExecutionState::ErrorOutOfGasSELFDESTRUCT => {
                assign_exec_step!(self.error_oog_self_destruct)
            }

            ExecutionState::ErrorOutOfGasCodeStore => {
                assign_exec_step!(self.error_oog_code_store)
            }
            ExecutionState::ErrorStack => {
                assign_exec_step!(self.error_stack)
            }

            ExecutionState::ErrorInsufficientBalance => {
                assign_exec_step!(self.error_insufficient_balance)
            }
            ExecutionState::ErrorInvalidJump => {
                assign_exec_step!(self.error_invalid_jump)
            }
            ExecutionState::ErrorWriteProtection => {
                assign_exec_step!(self.error_write_protection)
            }
            ExecutionState::ErrorDepth => {
                assign_exec_step!(self.error_depth)
            }
            ExecutionState::ErrorContractAddressCollision => {
                assign_exec_step!(self.error_contract_address_collision)
            }
            ExecutionState::ErrorInvalidCreationCode => {
                assign_exec_step!(self.error_invalid_creation_code)
            }
            ExecutionState::ErrorReturnDataOutOfBound => {
                assign_exec_step!(self.error_return_data_out_of_bound)
            }

            ExecutionState::ErrorInvalidOpcode => {
                assign_exec_step!(self.invalid_opcode_gadget)
            }

            _ => unimplemented!("unimplemented ExecutionState: {:?}", step.execution_state),
        }

        // Fill in the witness values for stored expressions
        let assigned_stored_expressions = self.assign_stored_expressions(region, offset, step)?;

        // enable with `RUST_LOG=debug`
        if log::log_enabled!(log::Level::Debug) {
            let is_padding_step = matches!(step.execution_state, ExecutionState::EndBlock)
                && step.rw_indices.is_empty();
            if !is_padding_step {
                // expensive function call
                Self::check_rw_lookup(
                    &assigned_stored_expressions,
                    offset,
                    step,
                    call,
                    transaction,
                    block,
                );
            }
        }
        //}
        Ok(())
    }

    fn assign_stored_expressions(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<Vec<(String, F)>, Error> {
        let mut assigned_stored_expressions = Vec::new();
        for stored_expression in self
            .stored_expressions_map
            .get(&step.execution_state)
            .unwrap_or_else(|| panic!("Execution state unknown: {:?}", step.execution_state))
        {
            let assigned = stored_expression.assign(region, offset)?;
            assigned.value().map(|v| {
                let name = stored_expression.name.clone();
                assigned_stored_expressions.push((name, *v));
            });
        }
        Ok(assigned_stored_expressions)
    }

    fn check_rw_lookup(
        assigned_stored_expressions: &[(String, F)],
        offset: usize,
        step: &ExecStep,
        call: &Call,
        transaction: &Transaction,
        block: &Block<F>,
    ) {
        let mut assigned_rw_values = Vec::new();
        // Reversion lookup expressions have different ordering compared to rw table,
        // making it a bit complex to check,
        // so we skip checking reversion lookups.
        for (name, v) in assigned_stored_expressions {
            if name.starts_with("rw lookup ")
                && !name.contains(" with reversion")
                && !v.is_zero_vartime()
                && !assigned_rw_values.contains(&(name.clone(), *v))
            {
                assigned_rw_values.push((name.clone(), *v));
            }
        }

        let rlc_assignments: BTreeSet<_> = step
            .rw_indices
            .iter()
            .map(|rw_idx| block.rws[*rw_idx])
            .map(|rw| {
                rw.table_assignment_aux(block.randomness)
                    .rlc(block.randomness)
            })
            .collect();

        for (idx, (_name, value)) in assigned_rw_values.iter().enumerate() {
            let log_ctx = || {
                log::error!("assigned_rw_values {:?}", assigned_rw_values);
                for (idx, rw_idx) in step.rw_indices.iter().enumerate() {
                    log::error!(
                        "{}th rw of step: {:?} rlc {:?}",
                        idx,
                        block.rws[*rw_idx],
                        block.rws[*rw_idx]
                            .table_assignment_aux(block.randomness)
                            .rlc(block.randomness)
                    );
                }
                let mut tx = transaction.clone();
                tx.call_data.clear();
                tx.calls.clear();
                tx.steps.clear();
                log::error!(
                    "ctx: offset {} step {:?}. call: {:?}, tx: {:?}",
                    offset,
                    step,
                    call,
                    tx
                );
            };
            if idx >= step.rw_indices.len() {
                log_ctx();
                panic!(
                    "invalid rw len exp {} witness {}",
                    assigned_rw_values.len(),
                    step.rw_indices.len()
                );
            }

            let rw_idx = step.rw_indices[idx];
            let rw = block.rws[rw_idx];
            let table_assignments = rw.table_assignment_aux(block.randomness);
            let rlc = table_assignments.rlc(block.randomness);

            if !rlc_assignments.contains(value) {
                log_ctx();
                log::error!(
                    "incorrect rw witness. input_value {:?}, name \"{}\". table_value {:?}, table_assignments {:?}, rw {:?}, index {:?}, {}th rw of step",
                    assigned_rw_values[idx].1,
                    assigned_rw_values[idx].0,
                    rlc,
                    table_assignments,
                    rw,
                    rw_idx, idx);

                //debug_assert_eq!(
                //    rlc, assigned_rw_values[idx].1,
                //    "left is witness, right is expression"
                //);
            }
        }
    }
}
