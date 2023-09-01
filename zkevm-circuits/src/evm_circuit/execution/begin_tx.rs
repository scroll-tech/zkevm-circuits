use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_U64, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            and,
            common_gadget::{
                TransferGadgetInfo, TransferWithGasFeeGadget, TxL1FeeGadget, TxL1MsgGadget,
            },
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::{
                ConstantDivisionGadget, ContractCreateGadget, IsEqualGadget, IsZeroGadget,
                LtGadget, MulWordByU64Gadget, RangeCheckGadget,
            },
            CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{
        AccountFieldTag, BlockContextFieldTag, CallContextFieldTag, RwTableTag,
        TxFieldTag as TxContextFieldTag,
    },
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{Address, Field, ToLittleEndian, ToScalar, U256};
use ethers_core::utils::{get_contract_address, keccak256, rlp::RlpStream};
use gadgets::util::{expr_from_bytes, not, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

// For Shanghai, EIP-3651 (Warm COINBASE) adds 1 write op for coinbase.
#[cfg(feature = "shanghai")]
const SHANGHAI_RW_DELTA: u8 = 1;
#[cfg(not(feature = "shanghai"))]
const SHANGHAI_RW_DELTA: u8 = 0;

const PRECOMPILE_COUNT: usize = 9;

#[derive(Clone, Debug)]
pub(crate) struct BeginTxGadget<F> {
    tx_id: Cell<F>,
    sender_nonce: Cell<F>,
    tx_nonce: Cell<F>,
    tx_gas: Cell<F>,
    tx_gas_price: Word<F>,
    mul_gas_fee_by_gas: MulWordByU64Gadget<F>,
    tx_fee: Word<F>,
    tx_caller_address: Cell<F>,
    tx_caller_address_is_zero: IsZeroGadget<F>,
    tx_callee_address: Cell<F>,
    tx_callee_address_is_zero: IsZeroGadget<F>,
    call_callee_address: Cell<F>,
    tx_is_create: Cell<F>,
    tx_value: Word<F>,
    tx_call_data_length: Cell<F>,
    is_call_data_empty: IsZeroGadget<F>,
    tx_call_data_word_length: ConstantDivisionGadget<F, N_BYTES_U64>,
    tx_call_data_gas_cost: Cell<F>,
    // The gas cost for rlp-encoded bytes of unsigned tx
    tx_data_gas_cost: Cell<F>,
    reversion_info: ReversionInfo<F>,
    intrinsic_gas_cost: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    account_code_hash: Cell<F>,
    account_code_hash_is_empty: IsEqualGadget<F>,
    account_code_hash_is_zero: IsZeroGadget<F>,
    #[cfg(feature = "scroll")]
    account_keccak_code_hash: Cell<F>,
    call_code_hash: Cell<F>,
    call_code_hash_is_empty: IsEqualGadget<F>,
    call_code_hash_is_zero: IsZeroGadget<F>,
    is_precompile_lt: LtGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
    /// Keccak256(RLP([tx_caller_address, tx_nonce]))
    caller_nonce_hash_bytes: [Cell<F>; N_BYTES_WORD],
    keccak_code_hash: Cell<F>,
    init_code_rlc: Cell<F>,
    /// RLP gadget for CREATE address.
    create: ContractCreateGadget<F, false>,
    is_caller_callee_equal: Cell<F>,
    // EIP-3651 (Warm COINBASE) for Shanghai
    coinbase: Cell<F>,
    // Caller, callee and a list addresses are added to the access list before
    // coinbase, and may be duplicate.
    // <https://github.com/ethereum/go-ethereum/blob/604e215d1bb070dff98fb76aa965064c74e3633f/core/state/statedb.go#LL1119C9-L1119C9>
    is_coinbase_warm: Cell<F>,
    tx_l1_fee: TxL1FeeGadget<F>,
    tx_l1_msg: TxL1MsgGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for BeginTxGadget<F> {
    const NAME: &'static str = "BeginTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginTx;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.query_cell();

        let sender_nonce = cb.query_cell();
        let [tx_nonce, tx_gas, tx_caller_address, tx_callee_address, tx_is_create, tx_call_data_length, tx_call_data_gas_cost, tx_data_gas_cost] =
            [
                TxContextFieldTag::Nonce,
                TxContextFieldTag::Gas,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::CalleeAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
                TxContextFieldTag::TxDataGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));

        let is_call_data_empty = IsZeroGadget::construct(cb, tx_call_data_length.expr());

        let tx_l1_msg = TxL1MsgGadget::construct(cb, tx_id.expr(), tx_caller_address.expr());
        let tx_l1_fee = cb.condition(not::expr(tx_l1_msg.is_l1_msg()), |cb| {
            cb.require_equal(
                "tx.nonce == sender.nonce",
                tx_nonce.expr(),
                sender_nonce.expr(),
            );
            TxL1FeeGadget::construct(cb, tx_id.expr(), tx_data_gas_cost.expr())
        });
        cb.condition(tx_l1_msg.is_l1_msg(), |cb| {
            cb.require_zero("l1fee is 0 for l1msg", tx_data_gas_cost.expr());
        });
        // the rw delta caused by l1 related handling
        let l1_rw_delta = select::expr(
            tx_l1_msg.is_l1_msg(),
            tx_l1_msg.rw_delta(),
            tx_l1_fee.rw_delta(),
        ) + 1.expr();

        // the cost caused by l1
        let l1_fee_cost = select::expr(tx_l1_msg.is_l1_msg(), 0.expr(), tx_l1_fee.tx_l1_fee());
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::L1Fee,
            l1_fee_cost.expr(),
        ); // rwc_delta += 1

        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::TxId,
            tx_id.expr(),
        ); // rwc_delta += 1
        let mut reversion_info = cb.reversion_info_write(None); // rwc_delta += 2
        let is_persistent = reversion_info.is_persistent();
        cb.call_context_lookup(
            1.expr(),
            Some(call_id.expr()),
            CallContextFieldTag::IsSuccess,
            is_persistent.expr(),
        ); // rwc_delta += 1

        let tx_caller_address_is_zero = IsZeroGadget::construct(cb, tx_caller_address.expr());
        cb.require_equal(
            "CallerAddress != 0 (not a padding tx)",
            tx_caller_address_is_zero.expr(),
            false.expr(),
        );
        let tx_callee_address_is_zero = IsZeroGadget::construct(cb, tx_callee_address.expr());
        cb.condition(tx_is_create.expr(), |cb| {
            cb.require_equal(
                "Contract creation tx expects callee address to be zero",
                tx_callee_address_is_zero.expr(),
                true.expr(),
            )
        });
        let [tx_gas_price, tx_value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag, None));

        let call_callee_address = cb.query_cell();
        cb.condition(not::expr(tx_is_create.expr()), |cb| {
            cb.require_equal(
                "Tx to non-zero address",
                tx_callee_address.expr(),
                call_callee_address.expr(),
            );
        });

        // Add first BeginTx step constraint to have tx_id == 1
        cb.step_first(|cb| {
            cb.require_equal("tx_id is initialized to be 1", tx_id.expr(), 1.expr());
        });

        // Increase caller's nonce.
        // (tx caller's nonce always increases even when tx ends with error)
        cb.account_write(
            tx_caller_address.expr(),
            AccountFieldTag::Nonce,
            sender_nonce.expr() + 1.expr(),
            sender_nonce.expr(),
            None,
        ); // rwc_delta += 1

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.expr());
        let tx_fee = cb.query_word_rlc();

        cb.require_equal(
            "tx_fee == l1_fee + l2_fee",
            l1_fee_cost + from_bytes::expr(&mul_gas_fee_by_gas.product().cells[..16]),
            from_bytes::expr(&tx_fee.cells[..16]),
        );

        // a valid precompile address is: 1 <= addr <= 9 (addr != 0 && addr < 0xA)
        let is_precompile_lt = LtGadget::construct(cb, tx_callee_address.expr(), 0xA.expr());
        let is_precompile = and::expr([
            not::expr(tx_callee_address_is_zero.expr()),
            is_precompile_lt.expr(),
        ]);

        let tx_call_data_word_length =
            ConstantDivisionGadget::construct(cb, tx_call_data_length.expr() + 31.expr(), 32);

        // TODO1: Take gas cost of access list (EIP 2930) into consideration.
        // Use intrinsic gas
        // TODO2: contrain calling precompile directly

        let intrinsic_gas_cost = cb.query_cell();
        cb.condition(not::expr(is_precompile.expr()), |cb| {
            // Calculate gas cost of init code only for EIP-3860 of Shanghai.
            #[cfg(feature = "shanghai")]
            let init_code_gas_cost = select::expr(
                tx_is_create.expr(),
                tx_call_data_word_length.quotient().expr()
                    * eth_types::evm_types::INIT_CODE_WORD_GAS.expr(),
                0.expr(),
            );
            #[cfg(not(feature = "shanghai"))]
            let init_code_gas_cost = 0.expr();

            cb.require_equal(
                "calculate intrinsic gas cost",
                intrinsic_gas_cost.expr(),
                select::expr(
                    tx_is_create.expr(),
                    eth_types::evm_types::GasCost::CREATION_TX.expr(),
                    eth_types::evm_types::GasCost::TX.expr(),
                ) + tx_call_data_gas_cost.expr()
                    + init_code_gas_cost,
            )
        });
        // Check gas_left is sufficient
        let gas_left = tx_gas.expr() - intrinsic_gas_cost.expr();
        let sufficient_gas_left = RangeCheckGadget::construct(cb, gas_left.clone());

        for addr in 1..=PRECOMPILE_COUNT {
            cb.account_access_list_write(tx_id.expr(), addr.expr(), 1.expr(), 0.expr(), None);
        } // rwc_delta += PRECOMPILE_COUNT

        // Prepare access list of caller and callee
        cb.account_access_list_write(
            tx_id.expr(),
            tx_caller_address.expr(),
            1.expr(),
            0.expr(),
            None,
        ); // rwc_delta += 1
        let is_caller_callee_equal = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            call_callee_address.expr(),
            1.expr(),
            // No extra constraint being used here.
            // Correctness will be enforced in build_tx_access_list_account_constraints
            select::expr(
                is_precompile.expr(),
                1.expr(),
                is_caller_callee_equal.expr(),
            ),
            None,
        ); // rwc_delta += 1

        // Query coinbase address for Shanghai.
        let coinbase = cb.query_cell();
        let is_coinbase_warm = cb.query_bool();
        cb.block_lookup(
            BlockContextFieldTag::Coinbase.expr(),
            cb.curr.state.block_number.expr(),
            coinbase.expr(),
        );

        #[cfg(feature = "shanghai")]
        cb.account_access_list_write(
            tx_id.expr(),
            coinbase.expr(),
            1.expr(),
            is_coinbase_warm.expr(),
            None,
        ); // rwc_delta += 1

        let account_code_hash = cb.query_cell_phase2();
        let account_code_hash_is_empty =
            IsEqualGadget::construct(cb, account_code_hash.expr(), cb.empty_code_hash_rlc());
        let account_code_hash_is_zero = IsZeroGadget::construct(cb, account_code_hash.expr());
        let account_code_hash_is_empty_or_zero =
            account_code_hash_is_empty.expr() + account_code_hash_is_zero.expr();
        #[cfg(feature = "scroll")]
        let account_keccak_code_hash = cb.query_cell_phase2();

        let call_code_hash = cb.query_cell_phase2();
        let call_code_hash_is_empty =
            IsEqualGadget::construct(cb, call_code_hash.expr(), cb.empty_code_hash_rlc());
        let call_code_hash_is_zero = IsZeroGadget::construct(cb, call_code_hash.expr());
        let call_code_hash_is_empty_or_zero =
            call_code_hash_is_empty.expr() + call_code_hash_is_zero.expr();

        cb.account_read(
            call_callee_address.expr(),
            AccountFieldTag::CodeHash,
            account_code_hash.expr(),
        ); // rwc_delta += 1

        // Transfer value from caller to callee, creating account if necessary.
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            call_callee_address.expr(),
            not::expr(account_code_hash_is_zero.expr()),
            tx_is_create.expr(),
            account_code_hash.expr(),
            #[cfg(feature = "scroll")]
            account_keccak_code_hash.expr(),
            tx_value.clone(),
            tx_fee.clone(),
            &mut reversion_info,
        );

        let caller_nonce_hash_bytes = array_init::array_init(|_| cb.query_byte());
        let create = ContractCreateGadget::construct(cb);
        cb.require_equal(
            "tx caller address equivalence",
            tx_caller_address.expr(),
            create.caller_address(),
        );
        cb.condition(tx_is_create.expr(), |cb| {
            cb.require_equal(
                "call callee address equivalence",
                call_callee_address.expr(),
                expr_from_bytes(&caller_nonce_hash_bytes[0..N_BYTES_ACCOUNT_ADDRESS]),
            );
        });
        cb.require_equal(
            "tx nonce equivalence",
            tx_nonce.expr(),
            create.caller_nonce(),
        );
        cb.condition(not::expr(call_code_hash_is_empty_or_zero.expr()), |cb| {
            cb.require_equal(
                "code hash equivalence",
                cb.curr.state.code_hash.expr(),
                call_code_hash.expr(),
            );
        });

        // 1. Handle contract creation transaction.
        let (init_code_rlc, keccak_code_hash) = cb.condition(tx_is_create.expr(), |cb| {
            let output_rlc = cb.word_rlc::<N_BYTES_WORD>(
                caller_nonce_hash_bytes
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );
            cb.keccak_table_lookup(create.input_rlc(cb), create.input_length(), output_rlc);

            let keccak_code_hash = cb.query_cell_phase2();
            let init_code_rlc = cb.query_cell_phase2();
            // keccak table lookup for init code.
            cb.keccak_table_lookup(
                init_code_rlc.expr(),
                tx_call_data_length.expr(),
                keccak_code_hash.expr(),
            );
            // copy table lookup for init code.
            cb.condition(is_call_data_empty.expr(), |cb| {
                cb.require_zero(
                    "init_code_rlc is zero when calldata is empty",
                    init_code_rlc.expr(),
                )
            });
            cb.condition(not::expr(is_call_data_empty.expr()), |cb| {
                cb.copy_table_lookup(
                    tx_id.expr(),                    // src_id
                    CopyDataType::TxCalldata.expr(), // src_tag
                    cb.curr.state.code_hash.expr(),  // dst_id
                    CopyDataType::Bytecode.expr(),   // dst_tag
                    0.expr(),                        // src_addr
                    tx_call_data_length.expr(),      // src_addr_end
                    0.expr(),                        // dst_addr
                    tx_call_data_length.expr(),      // length
                    init_code_rlc.expr(),            // rlc_acc
                    0.expr(),                        // rwc increase
                )
            });

            cb.account_write(
                call_callee_address.expr(),
                AccountFieldTag::Nonce,
                1.expr(),
                0.expr(),
                Some(&mut reversion_info),
            );
            for (field_tag, value) in [
                (CallContextFieldTag::Depth, 1.expr()),
                (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
                (
                    CallContextFieldTag::CalleeAddress,
                    call_callee_address.expr(),
                ),
                (CallContextFieldTag::CallDataOffset, 0.expr()),
                (CallContextFieldTag::CallDataLength, 0.expr()),
                (CallContextFieldTag::Value, tx_value.expr()),
                (CallContextFieldTag::IsStatic, 0.expr()),
                (CallContextFieldTag::LastCalleeId, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                (CallContextFieldTag::IsRoot, 1.expr()),
                (CallContextFieldTag::IsCreate, 1.expr()),
                (
                    CallContextFieldTag::CodeHash,
                    cb.curr.state.code_hash.expr(),
                ),
            ] {
                cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
            }

            cb.require_step_state_transition(StepStateTransition {
                // 21 + a reads and writes:
                //   - a TxL1FeeGadget
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account (Caller) Nonce
                //   - Write TxAccessListAccount (Precompile) x PRECOMPILE_COUNT
                //   - Write TxAccessListAccount (Caller)
                //   - Write TxAccessListAccount (Callee)
                //   - Write TxAccessListAccount (Coinbase) only for Shanghai
                //   - Read Account CodeHash
                //   - a TransferWithGasFeeGadget
                //   - Write Account (Callee) Nonce (Reversible)
                //   - Write CallContext Depth
                //   - Write CallContext CallerAddress
                //   - Write CallContext CalleeAddress
                //   - Write CallContext CallDataOffset
                //   - Write CallContext CallDataLength
                //   - Write CallContext Value
                //   - Write CallContext IsStatic
                //   - Write CallContext LastCalleeId
                //   - Write CallContext LastCalleeReturnDataOffset
                //   - Write CallContext LastCalleeReturnDataLength
                //   - Write CallContext IsRoot
                //   - Write CallContext IsCreate
                //   - Write CallContext CodeHash
                rw_counter: Delta(
                    22.expr()
                        + l1_rw_delta.expr()
                        + transfer_with_gas_fee.rw_delta()
                        + SHANGHAI_RW_DELTA.expr()
                        + PRECOMPILE_COUNT.expr(),
                ),
                call_id: To(call_id.expr()),
                is_root: To(true.expr()),
                is_create: To(tx_is_create.expr()),
                code_hash: To(cb.curr.state.code_hash.expr()),
                gas_left: To(gas_left.clone()),
                // There are a + 1 reversible writes:
                //  - a TransferWithGasFeeGadget
                //  - Callee Account Nonce
                reversible_write_counter: To(transfer_with_gas_fee.reversible_w_delta() + 1.expr()),
                log_id: To(0.expr()),
                ..StepStateTransition::new_context()
            });

            (init_code_rlc, keccak_code_hash)
        });

        // 2. Handle call to precompiled contracts.
        cb.condition(is_precompile.expr(), |cb| {
            cb.require_equal(
                "precompile should be empty code hash",
                // FIXME: see in opcodes.rs gen_begin_tx_ops
                account_code_hash_is_empty_or_zero.expr(),
                true.expr(),
            );
            cb.require_equal(
                "Go to EndTx when Tx to precompile",
                cb.next.execution_state_selector([ExecutionState::EndTx]),
                1.expr(),
            );

            cb.require_step_state_transition(StepStateTransition {
                // 7 + TxL1FeeGadget + TransferWithGasFeeGadget associated reads or writes:
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account (Caller) Nonce
                //   - Write TxAccessListAccount (Precompile) x PRECOMPILE_COUNT
                //   - Write TxAccessListAccount (Caller)
                //   - Write TxAccessListAccount (Callee)
                //   - Write TxAccessListAccount (Coinbase) only for Shanghai
                //   - Read Account CodeHash
                //   - a TxL1FeeGadget
                //   - a TransferWithGasFeeGadget
                rw_counter: Delta(
                    8.expr()
                        + l1_rw_delta.expr()
                        + transfer_with_gas_fee.rw_delta()
                        + SHANGHAI_RW_DELTA.expr()
                        + PRECOMPILE_COUNT.expr()
                        // TRICKY:
                        // Process the reversion only for Precompile in begin TX. Since no
                        // associated opcodes could process reversion afterwards
                        // (corresponding to `handle_reversion` call in `gen_begin_tx_ops`).
                        // TODO:
                        // Move it to code of generating precompiled operations when implemented.
                        + not::expr(is_persistent.expr())
                            * transfer_with_gas_fee.reversible_w_delta(),
                ),
                call_id: To(call_id.expr()),
                ..StepStateTransition::any()
            });
        });

        // 3. Call to account with empty code.
        cb.condition(
            and::expr([
                not::expr(tx_is_create.expr()),
                account_code_hash_is_empty_or_zero.expr(),
                not::expr(is_precompile.expr()),
            ]),
            |cb| {
                cb.require_equal(
                    "Tx to account with empty code should be persistent",
                    reversion_info.is_persistent(),
                    1.expr(),
                );
                cb.require_equal(
                    "Go to EndTx when Tx to account with empty code",
                    cb.next.execution_state_selector([ExecutionState::EndTx]),
                    1.expr(),
                );

                cb.require_step_state_transition(StepStateTransition {
                    // 8 reads and writes:
                    //   - Write CallContext TxId
                    //   - Write CallContext RwCounterEndOfReversion
                    //   - Write CallContext IsPersistent
                    //   - Write CallContext IsSuccess
                    //   - Write Account Nonce
                    //   - Write TxAccessListAccount (Precompile) x PRECOMPILE_COUNT
                    //   - Write TxAccessListAccount (Caller)
                    //   - Write TxAccessListAccount (Callee)
                    //   - Write TxAccessListAccount (Coinbase) only for Shanghai
                    //   - Read Account CodeHash
                    //   - a TxL1FeeGadget
                    //   - a TransferWithGasFeeGadget
                    rw_counter: Delta(
                        8.expr()
                            + l1_rw_delta.expr()
                            + transfer_with_gas_fee.rw_delta()
                            + SHANGHAI_RW_DELTA.expr()
                            + PRECOMPILE_COUNT.expr(),
                    ),
                    call_id: To(call_id.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        // 4. Call to account with non-empty code.
        cb.condition(
            and::expr([
                not::expr(tx_is_create.expr()),
                not::expr(account_code_hash_is_empty_or_zero),
            ]),
            |cb| {
                // Setup first call's context.
                for (field_tag, value) in [
                    (CallContextFieldTag::Depth, 1.expr()),
                    (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
                    (
                        CallContextFieldTag::CalleeAddress,
                        call_callee_address.expr(),
                    ),
                    (CallContextFieldTag::CallDataOffset, 0.expr()),
                    (
                        CallContextFieldTag::CallDataLength,
                        tx_call_data_length.expr(),
                    ),
                    (CallContextFieldTag::Value, tx_value.expr()),
                    (CallContextFieldTag::IsStatic, 0.expr()),
                    (CallContextFieldTag::LastCalleeId, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                    (CallContextFieldTag::IsRoot, 1.expr()),
                    (CallContextFieldTag::IsCreate, tx_is_create.expr()),
                    (CallContextFieldTag::CodeHash, account_code_hash.expr()),
                ] {
                    cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
                }

                cb.require_step_state_transition(StepStateTransition {
                    // 21 reads and writes:
                    //   - a TxL1FeeGadget
                    //   - Write CallContext TxId
                    //   - Write CallContext RwCounterEndOfReversion
                    //   - Write CallContext IsPersistent
                    //   - Write CallContext IsSuccess
                    //   - Write Account Nonce
                    //   - Write TxAccessListAccount (Precompile) x PRECOMPILE_COUNT
                    //   - Write TxAccessListAccount (Caller)
                    //   - Write TxAccessListAccount (Callee)
                    //   - Write TxAccessListAccount (Coinbase) only for Shanghai
                    //   - Read Account CodeHash
                    //   - a TransferWithGasFeeGadget
                    //   - Write CallContext Depth
                    //   - Write CallContext CallerAddress
                    //   - Write CallContext CalleeAddress
                    //   - Write CallContext CallDataOffset
                    //   - Write CallContext CallDataLength
                    //   - Write CallContext Value
                    //   - Write CallContext IsStatic
                    //   - Write CallContext LastCalleeId
                    //   - Write CallContext LastCalleeReturnDataOffset
                    //   - Write CallContext LastCalleeReturnDataLength
                    //   - Write CallContext IsRoot
                    //   - Write CallContext IsCreate
                    //   - Write CallContext CodeHash
                    rw_counter: Delta(
                        21.expr()
                            + l1_rw_delta.expr()
                            + transfer_with_gas_fee.rw_delta()
                            + SHANGHAI_RW_DELTA.expr()
                            + PRECOMPILE_COUNT.expr(),
                    ),
                    call_id: To(call_id.expr()),
                    is_root: To(true.expr()),
                    is_create: To(tx_is_create.expr()),
                    code_hash: To(account_code_hash.expr()),
                    gas_left: To(gas_left),
                    reversible_write_counter: To(transfer_with_gas_fee.reversible_w_delta()),
                    log_id: To(0.expr()),
                    ..StepStateTransition::new_context()
                });
            },
        );

        Self {
            tx_id,
            tx_nonce,
            sender_nonce,
            tx_gas,
            tx_gas_price,
            mul_gas_fee_by_gas,
            tx_fee,
            tx_caller_address,
            tx_caller_address_is_zero,
            tx_callee_address,
            tx_callee_address_is_zero,
            call_callee_address,
            tx_is_create,
            tx_value,
            tx_call_data_length,
            is_call_data_empty,
            tx_call_data_word_length,
            tx_call_data_gas_cost,
            tx_data_gas_cost,
            reversion_info,
            sufficient_gas_left,
            transfer_with_gas_fee,
            account_code_hash,
            account_code_hash_is_empty,
            account_code_hash_is_zero,
            #[cfg(feature = "scroll")]
            account_keccak_code_hash,
            call_code_hash,
            call_code_hash_is_empty,
            call_code_hash_is_zero,
            intrinsic_gas_cost,
            is_precompile_lt,
            caller_nonce_hash_bytes,
            init_code_rlc,
            keccak_code_hash,
            create,
            is_caller_callee_equal,
            coinbase,
            is_coinbase_warm,
            tx_l1_fee,
            tx_l1_msg,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        /*
        for (i, idx) in step.rw_indices.iter().copied().enumerate() {
            log::trace!("begin_tx assign rw: #{i} {:?}", block.rws[idx]);
        }
        */

        let mut rws = StepRws::new(block, step);

        let caller_code_hash = if tx.tx_type.is_l1_msg() {
            let caller_code_hash_pair = rws.next().account_codehash_pair();
            assert_eq!(
                caller_code_hash_pair.0, caller_code_hash_pair.1,
                "expected a read for code hash"
            );
            caller_code_hash_pair.0
        } else {
            U256::zero()
        };
        self.tx_l1_msg
            .assign(region, offset, tx.tx_type, caller_code_hash)?;

        ////////////// RWS ////////////////
        // if L1:
        //      CodeHash
        //      if empty:
        //          CodeHash
        //          if scroll:
        //              KeccakCodeHash
        // else:
        //      3 l1 fee rw
        // TxId
        // RwCounterEndOfReversion
        // IsPersistent
        // IsSuccess
        // Nonce
        // Precompiles
        // caller addr
        // callee addr
        // coinbase
        rws.offset_add(if tx.tx_type.is_l1_msg() {
            if caller_code_hash.is_zero() {
                assert_eq!(
                    tx.nonce, 0,
                    "unexpected nonce {} when caller is not existed (must be 0)",
                    tx.nonce
                );
                if cfg!(feature = "scroll") {
                    2
                } else {
                    1
                }
            } else {
                0
            }
        } else {
            3
        });

        let rw = rws.next();
        debug_assert_eq!(rw.tag(), RwTableTag::CallContext);
        debug_assert_eq!(rw.field_tag(), Some(CallContextFieldTag::L1Fee as u64));

        let rw = rws.next();
        debug_assert_eq!(rw.tag(), RwTableTag::CallContext);
        debug_assert_eq!(rw.field_tag(), Some(CallContextFieldTag::TxId as u64));
        rws.offset_add(3);

        let rw = rws.next();
        debug_assert_eq!(rw.tag(), RwTableTag::Account);
        debug_assert_eq!(rw.field_tag(), Some(AccountFieldTag::Nonce as u64));
        let nonce_rw = rw.account_nonce_pair();

        rws.offset_add(PRECOMPILE_COUNT + 2);

        #[cfg(feature = "shanghai")]
        let is_coinbase_warm = rws.next().tx_access_list_value_pair().1;
        #[cfg(not(feature = "shanghai"))]
        let is_coinbase_warm = false;

        let account_code_hash = rws.next().account_codehash_pair().1;
        let transfer_assign_result = self.transfer_with_gas_fee.assign_from_rws(
            region,
            offset,
            !account_code_hash.is_zero(),
            tx.is_create,
            tx.value,
            &mut rws,
        )?;

        let tx_fee = transfer_assign_result.gas_fee.unwrap();
        self.tx_fee
            .assign(region, offset, Some(tx_fee.to_le_bytes()))?;
        log::debug!(
            "tx_fee assigned {:?}, gas price {:?}, gas {}",
            tx_fee,
            tx.gas_price,
            tx.gas
        );
        self.account_code_hash.assign(
            region,
            offset,
            region.code_hash(
                transfer_assign_result
                    .account_code_hash
                    .unwrap_or(account_code_hash),
            ),
        )?;
        #[cfg(feature = "scroll")]
        {
            self.account_keccak_code_hash.assign(
                region,
                offset,
                region.word_rlc(
                    transfer_assign_result
                        .account_keccak_code_hash
                        .unwrap_or_default(),
                ),
            )?;
        }

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_nonce
            .assign(region, offset, Value::known(F::from(tx.nonce)))?;
        self.sender_nonce
            .assign(region, offset, Value::known(F::from(nonce_rw.1.as_u64())))?;
        self.tx_gas
            .assign(region, offset, Value::known(F::from(tx.gas)))?;
        self.tx_gas_price
            .assign(region, offset, Some(tx.gas_price.to_le_bytes()))?;
        self.tx_value
            .assign(region, offset, Some(tx.value.to_le_bytes()))?;
        self.mul_gas_fee_by_gas.assign(
            region,
            offset,
            tx.gas_price,
            tx.gas,
            tx.gas_price * tx.gas,
        )?;
        let caller_address = tx
            .caller_address
            .to_scalar()
            .expect("unexpected Address -> Scalar conversion failure");
        let callee_address = tx
            .callee_address
            .unwrap_or(Address::zero())
            .to_scalar()
            .expect("unexpected Address -> Scalar conversion failure");
        self.tx_caller_address
            .assign(region, offset, Value::known(caller_address))?;
        self.tx_caller_address_is_zero
            .assign(region, offset, caller_address)?;
        self.tx_callee_address
            .assign(region, offset, Value::known(callee_address))?;
        self.tx_callee_address_is_zero
            .assign(region, offset, callee_address)?;
        self.is_precompile_lt
            .assign(region, offset, callee_address, F::from(0xA))?;
        self.call_callee_address.assign(
            region,
            offset,
            Value::known(
                if tx.is_create {
                    get_contract_address(tx.caller_address, tx.nonce)
                } else {
                    tx.callee_address.unwrap_or(Address::zero())
                }
                .to_scalar()
                .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.is_caller_callee_equal.assign(
            region,
            offset,
            Value::known(F::from(caller_address == callee_address)),
        )?;
        self.tx_is_create
            .assign(region, offset, Value::known(F::from(tx.is_create as u64)))?;
        self.tx_call_data_length.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_length as u64)),
        )?;
        self.is_call_data_empty
            .assign(region, offset, F::from(tx.call_data_length as u64))?;
        self.tx_call_data_word_length
            .assign(region, offset, tx.call_data_length as u128 + 31)?;
        self.tx_call_data_gas_cost.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_gas_cost)),
        )?;
        self.tx_data_gas_cost
            .assign(region, offset, Value::known(F::from(tx.tx_data_gas_cost)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.intrinsic_gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        self.sufficient_gas_left
            .assign(region, offset, F::from(tx.gas - step.gas_cost))?;
        self.call_code_hash
            .assign(region, offset, region.code_hash(call.code_hash))?;
        let untrimmed_contract_addr = {
            let mut stream = RlpStream::new();
            stream.begin_list(2);
            stream.append(&tx.caller_address);
            stream.append(&eth_types::U256::from(tx.nonce));
            let rlp_encoding = stream.out().to_vec();
            keccak256(&rlp_encoding)
        };
        for (c, v) in self
            .caller_nonce_hash_bytes
            .iter()
            .rev()
            .zip(untrimmed_contract_addr.iter())
        {
            c.assign(region, offset, Value::known(F::from(*v as u64)))?;
        }
        self.account_code_hash_is_empty.assign_value(
            region,
            offset,
            region.code_hash(account_code_hash),
            region.empty_code_hash_rlc(),
        )?;
        self.account_code_hash_is_zero.assign_value(
            region,
            offset,
            region.code_hash(account_code_hash),
        )?;
        self.call_code_hash_is_empty.assign_value(
            region,
            offset,
            region.code_hash(call.code_hash),
            region.empty_code_hash_rlc(),
        )?;
        self.call_code_hash_is_zero.assign_value(
            region,
            offset,
            region.code_hash(call.code_hash),
        )?;

        let untrimmed_contract_addr = {
            let mut stream = ethers_core::utils::rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&tx.caller_address);
            stream.append(&eth_types::U256::from(tx.nonce));
            let rlp_encoding = stream.out().to_vec();
            keccak256(&rlp_encoding)
        };
        for (c, v) in self
            .caller_nonce_hash_bytes
            .iter()
            .rev()
            .zip(untrimmed_contract_addr.iter())
        {
            c.assign(region, offset, Value::known(F::from(*v as u64)))?;
        }
        let (init_code_rlc, keccak_code_hash_rlc) = if tx.is_create {
            let init_code_rlc =
                region.keccak_rlc(&tx.call_data.iter().cloned().rev().collect::<Vec<u8>>());
            let keccak_code_hash_rlc = region.word_rlc(U256::from(keccak256(&tx.call_data)));
            (init_code_rlc, keccak_code_hash_rlc)
        } else {
            (Value::known(F::zero()), Value::known(F::zero()))
        };
        self.init_code_rlc.assign(region, offset, init_code_rlc)?;
        self.keccak_code_hash
            .assign(region, offset, keccak_code_hash_rlc)?;

        self.create.assign(
            region,
            offset,
            tx.caller_address,
            tx.nonce,
            None,
            Some(account_code_hash),
            None,
        )?;

        self.coinbase.assign(
            region,
            offset,
            Value::known(
                block.context.ctxs[&tx.block_number]
                    .coinbase
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.is_coinbase_warm
            .assign(region, offset, Value::known(F::from(is_coinbase_warm)))?;

        let tx_l1_fee = if tx.tx_type.is_l1_msg() {
            log::trace!("tx is l1msg and l1 fee is 0");
            0
        } else {
            tx.l1_fee.tx_l1_fee(tx.tx_data_gas_cost).0
        };
        let tx_l2_fee = tx.gas_price * tx.gas;
        if tx_fee != tx_l2_fee + tx_l1_fee {
            log::error!(
                "begin_tx assign: tx_fee ({}) != tx_l1_fee ({}) + tx_l2_fee ({})",
                tx_fee,
                tx_l1_fee,
                tx_l2_fee
            );
        }

        self.tx_l1_fee.assign(
            region,
            offset,
            tx.l1_fee,
            tx.l1_fee_committed,
            tx.tx_data_gas_cost,
        )
    }
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, vec};

    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use bus_mapping::evm::OpcodeId;
    use eth_types::{self, address, bytecode, evm_types::GasCost, word, Bytecode, Hash, Word};
    use ethers_core::types::Bytes;

    use mock::{eth, gwei, MockTransaction, TestContext, MOCK_ACCOUNTS};

    fn gas(call_data: &[u8]) -> Word {
        Word::from(
            GasCost::TX.as_u64()
                + 2 * OpcodeId::PUSH32.constant_gas_cost().as_u64()
                + call_data
                    .iter()
                    .map(|&x| if x == 0 { 4 } else { 16 })
                    .sum::<u64>(),
        )
    }

    fn code_with_return() -> Bytecode {
        bytecode! {
            PUSH1(0)
            PUSH1(0)
            RETURN
        }
    }

    fn code_with_revert() -> Bytecode {
        bytecode! {
            PUSH1(0)
            PUSH1(0)
            REVERT
        }
    }

    fn test_ok(tx: eth_types::Transaction, code: Option<Bytecode>) {
        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(10));
                if let Some(code) = code {
                    accs[0].code(code);
                }
                accs[1].address(MOCK_ACCOUNTS[1]).balance(eth(10));
            },
            |mut txs, _accs| {
                txs[0]
                    .to(tx.to.unwrap())
                    .from(tx.from)
                    .gas_price(tx.gas_price.unwrap())
                    .gas(tx.gas)
                    .input(tx.input)
                    .value(tx.value);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn mock_tx(value: Word, gas_price: Word, calldata: Vec<u8>) -> eth_types::Transaction {
        let from = MOCK_ACCOUNTS[1];
        let to = MOCK_ACCOUNTS[0];

        let mock_transaction = MockTransaction::default()
            .from(from)
            .to(to)
            .value(value)
            .gas(gas(&calldata))
            .gas_price(gas_price)
            .input(calldata.into())
            .build();

        eth_types::Transaction::from(mock_transaction)
    }

    #[test]
    fn begin_tx_gadget_simple() {
        // Transfer 1 ether to account with empty code, successfully
        test_ok(mock_tx(eth(1), gwei(2), vec![]), None);

        // Transfer 1 ether, successfully
        test_ok(mock_tx(eth(1), gwei(2), vec![]), Some(code_with_return()));

        // Transfer 1 ether, tx reverts
        test_ok(mock_tx(eth(1), gwei(2), vec![]), Some(code_with_revert()));

        // Transfer nothing with some calldata
        test_ok(
            mock_tx(eth(0), gwei(2), vec![1, 2, 3, 4, 0, 0, 0, 0]),
            Some(code_with_return()),
        );
    }

    #[test]
    fn begin_tx_large_nonce() {
        // This test checks that the rw table assignment and evm circuit are consistent
        // in not applying an RLC to account and tx nonces.
        // https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/592
        let multibyte_nonce = Word::from(700);

        let to = MOCK_ACCOUNTS[0];
        let from = MOCK_ACCOUNTS[1];

        let code = bytecode! {
            STOP
        };

        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0].address(to).balance(eth(1)).code(code);
                accs[1].address(from).balance(eth(1)).nonce(multibyte_nonce);
            },
            |mut txs, _| {
                txs[0].to(to).from(from).nonce(multibyte_nonce);
            },
            |block, _| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn begin_tx_gadget_rand() {
        let random_amount = Word::from_little_endian(&rand_bytes(32)) % eth(1);
        let random_gas_price = Word::from_little_endian(&rand_bytes(32)) % gwei(2);
        // If this test fails, we want these values to appear in the CI logs.
        dbg!(random_amount, random_gas_price);

        for (value, gas_price, calldata, code) in [
            // Transfer random ether to account with empty code, successfully
            (random_amount, gwei(2), vec![], None),
            // Transfer nothing with random gas_price to account with empty code, successfully
            (eth(0), random_gas_price, vec![], None),
            // Transfer random ether, successfully
            (random_amount, gwei(2), vec![], Some(code_with_return())),
            // Transfer nothing with random gas_price, successfully
            (eth(0), random_gas_price, vec![], Some(code_with_return())),
            // Transfer random ether, tx reverts
            (random_amount, gwei(2), vec![], Some(code_with_revert())),
            // Transfer nothing with random gas_price, tx reverts
            (eth(0), random_gas_price, vec![], Some(code_with_revert())),
        ] {
            test_ok(mock_tx(value, gas_price, calldata), code);
        }
    }

    #[test]
    fn begin_tx_no_code() {
        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
                accs[1].address(MOCK_ACCOUNTS[1]).balance(eth(10));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .to(MOCK_ACCOUNTS[1])
                    .gas_price(gwei(2))
                    .gas(Word::from(0x10000))
                    .value(eth(2));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn begin_tx_no_account() {
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .to(MOCK_ACCOUNTS[1])
                    .gas_price(gwei(2))
                    .gas(Word::from(0x10000))
                    .value(eth(2));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn begin_tx_deploy(nonce: u64) {
        let code = bytecode! {
            // [ADDRESS, STOP]
            PUSH32(word!("3000000000000000000000000000000000000000000000000000000000000000"))
            PUSH1(0)
            MSTORE

            CALLDATASIZE
            PUSH1(2)
            PUSH1(0)
            RETURN
        };
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(eth(20))
                    .nonce(nonce.into());
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .nonce(nonce.into())
                    .gas_price(gwei(2))
                    .gas(Word::from(0x10000))
                    .value(eth(2))
                    .input(code.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn begin_tx_deploy_nonce_zero() {
        begin_tx_deploy(0);
    }
    #[test]
    fn begin_tx_deploy_nonce_small_1byte() {
        begin_tx_deploy(1);
        begin_tx_deploy(127);
    }
    #[test]
    fn begin_tx_deploy_nonce_big_1byte() {
        begin_tx_deploy(128);
        begin_tx_deploy(255);
    }
    #[test]
    fn begin_tx_deploy_nonce_2bytes() {
        begin_tx_deploy(0x0100u64);
        begin_tx_deploy(0x1020u64);
        begin_tx_deploy(0xffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_3bytes() {
        begin_tx_deploy(0x010000u64);
        begin_tx_deploy(0x102030u64);
        begin_tx_deploy(0xffffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_4bytes() {
        begin_tx_deploy(0x01000000u64);
        begin_tx_deploy(0x10203040u64);
        begin_tx_deploy(0xffffffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_5bytes() {
        begin_tx_deploy(0x0100000000u64);
        begin_tx_deploy(0x1020304050u64);
        begin_tx_deploy(0xffffffffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_6bytes() {
        begin_tx_deploy(0x010000000000u64);
        begin_tx_deploy(0x102030405060u64);
        begin_tx_deploy(0xffffffffffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_7bytes() {
        begin_tx_deploy(0x01000000000000u64);
        begin_tx_deploy(0x10203040506070u64);
        begin_tx_deploy(0xffffffffffffffu64);
    }
    #[test]
    fn begin_tx_deploy_nonce_8bytes() {
        begin_tx_deploy(0x0100000000000000u64);
        begin_tx_deploy(0x1020304050607080u64);
        begin_tx_deploy(0xfffffffffffffffeu64);
    }

    #[test]
    fn begin_tx_precompile() {
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(address!("0x0000000000000000000000000000000000000004"))
                    .input(Bytes::from(vec![0x01, 0x02, 0x03]));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn begin_tx_precompile_oog() {
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(address!("0x0000000000000000000000000000000000000004"))
                    .input(Bytes::from(vec![0x01, 0x02, 0x03]))
                    .gas((21048 + 17).into()) // 17 < 15 + 3
                    ;
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn begin_tx_precompile_with_value() {
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(address!("0x0000000000000000000000000000000000000004"))
                    .value(eth(1))
                    .input(Bytes::from(vec![0x01, 0x02, 0x03]));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    /// testool case EmptyTransaction3_d0_g0_v0
    #[test]
    fn begin_tx_create_empty_tx() {
        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"))
                    .balance(100000000.into());
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .gas_price(Word::from(10))
                    .gas(Word::from(55000));
            },
            |block, _tx| {
                block
                    .difficulty(Word::from(0x020000))
                    .gas_limit(Word::from(1000000))
                    .number(1)
                    .timestamp(Word::from(1000))
                    .parent_hash(
                        Hash::from_str(
                            "5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
                        )
                        .unwrap(),
                    )
            },
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
