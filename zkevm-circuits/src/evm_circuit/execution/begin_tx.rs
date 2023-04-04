use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            and,
            common_gadget::TransferWithGasFeeGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            is_precompiled,
            math_gadget::{
                ContractCreateGadget, IsEqualGadget, IsZeroGadget, LtGadget, MulWordByU64Gadget,
                RangeCheckGadget,
            },
            CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag, TxFieldTag as TxContextFieldTag},
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar};
use ethers_core::utils::{get_contract_address, keccak256, rlp::RlpStream};
use gadgets::util::{expr_from_bytes, not, or, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[cfg(feature = "reject-eip2718")]
use gadgets::util::select;

#[derive(Clone, Debug)]
pub(crate) struct BeginTxGadget<F> {
    tx_id: Cell<F>,
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
    tx_call_data_gas_cost: Cell<F>,
    reversion_info: ReversionInfo<F>,
    intrinsic_gas_cost: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    phase2_code_hash: Cell<F>,
    is_empty_code_hash: IsEqualGadget<F>,
    is_precompile_lt: LtGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
    /// Keccak256(RLP([tx_caller_address, tx_nonce]))
    caller_nonce_hash_bytes: [Cell<F>; N_BYTES_WORD],
    /// RLP gadget for CREATE address.
    create: ContractCreateGadget<F, false>,
    callee_not_exists: IsZeroGadget<F>,
    is_caller_callee_equal: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BeginTxGadget<F> {
    const NAME: &'static str = "BeginTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.query_cell();
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

        let [tx_nonce, tx_gas, tx_caller_address, tx_callee_address, tx_is_create, tx_call_data_length, tx_call_data_gas_cost] =
            [
                TxContextFieldTag::Nonce,
                TxContextFieldTag::Gas,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::CalleeAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));

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
            tx_nonce.expr() + 1.expr(),
            tx_nonce.expr(),
            None,
        ); // rwc_delta += 1

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.expr());
        let tx_fee = cb.query_word_rlc();

        // TODO: contraint l1 fee
        #[cfg(not(feature = "scroll"))]
        cb.require_equal(
            "tx_fee == l1_fee + l2_fee, l1_fee == 0",
            mul_gas_fee_by_gas.product().expr(),
            tx_fee.expr(),
        );

        // a valid precompile address is: 1 <= addr <= 9 (addr != 0 && addr < 0xA)
        let is_precompile_lt = LtGadget::construct(cb, tx_callee_address.expr(), 0xA.expr());
        let is_precompile = and::expr([
            not::expr(tx_callee_address_is_zero.expr()),
            is_precompile_lt.expr(),
        ]);

        // TODO1: Take gas cost of access list (EIP 2930) into consideration.
        // Use intrinsic gas
        // TODO2: contrain calling precompile directly
        let intrinsic_gas_cost = cb.query_cell();
        #[cfg(feature = "reject-eip2718")]
        cb.condition(not::expr(is_precompile.expr()), |cb| {
            cb.require_equal(
                "calculate intrinsic gas cost",
                intrinsic_gas_cost.expr(),
                select::expr(
                    tx_is_create.expr(),
                    eth_types::evm_types::GasCost::CREATION_TX.expr(),
                    eth_types::evm_types::GasCost::TX.expr(),
                ) + tx_call_data_gas_cost.expr(),
            )
        });
        // Check gas_left is sufficient
        let gas_left = tx_gas.expr() - intrinsic_gas_cost.expr();
        let sufficient_gas_left = RangeCheckGadget::construct(cb, gas_left.clone());

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
            is_caller_callee_equal.expr(),
            None,
        ); // rwc_delta += 1

        // Read code_hash of callee
        let phase2_code_hash = cb.query_cell_phase2();
        let is_empty_code_hash =
            IsEqualGadget::construct(cb, phase2_code_hash.expr(), cb.empty_code_hash_rlc());
        let callee_not_exists = IsZeroGadget::construct(cb, phase2_code_hash.expr());
        // no_callee_code is true when the account exists and has empty
        // code hash, or when the account doesn't exist (which we encode with
        // code_hash = 0).
        let no_callee_code = is_empty_code_hash.expr() + callee_not_exists.expr();

        cb.condition(
            and::expr([
                not::expr(tx_is_create.expr()),
                not::expr(is_precompile.expr()),
            ]),
            |cb| {
                cb.account_read(
                    call_callee_address.expr(),
                    AccountFieldTag::CodeHash,
                    phase2_code_hash.expr(),
                ); // rwc_delta += 1
            },
        );

        // Transfer value from caller to callee, creating account if necessary.
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            call_callee_address.expr(),
            or::expr([not::expr(callee_not_exists.expr()), is_precompile.expr()]),
            tx_is_create.expr(),
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
        cb.condition(not::expr(no_callee_code.expr()), |cb| {
            cb.require_equal(
                "code hash equivalence",
                cb.curr.state.code_hash.expr(),
                phase2_code_hash.expr(),
            );
        });

        // 1. Handle contract creation transaction.
        cb.condition(tx_is_create.expr(), |cb| {
            let output_rlc = cb.word_rlc::<N_BYTES_WORD>(
                caller_nonce_hash_bytes
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );
            cb.keccak_table_lookup(create.input_rlc(cb), create.input_length(), output_rlc);

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
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account (Caller) Nonce
                //   - Write TxAccessListAccount
                //   - Write TxAccessListAccount
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
                rw_counter: Delta(21.expr() + transfer_with_gas_fee.rw_delta()),
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
        });

        // 2. Handle call to precompiled contracts.
        cb.condition(is_precompile.expr(), |cb| {
            cb.require_equal(
                "precompile should be zero code hash",
                // FIXME: see in opcodes.rs gen_begin_tx_ops
                no_callee_code.expr(),
                true.expr(),
            );
            // TODO: verify that precompile could fail in begin tx.
            // cb.require_equal(
            // "Tx to precompile should be persistent",
            // reversion_info.is_persistent(),
            // 1.expr(),
            // );
            cb.require_equal(
                "Go to EndTx when Tx to precompile",
                cb.next.execution_state_selector([ExecutionState::EndTx]),
                1.expr(),
            );

            cb.require_step_state_transition(StepStateTransition {
                // 7 + TransferWithGasFeeGadget associated reads or writes:
                //   - Write CallContext TxId
                //   - Write CallContext RwCounterEndOfReversion
                //   - Write CallContext IsPersistent
                //   - Write CallContext IsSuccess
                //   - Write Account (Caller) Nonce
                //   - Write TxAccessListAccount (Caller)
                //   - Write TxAccessListAccount (Callee)
                //   - a TransferWithGasFeeGadget
                rw_counter: Delta(
                    7.expr()
                        + transfer_with_gas_fee.rw_delta()
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
                no_callee_code.expr(),
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
                    //   - Write TxAccessListAccount
                    //   - Write TxAccessListAccount
                    //   - Read Account CodeHash
                    //   - a TransferWithGasFeeGadget
                    rw_counter: Delta(8.expr() + transfer_with_gas_fee.rw_delta()),
                    call_id: To(call_id.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        // 4. Call to account with non-empty code.
        cb.condition(
            and::expr([not::expr(tx_is_create.expr()), not::expr(no_callee_code)]),
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
                    (CallContextFieldTag::CodeHash, phase2_code_hash.expr()),
                ] {
                    cb.call_context_lookup(true.expr(), Some(call_id.expr()), field_tag, value);
                }

                cb.require_step_state_transition(StepStateTransition {
                    // 21 reads and writes:
                    //   - Write CallContext TxId
                    //   - Write CallContext RwCounterEndOfReversion
                    //   - Write CallContext IsPersistent
                    //   - Write CallContext IsSuccess
                    //   - Write Account Nonce
                    //   - Write TxAccessListAccount
                    //   - Write TxAccessListAccount
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
                    rw_counter: Delta(21.expr() + transfer_with_gas_fee.rw_delta()),
                    call_id: To(call_id.expr()),
                    is_root: To(true.expr()),
                    is_create: To(tx_is_create.expr()),
                    code_hash: To(phase2_code_hash.expr()),
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
            tx_call_data_gas_cost,
            reversion_info,
            sufficient_gas_left,
            transfer_with_gas_fee,
            phase2_code_hash,
            intrinsic_gas_cost,
            is_empty_code_hash,
            is_precompile_lt,
            caller_nonce_hash_bytes,
            create,
            callee_not_exists,
            is_caller_callee_equal,
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
        let zero = eth_types::Word::zero();

        let mut rws = StepRws::new(block, step);
        rws.offset_add(7);
        let mut callee_code_hash = zero;
        if !tx.is_create && !is_precompiled(&tx.callee_address.unwrap_or_default()) {
            callee_code_hash = rws.next().account_codehash_pair().1;
        }
        let callee_exists = is_precompiled(&tx.callee_address.unwrap_or_default())
            || (!tx.is_create && !callee_code_hash.is_zero());
        let caller_balance_sub_fee_pair = rws.next().account_balance_pair();
        let must_create = tx.is_create;
        if (!callee_exists && !tx.value.is_zero()) || must_create {
            callee_code_hash = rws.next().account_codehash_pair().1;
        }
        let mut caller_balance_sub_value_pair = (zero, zero);
        let mut callee_balance_pair = (zero, zero);
        if !tx.value.is_zero() {
            caller_balance_sub_value_pair = rws.next().account_balance_pair();
            callee_balance_pair = rws.next().account_balance_pair();
        };

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.tx_nonce
            .assign(region, offset, Value::known(F::from(tx.nonce)))?;
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
        self.tx_call_data_gas_cost.assign(
            region,
            offset,
            Value::known(F::from(tx.call_data_gas_cost)),
        )?;
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
        let tx_fee = caller_balance_sub_fee_pair.1 - caller_balance_sub_fee_pair.0;
        self.tx_fee
            .assign(region, offset, Some(tx_fee.to_le_bytes()))?;
        self.transfer_with_gas_fee.assign(
            region,
            offset,
            caller_balance_sub_fee_pair,
            caller_balance_sub_value_pair,
            callee_balance_pair,
            tx.value,
            tx_fee,
        )?;
        self.phase2_code_hash
            .assign(region, offset, region.word_rlc(callee_code_hash))?;
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
        self.is_empty_code_hash.assign_value(
            region,
            offset,
            region.word_rlc(callee_code_hash),
            region.empty_code_hash_rlc(),
        )?;
        self.callee_not_exists
            .assign_value(region, offset, region.word_rlc(callee_code_hash))?;

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
        self.create.assign(
            region,
            offset,
            tx.caller_address,
            tx.nonce,
            Some(callee_code_hash),
            None,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use bus_mapping::evm::OpcodeId;
    use eth_types::{self, address, bytecode, evm_types::GasCost, word, Bytecode, Word};
    use ethers_core::types::Bytes;

    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS};

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

    // TODO: Use `mock` crate.
    fn mock_tx(value: Word, gas_price: Word, calldata: Vec<u8>) -> eth_types::Transaction {
        let from = MOCK_ACCOUNTS[1];
        let to = MOCK_ACCOUNTS[0];
        eth_types::Transaction {
            from,
            to: Some(to),
            value,
            gas: gas(&calldata),
            gas_price: Some(gas_price),
            input: calldata.into(),
            ..Default::default()
        }
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
}
