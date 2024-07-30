use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::{
        param::N_BYTES_U64,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::LtGadget,
            U64Word, Word,
        },
    },
    util::{Expr, Field},
};
use bus_mapping::{
    circuit_input_builder::{TxL1Fee, TX_L1_COMMIT_EXTRA_COST, TX_L1_FEE_PRECISION},
    l2_predeployed::l1_gas_price_oracle,
};
use eth_types::{ToLittleEndian, U256};
use gadgets::util::not;
use gadgets::ToScalar;
use halo2_proofs::plonk::{Error, Expression};

/// Transaction L1 fee gadget for L1GasPriceOracle contract
#[derive(Clone, Debug)]
pub(crate) struct TxL1FeeGadget<F> {
    /// Transaction L1 fee
    /// It should be an Uint64, but it's also used to check sender balance which
    /// needs to be added as a Word.
    tx_l1_fee_word: Word<F>,
    /// Remainder when calculating L1 fee
    remainder_word: U64Word<F>,
    /// Remainder must in [0, TX_L1_FEE_PRECISION)
    remainder_range: LtGadget<F, 8>,
    /// Current value of L1 base fee
    base_fee_word: U64Word<F>,
    /// Current value of L1 fee overhead
    fee_overhead_word: U64Word<F>,
    /// Current value of L1 fee scalar
    fee_scalar_word: U64Word<F>,
    /// Current value of L1 blob base fee
    l1_blob_basefee_word: U64Word<F>,
    /// Current value of L1 scalar fee
    commit_scalar_word: U64Word<F>,
    /// Current value of L1 blob scalar fee
    blob_scalar_word: U64Word<F>,
    /// Current value of L1 base fee
    base_fee_committed: Cell<F>,
    /// Committed value of L1 fee overhead
    fee_overhead_committed: Cell<F>,
    /// Committed value of L1 fee scalar
    fee_scalar_committed: Cell<F>,
    /// Committed value of L1 blob base fee
    l1_blob_basefee_committed: Cell<F>,
    /// Committed value of L1 scalar fee
    commit_scalar_committed: Cell<F>,
    /// Committed value of L1 blob scalar fee
    blob_scalar_committed: Cell<F>,
}

impl<F: Field> TxL1FeeGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        is_curie: Expression<F>,
        tx_id: Expression<F>,
        tx_data_gas_cost: Expression<F>,
        tx_signed_length: Expression<F>,
    ) -> Self {
        let this = Self::raw_construct(cb, is_curie.expr(), tx_data_gas_cost, tx_signed_length);

        let l1_fee_address = Expression::Constant(l1_gas_price_oracle::ADDRESS.to_scalar().expect(
            "Unexpected address of l2 gasprice oracle contract -> Scalar conversion failure",
        ));

        let [base_fee_slot, overhead_slot, scalar_slot] = [
            &l1_gas_price_oracle::BASE_FEE_SLOT,
            &l1_gas_price_oracle::OVERHEAD_SLOT,
            &l1_gas_price_oracle::SCALAR_SLOT,
        ]
        .map(|slot| cb.word_rlc(slot.to_le_bytes().map(|b| b.expr())));

        let [l1_blob_basefee, commit_scalar, blob_scalar] = [
            &l1_gas_price_oracle::L1_BLOB_BASEFEE_SLOT,
            &l1_gas_price_oracle::COMMIT_SCALAR_SLOT,
            &l1_gas_price_oracle::BLOB_SCALAR_SLOT,
        ]
        .map(|slot| cb.word_rlc(slot.to_le_bytes().map(|b| b.expr())));

        // Read L1 base fee
        cb.account_storage_read(
            l1_fee_address.expr(),
            base_fee_slot,
            this.base_fee_word.expr(),
            tx_id.expr(),
            this.base_fee_committed.expr(),
        );

        // Read L1 fee overhead
        cb.account_storage_read(
            l1_fee_address.expr(),
            overhead_slot,
            this.fee_overhead_word.expr(),
            tx_id.expr(),
            this.fee_overhead_committed.expr(),
        );

        // Read L1 fee scalar
        cb.account_storage_read(
            l1_fee_address.clone(),
            scalar_slot,
            this.fee_scalar_word.expr(),
            tx_id.clone(),
            this.fee_scalar_committed.expr(),
        );

        cb.condition(is_curie.expr(), |cb| {
            // Read l1blob_basefee_committed
            cb.account_storage_read(
                l1_fee_address.expr(),
                l1_blob_basefee,
                this.l1_blob_basefee_word.expr(),
                tx_id.clone(),
                this.l1_blob_basefee_committed.expr(),
            );

            // Read L1 commit_scalar_committed
            cb.account_storage_read(
                l1_fee_address.expr(),
                commit_scalar,
                this.commit_scalar_word.expr(),
                tx_id.expr(),
                this.commit_scalar_committed.expr(),
            );

            // Read L1 blob_scalar_committed scalar
            cb.account_storage_read(
                l1_fee_address,
                blob_scalar,
                this.blob_scalar_word.expr(),
                tx_id,
                this.blob_scalar_committed.expr(),
            );
        });
        this
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        l1_fee: TxL1Fee,
        l1_fee_committed: TxL1Fee,
        tx_data_gas_cost: u64,
        tx_signed_length: u64,
    ) -> Result<(), Error> {
        log::debug!(
            "assign: tx_l1_fee {:?} l1_fee_committed {:?} tx_signed_length {}",
            l1_fee,
            l1_fee_committed,
            tx_signed_length
        );
        let (tx_l1_fee, remainder) = l1_fee.tx_l1_fee(tx_data_gas_cost, tx_signed_length);

        self.tx_l1_fee_word
            .assign(region, offset, Some(U256::from(tx_l1_fee).to_le_bytes()))?;
        self.remainder_word
            .assign(region, offset, Some(remainder.to_le_bytes()))?;
        self.base_fee_word
            .assign(region, offset, Some(l1_fee.base_fee.to_le_bytes()))?;
        self.fee_overhead_word
            .assign(region, offset, Some(l1_fee.fee_overhead.to_le_bytes()))?;
        self.fee_scalar_word
            .assign(region, offset, Some(l1_fee.fee_scalar.to_le_bytes()))?;
        self.remainder_range.assign(
            region,
            offset,
            F::from(remainder),
            F::from(TX_L1_FEE_PRECISION),
        )?;

        // curie fields
        self.l1_blob_basefee_word.assign(
            region,
            offset,
            Some(l1_fee.l1_blob_basefee.to_le_bytes()),
        )?;
        self.commit_scalar_word
            .assign(region, offset, Some(l1_fee.commit_scalar.to_le_bytes()))?;
        self.blob_scalar_word
            .assign(region, offset, Some(l1_fee.blob_scalar.to_le_bytes()))?;

        self.base_fee_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.base_fee.into()),
        )?;
        self.fee_overhead_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.fee_overhead.into()),
        )?;
        self.fee_scalar_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.fee_scalar.into()),
        )?;

        // curie fields
        self.l1_blob_basefee_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.l1_blob_basefee.into()),
        )?;
        self.commit_scalar_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.commit_scalar.into()),
        )?;
        self.blob_scalar_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.blob_scalar.into()),
        )?;

        Ok(())
    }

    pub(crate) fn rw_delta(&self, is_curie: Expression<F>) -> Expression<F> {
        // L1 base fee Read
        // L1 fee overhead Read
        // L1 fee scalar Read
        // + curie fields
        // l1 blob baseFee
        // commit scalar
        // blob scalar
        // TODO: we could optimize the "overhead" and "scalar" for curie
        3.expr() + is_curie.expr() * 3.expr()
    }

    pub(crate) fn tx_l1_fee(&self) -> Expression<F> {
        from_bytes::expr(&self.tx_l1_fee_word.cells[..N_BYTES_U64])
    }

    pub(crate) fn tx_l1_fee_word(&self) -> &Word<F> {
        &self.tx_l1_fee_word
    }

    fn raw_construct(
        cb: &mut EVMConstraintBuilder<F>,
        is_curie: Expression<F>,
        tx_data_gas_cost: Expression<F>,
        tx_signed_length: Expression<F>,
    ) -> Self {
        let tx_l1_fee_word = cb.query_word_rlc();
        let remainder_word = cb.query_word_rlc();

        let base_fee_word = cb.query_word_rlc();
        let fee_overhead_word = cb.query_word_rlc();
        let fee_scalar_word = cb.query_word_rlc();
        // curie fields
        let l1_blob_basefee_word = cb.query_word_rlc();
        let commit_scalar_word = cb.query_word_rlc();
        let blob_scalar_word = cb.query_word_rlc();

        let tx_l1_fee = from_bytes::expr(&tx_l1_fee_word.cells[..N_BYTES_U64]);
        let [remainder, base_fee, fee_overhead, fee_scalar] = [
            &remainder_word,
            &base_fee_word,
            &fee_overhead_word,
            &fee_scalar_word,
        ]
        .map(|word| from_bytes::expr(&word.cells[..N_BYTES_U64]));

        let remainder_range = LtGadget::construct(cb, remainder.expr(), TX_L1_FEE_PRECISION.expr());
        cb.require_equal(
            "remainder must less than l1 fee precision",
            1.expr(),
            remainder_range.expr(),
        );

        let [l1_blob_basefee, commit_scalar, blob_scalar] = [
            &l1_blob_basefee_word,
            &commit_scalar_word,
            &blob_scalar_word,
        ]
        .map(|word| from_bytes::expr(&word.cells[..N_BYTES_U64]));

        // For curie and non-curie, see l2geth side implementation:
        // <https://github.com/scroll-tech/go-ethereum/blob/36d7325ea1cb6749f353f84df7e9903f93aa903b/rollup/fees/rollup_fee.go#L76>
        cb.condition(is_curie.expr(), |cb| {
            cb.require_equal(
                "commitScalar * l1BaseFee + blobScalar * _data.length * l1BlobBaseFee == tx_l1_fee * 10e9 + remainder",
                commit_scalar * base_fee.clone() + blob_scalar * tx_signed_length * l1_blob_basefee,
                tx_l1_fee.clone() * TX_L1_FEE_PRECISION.expr() + remainder.clone(),
            );
        });

        cb.condition(not::expr(is_curie.expr()), |cb| {
            let tx_l1_gas = tx_data_gas_cost + TX_L1_COMMIT_EXTRA_COST.expr() + fee_overhead;
            cb.require_equal(
                "fee_scalar * base_fee * tx_l1_gas == tx_l1_fee * 10e9 + remainder",
                fee_scalar * base_fee * tx_l1_gas,
                tx_l1_fee * TX_L1_FEE_PRECISION.expr() + remainder,
            );
        });

        let base_fee_committed = cb.query_cell_phase2();
        let fee_overhead_committed = cb.query_cell_phase2();
        let fee_scalar_committed = cb.query_cell_phase2();
        // curie fields
        let l1_blob_basefee_committed = cb.query_cell_phase2();
        let commit_scalar_committed = cb.query_cell_phase2();
        let blob_scalar_committed = cb.query_cell_phase2();

        Self {
            tx_l1_fee_word,
            remainder_word,
            remainder_range,
            base_fee_word,
            fee_overhead_word,
            fee_scalar_word,
            l1_blob_basefee_word,
            commit_scalar_word,
            blob_scalar_word,
            base_fee_committed,
            fee_overhead_committed,
            fee_scalar_committed,
            l1_blob_basefee_committed,
            commit_scalar_committed,
            blob_scalar_committed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_circuit::util::{
        constraint_builder::ConstrainBuilderCommon,
        math_gadget::test_util::{test_math_gadget_container, try_test, MathGadgetContainer},
    };
    use eth_types::U256;
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

    //refer to test in <https://github.com/scroll-tech/go-ethereum/blob/develop/rollup/fees/rollup_fee_test.go#L10>
    const TEST_BASE_FEE_BEFORE_CURIE: u64 = 15_000_000;
    const TEST_FEE_OVERHEAD: u64 = 100;
    const TEST_FEE_SCALAR: u64 = 10;
    const TEST_TX_DATA_GAS_COST: u64 = 40; // 2 (zeros) * 4 + 2 (non-zeros) * 16
    const TEST_TX_L1_FEE_BEFORE_CURIE: u128 = 30;

    const TEST_AFTER_CURIE: u64 = 1;
    const TEST_BEFORE_CURIE: u64 = 0;

    // refer to test in https://github.com/scroll-tech/go-ethereum/blob/develop/rollup/fees/rollup_fee_test.go#L22
    const TEST_BASE_FEE_AFTER_CURIE: u64 = 1_500_000_000;

    const L1_BLOB_BASEFEE: u64 = 150_000_000;
    const COMMIT_SCALAR: u64 = 10;
    const BLOB_SCALAR: u64 = 10;

    const TEST_TX_RLP_SIGNED_LENGTH: u128 = 4;
    const TEST_TX_L1_FEE_AFTER_CURIE: u128 = 21;

    #[test]
    fn test_tx_l1_fee_with_right_values() {
        // test both before & after curie upgrade
        for is_curie in [TEST_BEFORE_CURIE, TEST_AFTER_CURIE] {
            let witnesses = [
                is_curie.into(),
                TEST_BASE_FEE_BEFORE_CURIE.into(),
                TEST_FEE_OVERHEAD.into(),
                TEST_FEE_SCALAR.into(),
                TEST_TX_DATA_GAS_COST.into(),
                TEST_TX_L1_FEE_BEFORE_CURIE,
                // Curie fields
                TEST_BASE_FEE_AFTER_CURIE.into(),
                L1_BLOB_BASEFEE.into(),
                COMMIT_SCALAR.into(),
                BLOB_SCALAR.into(),
                TEST_TX_RLP_SIGNED_LENGTH,
                TEST_TX_L1_FEE_AFTER_CURIE,
            ]
            .map(U256::from);

            try_test!(TxL1FeeGadgetTestContainer<Fr>, witnesses, true);
        }
    }

    #[test]
    fn test_tx_l1_fee_with_wrong_values() {
        // test both before & after curie upgrade
        for is_curie in [TEST_BEFORE_CURIE, TEST_AFTER_CURIE] {
            let witnesses = [
                is_curie.into(),
                TEST_BASE_FEE_BEFORE_CURIE.into(),
                TEST_FEE_OVERHEAD.into(),
                TEST_FEE_SCALAR.into(),
                TEST_TX_DATA_GAS_COST.into(),
                // set wrong l1 fee
                TEST_TX_L1_FEE_BEFORE_CURIE + 1,
                // Curie fields
                TEST_BASE_FEE_AFTER_CURIE.into(),
                L1_BLOB_BASEFEE.into(),
                COMMIT_SCALAR.into(),
                BLOB_SCALAR.into(),
                TEST_TX_RLP_SIGNED_LENGTH,
                // set wrong l1 fee
                TEST_TX_L1_FEE_AFTER_CURIE + 1,
            ]
            .map(U256::from);

            try_test!(TxL1FeeGadgetTestContainer<Fr>, witnesses, false);
        }
    }

    #[derive(Clone)]
    struct TxL1FeeGadgetTestContainer<F> {
        is_curie: Cell<F>,
        gadget: TxL1FeeGadget<F>,
        tx_data_gas_cost: Cell<F>,
        tx_signed_length: Cell<F>,
        expected_tx_l1_fee: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for TxL1FeeGadgetTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let tx_data_gas_cost: Cell<F> = cb.query_cell();
            let tx_signed_length = cb.query_cell();

            let expected_tx_l1_fee = cb.query_cell();
            let is_curie = cb.query_cell();

            cb.require_boolean("is_curie is bool", is_curie.expr());
            // l1 fee for both before and after Curie upgrade
            let gadget = TxL1FeeGadget::<F>::raw_construct(
                cb,
                is_curie.expr(),
                tx_data_gas_cost.expr(),
                tx_signed_length.expr(),
            );

            cb.require_equal(
                "tx_l1_fee must be correct",
                gadget.tx_l1_fee(),
                expected_tx_l1_fee.expr(),
            );

            TxL1FeeGadgetTestContainer {
                is_curie,
                gadget,
                tx_data_gas_cost,
                tx_signed_length,
                expected_tx_l1_fee,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[U256],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let [is_curie, base_fee_before_curie, fee_overhead, fee_scalar, tx_data_gas_cost, tx_l1_fee_before_curie] =
                [0, 1, 2, 3, 4, 5].map(|i| witnesses[i].as_u64());

            let [base_fee_after_curie, l1_blob_basefee, commit_scalar, blob_scalar, tx_signed_length, tx_l1_fee_after_curie] =
                [6, 7, 8, 9, 10, 11].map(|i| witnesses[i].as_u64());

            let l1_fee = TxL1Fee {
                chain_id: eth_types::forks::SCROLL_DEVNET_CHAIN_ID,
                // block_number 5 is starting number for curie in test devnet.
                block_number: if is_curie == 1 { 5 + 1 } else { 1 },
                base_fee: if is_curie == 1 {
                    base_fee_after_curie
                } else {
                    base_fee_before_curie
                },
                fee_overhead,
                fee_scalar,
                l1_blob_basefee,
                commit_scalar,
                blob_scalar,
            };
            self.gadget.assign(
                region,
                0,
                l1_fee,
                TxL1Fee::default(),
                tx_data_gas_cost,
                tx_signed_length,
            )?;

            self.tx_data_gas_cost.assign(
                region,
                0,
                Value::known(tx_data_gas_cost.to_scalar().unwrap()),
            )?;

            self.is_curie
                .assign(region, 0, Value::known(F::from(is_curie)))?;
            let rlp_signed_len = if is_curie == 1 { tx_signed_length } else { 0 };
            self.tx_signed_length
                .assign(region, 0, Value::known(F::from(rlp_signed_len)))?;

            let expected_tx_l1_fee = if is_curie == 1 {
                tx_l1_fee_after_curie
            } else {
                tx_l1_fee_before_curie
            };
            self.expected_tx_l1_fee
                .assign(region, 0, Value::known(F::from(expected_tx_l1_fee)))?;

            Ok(())
        }
    }
}
