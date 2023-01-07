//! The transaction circuit implementation.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

pub mod sign_verify;

use crate::table::RlpTable;
use crate::table::{KeccakTable, TxFieldTag, TxTable};
use crate::util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness;
use crate::witness::signed_tx_from_geth_tx;
use bus_mapping::circuit_input_builder::keccak_inputs_tx_circuit;
use eth_types::{
    sign_types::SignData,
    {geth_types::Transaction, Address, Field, ToLittleEndian, ToScalar},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use log::error;
use sign_verify::{AssignedSignatureVerify, SignVerifyChip, SignVerifyConfig};
use std::marker::PhantomData;

pub use halo2_proofs::halo2curves::{
    group::{
        ff::{Field as GroupField, PrimeField},
        prime::PrimeCurveAffine,
        Curve, Group, GroupEncoding,
    },
    secp256k1::{self, Secp256k1Affine, Secp256k1Compressed},
};

/// Config for TxCircuit
#[derive(Clone, Debug)]
pub struct TxCircuitConfig<F: Field> {
    tx_id: Column<Advice>,
    tag: Column<Advice>,
    index: Column<Advice>,
    value: Column<Advice>,
    sign_verify: SignVerifyConfig,
    rlp_table: RlpTable,
    _marker: PhantomData<F>,
    // External tables
    keccak_table: KeccakTable,
}

/// Circuit configuration arguments
pub struct TxCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// RlpTable
    pub rlp_table: RlpTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for TxCircuitConfig<F> {
    type ConfigArgs = TxCircuitConfigArgs<F>;

    /// Return a new TxCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            keccak_table,
            rlp_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let tx_id = tx_table.tx_id;
        let tag = tx_table.tag;
        let index = tx_table.index;
        let value = tx_table.value;
        meta.enable_equality(value);

        let sign_verify = SignVerifyConfig::new(meta, keccak_table.clone(), challenges);

        Self {
            tx_id,
            tag,
            index,
            value,
            sign_verify,
            keccak_table,
            rlp_table,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> TxCircuitConfig<F> {
    /// Load ECDSA RangeChip table.
    pub fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.sign_verify.load_range(layouter)
    }

    /// Assigns a tx circuit row and returns the assigned cell of the value in
    /// the row.
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        value: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || "tx_id",
            self.tx_id,
            offset,
            || Value::known(F::from(tx_id as u64)),
        )?;
        region.assign_advice(
            || "tag",
            self.tag,
            offset,
            || Value::known(F::from(tag as u64)),
        )?;
        region.assign_advice(
            || "index",
            self.index,
            offset,
            || Value::known(F::from(index as u64)),
        )?;
        region.assign_advice(|| "value", self.value, offset, || value)
    }

    /// Get number of rows required.
    pub fn get_num_rows_required(num_tx: usize) -> usize {
        let num_rows_range_table = 1 << 18;
        // Number of rows required to verify a transaction.
        let num_rows_per_tx = 140436;
        (num_tx * num_rows_per_tx).max(num_rows_range_table)
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct TxCircuit<F: Field> {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// SignVerify chip
    pub sign_verify: SignVerifyChip<F>,
    /// List of Transactions
    pub txs: Vec<Transaction>,
    /// Chain ID
    pub chain_id: u64,
}

impl<F: Field> TxCircuit<F> {
    /// Return a new TxCircuit
    pub fn new(max_txs: usize, max_calldata: usize, chain_id: u64, txs: Vec<Transaction>) -> Self {
        TxCircuit::<F> {
            max_txs,
            max_calldata,
            sign_verify: SignVerifyChip::new(max_txs),
            txs,
            chain_id,
        }
    }

    fn assign_tx_table(
        &self,
        config: &TxCircuitConfig<F>,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        assigned_sig_verifs: Vec<AssignedSignatureVerify<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                // Empty entry
                config.assign_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    Value::known(F::zero()),
                )?;
                offset += 1;
                // Assign al Tx fields except for call data
                let tx_default = Transaction::default();
                for (i, assigned_sig_verif) in assigned_sig_verifs.iter().enumerate() {
                    let tx = if i < self.txs.len() {
                        &self.txs[i]
                    } else {
                        &tx_default
                    };

                    for (tag, value) in [
                        (
                            TxFieldTag::Nonce,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.nonce.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::Gas,
                            Value::known(F::from(tx.gas_limit.as_u64())),
                        ),
                        (
                            TxFieldTag::GasPrice,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.gas_price.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            Value::known(tx.from.to_scalar().expect("tx.from too big")),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            Value::known(
                                tx.to
                                    .unwrap_or_else(Address::zero)
                                    .to_scalar()
                                    .expect("tx.to too big"),
                            ),
                        ),
                        (
                            TxFieldTag::IsCreate,
                            Value::known(F::from(tx.to.is_none() as u64)),
                        ),
                        (
                            TxFieldTag::Value,
                            challenges
                                .evm_word()
                                .map(|challenge| rlc(tx.value.to_le_bytes(), challenge)),
                        ),
                        (
                            TxFieldTag::CallDataLength,
                            Value::known(F::from(tx.call_data.0.len() as u64)),
                        ),
                        (
                            TxFieldTag::CallDataGasCost,
                            Value::known(F::from(
                                tx.call_data
                                    .0
                                    .iter()
                                    .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
                            )),
                        ),
                        (
                            TxFieldTag::TxSignHash,
                            assigned_sig_verif.msg_hash_rlc.value().copied(),
                        ),
                    ] {
                        let assigned_cell =
                            config.assign_row(&mut region, offset, i + 1, tag, 0, value)?;
                        offset += 1;

                        // Ref. spec 0. Copy constraints using fixed offsets between the tx rows and
                        // the SignVerifyChip
                        match tag {
                            TxFieldTag::CallerAddress => region.constrain_equal(
                                assigned_cell.cell(),
                                assigned_sig_verif.address.cell(),
                            )?,
                            TxFieldTag::TxSignHash => region.constrain_equal(
                                assigned_cell.cell(),
                                assigned_sig_verif.msg_hash_rlc.cell(),
                            )?,
                            _ => (),
                        }
                    }
                }

                // Assign call data
                let mut calldata_count = 0;
                for (i, tx) in self.txs.iter().enumerate() {
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < self.max_calldata);
                        config.assign_row(
                            &mut region,
                            offset,
                            i + 1, // tx_id
                            TxFieldTag::CallData,
                            index,
                            Value::known(F::from(*byte as u64)),
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..self.max_calldata {
                    config.assign_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        TxFieldTag::CallData,
                        0,
                        Value::known(F::zero()),
                    )?;
                    offset += 1;
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> SubCircuit<F> for TxCircuit<F> {
    type Config = TxCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.context.chain_id().as_u64(),
            block
                .context
                .first()
                .eth_block
                .transactions
                .iter()
                .map(|tx| tx.into())
                .collect(),
        )
    }

    /// Make the assignments to the TxCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        assert!(self.txs.len() <= self.max_txs);
        let sign_datas: Vec<SignData> = self
            .txs
            .iter()
            .map(|tx| {
                tx.sign_data(self.chain_id).map_err(|e| {
                    error!("tx_to_sign_data error for tx {:?}", e);
                    Error::Synthesis
                })
            })
            .try_collect()?;

        config.load_aux_tables(layouter)?;
        let assigned_sig_verifs =
            self.sign_verify
                .assign(&config.sign_verify, layouter, &sign_datas, challenges)?;
        self.assign_tx_table(config, challenges, layouter, assigned_sig_verifs)?;
        Ok(())
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for TxCircuit<F> {
    type Config = (TxCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let rlp_table = RlpTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            TxCircuitConfig::new(
                meta,
                TxCircuitConfigArgs {
                    tx_table,
                    keccak_table,
                    rlp_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);

        config.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_tx_circuit(&self.txs[..], self.chain_id).map_err(|e| {
                error!("keccak_inputs_tx_circuit error: {:?}", e);
                Error::Synthesis
            })?,
            &challenges,
        )?;
        config.rlp_table.dev_load(
            &mut layouter,
            signed_tx_from_geth_tx(self.txs.as_slice(), self.chain_id),
            &challenges,
        )?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(test)]
mod tx_circuit_tests {
    use super::*;
    use eth_types::address;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use mock::AddrOrWallet;
    use pretty_assertions::assert_eq;

    fn run<F: Field>(
        k: u32,
        txs: Vec<Transaction>,
        chain_id: u64,
        max_txs: usize,
        max_calldata: usize,
    ) -> Result<(), Vec<VerifyFailure>> {
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let circuit = TxCircuit::<F>::new(max_txs, max_calldata, chain_id, txs);

        let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn tx_circuit_2tx() {
        const NUM_TXS: usize = 2;
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;

        let k = 19;
        assert_eq!(
            run::<Fr>(
                k,
                mock::CORRECT_MOCK_TXS[..NUM_TXS]
                    .iter()
                    .map(|tx| Transaction::from(tx.clone()))
                    .collect_vec(),
                mock::MOCK_CHAIN_ID.as_u64(),
                MAX_TXS,
                MAX_CALLDATA
            ),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_1tx() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

        let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

        let k = 19;
        assert_eq!(
            run::<Fr>(k, vec![tx], chain_id, MAX_TXS, MAX_CALLDATA),
            Ok(())
        );
    }

    #[test]
    fn tx_circuit_bad_address() {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
        // This address doesn't correspond to the account that signed this tx.
        tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

        let k = 19;
        assert!(run::<Fr>(
            k,
            vec![tx.into()],
            mock::MOCK_CHAIN_ID.as_u64(),
            MAX_TXS,
            MAX_CALLDATA
        )
        .is_err(),);
    }
}
