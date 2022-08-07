//! The Super Circuit is a circuit that contains all the circuits of the
//! zkEVM in order to achieve two things:
//! - Check the correct integration between circuits via the shared lookup
//!   tables, to verify that the table layouts match.
//! - Allow having a single circuit setup for which a proof can be generated
//!   that would be verified under a single aggregation circuit for the first
//!   milestone.
//!
//! The current implementation contains the following circuits:
//!
//! - [x] EVM Circuit
//! - [ ] State Circuit
//! - [x] Tx Circuit
//! - [x] Bytecode Circuit
//! - [ ] Copy Circuit
//! - [ ] Keccak Circuit
//! - [ ] MPT Circuit
//! - [ ] PublicInputs Circuit
//!
//! And the following shared tables, with the circuits that use them:
//!
//! - [x] Copy Table
//!   - [ ] Copy Circuit
//!   - [x] EVM Circuit
//! - [ ] Rw Table
//!   - [ ] State Circuit
//!   - [ ] EVM Circuit
//!   - [ ] Copy Circuit
//! - [x] Tx Table
//!   - [x] Tx Circuit
//!   - [x] EVM Circuit
//!   - [ ] Copy Circuit
//!   - [ ] PublicInputs Circuit
//! - [x] Bytecode Table
//!   - [x] Bytecode Circuit
//!   - [x] EVM Circuit
//!   - [ ] Copy Circuit
//! - [ ] Block Table
//!   - [ ] EVM Circuit
//!   - [ ] PublicInputs Circuit
//! - [ ] MPT Table
//!   - [ ] MPT Circuit
//!   - [ ] State Circuit
//! - [x] Keccak Table
//!   - [ ] Keccak Circuit
//!   - [ ] EVM Circuit
//!   - [x] Bytecode Circuit
//!   - [x] Tx Circuit
//!   - [ ] MPT Circuit

use crate::copy_circuit::CopyCircuit;
use crate::state_circuit::StateCircuitConfig;
use crate::tx_circuit::{self, TxCircuit, TxCircuitConfig};

use crate::bytecode_circuit::bytecode_unroller::{
    unroll, Config as BytecodeConfig, UnrolledBytecode,
};

use crate::evm_circuit::{table::FixedTableTag, witness::Block, EvmCircuitConfig};
use crate::table::{BlockTable, BytecodeTable, CopyTable, KeccakTable, RwTable, TxTable};
use crate::util::power_of_randomness_from_instance;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    tx_table: TxTable,
    rw_table: RwTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    keccak_table: KeccakTable,
    copy_table: CopyTable,
    evm_circuit: EvmCircuitConfig<F>,
    state_circuit: StateCircuitConfig<F>,
    tx_circuit: TxCircuitConfig<F>,
    bytecode_circuit: BytecodeConfig<F>,
    copy_circuit: CopyCircuit<F>,
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Default)]
pub struct SuperCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> {
    // EVM Circuit
    block: Block<F>,
    fixed_table_tags: Vec<FixedTableTag>,
    // Tx Circuit
    tx_circuit: TxCircuit<F, MAX_TXS, MAX_CALLDATA>,
    // Bytecode Circuit
    // bytecodes: Vec<UnrolledBytecode<F>>,
    bytecode_size: usize,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>
    SuperCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let mut cs = ConstraintSystem::default();
        let config = Self::configure(&mut cs);
        config.evm_circuit.get_num_rows_required(block)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for SuperCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = SuperCircuitConfig<F, MAX_TXS, MAX_CALLDATA>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);

        let power_of_randomness = power_of_randomness_from_instance(meta);
        let evm_circuit = EvmCircuitConfig::configure(
            meta,
            power_of_randomness[..31].to_vec().try_into().unwrap(),
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
        );
        let state_circuit = StateCircuitConfig::configure(
            meta,
            power_of_randomness[..31].to_vec().try_into().unwrap(),
            &rw_table,
        );

        Self::Config {
            tx_table: tx_table.clone(),
            rw_table,
            bytecode_table: bytecode_table.clone(),
            block_table,
            keccak_table: keccak_table.clone(),
            copy_table,
            evm_circuit,
            state_circuit,
            copy_circuit: CopyCircuit::configure(
                meta,
                &tx_table,
                &rw_table,
                &bytecode_table,
                copy_table,
                q_copy_table,
                power_of_randomness[0].clone(),
            ),
            tx_circuit: TxCircuitConfig::new(
                meta,
                power_of_randomness.clone(),
                tx_table,
                keccak_table.clone(),
            ),
            bytecode_circuit: BytecodeConfig::configure(
                meta,
                power_of_randomness[0].clone(),
                bytecode_table,
                keccak_table,
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // --- EVM Circuit ---
        config
            .evm_circuit
            .load_fixed_table(&mut layouter, self.fixed_table_tags.clone())?;
        config.evm_circuit.load_byte_table(&mut layouter)?;
        config.rw_table.load(
            &mut layouter,
            &self.block.rws.table_assignments(),
            self.block.randomness,
            self.block.state_circuit_pad_to,
        )?;
        config.state_circuit.load(&mut layouter)?;
        config
            .block_table
            .load(&mut layouter, &self.block.context, self.block.randomness)?;
        config
            .copy_table
            .load(&mut layouter, &self.block, self.block.randomness)?;
        config
            .evm_circuit
            .assign_block(&mut layouter, &self.block)?;
        config.state_circuit.assign(
            &mut layouter,
            &self.block.rws.table_assignments(),
            self.block.state_circuit_pad_to,
            self.block.randomness,
        )?;
        // --- Tx Circuit ---
        self.tx_circuit.assign(&config.tx_circuit, &mut layouter)?;
        // --- Bytecode Circuit ---
        let bytecodes: Vec<UnrolledBytecode<F>> = self
            .block
            .bytecodes
            .iter()
            .map(|(_, b)| unroll(b.bytes.clone(), self.block.randomness))
            .collect();
        config.bytecode_circuit.load(&mut layouter)?;
        config.bytecode_circuit.assign(
            &mut layouter,
            self.bytecode_size,
            &bytecodes,
            self.block.randomness,
        )?;
        // --- Keccak Table ---
        let mut keccak_inputs = Vec::new();
        // Lookups from TxCircuit
        keccak_inputs.extend_from_slice(&tx_circuit::keccak_inputs(
            &self.tx_circuit.txs,
            self.block.context.chain_id.as_u64(),
        )?);
        // Lookups from BytecodeCircuit
        for bytecode in self.block.bytecodes.values() {
            keccak_inputs.push(bytecode.bytes.clone());
        }
        // Load Keccak Table
        config
            .keccak_table
            .load(&mut layouter, keccak_inputs, self.block.randomness)?;
        // --- Copy Circuit ---
        config
            .copy_circuit
            .assign_block(&mut layouter, &self.block, self.block.randomness)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use eth_types::{Address, U64};
    use ethers_core::{types::TransactionRequest, utils::keccak256};
    use ethers_signers::LocalWallet;
    use std::collections::HashMap;
    // Testing function
    pub fn sign_txs(
        txs: &mut [eth_types::Transaction],
        chain_id: u64,
        wallets: &HashMap<Address, LocalWallet>,
    ) {
        for tx in txs.iter_mut() {
            let wallet = wallets.get(&tx.from).unwrap();
            let req = TransactionRequest::new()
                .from(tx.from)
                .to(tx.to.unwrap())
                .nonce(tx.nonce)
                .value(tx.value)
                .data(tx.input.clone())
                .gas(tx.gas)
                .gas_price(tx.gas_price.unwrap());
            let tx_rlp = req.rlp(chain_id);
            let sighash = keccak256(tx_rlp.as_ref()).into();
            let sig = wallet.sign_hash(sighash, true);
            tx.v = U64::from(sig.v);
            tx.r = sig.r;
            tx.s = sig.s;
        }
    }
}

#[cfg(test)]
mod super_circuit_tests {
    use super::test::*;
    use super::*;
    use crate::{evm_circuit::witness::block_convert, tx_circuit::sign_verify::POW_RAND_SIZE};
    use bus_mapping::mock::BlockData;
    use eth_types::{
        address, bytecode,
        geth_types::{self, GethData},
        Word,
    };
    use ethers_signers::{LocalWallet, Signer};
    use group::{Curve, Group};
    use halo2_proofs::arithmetic::{CurveAffine, Field as Halo2Field};
    use halo2_proofs::dev::{MockProver, VerifyFailure};
    use halo2_proofs::pairing::bn256::Fr;
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use secp256k1::Secp256k1Affine;
    use std::collections::HashMap;
    use strum::IntoEnumIterator;

    struct Inputs<F: Field> {
        block: Block<F>,
        txs: Vec<geth_types::Transaction>,
        aux_generator: Secp256k1Affine,
    }

    fn run_test_circuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        inputs: Inputs<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let Inputs {
            block,
            txs,
            aux_generator,
        } = inputs;

        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required_for_steps =
            SuperCircuit::<F, MAX_TXS, MAX_CALLDATA>::get_num_rows_required(&block);

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<F>().count())
                .sum::<usize>(),
        );
        let bytecodes_len = block
            .bytecodes
            .iter()
            .map(|(_, bytecode)| bytecode.bytes.len())
            .sum::<usize>();
        let k = k.max(log2_ceil(64 + bytecodes_len));
        let k = k.max(log2_ceil(64 + num_rows_required_for_steps));
        let k = k + 1;
        log::debug!("super circuit uses k = {}", k);

        let mut instance: Vec<Vec<F>> = (1..POW_RAND_SIZE + 1)
            .map(|exp| vec![block.randomness.pow(&[exp as u64, 0, 0, 0]); (1 << k) - 64])
            .collect();
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        instance.push(vec![]);

        let chain_id = block.context.chain_id;
        let tx_circuit = TxCircuit::new(aux_generator, block.randomness, chain_id.as_u64(), txs);
        let circuit = SuperCircuit::<F, MAX_TXS, MAX_CALLDATA> {
            block,
            fixed_table_tags,
            tx_circuit,
            // Instead of using 1 << k - NUM_BLINDING_ROWS, we use a much smaller number of enabled
            // rows for the Bytecode Circuit because otherwise it penalizes significantly the
            // MockProver verification time.
            bytecode_size: bytecodes_len + 64,
        };
        let prover = MockProver::<F>::run(k, &circuit, instance).unwrap();
        prover.verify_par()
    }

    fn run_test_circuit_complete_fixed_table<F: Field>(
        inputs: Inputs<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;

        run_test_circuit::<F, MAX_TXS, MAX_CALLDATA>(inputs, FixedTableTag::iter().collect())
    }

    // High memory usage test.  Run in serial with:
    // `cargo test [...] skip_ -- --ignored --test-threads 1`
    // NOTE: This test is not run as part of CI because it requires more memory than
    // is available in github workers and so it gets killed before completion.
    #[ignore]
    #[test]
    fn skip_test_super_circuit() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            GAS
            STOP
        };

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);

        let addr_a = wallet_a.address();
        let addr_b = address!("0x000000000000000000000000000000000000BBBB");

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let mut block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(addr_b)
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1].address(addr_a).balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        sign_txs(&mut block.eth_block.transactions, chain_id, &wallets);
        let txs = block
            .eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from_eth_tx)
            .collect();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        assert_eq!(builder.block.chain_id.as_u64(), chain_id);

        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .expect("could not handle block tx");
        let mut block = block_convert(&builder.block, &builder.code_db);
        block.randomness = Fr::random(&mut rng);

        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
        let inputs = Inputs {
            block,
            txs,
            aux_generator,
        };

        let res = run_test_circuit_complete_fixed_table(inputs);
        if let Err(err) = res {
            eprintln!("Verification failures:");
            eprintln!("{:#?}", err);
            panic!("Failed verification");
        }
    }
}
