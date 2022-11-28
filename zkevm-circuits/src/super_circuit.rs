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
//! - [x] Copy Circuit
//! - [x] Exponentiation Circuit
//! - [ ] Keccak Circuit
//! - [ ] MPT Circuit
//! - [x] PublicInputs Circuit
//!
//! And the following shared tables, with the circuits that use them:
//!
//! - [x] Copy Table
//!   - [x] Copy Circuit
//!   - [x] EVM Circuit
//! - [x] Exponentiation Table
//!   - [x] EVM Circuit
//! - [ ] Rw Table
//!   - [ ] State Circuit
//!   - [ ] EVM Circuit
//!   - [ ] Copy Circuit
//! - [x] Tx Table
//!   - [x] Tx Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//!   - [x] PublicInputs Circuit
//! - [x] Bytecode Table
//!   - [x] Bytecode Circuit
//!   - [x] EVM Circuit
//!   - [x] Copy Circuit
//! - [ ] Block Table
//!   - [ ] EVM Circuit
//!   - [x] PublicInputs Circuit
//! - [ ] MPT Table
//!   - [ ] MPT Circuit
//!   - [ ] State Circuit
//! - [x] Keccak Table
//!   - [ ] Keccak Circuit
//!   - [ ] EVM Circuit
//!   - [x] Bytecode Circuit
//!   - [x] Tx Circuit
//!   - [ ] MPT Circuit

use crate::bytecode_circuit::bytecode_unroller::{
    unroll, Config as BytecodeConfig, UnrolledBytecode,
};
use crate::copy_circuit::CopyCircuit;
use crate::evm_circuit::{table::FixedTableTag, EvmCircuit};
use crate::exp_circuit::ExpCircuitConfig;
use crate::keccak_circuit::keccak_packed_multi::KeccakPackedConfig as KeccakConfig;
use crate::pi_circuit::{PiCircuit, PiCircuitConfig, PublicData};
use crate::state_circuit::StateCircuitConfig;
use crate::table::{BlockTable, BytecodeTable, CopyTable, ExpTable, MptTable, RwTable, TxTable};
use crate::tx_circuit::{TxCircuit, TxCircuitConfig};
use crate::util::Challenges;
use crate::witness::{block_convert, Block, MptUpdates};
use bus_mapping::circuit_input_builder::CopyDataType;
use bus_mapping::circuit_input_builder::{CircuitInputBuilder, CircuitsParams};
use bus_mapping::mock::BlockData;
use eth_types::geth_types::{self, GethData, Transaction};
use eth_types::Field;
use ethers_core::types::H256;
use gadgets::util::not;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::{
    bn256::Fr,
    group::{Curve, Group},
    secp256k1::Secp256k1Affine,
};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

use rand::RngCore;
use std::array;
use strum::IntoEnumIterator;

/// Mock randomness used for `SuperCircuit`.
pub const MOCK_RANDOMNESS: u64 = 0x100;
// TODO: Figure out if we can remove MAX_TXS, MAX_CALLDATA and MAX_RWS from the
// struct.

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
> {
    tx_table: TxTable,
    rw_table: RwTable,
    mpt_table: MptTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    exp_table: ExpTable,
    evm_circuit: EvmCircuit<F>,
    state_circuit: StateCircuitConfig<F>,
    tx_circuit: TxCircuitConfig<F>,
    bytecode_circuit: BytecodeConfig<F>,
    copy_circuit: CopyCircuit<F>,
    keccak_circuit: KeccakConfig<F>,
    pi_circuit: PiCircuitConfig<F, MAX_TXS, MAX_CALLDATA>,
    exp_circuit: ExpCircuitConfig<F>,
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_RWS: usize,
> {
    // EVM Circuit
    /// Block witness. Usually derived via
    /// `evm_circuit::witness::block_convert`.
    pub block: Option<Block<F>>,
    /// Inputs for the keccak circuit
    pub keccak_inputs: Vec<Vec<u8>>,
    /// Passed down to the evm_circuit. Usually that will be
    /// `FixedTableTag::iter().collect()`.
    pub fixed_table_tags: Vec<FixedTableTag>,
    // Tx Circuit
    /// The transaction circuit that will be used in the `synthesize` step.
    pub tx_circuit: TxCircuit<F, MAX_TXS, MAX_CALLDATA>,
    // Bytecode Circuit
    // bytecodes: Vec<UnrolledBytecode<F>>,
    /// The maximium size for the underlying bytecode circuit.
    pub bytecode_size: usize,
    /// Public Input Circuit
    pub pi_circuit: PiCircuit<F, MAX_TXS, MAX_CALLDATA>,
    /// Configuration parameters for various parts of the circuit.
    pub circuits_params: CircuitsParams,
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize>
    SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let num_rows_evm_circuit = {
            let mut cs = ConstraintSystem::default();
            let config = Self::configure(&mut cs);
            config.evm_circuit.get_num_rows_required(block)
        };
        let num_rows_tx_circuit = TxCircuitConfig::<F>::get_num_rows_required(MAX_TXS);
        num_rows_evm_circuit.max(num_rows_tx_circuit)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize> Circuit<F>
    for SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    type Config = SuperCircuitConfig<F, MAX_TXS, MAX_CALLDATA, MAX_RWS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);
        let exp_table = ExpTable::construct(meta);

        let power_of_randomness = array::from_fn(|i| {
            Expression::Constant(F::from(MOCK_RANDOMNESS).pow(&[1 + i as u64, 0, 0, 0]))
        });

        let challenges = Challenges::mock(
            power_of_randomness[0].clone(),
            power_of_randomness[0].clone(),
        );

        let keccak_circuit = KeccakConfig::configure(meta, power_of_randomness[0].clone());
        let keccak_table = keccak_circuit.keccak_table.clone();

        let evm_circuit = EvmCircuit::configure(
            meta,
            power_of_randomness.clone(),
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
            &exp_table,
        );
        let state_circuit =
            StateCircuitConfig::configure(meta, &rw_table, &mpt_table, challenges.clone());
        let pi_circuit = PiCircuitConfig::new(meta, block_table.clone(), tx_table.clone());
        let copy_circuit = CopyCircuit::configure(
            meta,
            &tx_table,
            &rw_table,
            &bytecode_table,
            copy_table,
            q_copy_table,
            power_of_randomness[0].clone(),
        );
        // copy circuit <-> keccak circuit
        meta.lookup_any("copy<->keccak", |meta| {
            let input_enabled = meta.query_fixed(copy_circuit.q_enable, Rotation::cur())
                * not::expr(meta.query_selector(copy_circuit.q_step))
                * copy_table
                    .tag
                    .value_equals(CopyDataType::SHA3, Rotation::cur())(meta);

            vec![
                (
                    input_enabled.clone() * meta.query_advice(copy_table.id, Rotation::cur()),
                    meta.query_advice(keccak_table.hash_id, Rotation::cur()),
                ),
                (
                    input_enabled.clone()
                        * meta.query_advice(copy_table.bytes_left, Rotation::cur()),
                    meta.query_advice(keccak_table.bytes_left, Rotation::cur()),
                ),
                (
                    input_enabled * meta.query_advice(copy_circuit.value, Rotation::cur()),
                    meta.query_advice(keccak_table.byte_value, Rotation::cur()),
                ),
            ]
        });

        Self::Config {
            tx_table: tx_table.clone(),
            rw_table,
            mpt_table,
            bytecode_table: bytecode_table.clone(),
            block_table,
            copy_table,
            exp_table,
            evm_circuit,
            state_circuit,
            copy_circuit,
            tx_circuit: TxCircuitConfig::new(
                meta,
                tx_table,
                keccak_table.clone(),
                challenges.clone(),
            ),
            bytecode_circuit: BytecodeConfig::configure(
                meta,
                bytecode_table,
                keccak_table,
                challenges,
            ),
            keccak_circuit,
            pi_circuit,
            exp_circuit: ExpCircuitConfig::configure(meta, exp_table),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();
        let challenges = Challenges::mock(
            Value::known(block.randomness),
            Value::known(block.randomness),
        );

        // --- EVM Circuit ---
        let rws = block.rws.table_assignments();
        config
            .evm_circuit
            .load_fixed_table(&mut layouter, self.fixed_table_tags.clone())?;
        config.evm_circuit.load_byte_table(&mut layouter)?;
        config.rw_table.load(
            &mut layouter,
            &rws,
            block.circuits_params.max_rws,
            Value::known(block.randomness),
        )?;
        config.state_circuit.load(&mut layouter)?;
        config
            .block_table
            .load(&mut layouter, &block.context, block.randomness)?;
        config.evm_circuit.assign_block(&mut layouter, block)?;
        // --- State Circuit ---
        config.mpt_table.load(
            &mut layouter,
            &MptUpdates::mock_from(&rws),
            Value::known(block.randomness),
        )?;
        config.state_circuit.assign(
            &mut layouter,
            &rws,
            block.circuits_params.max_rws,
            &challenges,
        )?;
        // --- Tx Circuit ---
        config.tx_circuit.load(&mut layouter)?;
        self.tx_circuit
            .assign(&config.tx_circuit, &mut layouter, &challenges)?;
        // --- Bytecode Circuit ---
        let bytecodes: Vec<UnrolledBytecode<F>> = block
            .bytecodes
            .iter()
            .map(|(_, b)| unroll(b.bytes.clone()))
            .collect();
        config.bytecode_circuit.load(&mut layouter)?;
        config.bytecode_circuit.assign(
            &mut layouter,
            self.bytecode_size,
            &bytecodes,
            &challenges,
        )?;
        // --- Exponentiation Circuit ---
        config.exp_circuit.assign_block(&mut layouter, block)?;
        // --- Keccak Table ---
        config.keccak_circuit.load(&mut layouter)?;
        config.keccak_circuit.assign_from_witness(
            &mut layouter,
            &self.keccak_inputs,
            block.randomness,
            self.circuits_params.keccak_padding,
        )?;
        // --- Copy Circuit ---
        config
            .copy_circuit
            .assign_block(&mut layouter, block, block.randomness)?;
        // --- Public Input Circuit ---
        self.pi_circuit.synthesize(config.pi_circuit, layouter)?;
        Ok(())
    }
}

impl<const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_RWS: usize>
    SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_RWS>
{
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
        rng: &mut (impl RngCore + Clone),
    ) -> Result<(u32, Self, Vec<Vec<Fr>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data = BlockData::new_from_geth_data(geth_data.clone());
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder, geth_data.eth_block, rng)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }

    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
        eth_block: eth_types::Block<eth_types::Transaction>,
        rng: &mut (impl RngCore + Clone),
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        let keccak_inputs = builder.keccak_inputs()?;
        let mut block = block_convert(&builder.block, &builder.code_db);
        block.randomness = Fr::from(MOCK_RANDOMNESS);

        let fixed_table_tags: Vec<FixedTableTag> = FixedTableTag::iter().collect();
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required =
            SuperCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS>::get_num_rows_required(&block);

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<Fr>().count())
                .sum::<usize>(),
        );
        let bytecodes_len = block
            .bytecodes
            .iter()
            .map(|(_, bytecode)| bytecode.bytes.len())
            .sum::<usize>();
        let k = k.max(log2_ceil(64 + bytecodes_len));
        let k = k.max(log2_ceil(64 + num_rows_required));
        log::debug!("super circuit uses k = {}", k);

        let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(rng).to_affine();
        let chain_id = block.context.chain_id;
        let txs: Vec<Transaction> = eth_block
            .transactions
            .iter()
            .map(geth_types::Transaction::from)
            .collect();
        let tx_circuit = TxCircuit::new(aux_generator, chain_id.as_u64(), txs);

        let public_data = PublicData {
            chain_id,
            history_hashes: builder.block.history_hashes.clone(),
            eth_block,
            block_constants: geth_types::BlockConstants {
                coinbase: block.context.coinbase,
                timestamp: block.context.timestamp,
                number: block.context.number.as_u64().into(),
                difficulty: block.context.difficulty,
                gas_limit: block.context.gas_limit.into(),
                base_fee: block.context.base_fee,
            },
            prev_state_root: H256::default(),
        };
        let pi_circuit = PiCircuit::new(MOCK_RANDOMNESS, MOCK_RANDOMNESS + 1, public_data);

        let circuit = SuperCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_RWS> {
            block: Some(block),
            fixed_table_tags,
            tx_circuit,
            keccak_inputs,
            // Instead of using 1 << k - NUM_BLINDING_ROWS, we use a much smaller number of enabled
            // rows for the Bytecode Circuit because otherwise it penalizes significantly the
            // MockProver verification time.
            bytecode_size: bytecodes_len + 128,
            pi_circuit,
            circuits_params: builder.block.circuits_params.clone(),
        };

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }

    /// Returns suitable inputs for the SuperCircuit.
    pub fn instance(&self) -> Vec<Vec<Fr>> {
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let pi_instance = self.pi_circuit.instance();
        let instance = vec![pi_instance[0].clone(), vec![]];

        instance
    }
}

// TODO: Add tests
// - multiple txs == MAX_TXS
// - multiple txs < MAX_TXS
// - max_rws padding
// - evm_rows padding

#[cfg(test)]
mod super_circuit_tests {
    use super::*;
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::dev::MockProver;
    use mock::{TestContext, MOCK_CHAIN_ID};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashMap;

    use eth_types::{address, bytecode, geth_types::GethData, Word};

    // High memory usage test.  Run in serial with:
    // `cargo test [...] serial_ -- --ignored --test-threads 1`
    #[ignore]
    #[test]
    fn serial_test_super_circuit() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let bytecode = bytecode! {
            PUSH32(100) // size
            PUSH32(0) // offset
            SHA3
            PUSH32(200)
            PUSH32(0)
            SHA3
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

        block.sign(&wallets);

        let (k, circuit, instance, _) =
            SuperCircuit::<_, 1, 32, 256>::build(block, &mut ChaCha20Rng::seed_from_u64(2))
                .unwrap();
        println!("k is {}", k);
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            eprintln!("Verification failures:");
            eprintln!("{:#?}", err);
            panic!("Failed verification");
        }
    }
}
