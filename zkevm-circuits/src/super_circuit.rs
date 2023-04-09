//! The Super Circuit is a circuit that contains all the circuits of the
//! zkEVM in order to achieve two things:
//! - Check the correct integration between circuits via the shared lookup tables, to verify that
//!   the table layouts match.
//! - Allow having a single circuit setup for which a proof can be generated that would be verified
//!   under a single aggregation circuit for the first milestone.
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

#[cfg(feature = "poseidon-codehash")]
use crate::bytecode_circuit::circuit::to_poseidon_hash::{
    ToHashBlockBytecodeCircuitConfigArgs, ToHashBlockCircuitConfig, HASHBLOCK_BYTES_IN_FIELD,
};
#[cfg(not(feature = "poseidon-codehash"))]
use crate::bytecode_circuit::circuit::BytecodeCircuitConfig;
use crate::{
    bytecode_circuit::circuit::{BytecodeCircuit, BytecodeCircuitConfigArgs},
    copy_circuit::{CopyCircuit, CopyCircuitConfig, CopyCircuitConfigArgs},
    evm_circuit::{EvmCircuit, EvmCircuitConfig, EvmCircuitConfigArgs},
    exp_circuit::{ExpCircuit, ExpCircuitConfig},
    keccak_circuit::{KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs},
    poseidon_circuit::{PoseidonCircuit, PoseidonCircuitConfig, PoseidonCircuitConfigArgs},
    tx_circuit::{TxCircuit, TxCircuitConfig, TxCircuitConfigArgs},
    util::{log2_ceil, SubCircuit, SubCircuitConfig},
    witness::{block_convert, Block},
};

#[cfg(feature = "zktrie")]
use crate::mpt_circuit::{MptCircuit, MptCircuitConfig, MptCircuitConfigArgs};

#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
#[cfg(feature = "onephase")]
use crate::util::MockChallenges as Challenges;

use crate::{
    state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs},
    table::{
        BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, MptTable, PoseidonTable,
        RlpTable, RwTable, TxTable,
    },
};

use crate::{util::circuit_stats, witness::SignedTransaction};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

use crate::{
    pi_circuit::{PiCircuit, PiCircuitConfig, PiCircuitConfigArgs},
    rlp_circuit::{RlpCircuit, RlpCircuitConfig},
};

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field> {
    block_table: BlockTable,
    mpt_table: MptTable,
    rlp_table: RlpTable,
    tx_table: TxTable,
    poseidon_table: PoseidonTable,
    evm_circuit: EvmCircuitConfig<F>,
    state_circuit: StateCircuitConfig<F>,
    tx_circuit: TxCircuitConfig<F>,
    #[cfg(not(feature = "poseidon-codehash"))]
    bytecode_circuit: BytecodeCircuitConfig<F>,
    #[cfg(feature = "poseidon-codehash")]
    bytecode_circuit: ToHashBlockCircuitConfig<F, HASHBLOCK_BYTES_IN_FIELD>,
    copy_circuit: CopyCircuitConfig<F>,
    keccak_circuit: KeccakCircuitConfig<F>,
    poseidon_circuit: PoseidonCircuitConfig<F>,
    pi_circuit: PiCircuitConfig<F>,
    exp_circuit: ExpCircuitConfig<F>,
    rlp_circuit: RlpCircuitConfig<F>,
    /// Mpt Circuit
    #[cfg(feature = "zktrie")]
    mpt_circuit: MptCircuitConfig,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs<F: Field> {
    /// Max txs
    pub max_txs: usize,
    /// Max calldata
    pub max_calldata: usize,
    /// Max inner blocks
    pub max_inner_blocks: usize,
    /// Mock randomness
    pub mock_randomness: u64,
    /// Challenges
    pub challenges: crate::util::Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = SuperCircuitConfigArgs<F>;

    /// Configure SuperCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            max_txs,
            max_calldata,
            max_inner_blocks,
            mock_randomness: _mock_randomness,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let log_circuit_info = |meta: &ConstraintSystem<F>, tag: &str| {
            log::debug!("circuit info after {}: {:#?}", tag, circuit_stats(meta));
        };
        let tx_table = TxTable::construct(meta);
        log_circuit_info(meta, "tx table");
        let rw_table = RwTable::construct(meta);
        log_circuit_info(meta, "rw table");

        let mpt_table = MptTable::construct(meta);
        log_circuit_info(meta, "mpt table");
        let poseidon_table = PoseidonTable::construct(meta);
        log_circuit_info(meta, "poseidon table");

        let bytecode_table = BytecodeTable::construct(meta);
        log_circuit_info(meta, "bytecode table");
        let block_table = BlockTable::construct(meta);
        log_circuit_info(meta, "block table");
        let q_copy_table = meta.fixed_column();
        log::debug!("q_copy_table {:?}", q_copy_table);
        let copy_table = CopyTable::construct(meta, q_copy_table);
        log_circuit_info(meta, "copy table");
        let exp_table = ExpTable::construct(meta);
        log_circuit_info(meta, "exp table");
        let rlp_table = RlpTable::construct(meta);
        log_circuit_info(meta, "rlp table");
        let keccak_table = KeccakTable::construct(meta);
        log_circuit_info(meta, "keccak table");

        let keccak_circuit = KeccakCircuitConfig::new(
            meta,
            KeccakCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                challenges: challenges.clone(),
            },
        );
        log_circuit_info(meta, "keccak circuit");

        let poseidon_circuit =
            PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table });
        log_circuit_info(meta, "poseidon circuit");

        let rlp_circuit = RlpCircuitConfig::configure(meta, &rlp_table, &challenges);
        log_circuit_info(meta, "rlp circuit");

        let pi_circuit = PiCircuitConfig::new(
            meta,
            PiCircuitConfigArgs {
                max_txs,
                max_calldata,
                max_inner_blocks,
                block_table: block_table.clone(),
                keccak_table: keccak_table.clone(),
                tx_table: tx_table.clone(),
                challenges: challenges.clone(),
            },
        );
        log_circuit_info(meta, "pi circuit");

        let tx_circuit = TxCircuitConfig::new(
            meta,
            TxCircuitConfigArgs {
                block_table: block_table.clone(),
                tx_table: tx_table.clone(),
                keccak_table: keccak_table.clone(),
                rlp_table,
                challenges: challenges.clone(),
            },
        );
        log_circuit_info(meta, "tx circuit");

        #[cfg(not(feature = "poseidon-codehash"))]
        let bytecode_circuit = BytecodeCircuitConfig::new(
            meta,
            BytecodeCircuitConfigArgs {
                bytecode_table: bytecode_table.clone(),
                keccak_table: keccak_table.clone(),
                challenges: challenges.clone(),
            },
        );
        #[cfg(feature = "poseidon-codehash")]
        let bytecode_circuit = ToHashBlockCircuitConfig::new(
            meta,
            ToHashBlockBytecodeCircuitConfigArgs {
                base_args: BytecodeCircuitConfigArgs {
                    bytecode_table: bytecode_table.clone(),
                    keccak_table: keccak_table.clone(),
                    challenges: challenges.clone(),
                },
                poseidon_table,
            },
        );

        log_circuit_info(meta, "bytecode circuit");

        let copy_circuit = CopyCircuitConfig::new(
            meta,
            CopyCircuitConfigArgs {
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table: bytecode_table.clone(),
                copy_table,
                q_enable: q_copy_table,
                challenges: challenges.clone(),
            },
        );
        log_circuit_info(meta, "copy circuit");

        #[cfg(feature = "zktrie")]
        let mpt_circuit = MptCircuitConfig::new(
            meta,
            MptCircuitConfigArgs {
                poseidon_table,
                mpt_table,
                challenges: challenges.clone(),
            },
        );
        #[cfg(feature = "zktrie")]
        log_circuit_info(meta, "zktrie circuit");

        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                rw_table,
                mpt_table,
                challenges: challenges.clone(),
            },
        );
        log_circuit_info(meta, "state circuit");

        let exp_circuit = ExpCircuitConfig::new(meta, exp_table);
        log_circuit_info(meta, "exp circuit");

        let evm_circuit = EvmCircuitConfig::new(
            meta,
            EvmCircuitConfigArgs {
                challenges,
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table,
                block_table: block_table.clone(),
                copy_table,
                keccak_table,
                exp_table,
            },
        );
        log_circuit_info(meta, "evm circuit");

        #[cfg(feature = "onephase")]
        if meta.max_phase() != 0 {
            log::warn!("max_phase: {}", meta.max_phase());
        }

        SuperCircuitConfig::<F> {
            block_table,
            mpt_table,
            tx_table,
            rlp_table,
            poseidon_table,
            evm_circuit,
            state_circuit,
            copy_circuit,
            bytecode_circuit,
            keccak_circuit,
            poseidon_circuit,
            pi_circuit,
            rlp_circuit,
            tx_circuit,
            exp_circuit,
            #[cfg(feature = "zktrie")]
            mpt_circuit,
        }
    }
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
    const MOCK_RANDOMNESS: u64,
> {
    /// EVM Circuit
    pub evm_circuit: EvmCircuit<F>,
    /// State Circuit
    pub state_circuit: StateCircuit<F>,
    /// The transaction circuit that will be used in the `synthesize` step.
    pub tx_circuit: TxCircuit<F>,
    /// Public Input Circuit
    pub pi_circuit: PiCircuit<F>,
    /// Bytecode Circuit
    pub bytecode_circuit: BytecodeCircuit<F>,
    /// Copy Circuit
    pub copy_circuit: CopyCircuit<F>,
    /// Exp Circuit
    pub exp_circuit: ExpCircuit<F>,
    /// Keccak Circuit
    pub keccak_circuit: KeccakCircuit<F>,
    /// Poseidon hash Circuit
    pub poseidon_circuit: PoseidonCircuit<F>,
    /// Rlp Circuit
    pub rlp_circuit: RlpCircuit<F, SignedTransaction>,
    /// Mpt Circuit
    #[cfg(feature = "zktrie")]
    pub mpt_circuit: MptCircuit<F>,
}

impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    /// Return the number of rows required to verify a given block
    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let num_rows_evm_circuit = EvmCircuit::<F>::get_num_rows_required(block);
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        let num_rows_tx_circuit =
            TxCircuitConfig::<F>::get_num_rows_required(block.circuits_params.max_txs);
        num_rows_evm_circuit.max(num_rows_tx_circuit)
    }
    /// Return the minimum number of rows required to prove the block
    pub fn min_num_rows_block_subcircuits(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let evm = EvmCircuit::min_num_rows_block(block);
        let state = StateCircuit::min_num_rows_block(block);
        let bytecode = BytecodeCircuit::min_num_rows_block(block);
        let copy = CopyCircuit::min_num_rows_block(block);
        let keccak = KeccakCircuit::min_num_rows_block(block);
        let tx = TxCircuit::min_num_rows_block(block);
        let rlp = RlpCircuit::min_num_rows_block(block);
        let exp = ExpCircuit::min_num_rows_block(block);
        let pi = PiCircuit::min_num_rows_block(block);
        let poseidon = PoseidonCircuit::min_num_rows_block(block);
        #[cfg(feature = "zktrie")]
        let mpt = MptCircuit::min_num_rows_block(block);

        let rows: Vec<(usize, usize)> = vec![
            evm,
            state,
            bytecode,
            copy,
            keccak,
            tx,
            rlp,
            exp,
            pi,
            poseidon,
            #[cfg(feature = "zktrie")]
            mpt,
        ];
        let (rows_without_padding, rows_with_padding): (Vec<usize>, Vec<usize>) =
            rows.into_iter().unzip();
        log::debug!(
            "subcircuit rows(without padding): {:?}",
            rows_without_padding
        );
        log::debug!("subcircuit rows(with    padding): {:?}", rows_with_padding);
        (rows_without_padding, rows_with_padding)
    }
}

// Eventhough the SuperCircuit is not a subcircuit we implement the SubCircuit
// trait for it in order to get the `new_from_block` and `instance` methods that
// allow us to generalize integration tests.
impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SubCircuit<F> for SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = SuperCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        let evm_circuit = EvmCircuit::new_from_block(block);
        let state_circuit = StateCircuit::new_from_block(block);
        let tx_circuit = TxCircuit::new_from_block(block);
        let pi_circuit = PiCircuit::new_from_block(block);
        let bytecode_circuit = BytecodeCircuit::new_from_block(block);
        let copy_circuit = CopyCircuit::new_from_block_no_external(block);
        let exp_circuit = ExpCircuit::new_from_block(block);
        let keccak_circuit = KeccakCircuit::new_from_block(block);
        let poseidon_circuit = PoseidonCircuit::new_from_block(block);
        let rlp_circuit = RlpCircuit::new_from_block(block);
        #[cfg(feature = "zktrie")]
        let mpt_circuit = MptCircuit::new_from_block(block);
        SuperCircuit::<_, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS> {
            evm_circuit,
            state_circuit,
            tx_circuit,
            pi_circuit,
            bytecode_circuit,
            copy_circuit,
            exp_circuit,
            keccak_circuit,
            poseidon_circuit,
            rlp_circuit,
            #[cfg(feature = "zktrie")]
            mpt_circuit,
        }
    }

    /// Returns suitable inputs for the SuperCircuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.keccak_circuit.instance());
        instance.extend_from_slice(&self.pi_circuit.instance());
        instance.extend_from_slice(&self.tx_circuit.instance());
        instance.extend_from_slice(&self.bytecode_circuit.instance());
        instance.extend_from_slice(&self.copy_circuit.instance());
        instance.extend_from_slice(&self.state_circuit.instance());
        instance.extend_from_slice(&self.exp_circuit.instance());
        instance.extend_from_slice(&self.evm_circuit.instance());

        instance
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        let (rows_without_padding, rows_with_padding) = Self::min_num_rows_block_subcircuits(block);
        (
            itertools::max(rows_without_padding).unwrap(),
            itertools::max(rows_with_padding).unwrap(),
        )
    }

    /// Make the assignments to the SuperCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.keccak_circuit
            .synthesize_sub(&config.keccak_circuit, challenges, layouter)?;
        self.poseidon_circuit
            .synthesize_sub(&config.poseidon_circuit, challenges, layouter)?;
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, challenges, layouter)?;
        self.tx_circuit
            .synthesize_sub(&config.tx_circuit, challenges, layouter)?;
        self.state_circuit
            .synthesize_sub(&config.state_circuit, challenges, layouter)?;
        self.copy_circuit
            .synthesize_sub(&config.copy_circuit, challenges, layouter)?;
        self.exp_circuit
            .synthesize_sub(&config.exp_circuit, challenges, layouter)?;
        self.evm_circuit
            .synthesize_sub(&config.evm_circuit, challenges, layouter)?;

        // TODO: enable this after zktrie deletion deployed inside l2geth and
        // test data regenerated.
        // config.pi_circuit.state_roots =
        // self.state_circuit.exports.borrow().clone();
        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, challenges, layouter)?;

        self.rlp_circuit
            .synthesize_sub(&config.rlp_circuit, challenges, layouter)?;
        // load both poseidon table and zktrie table
        #[cfg(feature = "zktrie")]
        self.mpt_circuit
            .synthesize_sub(&config.mpt_circuit, challenges, layouter)?;

        Ok(())
    }
}

impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > Circuit<F> for SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = (SuperCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            SuperCircuitConfig::new(
                meta,
                SuperCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    max_inner_blocks: MAX_INNER_BLOCKS,
                    mock_randomness: MOCK_RANDOMNESS,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        let block = self.evm_circuit.block.as_ref().unwrap();

        // PI circuit had the hardcoded constants for RegionIndex of block table
        // and tx table (which are 0 and 1).
        // The reason for that is the assignment of block/tx tables are done in
        // their load() functions which however do not emit the cells.
        // To set up copy constraints between pi cells and block/tx table cells,
        // we need to construct them manually.
        config.tx_table.load(
            &mut layouter,
            &block.txs,
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.chain_id.as_u64(),
            &challenges,
        )?;

        config.mpt_table.load(
            &mut layouter,
            &self.state_circuit.updates,
            challenges.evm_word(),
        )?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
        circuits_params: CircuitsParams,
    ) -> Result<(u32, Self, Vec<Vec<F>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data =
            BlockData::new_from_geth_data_with_params(geth_data.clone(), circuits_params);

        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }

    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
    ) -> Result<(u32, Self, Vec<Vec<F>>), bus_mapping::Error> {
        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.randomness = F::from(MOCK_RANDOMNESS);
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);
        Self::build_from_witness_block(block)
    }
    /// ..
    pub fn build_from_witness_block(
        block: Block<F>,
    ) -> Result<(u32, Self, Vec<Vec<F>>), bus_mapping::Error> {
        log::debug!(
            "super circuit build_from_witness_block, circuits_params {:?}",
            block.circuits_params
        );

        const NUM_BLINDING_ROWS: usize = 64;
        let (_, rows_needed) = Self::min_num_rows_block(&block);
        let k = log2_ceil(NUM_BLINDING_ROWS + rows_needed);
        log::debug!("super circuit needs k = {}", k);

        let circuit =
            SuperCircuit::<_, MAX_TXS, MAX_CALLDATA,MAX_INNER_BLOCKS,  MOCK_RANDOMNESS>::new_from_block(&block);

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
}

#[cfg(test)]
pub(crate) mod super_circuit_tests {
    use super::*;
    use ethers_signers::{LocalWallet, Signer};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use log::error;
    use mock::{eth, TestContext, MOCK_CHAIN_ID, MOCK_DIFFICULTY};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::{collections::HashMap, env::set_var};

    use eth_types::{address, bytecode, evm_types::OpcodeId, geth_types::GethData, Bytecode, Word};

    #[test]
    fn super_circuit_degree() {
        let mut cs = ConstraintSystem::<Fr>::default();
        SuperCircuit::<_, 1, 32, 64, 0x100>::configure(&mut cs);
        log::info!("super circuit degree: {}", cs.degree());
        log::info!("super circuit minimum_rows: {}", cs.minimum_rows());
        assert!(cs.degree() <= 9);
    }

    fn test_super_circuit<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    >(
        block: GethData,
        circuits_params: CircuitsParams,
    ) {
        let mut difficulty_be_bytes = [0u8; 32];
        let mut chain_id_be_bytes = [0u8; 32];
        MOCK_DIFFICULTY.to_big_endian(&mut difficulty_be_bytes);
        MOCK_CHAIN_ID.to_big_endian(&mut chain_id_be_bytes);
        set_var("CHAIN_ID", hex::encode(chain_id_be_bytes));
        set_var("DIFFICULTY", hex::encode(difficulty_be_bytes));

        let (k, circuit, instance, _) =
            SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>::build(
                block,
                circuits_params,
            )
            .unwrap();
        let prover = MockProver::run(k, &circuit, instance).unwrap();
        let res = prover.verify_par();
        if let Err(err) = res {
            error!("Verification failures: {:#?}", err);
            panic!("Failed verification");
        }
    }

    fn callee_bytecode(is_return: bool, offset: u64, length: u64) -> Bytecode {
        let memory_bytes = [0x60; 10];
        let memory_address = 0;
        let memory_value = Word::from_big_endian(&memory_bytes);
        let mut code = bytecode! {
            PUSH10(memory_value)
            PUSH1(memory_address)
            MSTORE
            PUSH2(length)
            PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap() + offset)
        };
        code.write_op(if is_return {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        });
        code
    }

    fn block_1tx_deploy() -> GethData {
        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let chain_id = (*MOCK_CHAIN_ID).as_u64();

        let wallet_a = LocalWallet::new(&mut rng).with_chain_id(chain_id);
        let addr_a = wallet_a.address();

        let mut wallets = HashMap::new();
        wallets.insert(wallet_a.address(), wallet_a);

        let tx_input = callee_bytecode(true, 300, 20).code();
        let mut block: GethData = TestContext::<2, 1>::new(
            Some(vec![Word::zero()]),
            |accs| {
                accs[0].address(addr_a).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[0].address).input(tx_input.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        block.sign(&wallets);
        block
    }

    pub(crate) fn block_1tx() -> GethData {
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
            Some(vec![Word::zero()]),
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
        block
    }

    fn block_2tx() -> GethData {
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

        let mut block: GethData = TestContext::<2, 2>::new(
            Some(vec![Word::zero()]),
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
                txs[1]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(Word::from(1_000_000u64));
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        block.sign(&wallets);
        block
    }

    const TEST_MOCK_RANDOMNESS: u64 = 0x100;

    // High memory usage test.  Run in serial with:
    // `cargo test [...] serial_ -- --ignored --test-threads 1`
    #[ignore]
    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_super_circuit_1tx_1max_tx() {
        let block = block_1tx();
        const MAX_TXS: usize = 1;
        const MAX_CALLDATA: usize = 32;
        const MAX_INNER_BLOCKS: usize = 1;
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
            max_inner_blocks: MAX_INNER_BLOCKS,
        };
        test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
            block,
            circuits_params,
        );
    }

    #[ignore]
    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_super_circuit_1tx_deploy_2max_tx() {
        let block = block_1tx_deploy();
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;
        const MAX_INNER_BLOCKS: usize = 1;
        const MAX_RWS: usize = 256;
        const MAX_COPY_ROWS: usize = 256;
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: MAX_RWS,
            max_copy_rows: MAX_COPY_ROWS,
            max_bytecode: 512,
            max_keccak_rows: 0,
            max_inner_blocks: MAX_INNER_BLOCKS,
            max_exp_steps: 256,
            max_evm_rows: 0,
        };
        test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
            block,
            circuits_params,
        );
    }

    #[ignore]
    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_super_circuit_1tx_2max_tx() {
        let block = block_1tx();
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;
        const MAX_INNER_BLOCKS: usize = 1;
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
            max_inner_blocks: MAX_INNER_BLOCKS,
        };
        test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
            block,
            circuits_params,
        );
    }

    #[ignore]
    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_super_circuit_2tx_4max_tx() {
        let block = block_2tx();
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 320;
        const MAX_INNER_BLOCKS: usize = 1;
        const MAX_RWS: usize = 256;
        const MAX_COPY_ROWS: usize = 256;
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: MAX_RWS,
            max_copy_rows: MAX_COPY_ROWS,
            max_bytecode: 512,
            max_keccak_rows: 0,
            max_inner_blocks: MAX_INNER_BLOCKS,
            max_exp_steps: 256,
            max_evm_rows: 0,
        };
        test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
            block,
            circuits_params,
        );
    }

    #[ignore]
    #[cfg(feature = "scroll")]
    #[test]
    fn serial_test_super_circuit_2tx_2max_tx() {
        let block = block_2tx();
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 32;
        const MAX_INNER_BLOCKS: usize = 1;
        let circuits_params = CircuitsParams {
            max_txs: MAX_TXS,
            max_calldata: MAX_CALLDATA,
            max_rws: 256,
            max_copy_rows: 256,
            max_exp_steps: 256,
            max_bytecode: 512,
            max_evm_rows: 0,
            max_keccak_rows: 0,
            max_inner_blocks: MAX_INNER_BLOCKS,
        };
        test_super_circuit::<MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, TEST_MOCK_RANDOMNESS>(
            block,
            circuits_params,
        );
    }
}
