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

#[cfg(any(feature = "test", test))]
pub(crate) mod test;

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
    sig_circuit::{SigCircuit, SigCircuitConfig, SigCircuitConfigArgs},
    table::SigTable,
    tx_circuit::{TxCircuit, TxCircuitConfig, TxCircuitConfigArgs},
    util::{log2_ceil, SubCircuit, SubCircuitConfig},
    witness::{block_convert, Block},
};

#[cfg(feature = "zktrie")]
use crate::mpt_circuit::{MptCircuit, MptCircuitConfig, MptCircuitConfigArgs};

use crate::util::Challenges;

use crate::{
    state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs},
    table::{
        BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, MptTable, PoseidonTable,
        PowOfRandTable, RlpFsmRlpTable as RlpTable, RwTable, TxTable,
    },
};

use crate::util::circuit_stats;
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    mock::BlockData,
};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;

use crate::{
    pi_circuit::{PiCircuit, PiCircuitConfig, PiCircuitConfigArgs},
    rlp_circuit_fsm::{RlpCircuit, RlpCircuitConfig, RlpCircuitConfigArgs},
    witness::Transaction,
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
    sig_circuit: SigCircuitConfig<F>,
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
    mpt_circuit: MptCircuitConfig<F>,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs {
    /// Max txs
    pub max_txs: usize,
    /// Max calldata
    pub max_calldata: usize,
    /// Max inner blocks
    pub max_inner_blocks: usize,
    /// Mock randomness
    pub mock_randomness: u64,
    /// Challenges
    pub challenges: crate::util::Challenges,
}

impl SubCircuitConfig<Fr> for SuperCircuitConfig<Fr> {
    type ConfigArgs = SuperCircuitConfigArgs;

    /// Configure SuperCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<Fr>,
        Self::ConfigArgs {
            max_txs,
            max_calldata,
            max_inner_blocks,
            mock_randomness: _mock_randomness,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let log_circuit_info = |meta: &ConstraintSystem<Fr>, tag: &str| {
            log::debug!("circuit info after {}: {:#?}", tag, circuit_stats(meta));
        };
        let challenges_expr = challenges.exprs(meta);

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
        let sig_table = SigTable::construct(meta);
        log_circuit_info(meta, "sig table");
        let pow_of_rand_table = PowOfRandTable::construct(meta, &challenges_expr);
        log_circuit_info(meta, "power of randomness table");

        let keccak_circuit = KeccakCircuitConfig::new(
            meta,
            KeccakCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "keccak circuit");

        let poseidon_circuit =
            PoseidonCircuitConfig::new(meta, PoseidonCircuitConfigArgs { poseidon_table });
        log_circuit_info(meta, "poseidon circuit");

        let rlp_circuit = RlpCircuitConfig::new(
            meta,
            RlpCircuitConfigArgs {
                rlp_table,
                challenges: challenges_expr.clone(),
            },
        );
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
                challenges: challenges_expr.clone(),
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
                sig_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "tx circuit");

        #[cfg(not(feature = "poseidon-codehash"))]
        let bytecode_circuit = BytecodeCircuitConfig::new(
            meta,
            BytecodeCircuitConfigArgs {
                bytecode_table: bytecode_table.clone(),
                keccak_table: keccak_table.clone(),
                challenges: challenges_expr.clone(),
            },
        );
        #[cfg(feature = "poseidon-codehash")]
        let bytecode_circuit = ToHashBlockCircuitConfig::new(
            meta,
            ToHashBlockBytecodeCircuitConfigArgs {
                base_args: BytecodeCircuitConfigArgs {
                    bytecode_table: bytecode_table.clone(),
                    keccak_table: keccak_table.clone(),
                    challenges: challenges_expr.clone(),
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
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "copy circuit");

        #[cfg(feature = "zktrie")]
        let mpt_circuit = MptCircuitConfig::new(
            meta,
            MptCircuitConfigArgs {
                poseidon_table,
                mpt_table,
                challenges,
            },
        );
        #[cfg(feature = "zktrie")]
        log_circuit_info(meta, "zktrie circuit");

        let sig_circuit = SigCircuitConfig::new(
            meta,
            SigCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                sig_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "sig circuit");

        let state_circuit = StateCircuitConfig::new(
            meta,
            StateCircuitConfigArgs {
                rw_table,
                mpt_table,
                challenges: challenges_expr.clone(),
            },
        );
        log_circuit_info(meta, "state circuit");

        let exp_circuit = ExpCircuitConfig::new(meta, exp_table);
        log_circuit_info(meta, "exp circuit");

        let evm_circuit = EvmCircuitConfig::new(
            meta,
            EvmCircuitConfigArgs {
                challenges: challenges_expr,
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table,
                block_table: block_table.clone(),
                copy_table,
                keccak_table,
                exp_table,
                sig_table,
                pow_of_rand_table,
            },
        );
        log_circuit_info(meta, "evm circuit");

        #[cfg(feature = "onephase")]
        if meta.max_phase() != 0 {
            log::warn!("max_phase: {}", meta.max_phase());
        }

        SuperCircuitConfig {
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
            sig_circuit,
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
    /// Sig Circuit
    pub sig_circuit: SigCircuit<F>,
    /// Rlp Circuit
    pub rlp_circuit: RlpCircuit<F, Transaction>,
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
    pub fn get_num_rows_required(block: &Block<Fr>) -> usize {
        let num_rows_evm_circuit = EvmCircuit::<Fr>::get_num_rows_required(block);
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        // FIXME: need to call the SigCircuit::get_num_rows_required instead
        // let num_rows_tx_circuit =
        //     TxCircuitConfig::<F>::get_num_rows_required(block.circuits_params.max_txs);
        // num_rows_evm_circuit.max(num_rows_tx_circuit)
        num_rows_evm_circuit
    }
    /// Return the minimum number of rows required to prove the block
    pub fn min_num_rows_block_subcircuits(block: &Block<Fr>) -> (Vec<usize>, Vec<usize>) {
        let evm = EvmCircuit::min_num_rows_block(block);
        let state = StateCircuit::min_num_rows_block(block);
        let bytecode = BytecodeCircuit::min_num_rows_block(block);
        let copy = CopyCircuit::min_num_rows_block(block);
        let keccak = KeccakCircuit::min_num_rows_block(block);
        let tx = TxCircuit::min_num_rows_block(block);
        let rlp = RlpCircuit::min_num_rows_block(block);
        let exp = ExpCircuit::min_num_rows_block(block);
        let pi = PiCircuit::min_num_rows_block(block);
        let poseidon = (0, 0); //PoseidonCircuit::min_num_rows_block(block);
        #[cfg(feature = "zktrie")]
        let mpt = MptCircuit::<Fr>::min_num_rows_block(block);

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
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SubCircuit<Fr>
    for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = SuperCircuitConfig<Fr>;

    fn unusable_rows() -> usize {
        itertools::max([
            EvmCircuit::<Fr>::unusable_rows(),
            StateCircuit::<Fr>::unusable_rows(),
            TxCircuit::<Fr>::unusable_rows(),
            PiCircuit::<Fr>::unusable_rows(),
            BytecodeCircuit::<Fr>::unusable_rows(),
            CopyCircuit::<Fr>::unusable_rows(),
            ExpCircuit::<Fr>::unusable_rows(),
            KeccakCircuit::<Fr>::unusable_rows(),
        ])
        .unwrap()
    }

    fn new_from_block(block: &Block<Fr>) -> Self {
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
        let sig_circuit = SigCircuit::new_from_block(block);
        #[cfg(feature = "zktrie")]
        let mpt_circuit = MptCircuit::new_from_block(block);
        SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS> {
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
            sig_circuit,
            #[cfg(feature = "zktrie")]
            mpt_circuit,
        }
    }

    /// Returns suitable inputs for the SuperCircuit.
    fn instance(&self) -> Vec<Vec<Fr>> {
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
    fn min_num_rows_block(block: &Block<Fr>) -> (usize, usize) {
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
        challenges: &crate::util::Challenges<Value<Fr>>,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(), Error> {
        self.keccak_circuit
            .synthesize_sub(&config.keccak_circuit, challenges, layouter)?;
        self.poseidon_circuit
            .synthesize_sub(&config.poseidon_circuit, challenges, layouter)?;
        self.bytecode_circuit
            .synthesize_sub(&config.bytecode_circuit, challenges, layouter)?;
        self.tx_circuit
            .synthesize_sub(&config.tx_circuit, challenges, layouter)?;
        self.sig_circuit
            .synthesize_sub(&config.sig_circuit, challenges, layouter)?;
        self.state_circuit
            .synthesize_sub(&config.state_circuit, challenges, layouter)?;
        self.copy_circuit
            .synthesize_sub(&config.copy_circuit, challenges, layouter)?;
        self.exp_circuit
            .synthesize_sub(&config.exp_circuit, challenges, layouter)?;
        self.evm_circuit
            .synthesize_sub(&config.evm_circuit, challenges, layouter)?;

        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, challenges, layouter)?;

        self.pi_circuit.connect_export(
            layouter,
            self.state_circuit.exports.borrow().as_ref(),
            self.evm_circuit.exports.borrow().as_ref(),
        )?;

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
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > Circuit<Fr> for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    type Config = (SuperCircuitConfig<Fr>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        (
            SuperCircuitConfig::new(
                meta,
                SuperCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    max_inner_blocks: MAX_INNER_BLOCKS,
                    mock_randomness: MOCK_RANDOMNESS,
                    challenges,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        let block = self.evm_circuit.block.as_ref().unwrap();

        config.tx_table.load(
            &mut layouter,
            &block.txs,
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.chain_id,
            &challenges,
        )?;

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > CircuitExt<Fr>
    for SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
{
    fn num_instance(&self) -> Vec<usize> {
        self.instances().iter().map(|l| l.len()).collect_vec()
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        self.instance()
    }
}

impl<
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
        const MOCK_RANDOMNESS: u64,
    > SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, MOCK_RANDOMNESS>
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
    ) -> Result<(u32, Self, Vec<Vec<Fr>>, CircuitInputBuilder), bus_mapping::Error> {
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
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        let mut block = block_convert(&builder.block, &builder.code_db).unwrap();
        block.randomness = Fr::from(MOCK_RANDOMNESS);
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);
        Self::build_from_witness_block(block)
    }
    /// ..
    pub fn build_from_witness_block(
        block: Block<Fr>,
    ) -> Result<(u32, Self, Vec<Vec<Fr>>), bus_mapping::Error> {
        log::debug!(
            "super circuit build_from_witness_block, circuits_params {:?}",
            block.circuits_params
        );

        let (_, rows_needed) = Self::min_num_rows_block(&block);
        let k = log2_ceil(Self::unusable_rows() + rows_needed);
        log::debug!("super circuit needs k = {}", k);

        let circuit =
            SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA,MAX_INNER_BLOCKS,  MOCK_RANDOMNESS>::new_from_block(&block);

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
}
