//! The EVM circuit implementation.

#![allow(missing_docs)]
use gadgets::bus::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_chip::BusConfig,
    bus_codec::{BusCodecExpr, BusCodecVal},
    bus_lookup::BusLookupChip,
};
use halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    plonk::*,
    poly::Rotation,
};

mod execution;
pub mod param;
pub(crate) mod step;
pub use step::ExecutionState;
pub mod table;
pub(crate) mod util;

#[cfg(any(feature = "test", test))]
pub(crate) mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use self::EvmCircuit as TestEvmCircuit;

pub use crate::witness;
use crate::{
    evm_bus::EVMBusLookups,
    evm_circuit::param::{MAX_STEP_HEIGHT, STEP_STATE_HEIGHT},
    table::{
        BlockTable, BytecodeTable, CopyTable, EccTable, ExpTable, KeccakTable, LookupTable,
        ModExpTable, PowOfRandTable, RwTable, SigTable, TxTable,
    },
    util::{assign_global, query_expression, SubCircuit, SubCircuitConfig},
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use strum::IntoEnumIterator;
use table::{FixedTableTag, Lookup, MsgExpr, MsgF};
use witness::Block;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuitConfig<F> {
    fixed_table: [Column<Fixed>; 4],
    dual_byte_table: [Column<Fixed>; 2],
    bus_lookup: [BusLookupChip<F>; 2],
    enable_bus_lookup: Column<Fixed>,
    pub(crate) execution: Box<ExecutionConfig<F>>,
    // External tables
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    keccak_table: KeccakTable,
    exp_table: ExpTable,
    sig_table: SigTable,
    modexp_table: ModExpTable,
    ecc_table: EccTable,
    pow_of_rand_table: PowOfRandTable,
}

/// Circuit configuration arguments
pub struct EvmCircuitConfigArgs<F: Field> {
    /// Challenge
    pub challenges: crate::util::Challenges<Expression<F>>,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ExpTable
    pub exp_table: ExpTable,
    /// SigTable
    pub sig_table: SigTable,
    /// ModExpTable
    pub modexp_table: ModExpTable,
    /// Ecc Table.
    pub ecc_table: EccTable,
    // Power of Randomness Table.
    pub pow_of_rand_table: PowOfRandTable,
}

/// Circuit exported cells after synthesis, used for subcircuit
#[derive(Clone, Debug)]
pub struct EvmCircuitExports<V> {
    /// withdraw root
    pub withdraw_root: (Cell, Value<V>),
}

// Implement this marker trait. Its method is never called.
impl<F: Field> SubCircuitConfig<F> for EvmCircuitConfig<F> {
    type ConfigArgs = Unreachable;

    #[allow(clippy::too_many_arguments)]
    fn new(_: &mut ConstraintSystem<F>, _: Self::ConfigArgs) -> Self {
        unreachable!()
    }
}

/// This type guarantees that SubCircuitConfig::new() is never called.
pub struct Unreachable {
    _private: (),
}

impl<F: Field> EvmCircuitConfig<F> {
    /// Configure EvmCircuitConfig
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        EvmCircuitConfigArgs {
            challenges,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            sig_table,
            modexp_table,
            ecc_table,
            pow_of_rand_table,
        }: EvmCircuitConfigArgs<F>,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let dual_byte_table = [(); 2].map(|_| meta.fixed_column());
        let enable_bus_lookup = meta.fixed_column(); // TODO: replace with q_usable, or BusConfig.enabled?

        let bus_lookup = Self::configure_bus_lookup(
            meta,
            bus_builder,
            enable_bus_lookup,
            &dual_byte_table,
            &fixed_table,
        );

        let execution = Box::new(ExecutionConfig::configure(
            meta,
            challenges,
            bus_builder,
            &bytecode_table,
            &block_table,
            &copy_table,
            &keccak_table,
            &exp_table,
            &sig_table,
            &modexp_table,
            &ecc_table,
            &pow_of_rand_table,
        ));

        meta.annotate_lookup_any_column(dual_byte_table[0], || "dual_byte_table_0");
        meta.annotate_lookup_any_column(dual_byte_table[1], || "dual_byte_table_1");
        fixed_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_any_column(col, || format!("fix_table_{idx}"))
        });
        bytecode_table.annotate_columns(meta);
        block_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);
        keccak_table.annotate_columns(meta);
        exp_table.annotate_columns(meta);
        sig_table.annotate_columns(meta);
        modexp_table.annotate_columns(meta);
        ecc_table.annotate_columns(meta);
        pow_of_rand_table.annotate_columns(meta);

        Self {
            fixed_table,
            dual_byte_table,
            bus_lookup,
            enable_bus_lookup,
            execution,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            sig_table,
            modexp_table,
            ecc_table,
            pow_of_rand_table,
        }
    }

    fn configure_bus_lookup(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, MsgExpr<F>>,
        enabled: Column<Fixed>,
        dual_byte_table: &[Column<Fixed>; 2],
        fixed_table: &[Column<Fixed>; 4],
    ) -> [BusLookupChip<F>; 2] {
        let enabled = query_expression(meta, |meta| meta.query_fixed(enabled, Rotation::cur()));

        let byte_lookup = {
            let message = query_expression(meta, |meta| {
                MsgExpr::bytes([
                    meta.query_fixed(dual_byte_table[0], Rotation::cur()),
                    meta.query_fixed(dual_byte_table[1], Rotation::cur()),
                ])
            });
            BusLookupChip::connect(meta, bus_builder, enabled.clone(), message)
        };

        let fixed_lookup = {
            let message = query_expression(meta, |meta| {
                MsgExpr::lookup(Lookup::Fixed {
                    tag: meta.query_fixed(fixed_table[0], Rotation::cur()),
                    values: [
                        meta.query_fixed(fixed_table[1], Rotation::cur()),
                        meta.query_fixed(fixed_table[2], Rotation::cur()),
                        meta.query_fixed(fixed_table[3], Rotation::cur()),
                    ],
                })
            });
            BusLookupChip::connect(meta, bus_builder, enabled, message)
        };

        [byte_lookup, fixed_lookup]
    }
}

impl<F: Field> EvmCircuitConfig<F> {
    /// Load fixed table
    fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
        bus_lookup: &BusLookupChip<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }

                    region.assign_fixed(
                        || "",
                        self.enable_bus_lookup,
                        offset,
                        || Value::known(F::one()),
                    )?;

                    bus_lookup.assign(&mut region, bus_assigner, offset, MsgF::fixed(row))?;
                }

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )
    }

    /// Load dual byte table
    fn load_dual_byte_table(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
        bus_lookup: &BusLookupChip<F>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "byte table",
            |mut region| {
                for i in 0..256 {
                    let b0 = F::from(i);
                    for j in 0..256 {
                        let offset = (i * 256 + j) as usize;
                        let b1 = F::from(j);

                        region.assign_fixed(
                            || "",
                            self.enable_bus_lookup,
                            offset,
                            || Value::known(F::one()),
                        )?;

                        region.assign_fixed(
                            || "",
                            self.dual_byte_table[0],
                            offset,
                            || Value::known(b0),
                        )?;
                        region.assign_fixed(
                            || "",
                            self.dual_byte_table[1],
                            offset,
                            || Value::known(b1),
                        )?;

                        bus_lookup.assign(
                            &mut region,
                            bus_assigner,
                            offset,
                            MsgF::bytes([b0, b1]),
                        )?;
                    }
                }

                bus_assigner.finish_ports(&mut region);
                Ok(())
            },
        )
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct EvmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
    pub(crate) exports: std::cell::RefCell<Option<EvmCircuitExports<Assigned<F>>>>,
}

impl<F: Field> EvmCircuit<F> {
    /// Return a new EvmCircuit
    pub fn new(block: Block<F>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags: FixedTableTag::iter().collect(),
            ..Default::default()
        }
    }

    pub fn new_dev(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags,
            ..Default::default()
        }
    }

    /// Calculate which rows are "actually" used in the circuit
    pub fn get_active_rows(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let max_offset = Self::get_num_rows_required(block);
        // some gates are enabled on all rows
        let gates_row_ids = (0..max_offset).collect();
        // lookups are enabled at "q_step" rows and byte lookup rows
        let lookup_row_ids = (0..max_offset).collect();
        (gates_row_ids, lookup_row_ids)
    }

    pub fn get_num_rows_required_no_padding(block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += step.execution_state.get_step_height();
            }
        }
        num_rows += 1; // EndBlock
        num_rows
    }

    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        let evm_rows = block.circuits_params.max_evm_rows;
        if evm_rows == 0 {
            Self::get_min_num_rows_required(block)
        } else {
            // It must have at least one unused row.
            block.circuits_params.max_evm_rows + 1
        }
    }

    pub fn get_min_num_rows_required(block: &Block<F>) -> usize {
        let mut num_rows = 0;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += step.execution_state.get_step_height();
            }
        }

        // It must fit the dual byte table.
        // TODO: Find a way to make this smaller in tests.
        num_rows = num_rows.max(256 * 256);

        // It must have one row for EndBlock and at least one unused one
        num_rows + 2
    }
}

const FIXED_TABLE_ROWS_NO_BITWISE: usize = 3647;
const FIXED_TABLE_ROWS: usize = FIXED_TABLE_ROWS_NO_BITWISE + 3 * 65536;

impl<F: Field> SubCircuit<F> for EvmCircuit<F> {
    type Config = EvmCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // Most columns are queried at MAX_STEP_HEIGHT + STEP_STATE_HEIGHT distinct rotations, so
        // returns (MAX_STEP_HEIGHT + STEP_STATE_HEIGHT + 3) unusable rows.
        MAX_STEP_HEIGHT + STEP_STATE_HEIGHT + 3
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.clone())
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let num_rows_required_for_execution_steps: usize =
            Self::get_num_rows_required_no_padding(block);
        let mut total_rows = num_rows_required_for_execution_steps;
        total_rows = total_rows.max(block.circuits_params.max_evm_rows);

        if total_rows <= FIXED_TABLE_ROWS {
            // for many test cases, there is no need for bitwise table.
            // So using `detect_fixed_table_tags` can greatly improve CI time.
            let num_rows_required_for_fixed_table =
                get_fixed_table_row_num(need_bitwise_lookup(block));
            total_rows = total_rows.max(num_rows_required_for_fixed_table)
        }

        (num_rows_required_for_execution_steps, total_rows)
    }

    // TODO: remove.
    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &crate::util::Challenges<Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        unimplemented!("use synthesize_sub2")
    }
}

impl<F: Field> EvmCircuit<F> {
    /// Make the assignments to the EvmCircuit
    pub fn synthesize_sub2(
        &self,
        config: &EvmCircuitConfig<F>,
        challenges: &crate::util::Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
        bus_assigner: &mut BusAssigner<F, MsgF<F>>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        config.pow_of_rand_table.assign(layouter, challenges)?;

        let export = config
            .execution
            .assign_block(layouter, bus_assigner, block, challenges)?;
        self.exports.borrow_mut().replace(export);

        config.load_dual_byte_table(layouter, bus_assigner, &config.bus_lookup[0])?;

        config.load_fixed_table(
            layouter,
            bus_assigner,
            &config.bus_lookup[1],
            self.fixed_table_tags.clone(),
        )?;

        Ok(())
    }
}

fn get_fixed_table_row_num(need_bitwise_lookup: bool) -> usize {
    if need_bitwise_lookup {
        FIXED_TABLE_ROWS
    } else {
        FIXED_TABLE_ROWS_NO_BITWISE
    }
}

fn need_bitwise_lookup<F: Field>(block: &Block<F>) -> bool {
    block.txs.iter().any(|tx| {
        tx.steps.iter().any(|step| {
            matches!(
                step.opcode,
                Some(OpcodeId::AND)
                    | Some(OpcodeId::OR)
                    | Some(OpcodeId::XOR)
                    | Some(OpcodeId::NOT)
            )
        })
    })
}
/// create fixed_table_tags needed given witness block
pub(crate) fn detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
    if need_bitwise_lookup(block) {
        FixedTableTag::iter().collect()
    } else {
        FixedTableTag::iter()
            .filter(|t| {
                !matches!(
                    t,
                    FixedTableTag::BitwiseAnd
                        | FixedTableTag::BitwiseOr
                        | FixedTableTag::BitwiseXor
                )
            })
            .collect()
    }
}

#[cfg(all(feature = "disabled", test))]
pub(crate) mod cached {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;
    use lazy_static::lazy_static;

    struct Cache {
        cs: ConstraintSystem<Fr>,
        config: (EvmCircuitConfig<Fr>, Challenges),
    }

    lazy_static! {
        /// Cached values of the ConstraintSystem after the EVM Circuit configuration and the EVM
        /// Circuit configuration.  These values are calculated just once.
        static ref CACHE: Cache = {
            let mut meta = ConstraintSystem::<Fr>::default();
            let config = EvmCircuit::<Fr>::configure(&mut meta);
            Cache { cs: meta, config }
        };
    }

    /// Wrapper over the EvmCircuit that behaves the same way and also
    /// implements the halo2 Circuit trait, but reuses the precalculated
    /// results of the configuration which are cached in the public variable
    /// `CACHE`.  This wrapper is useful for testing because it allows running
    /// many unit tests while reusing the configuration step of the circuit.
    pub struct EvmCircuitCached(EvmCircuit<Fr>);

    impl Circuit<Fr> for EvmCircuitCached {
        type Config = (EvmCircuitConfig<Fr>, Challenges);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self(self.0.without_witnesses())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            *meta = CACHE.cs.clone();
            CACHE.config.clone()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            self.0.synthesize(config, layouter)
        }
    }

    impl EvmCircuitCached {
        pub fn get_test_cicuit_from_block(block: Block<Fr>) -> Self {
            Self(EvmCircuit::<Fr>::get_test_cicuit_from_block(block))
        }
    }
}

// Always exported because of `EXECUTION_STATE_HEIGHT_MAP`

#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
#[cfg(feature = "onephase")]
use crate::util::MockChallenges as Challenges;

impl<F: Field> Circuit<F> for EvmCircuit<F> {
    type Config = (
        EvmCircuitConfig<F>,
        BusConfig,
        EVMBusLookups<F>,
        Challenges,
        RwTable,
        TxTable,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenges_expr = challenges.exprs(meta);
        let mut bus_builder = BusBuilder::new(BusCodecExpr::new(challenges_expr.lookup_input()));
        let rw_table = RwTable::construct(meta);
        rw_table.annotate_columns(meta);
        let tx_table = TxTable::construct(meta);
        tx_table.annotate_columns(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let q_copy_table = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_copy_table);
        let keccak_table = KeccakTable::construct(meta);
        let exp_table = ExpTable::construct(meta);
        let sig_table = SigTable::construct(meta);
        let modexp_table = ModExpTable::construct(meta);
        let ecc_table = EccTable::construct(meta);
        let pow_of_rand_table = PowOfRandTable::construct(meta, &challenges_expr);
        let config = EvmCircuitConfig::new(
            meta,
            &mut bus_builder,
            EvmCircuitConfigArgs {
                challenges: challenges_expr,
                bytecode_table,
                block_table,
                copy_table,
                keccak_table,
                exp_table,
                sig_table,
                modexp_table,
                ecc_table,
                pow_of_rand_table,
            },
        );
        let evm_lookups = EVMBusLookups::configure(meta, &mut bus_builder, &rw_table, &tx_table);
        let bus = BusConfig::new(meta, &bus_builder.build());
        (config, bus, evm_lookups, challenges, rw_table, tx_table)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();
        let num_rows = Self::get_num_rows_required(block);

        let (config, bus, evm_lookups, challenges, rw_table, tx_table) = config;
        let challenges = challenges.values(&layouter);

        let mut bus_assigner =
            BusAssigner::new(BusCodecVal::new(challenges.lookup_input()), num_rows);

        let mut tx_messages = vec![];
        tx_table.load(
            &mut layouter,
            |offset, message| tx_messages.push((offset, message)),
            &block.txs,
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.chain_id,
            &challenges,
        )?;

        let mut rw_messages = vec![];
        block.rws.check_rw_counter_sanity();
        rw_table.load(
            &mut layouter,
            |offset, message| rw_messages.push((offset, message)),
            &block.rws.table_assignments(),
            block.circuits_params.max_rws,
            challenges.evm_word(),
        )?;

        config
            .bytecode_table
            .dev_load(&mut layouter, block.bytecodes.values(), &challenges)?;
        config
            .block_table
            .dev_load(&mut layouter, &block.context, &block.txs, &challenges)?;
        config
            .copy_table
            .dev_load(&mut layouter, block, &challenges)?;
        config
            .keccak_table
            .dev_load(&mut layouter, &block.sha3_inputs, &challenges)?;
        config.exp_table.dev_load(&mut layouter, block)?;
        config
            .sig_table
            .dev_load(&mut layouter, block, &challenges)?;
        config
            .modexp_table
            .dev_load(&mut layouter, &block.get_big_modexp())?;
        config.ecc_table.dev_load(
            &mut layouter,
            block.circuits_params.max_ec_ops,
            &block.get_ec_add_ops(),
            &block.get_ec_mul_ops(),
            &block.get_ec_pairing_ops(),
            &challenges,
        )?;

        self.synthesize_sub2(&config, &challenges, &mut layouter, &mut bus_assigner)?;

        evm_lookups.assign(&mut layouter, &mut bus_assigner, rw_messages, tx_messages)?;

        if !bus_assigner.op_counter().is_complete() {
            log::warn!("Incomplete bus assignment.");
            log::debug!("Missing bus ops: {:?}", bus_assigner.op_counter());
        }
        bus.finish_assigner(&mut layouter, bus_assigner)?;

        Ok(())
    }
}

#[cfg(test)]
mod evm_circuit_stats {
    use crate::{
        evm_circuit::{
            param::{
                LOOKUP_CONFIG, N_BYTE_LOOKUPS, N_COPY_COLUMNS, N_PHASE1_COLUMNS, N_PHASE2_COLUMNS,
                N_PHASE2_COPY_COLUMNS, N_PHASE3_COLUMNS,
            },
            step::ExecutionState,
            table::FixedTableTag,
            EvmCircuit, FIXED_TABLE_ROWS, FIXED_TABLE_ROWS_NO_BITWISE,
        },
        stats::print_circuit_stats_by_states,
        test_util::CircuitTestBuilder,
        util::{unusable_rows, SubCircuit},
        witness::block_convert,
    };
    use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
    use cli_table::{print_stdout, Cell, Style, Table};
    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, ToWord};
    use halo2_proofs::{
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, ConstraintSystem},
    };
    use itertools::Itertools;
    use mock::{
        test_ctx::{
            helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
            TestContext,
        },
        MOCK_ACCOUNTS,
    };
    use strum::IntoEnumIterator;

    #[test]
    fn test_fixed_table_rows() {
        let row_num_by_tags = |tags: Vec<FixedTableTag>| -> usize {
            tags.iter()
                .map(|tag| {
                    let count = tag.build::<Fr>().count();
                    log::debug!("fixed tab {tag:?} needs {count} rows");
                    count
                })
                .sum::<usize>()
        };
        assert_eq!(
            FIXED_TABLE_ROWS,
            row_num_by_tags(FixedTableTag::iter().collect_vec())
        );
        assert_eq!(
            FIXED_TABLE_ROWS_NO_BITWISE,
            row_num_by_tags(
                FixedTableTag::iter()
                    .filter(|t| {
                        !matches!(
                            t,
                            FixedTableTag::BitwiseAnd
                                | FixedTableTag::BitwiseOr
                                | FixedTableTag::BitwiseXor
                        )
                    })
                    .collect_vec()
            )
        );
    }

    #[test]
    fn evm_circuit_unusable_rows() {
        assert_eq!(
            EvmCircuit::<Fr>::unusable_rows(),
            unusable_rows::<Fr, EvmCircuit::<Fr>>(),
        )
    }

    #[test]
    pub fn empty_evm_circuit_no_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b).unwrap(),
        )
        .run();
    }

    #[test]
    pub fn empty_evm_circuit_with_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b).unwrap(),
        )
        .block_modifier(Box::new(|block| {
            block.circuits_params.max_evm_rows = (1 << 18) - 100
        }))
        .run();
    }

    /// Prints the stats of EVM circuit per execution state.  See
    /// `print_circuit_stats_by_states` for more details.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release --all-features
    /// get_evm_states_stats -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_evm_states_stats() {
        print_circuit_stats_by_states(
            |state| {
                !matches!(
                    state,
                    ExecutionState::ErrorInvalidOpcode | ExecutionState::SELFDESTRUCT
                )
            },
            |opcode| match opcode {
                OpcodeId::RETURNDATACOPY => {
                    bytecode! {
                    PUSH1(0x00) // retLength
                    PUSH1(0x00) // retOffset
                    PUSH1(0x00) // argsLength
                    PUSH1(0x00) // argsOffset
                    PUSH1(0x00) // value
                    PUSH32(MOCK_ACCOUNTS[3].to_word())
                    PUSH32(0x1_0000) // gas
                    CALL
                    PUSH2(0x01) // size
                    PUSH2(0x00) // offset
                    PUSH2(0x00) // destOffset
                    }
                }
                _ => bytecode! {
                    PUSH2(0x40)
                    PUSH2(0x50)
                },
            },
            |_, state, _| state.get_step_height_option().unwrap(),
        );
    }

    /// This function prints to stdout a table with the top X ExecutionState
    /// cell consumers of each EVM Cell type.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release get_exec_steps_occupancy
    /// --features test -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_exec_steps_occupancy() {
        let mut meta = ConstraintSystem::<Fr>::default();
        let circuit = EvmCircuit::configure(&mut meta);

        let report = circuit.0.execution.instrument().clone().analyze();
        macro_rules! gen_report {
            ($report:expr, $($id:ident, $cols:expr), +) => {
                $(
                let row_report = report
                    .iter()
                    .sorted_by(|a, b| a.$id.utilization.partial_cmp(&b.$id.utilization).unwrap())
                    .rev()
                    .take(10)
                    .map(|exec| {
                        vec![
                            format!("{:?}", exec.state),
                            format!("{:?}", exec.$id.available_cells),
                            format!("{:?}", exec.$id.unused_cells),
                            format!("{:?}", exec.$id.used_cells),
                            format!("{:?}", exec.$id.top_height),
                            format!("{:?}", exec.$id.used_columns),
                            format!("{:?}", exec.$id.utilization),
                        ]
                    })
                    .collect::<Vec<Vec<String>>>();

                let table = row_report.table().title(vec![
                    format!("{:?}", stringify!($id)).cell().bold(true),
                    format!("total_available_cells").cell().bold(true),
                    format!("unused_cells").cell().bold(true),
                    format!("cells").cell().bold(true),
                    format!("top_height").cell().bold(true),
                    format!("used columns (Max: {:?})", $cols).cell().bold(true),
                    format!("Utilization").cell().bold(true),
                ]);
                print_stdout(table).unwrap();
                )*
            };
        }

        gen_report!(
            report,
            storage_1,
            N_PHASE1_COLUMNS,
            storage_2,
            N_PHASE2_COLUMNS,
            storage_3,
            N_PHASE3_COLUMNS,
            storage_perm,
            N_COPY_COLUMNS,
            storage_perm_2,
            N_PHASE2_COPY_COLUMNS,
            byte_lookup,
            N_BYTE_LOOKUPS,
            fixed_table,
            LOOKUP_CONFIG[0].1,
            tx_table,
            LOOKUP_CONFIG[1].1,
            rw_table,
            LOOKUP_CONFIG[2].1,
            bytecode_table,
            LOOKUP_CONFIG[3].1,
            block_table,
            LOOKUP_CONFIG[4].1,
            copy_table,
            LOOKUP_CONFIG[5].1,
            keccak_table,
            LOOKUP_CONFIG[6].1,
            exp_table,
            LOOKUP_CONFIG[7].1,
            sig_table,
            LOOKUP_CONFIG[8].1,
            ecc_table,
            LOOKUP_CONFIG[9].1,
            pow_of_rand_table,
            LOOKUP_CONFIG[10].1
        );
    }

    #[ignore = "need to make table dev_load padding to fix this"]
    #[test]
    fn variadic_size_check() {
        let params = CircuitsParams {
            max_evm_rows: 1 << 12,
            max_keccak_rows: 1 << 12,
            max_bytecode: 1 << 12,
            ..Default::default()
        };
        // Empty
        let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
            .unwrap()
            .into();
        let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), params)
            .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let k = block.get_evm_test_circuit_degree();

        let circuit = EvmCircuit::<Fr>::get_test_cicuit_from_block(block);
        let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        let code = bytecode! {
            STOP
        };
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |b, _| b,
        )
        .unwrap()
        .into();
        let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), params)
            .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let k = block.get_evm_test_circuit_degree();
        let circuit = EvmCircuit::<Fr>::get_test_cicuit_from_block(block);
        let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover1.fixed(), prover2.fixed());
        assert_eq!(prover1.permutation(), prover2.permutation());
    }
}
