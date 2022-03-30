use super::cells::Cells;
use super::constraint_builder::ConstraintBuilder;
use super::param::N_LIMBS_ACCOUNT_ADDRESS;
use crate::state_circuit::constraint_builder::sort_key_values;
use crate::state_circuit::fixed_table::FixedTable;
use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        table::RwTableTag,
        util::{constraint_builder::BaseConstraintBuilder, RandomLinearCombination},
        witness::{Rw, RwMap, RwRow},
    },
    gadget::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
    util::Expr,
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;
use strum::IntoEnumIterator;

/*
(FIXME) Example state table:

|            |          |       |    keys(4)  |key2_limbs(8)|   key4_bytes(32)   |                |
| rw_counter | is_write | value | tag  | ...  | ...  | ...  |      |      |      |  storage_key   |
-------------------------------------------------------------------------------------------------------
|     0      |     1    |  0    |  1   |      |      |      |      |      |      |                |   // init row (write value 0)
|     12     |     1    |  12   |  2   |      |      |      |      |      |      |                |
|     24     |     0    |  12   |  2   |      |      |      |      |      |      |                |
|     0      |     1    |  0    |  2   |      |      |      |      |      |      |                |   // init row (write value 0)
|     2      |     0    |  12   |  2   |      |      |      |      |      |      |                |
|     3      |     1    |  4    |  3   |      |      |      |      |      |      |                |
|     17     |     1    |  32   |  3   |      |      |      |      |      |      |                |
|     89     |     0    |  32   |  3   |      |      |      |      |      |      |                |
|     48     |     1    |  32   |  3   |      |      |      |      |      |      |                |
|     49     |     0    |  32   |  3   |      |      |      |      |      |      |                |
|     55     |     1    |  32   |  4   |      |      |      |      |      |      |         5      |   // first storage op at the new address has to be write
|     56     |     1    |  33   |  4   |      |      |      |  <RLC storageKey>  |         8      |
*/

// tag:
// 1 - first row of either target (Note: only the first row, not all init rows)
// 2 - memory
// 3 - stack
// 4 - storage

const MEMORY_TAG: usize = RwTableTag::Memory as usize;
const STACK_TAG: usize = RwTableTag::Stack as usize;
const STORAGE_TAG: usize = RwTableTag::AccountStorage as usize;

const MAX_DEGREE: usize = 15;

#[derive(Clone, Debug)]
pub struct Config<
    F: FieldExt,
    // When SANITY_CHECK is true, max_address/rw_counter/stack_address are
    // required to be in the range of
    // MEMORY_ADDRESS_MAX/RW_COUNTER_MAX/STACK_ADDRESS_MAX during circuit
    // synthesis
    const SANITY_CHECK: bool,
    const RW_COUNTER_MAX: usize,
    const MEMORY_ADDRESS_MAX: usize,
    const STACK_ADDRESS_MAX: usize,
    const ROWS_MAX: usize,
> {
    s_enable: Column<Fixed>,
    // rw_counter: Column<Advice>,
    keys: [Column<Advice>; 5],

    key2_limbs: [Column<Advice>; N_LIMBS_ACCOUNT_ADDRESS],
    // Use WordConfig here instead.
    key4_bytes: [Column<Advice>; N_BYTES_WORD],

    auxs: Column<Advice>,

    power_of_randomness: [Expression<F>; N_BYTES_WORD - 1],

    lexicographic_ordering: [IsZeroConfig<F>; 2],

    // Fixed columns for range lookups
    fixed_table: FixedTable,

    cells: Cells<F>,
}

impl<
        F: Field,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const ROWS_MAX: usize,
    > Config<F, SANITY_CHECK, RW_COUNTER_MAX, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX, ROWS_MAX>
{
    /// Set up custom gates and lookup arguments for this configuration.
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; 31],
    ) -> Self {
        let cells = Cells::new(meta, power_of_randomness.clone());

        let fixed_table = FixedTable::configure(meta);

        // let rw_counter = meta.advice_column();
        let keys = [(); 5].map(|_| meta.advice_column());
        let key2_limbs = [(); N_LIMBS_ACCOUNT_ADDRESS].map(|_| meta.advice_column());
        let key4_bytes = [(); N_BYTES_WORD].map(|_| meta.advice_column());
        let auxs = meta.advice_column();

        let s_enable = meta.fixed_column();

        let new_cb = || BaseConstraintBuilder::<F>::new(MAX_DEGREE);
        let qb = ConstraintBuilder::<F>::new(
            meta,
            keys,
            key2_limbs,
            s_enable,
            key4_bytes,
            power_of_randomness.clone(), /* TODO: these don't both of these need
                                          * power_of_randomness */
                                         /* rw_counter, */
        );

        let lexicographic_ordering =
            [(0, meta.advice_column()), (1, meta.advice_column())].map(|(i, advice_column)| {
                IsZeroChip::configure(
                    meta,
                    |meta| qb.s_enable(meta),
                    |meta| qb.sort_keys_delta(meta)[i].clone(),
                    advice_column,
                )
            });

        let q_all_keys_same = |_: &mut VirtualCells<F>| {
            lexicographic_ordering[0].is_zero_expression.clone()
                * lexicographic_ordering[1].is_zero_expression.clone()
        };
        let q_not_all_keys_same = |meta: &mut VirtualCells<F>| 1u64.expr() - q_all_keys_same(meta);

        ///////////////////////// General constraints /////////////////////////////////

        meta.create_gate("General constraints", |meta| {
            let mut cb = new_cb();

            // 0. tag in RwTableTag range
            // TODO: check key1 and key3 ranges.
            cb.require_in_set(
                "tag in RwTableTag range",
                qb.tag(meta),
                RwTableTag::iter().map(|x| x.expr()).collect(),
            );

            // 1. key2 expands to its limbs
            cb.require_equal(
                "account address matches its limbs",
                qb.address(meta),
                qb.address_limbs(meta)
                    .iter()
                    .fold(0u64.expr(), |result, limb| {
                        limb.clone() + result * (1u64 << 16).expr()
                    }),
                // qb.address_from_limbs(meta),
            );

            // 2. key4 is RLC encoded
            cb.require_equal(
                "storage key matches its RLC encoding",
                qb.storage_key(meta),
                RandomLinearCombination::random_linear_combine_expr(
                    qb.storage_key_bytes(meta),
                    qb.power_of_randomness(meta),
                ),
            );

            // 3. is_write is boolean
            cb.require_boolean("is_write should be boolean", cells.is_write());

            // 4. Keys are sorted in lexicographic order for same Tag
            // see lexicographic_ordering chips

            // 5. RWC is monotonically strictly increasing for a set of all keys
            // see below

            // 6. Read consistency
            // When a row is READ AND When all the keys are equal in two consecutive a rows:
            //- The corresponding value must be equal to the previous row
            cb.require_zero(
                "if read and keys are same, value should be same with prev",
                q_all_keys_same(meta) * cells.is_read() * (cells.value_delta()),
            );

            cb.gate(qb.s_enable(meta))
        });

        // TODO: move this into constraint builder
        for i in 0..N_LIMBS_ACCOUNT_ADDRESS {
            meta.lookup_any("address limbs fit into u16", |meta| {
                vec![(
                    qb.s_enable(meta) * qb.address_limbs(meta)[i].clone(),
                    fixed_table.u16(meta),
                )]
            });
        }

        // Check that storage key bytes are between 0 and 255.
        // TODO: move this into constraint builder
        for i in 0..N_BYTES_WORD {
            meta.lookup_any("storage key byte is between 0 and 255", |meta| {
                vec![(
                    qb.s_enable(meta) * qb.storage_key_bytes(meta)[i].clone(),
                    fixed_table.u8(meta),
                )]
            });
        }

        // 5. RWC is monotonically strictly increasing for a set of all keys
        //
        // When tag is not Start and all the keys are equal in two consecutive a rows:
        // - The corresponding rwc must be strictly increasing.
        // TODO: rewrite using range check gates rather than lookup
        meta.lookup_any("rw counter monotonicity", |meta| {
            vec![(
                qb.s_enable(meta)
                    * q_all_keys_same(meta)
                    * (cells.rw_counter_delta() - 1u64.expr()),
                // TODO(mason) this isn't correct. The specs say this should be u32....
                fixed_table.u10(meta),
            )]
        });

        ///////////////////////// Memory related constraints /////////////////////////

        meta.create_gate("Memory operation", |meta| {
            let mut cb = new_cb();

            // 0. Unused keys are 0
            cb.require_zero("field tag is 0", qb.field_tag(meta));
            cb.require_zero("storage key is 0", qb.storage_key(meta));

            // 1. First access for a set of all keys
            //
            // When the set of all keys changes (first access of an address in a call)
            // - If READ, value must be 0
            cb.require_zero(
                "if address changes, read value should be 0",
                q_not_all_keys_same(meta) * cells.is_read() * cells.value(),
            );

            cb.gate(qb.s_enable(meta) * qb.tag_is(meta, RwTableTag::Memory))
        });

        // 2. value is a byte when tag is Memory
        meta.lookup_any("value is a byte when tag is Memory", |meta| {
            vec![(
                qb.tag_is(meta, RwTableTag::Memory) * cells.value(),
                fixed_table.u8(meta),
            )]
        });

        ///////////////////////// Stack related constraints /////////////////////////

        meta.create_gate("Stack operation", |meta| {
            let mut cb = new_cb();

            // 0. Unused keys are 0
            cb.require_zero("field tag is 0", qb.field_tag(meta));
            cb.require_zero("storage key is 0", qb.storage_key(meta));

            // 1. First access for a set of all keys
            //
            // The first stack operation in a stack position is always a write (can't
            // read if it isn't written before)
            //
            // When the set of all keys changes (first access of a stack position in a call)
            // - It must be a WRITE
            cb.require_zero(
                "if address changes, operation is always a write",
                q_not_all_keys_same(meta) * cells.is_read(),
            );
            cb.gate(qb.s_enable(meta) * qb.tag_is(meta, RwTableTag::Stack))
        });

        // 2. stack_ptr in range
        meta.lookup_any("Stack address in allowed range", |meta| {
            vec![(
                qb.tag_is(meta, RwTableTag::Stack) * qb.address(meta),
                // todo: this should be u32, so we need to add two rw limb columns.
                fixed_table.u10(meta),
            )]
        });

        // 3. stack_ptr only increases by 0 or 1
        meta.create_gate("Within a call, Stack pointer diff be 0 or 1", |meta| {
            let mut cb = new_cb();
            cb.require_boolean(
                "stack pointer only increases by 0 or 1",
                qb.address_delta(meta),
            );
            cb.gate(qb.s_enable(meta) * q_all_keys_same(meta) * qb.tag_is(meta, RwTableTag::Stack))
        });

        ///////////////////////// Storage related constraints /////////////////////////

        meta.create_gate("Storage Operation", |meta| {
            let mut cb = new_cb();
            // TODO: cold VS warm
            // TODO: connection to MPT on first and last access for each (address, key)

            // 0. Unused keys are 0
            // cb.require_zero("key1 is 0", qb.id(meta)); // moved from aux to key1
            cb.require_zero("key3 is 0", qb.field_tag(meta));

            // 1. First access for a set of all keys
            //
            // We add an extra write to set the value of the state in previous block, with
            // rwc=0.
            //
            // When the set of all keys changes (first access of storage (address, key))
            // - It must be a WRITE
            cb.require_zero(
                "First access for storage is write",
                q_not_all_keys_same(meta) * cells.is_read(),
            );
            cb.require_zero(
                "First access for storage has rw_counter as 0",
                q_not_all_keys_same(meta) * cells.rw_counter(),
            );

            cb.gate(qb.s_enable(meta) * qb.tag_is(meta, RwTableTag::AccountStorage))
        });

        Config {
            keys,
            key2_limbs,
            key4_bytes,
            auxs,
            s_enable,
            fixed_table,
            power_of_randomness,
            lexicographic_ordering,
            cells,
        }
    }

    /// Assign cells.
    pub(crate) fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        randomness: F,
        rw_map: &RwMap,
    ) -> Result<(), Error> {
        let sort_key_chips = self
            .lexicographic_ordering
            .clone()
            .map(|config| IsZeroChip::construct(config));

        layouter.assign_region(
            || "State operations",
            |mut region| {
                let mut offset = 1;
                let mut rows: Vec<(Rw, RwRow<F>)> = rw_map
                    .0
                    .values()
                    .flatten()
                    .map(|row| (row.clone(), row.table_assignment(randomness)))
                    .collect();
                rows.sort_by_key(|(_, rw)| {
                    (rw.tag, rw.key1, rw.key2, rw.key3, rw.key4, rw.rw_counter)
                });

                if rows.len() >= ROWS_MAX {
                    panic!("too many storage operations");
                }
                for (index, (rw, rw_row)) in rows.iter().enumerate() {
                    self.assign_row(&mut region, offset, *rw_row)?;

                    if let Some(address) = rw.address() {
                        self.assign_address_and_limbs(&mut region, offset, address)?;
                    }

                    if let Some(storage_key) = rw.storage_key() {
                        self.assign_storage_key_and_bytes(
                            &mut region,
                            offset,
                            randomness,
                            storage_key,
                        )?;
                    }

                    let (sort_key_0, sort_key_1): (F, F) = sort_key_values(
                        rw.tag(),
                        rw.id().unwrap_or_default().try_into().unwrap(),
                        rw.address().unwrap_or_default(),
                        rw.field_tag().unwrap_or_default(),
                        rw.storage_key().unwrap_or_default().to_le_bytes(),
                    );

                    let mut sort_key_prev_0 = F::zero();
                    let mut sort_key_prev_1 = F::zero();
                    if index != 0 {
                        let rw_prev = rows[index - 1].0.clone();

                        let (a, b) = sort_key_values(
                            rw_prev.tag(),
                            rw_prev.id().unwrap_or_default().try_into().unwrap(),
                            rw_prev.address().unwrap_or_default(),
                            rw_prev.field_tag().unwrap_or_default(),
                            rw_prev.storage_key().unwrap_or_default().to_le_bytes(),
                        );

                        sort_key_prev_0 = a;
                        sort_key_prev_1 = b;
                    }

                    sort_key_chips[0].assign(
                        &mut region,
                        offset,
                        Some(sort_key_0 - sort_key_prev_0),
                    )?;
                    sort_key_chips[1].assign(
                        &mut region,
                        offset,
                        Some(sort_key_1 - sort_key_prev_1),
                    )?;

                    offset += 1;
                }

                Ok(())
            },
        )
    }

    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: RwRow<F>,
    ) -> Result<(), Error> {
        let memory_or_stack_address = row.key3;
        let rw_counter = row.rw_counter;
        let value = row.value;
        let is_write = row.is_write;

        // check witness sanity
        if offset > ROWS_MAX {
            panic!("too many storage operations");
        }
        if SANITY_CHECK {
            if rw_counter > F::from(RW_COUNTER_MAX as u64) {
                panic!("rw_counter out of range");
            }
            if row.tag == F::from(STACK_TAG as u64)
                && memory_or_stack_address > F::from(STACK_ADDRESS_MAX as u64)
            {
                panic!(
                    "stack address out of range {:?} > {}",
                    memory_or_stack_address, STACK_ADDRESS_MAX
                );
            }
            if row.tag == F::from(MEMORY_TAG as u64)
                && memory_or_stack_address > F::from(MEMORY_ADDRESS_MAX as u64)
            {
                panic!(
                    "memory address out of range {:?} > {}",
                    memory_or_stack_address, MEMORY_ADDRESS_MAX
                );
            }
        }
        region.assign_fixed(|| "enable row", self.s_enable, offset, || Ok(F::one()))?;
        self.cells
            .rw_counter
            .assign(region, offset, Some(rw_counter))?;
        self.cells.value.assign(region, offset, Some(value))?;
        self.cells.is_write.assign(region, offset, Some(is_write))?;

        for i in 0..5 {
            let value = match i {
                // FIXME: find a better way here
                0 => row.tag,
                1 => row.key1,
                2 => row.key2,
                3 => row.key3,
                4 => row.key4,
                _ => unreachable!(),
            };
            region.assign_advice(
                || format!("assign key{}", i),
                self.keys[i],
                offset,
                || Ok(value),
            )?;
        }

        Ok(())
    }

    fn assign_address_and_limbs(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: Address,
    ) -> Result<(), Error> {
        let limbs = address
            .0
            .iter()
            .tuples()
            .map(|(hi, lo)| u16::from_le_bytes([*lo, *hi]));
        for (limb, col) in limbs.zip(&self.key2_limbs) {
            region.assign_advice(|| "key2_limb", *col, offset, || Ok(F::from(limb.into())))?;
        }

        region.assign_advice(
            || "key2 (address)",
            self.keys[2],
            offset,
            || Ok(address.to_scalar().unwrap()),
        )?;

        Ok(())
    }

    fn assign_storage_key_and_bytes(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        randomness: F,
        key: Word,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "key4 (storage_key)",
            self.keys[4],
            offset,
            || {
                Ok(RandomLinearCombination::random_linear_combine(
                    key.to_le_bytes(),
                    randomness,
                ))
            },
        )?;

        // TODO: use array_zip if/when it stabilizes.
        for (col, byte) in self.key4_bytes.iter().zip(&key.to_le_bytes()) {
            region.assign_advice(
                || "storage key byte",
                *col,
                offset,
                || Ok(F::from(*byte as u64)),
            )?;
        }

        Ok(())
    }
}

/// State Circuit struct.
#[derive(Default)]
pub struct StateCircuit<
    F: FieldExt,
    const SANITY_CHECK: bool,
    const RW_COUNTER_MAX: usize,
    const MEMORY_ADDRESS_MAX: usize,
    const STACK_ADDRESS_MAX: usize,
    const ROWS_MAX: usize,
> {
    /// randomness used in linear combination
    pub randomness: F,
    /// witness for rw map
    pub rw_map: RwMap,
    // pub operations: OperationContainer,
}

impl<
        F: FieldExt,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const ROWS_MAX: usize,
    >
    StateCircuit<F, SANITY_CHECK, RW_COUNTER_MAX, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX, ROWS_MAX>
{
    /// Use rw_map to build a StateCircuit instance
    pub fn new(randomness: F, rw_map: &RwMap) -> Self {
        Self {
            randomness,
            rw_map: rw_map.clone(),
            // operations,
        }
    }
}

impl<
        F: Field,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const ROWS_MAX: usize,
    > Circuit<F>
    for StateCircuit<
        F,
        SANITY_CHECK,
        RW_COUNTER_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ADDRESS_MAX,
        ROWS_MAX,
    >
{
    type Config =
        Config<F, SANITY_CHECK, RW_COUNTER_MAX, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX, ROWS_MAX>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let power_of_randomness = {
            let columns = [(); 31].map(|_| meta.instance_column());
            let mut power_of_randomness = None;

            meta.create_gate("", |meta| {
                power_of_randomness =
                    Some(columns.map(|column| meta.query_instance(column, Rotation::cur())));

                [0.expr()]
            });

            power_of_randomness.unwrap()
        };

        Config::configure(meta, power_of_randomness)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.fixed_table.load(&mut layouter)?;
        config.assign(layouter, self.randomness, &self.rw_map)?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bus_mapping::operation::{
        MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
    };
    use eth_types::evm_types::{MemoryAddress, StackAddress};
    use eth_types::{address, bytecode, ToAddress, Word, U256};
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::dev::MockProver;
    use pairing::bn256::Fr;

    macro_rules! test_state_circuit_ok {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr, $result:expr) => {{
            let rw_map = RwMap::from(&OperationContainer {
                memory: $memory_ops,
                stack: $stack_ops,
                storage: $storage_ops,
                ..Default::default()
            });
            let circuit = StateCircuit::<
                Fr,
                true,
                $rw_counter_max,
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
            >::new(Fr::rand(), &rw_map);

            let power_of_randomness: Vec<_> = (1..32)
                .map(|exp| {
                    vec![
                        circuit.randomness.pow(&[exp, 0, 0, 0]);
                        { $memory_rows_max + $stack_rows_max + $storage_rows_max } // I think this is the max offset?
                    ]
                })
                .collect();

            let prover = MockProver::<Fr>::run($k, &circuit, power_of_randomness).unwrap();
            let verify_result = prover.verify();
            assert!(verify_result.is_ok(), "verify err: {:#?}", verify_result);
        }};
    }

    macro_rules! test_state_circuit_error {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr) => {{
            let rw_map = RwMap::from(&OperationContainer {
                memory: $memory_ops,
                stack: $stack_ops,
                storage: $storage_ops,
                ..Default::default()
            });
            let circuit = StateCircuit::<
                Fr,
                false,
                $rw_counter_max,
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
            >::new(Fr::rand(), &rw_map);

            let power_of_randomness: Vec<_> = (1..32)
                .map(|exp| {
                    vec![
                        circuit.randomness.pow(&[exp, 0, 0, 0]);
                        { $memory_rows_max + $stack_rows_max + $storage_rows_max } // I think this is the max offset?
                    ]
                })
                .collect();

            let prover = MockProver::<Fr>::run($k, &circuit, power_of_randomness).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn state_circuit_simple() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(0),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );

        test_state_circuit_ok!(
            17,
            2000,
            100,
            2,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![storage_op_0, storage_op_1, storage_op_2],
            Ok(())
        );
    }

    #[test]
    fn no_stack_padding() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );

        const STACK_ROWS_MAX: usize = 2;
        test_state_circuit_ok!(
            17,
            2000,
            100,
            STACK_ROWS_MAX,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![],
            Ok(())
        );
    }

    #[test]
    fn same_address_read() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 31),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(
                1,
                MemoryAddress::from(0),
                32,
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(19),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(28),
            RW::READ,
            StackOp::new(
                1,
                StackAddress::from(0),
                Word::from(13),
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        const MEMORY_ROWS_MAX: usize = 7;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn first_write() {
        let stack_op_0 = Operation::new(
            RWCounter::from(28),
            RW::READ,
            StackOp::new(1, StackAddress::from(0), Word::from(13)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(17),
            RW::READ,
            StorageOp::new(
                /* Fails because the first storage op needs to be
                 * write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            RW::READ,
            StorageOp::new(
                /* Fails because when storage key changes, the op
                 * needs to be write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            RW::READ,
            StorageOp::new(
                /* Fails because when address changes, the op
                 * needs to be write. */
                address!("0x0000000000000000000000000000000000000003"),
                Word::from(0x40),
                /* Intentionally different storage key as the last one in the previous ops to
                have two conditions met. */
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![stack_op_0],
            vec![storage_op_0, storage_op_1, storage_op_2]
        );
    }

    #[test]
    fn max_values() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_2 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );

        let memory_op_3 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX + 1), 32),
        );
        let memory_op_4 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX + 1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX), Word::from(12)),
        );

        let stack_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );
        let stack_op_3 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 7;
        const STACK_ROWS_MAX: usize = 7;
        const STORAGE_ROWS_MAX: usize = 7;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            18,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![
                memory_op_0,
                memory_op_1,
                memory_op_2,
                memory_op_3,
                memory_op_4
            ],
            vec![stack_op_0, stack_op_1, stack_op_2, stack_op_3],
            vec![]
        );
    }

    #[test]
    fn max_values_first_row() {
        // first row of a target needs to be checked for address to be in range
        // too
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(
                1,
                MemoryAddress::from(MEMORY_ADDRESS_MAX + 1),
                // This address is not in the allowed range
                32,
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 2;
        const STACK_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            18,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![memory_op_0],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn non_monotone_rw_counter() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        // fails because it needs to be strictly monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(217),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(217),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(301),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(302),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(302),
            RW::READ,
            StorageOp::new(
                /*fails because the address and
                 * storage key are the same as in
                 * the previous row */
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(297),
            RW::WRITE,
            StorageOp::new(
                // Global counter goes down, but it doesn't fail because
                // the storage key is not the same as in the previous row.
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x41),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );

        let storage_op_4 = Operation::new(
            RWCounter::from(296),
            RW::WRITE,
            StorageOp::new(
                // Global counter goes down, but it doesn't fail because the
                // address is not the same as in the previous row (while the
                // storage key is).
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 100;
        const STACK_ROWS_MAX: usize = 100;
        test_state_circuit_error!(
            17,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            STACK_ROWS_MAX,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![
                storage_op_0,
                storage_op_1,
                storage_op_2,
                storage_op_3,
                storage_op_4
            ]
        );
    }

    #[ignore = "disabled temporarily since we sort rws inside the assign method. FIXME later"]
    #[test]
    fn non_monotone_address() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        // fails because it's not monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(229),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(230),
            RW::WRITE,
            StackOp::new(
                1,
                StackAddress::from(0), /* this fails because the
                                        * address is not
                                        * monotone */
                Word::from(12),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 10;
        test_state_circuit_error!(
            18,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            10,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![]
        );
    }

    #[test]
    fn storage() {
        let storage_op_0 = Operation::new(
            RWCounter::from(18),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(19),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(33), /* Fails because it is READ op
                                 * and not the same
                                 * value as in the previous
                                 * row. */
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(20),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(), /* Fails because not the same
                               * as value in the previous row - note: this
                               * is WRITE. */
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(21),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(1), /* Fails because not the same
                                * as value_prev in the previous row - note:
                                * this is READ. */
                1usize,
                Word::from(1),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![],
            vec![storage_op_0, storage_op_1, storage_op_2, storage_op_3]
        );
    }

    #[test]
    fn trace() {
        let bytecode = bytecode! {
            PUSH1(0x80)
            PUSH1(0x40)
            MSTORE
            PUSH1(0x40)
            MLOAD
            STOP
        };
        let block = bus_mapping::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code(&bytecode).unwrap(),
        );
        let mut builder = block.new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let stack_ops = builder.block.container.sorted_stack();
        let memory_ops = builder.block.container.sorted_memory();
        let storage_ops = builder.block.container.sorted_storage();

        test_state_circuit_ok!(
            17,
            2000,
            100,
            0x80,
            100,
            1023,
            1000,
            memory_ops,
            stack_ops,
            storage_ops,
            Ok(())
        );
    }
}
