use crate::{
    evm_circuit::{
        table::RwTableTag,
        util::{
            constraint_builder::BaseConstraintBuilder,
            math_gadget::generate_lagrange_base_polynomial,
        },
        witness::{RwMap, RwRow},
    },
    gadget::{
        is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
        Variable,
    },
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use pairing::arithmetic::FieldExt;

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

const EMPTY_TAG: usize = 0;
const START_TAG: usize = 1;
const MEMORY_TAG: usize = RwTableTag::Memory as usize;
const STACK_TAG: usize = RwTableTag::Stack as usize;
const STORAGE_TAG: usize = RwTableTag::AccountStorage as usize;

const MAX_DEGREE: usize = 15;

/// A mapping derived from witnessed operations.
#[derive(Clone, Debug)]
pub(crate) struct BusMapping<F: FieldExt> {
    rw_counter: Variable<F, F>,
    target: Variable<F, F>,
    is_write: Variable<F, F>,
    address: Variable<F, F>,
    value: Variable<F, F>,
    storage_key: Variable<F, F>,
}

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
    rw_counter: Column<Advice>,
    is_write: Column<Advice>,
    keys: [Column<Advice>; 5],

    // helper column used for IsZero chip
    keys_diff_inv: [Column<Advice>; 5],

    key2_limbs: [Column<Advice>; 8],
    key4_bytes: [Column<Advice>; 32],
    value: Column<Advice>,
    auxs: [Column<Advice>; 2],

    // helper chips here
    key_is_same_with_prev: [IsZeroConfig<F>; 5],

    // range tables here, TODO: organize them to a single struct?
    rw_counter_table: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    memory_value_table: Column<Fixed>,
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
    fn tag(&self) -> Column<Advice> {
        self.keys[0]
    }
    fn account_addr(&self) -> Column<Advice> {
        self.keys[2]
    }
    fn address(&self) -> Column<Advice> {
        self.keys[3]
    }
    fn storage_key(&self) -> Column<Advice> {
        self.keys[4]
    }

    /// Set up custom gates and lookup arguments for this configuration.
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let rw_counter = meta.advice_column();
        let is_write = meta.advice_column();
        let keys = [(); 5].map(|_| meta.advice_column());
        let keys_diff_inv = [(); 5].map(|_| meta.advice_column());
        let key2_limbs = [(); 8].map(|_| meta.advice_column());
        let key4_bytes = [(); 32].map(|_| meta.advice_column());
        let auxs = [(); 2].map(|_| meta.advice_column());

        let s_enable = meta.fixed_column();

        let value = meta.advice_column();

        let rw_counter_table = meta.fixed_column();
        let memory_address_table_zero = meta.fixed_column();
        let stack_address_table_zero = meta.fixed_column();
        let memory_value_table = meta.fixed_column();

        let new_cb = || BaseConstraintBuilder::<F>::new(MAX_DEGREE);

        // alias keys for later use
        let tag = keys[0];
        let address = keys[3];

        let one = Expression::Constant(F::from(1));

        let q_tag_is = |meta: &mut VirtualCells<F>, tag_value: usize| {
            let tag_cur = meta.query_advice(tag, Rotation::cur());
            let all_possible_values = EMPTY_TAG..=STORAGE_TAG;
            generate_lagrange_base_polynomial(tag_cur, tag_value, all_possible_values)
        };
        let q_memory = |meta: &mut VirtualCells<F>| q_tag_is(meta, MEMORY_TAG);
        let q_stack = |meta: &mut VirtualCells<F>| q_tag_is(meta, STACK_TAG);
        let q_storage = |meta: &mut VirtualCells<F>| q_tag_is(meta, STORAGE_TAG);

        let key_is_same_with_prev: [IsZeroConfig<F>; 5] = [0, 1, 2, 3, 4].map(|idx| {
            IsZeroChip::configure(
                meta,
                |meta| meta.query_fixed(s_enable, Rotation::cur()),
                |meta| {
                    let value_cur = meta.query_advice(keys[idx], Rotation::cur());
                    let value_prev = meta.query_advice(keys[idx], Rotation::prev());
                    value_cur - value_prev
                },
                keys_diff_inv[idx],
            )
        });

        let q_all_keys_same = |_meta: &mut VirtualCells<F>| {
            key_is_same_with_prev[0].is_zero_expression.clone()
                * key_is_same_with_prev[1].is_zero_expression.clone()
                * key_is_same_with_prev[2].is_zero_expression.clone()
                * key_is_same_with_prev[3].is_zero_expression.clone()
                * key_is_same_with_prev[4].is_zero_expression.clone()
        };
        let q_not_all_keys_same = |meta: &mut VirtualCells<F>| one.clone() - q_all_keys_same(meta);

        ///////////////////////// General constraints /////////////////////////////////
        // Constraints that affect all rows, no matter which Tag they use
        meta.create_gate("General constraints", |meta| {
            let mut cb = new_cb();
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let is_read = one.clone() - is_write.clone();
            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev = meta.query_advice(value, Rotation::prev());

            // TODO: 0. key0, key1, key3 are in the expected range

            // TODO: 1. key2 is linear combination of 10 x 16bit limbs and also in range

            // TODO: 2. key4 is RLC encoded

            // 3. is_write is boolean
            cb.require_boolean("is_write should be boolean", is_write);

            // 4. Keys are sorted in lexicographic order for same Tag
            //
            // This check also ensures that Tag monotonically increases for all values
            // except for Start
            //
            // When in two consecutive rows the keys are equal in a column:
            // - The corresponding keys in the following column must be increasing.
            //
            // key4 is RLC encoded, so it doesn't keep the order.  We use the key4 bytes
            // decomposition instead.  Since we will use a chain of comparison gadgets,
            // we try to merge multiple keys together to reduce the number of required
            // gadgets.

            // 6. Read consistency
            // When a row is READ
            // AND When all the keys are equal in two consecutive a rows:
            //- The corresponding value must be equal to the previous row
            cb.require_zero(
                "if read and keys are same, value should be same with prev",
                q_all_keys_same(meta) * is_read * (value_cur - value_prev),
            );

            cb.gate(s_enable)
        });

        // 5. RWC is monotonically strictly increasing for a set of all keys
        //
        // When tag is not Start and all the keys are equal in two consecutive a rows:
        // - The corresponding rwc must be strictly increasing.
        // TODO: rewrite using range check gates rather than lookup
        meta.lookup_any("rw counter monotonicity", |meta| {
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());

            vec![(
                s_enable * q_all_keys_same(meta)
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        ///////////////////////// Memory related constraints /////////////////////////

        meta.create_gate("Memory operation", |meta| {
            let mut cb = new_cb();
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let value_cur = meta.query_advice(value, Rotation::cur());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;

            // 0. Unused keys are 0
            let key2 = meta.query_advice(keys[2], Rotation::cur());
            let key4 = meta.query_advice(keys[4], Rotation::cur());
            cb.require_zero("key2 is 0", key2);
            cb.require_zero("key4 is 0", key4);

            // 1. First access for a set of all keys
            //
            // When the set of all keys changes (first access of an address in a call)
            // - If READ, value must be 0
            cb.require_zero(
                "if address changes, read value should be 0",
                q_not_all_keys_same(meta) * q_read * value_cur,
            );

            cb.gate(s_enable * q_memory(meta))
        });

        // 2. mem_addr in range
        // TODO: rewrite this using range check gates instead of lookup
        meta.lookup_any("Memory address in allowed range", |meta| {
            let q_memory = q_memory(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let memory_address_table_zero =
                meta.query_fixed(memory_address_table_zero, Rotation::cur());

            // s_enable is omitted here deliberately, since `memory_address_table_zero` will
            // contain '0', and 'q_memory * address_cur' on unused rows will be 0 too.
            vec![(q_memory * address_cur, memory_address_table_zero)]
        });

        // 3. value is a byte
        // Memory value is in the allowed range.
        meta.lookup_any("Memory value in allowed range", |meta| {
            let q_memory = q_memory(meta);
            let value = meta.query_advice(value, Rotation::cur());
            let memory_value_table = meta.query_fixed(memory_value_table, Rotation::cur());

            vec![(q_memory * value, memory_value_table)]
        });

        ///////////////////////// Stack related constraints /////////////////////////

        meta.create_gate("Stack operation", |meta| {
            let mut cb = new_cb();

            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;
            let key2 = meta.query_advice(keys[2], Rotation::cur());
            let key4 = meta.query_advice(keys[4], Rotation::cur());

            // 0. Unused keys are 0
            cb.require_zero("key2 is 0", key2);
            cb.require_zero("key4 is 0", key4);

            // 1. First access for a set of all keys
            //
            // The first stack operation in a stack position is always a write (can't
            // read if it isn't written before)
            //
            // When the set of all keys changes (first access of a stack position in a call)
            // - It must be a WRITE
            cb.require_zero(
                "if address changes, operation is always a write",
                q_not_all_keys_same(meta) * q_read,
            );
            cb.gate(s_enable * q_stack(meta))
        });

        // 2. stack_ptr in range
        meta.lookup_any("Stack address in allowed range", |meta| {
            let q_stack = q_stack(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let stack_address_table_zero =
                meta.query_fixed(stack_address_table_zero, Rotation::cur());

            vec![(q_stack * address_cur, stack_address_table_zero)]
        });

        // 3. stack_ptr only increases by 0 or 1
        meta.create_gate("Stack pointer diff be 0 or 1", |meta| {
            let mut cb = new_cb();
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let q_stack = q_stack(meta);
            let tag_is_same_with_prev = key_is_same_with_prev[0].is_zero_expression.clone();
            let call_id_same_with_prev = key_is_same_with_prev[1].is_zero_expression.clone();
            let stack_ptr = meta.query_advice(keys[3], Rotation::cur());
            let stack_ptr_prev = meta.query_advice(keys[3], Rotation::prev());
            cb.require_boolean(
                "stack pointer only increases by 0 or 1",
                stack_ptr - stack_ptr_prev,
            );
            cb.gate(s_enable * q_stack * tag_is_same_with_prev * call_id_same_with_prev)
        });

        ///////////////////////// Storage related constraints /////////////////////////

        meta.create_gate("Storage Operation", |meta| {
            let mut cb = new_cb();
            let q_storage = q_storage(meta);

            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let key1 = meta.query_advice(keys[1], Rotation::cur());
            let key3 = meta.query_advice(keys[3], Rotation::cur());

            // TODO: cold VS warm
            // TODO: connection to MPT on first and last access for each (address, key)

            // 0. Unused keys are 0
            cb.require_zero("key1 is 0", key1);
            cb.require_zero("key3 is 0", key3);

            // 1. First access for a set of all keys
            //
            // We add an extra write to set the value of the state in previous block, with
            // rwc=0.
            //
            // When the set of all keys changes (first access of storage (address, key))
            // - It must be a WRITE
            cb.require_zero(
                "First access for storage is write",
                q_not_all_keys_same(meta) * q_read,
            );
            cb.require_zero(
                "First access for storage has rw_counter as 0",
                q_not_all_keys_same(meta) * rw_counter,
            );

            cb.gate(s_enable * q_storage)
        });

        Config {
            rw_counter,
            value,
            is_write,
            keys,
            keys_diff_inv,
            key2_limbs,
            key4_bytes,
            auxs,
            s_enable,
            key_is_same_with_prev,
            rw_counter_table,
            memory_address_table_zero,
            stack_address_table_zero,
            memory_value_table,
        }
    }

    /// Load lookup table / other fixed constants for this configuration.
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter
            .assign_region(
                || "rw counter table",
                |mut region| {
                    for idx in 0..=RW_COUNTER_MAX {
                        region.assign_fixed(
                            || "rw counter table",
                            self.rw_counter_table,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter
            .assign_region(
                || "memory value table",
                |mut region| {
                    for idx in 0..=255 {
                        region.assign_fixed(
                            || "memory value table",
                            self.memory_value_table,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter
            .assign_region(
                || "memory address table with zero",
                |mut region| {
                    for idx in 0..=MEMORY_ADDRESS_MAX {
                        region.assign_fixed(
                            || "address table with zero",
                            self.memory_address_table_zero,
                            idx,
                            || Ok(F::from(idx as u64)),
                        )?;
                    }
                    Ok(())
                },
            )
            .ok();

        layouter.assign_region(
            || "stack address table with zero",
            |mut region| {
                for idx in 0..=STACK_ADDRESS_MAX {
                    region.assign_fixed(
                        || "stack address table with zero",
                        self.stack_address_table_zero,
                        idx,
                        || Ok(F::from(idx as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Assign cells.
    pub(crate) fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        randomness: F,
        rw_map: &RwMap,
    ) -> Result<(), Error> {
        let key_is_same_with_prev_chips: [IsZeroChip<F>; 5] = [0, 1, 2, 3, 4]
            .map(|idx| IsZeroChip::construct(self.key_is_same_with_prev[idx].clone()));

        layouter.assign_region(
            || "State operations",
            |mut region| {
                // TODO: a "START_TAG" row should be inserted before all other rows in the final
                // implmentation. Here we start from 1 to prevent some
                // col.prev() problems since blinding rows are unavailable for constaints.
                let mut offset = 1;

                let mut rows: Vec<RwRow<F>> = [
                    RwTableTag::Memory,
                    RwTableTag::Stack,
                    RwTableTag::AccountStorage,
                ]
                .iter()
                .map(|tag| {
                    rw_map.0[tag]
                        .iter()
                        .map(|rw| rw.table_assignment(randomness))
                })
                .flatten()
                .collect();
                rows.sort_by_key(|rw| (rw.tag, rw.key1, rw.key2, rw.key3, rw.key4, rw.rw_counter));

                if rows.len() >= ROWS_MAX {
                    panic!("too many storage operations");
                }
                for (index, row) in rows.iter().enumerate() {
                    let row_prev = if index == 0 {
                        RwRow::default()
                    } else {
                        rows[index - 1]
                    };
                    self.assign_row(
                        &mut region,
                        offset,
                        *row,
                        row_prev,
                        &key_is_same_with_prev_chips,
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
        row_prev: RwRow<F>,
        diff_is_zero_chips: &[IsZeroChip<F>; 5],
    ) -> Result<(), Error> {
        let address = row.key3;
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
            if row.tag == F::from(STACK_TAG as u64) && address > F::from(STACK_ADDRESS_MAX as u64) {
                panic!(
                    "stack address out of range {:?} > {}",
                    address, STACK_ADDRESS_MAX
                );
            }
            if row.tag == F::from(MEMORY_TAG as u64) && address > F::from(MEMORY_ADDRESS_MAX as u64)
            {
                panic!(
                    "memory address out of range {:?} > {}",
                    address, MEMORY_ADDRESS_MAX
                );
            }
        }
        region.assign_fixed(|| "enable row", self.s_enable, offset, || Ok(F::one()))?;
        region.assign_advice(|| "rw counter", self.rw_counter, offset, || Ok(rw_counter))?;
        region.assign_advice(|| "value", self.value, offset, || Ok(value))?;
        region.assign_advice(|| "is_write", self.is_write, offset, || Ok(is_write))?;

        for (i, diff_is_zero_chip) in diff_is_zero_chips.iter().enumerate() {
            let (value, diff) = match i {
                // FIXME: find a better way here
                0 => (row.tag, row.tag - row_prev.tag),
                1 => (row.key1, row.key1 - row_prev.key1),
                2 => (row.key2, row.key2 - row_prev.key2),
                3 => (row.key3, row.key3 - row_prev.key3),
                4 => (row.key4, row.key4 - row_prev.key4),
                _ => unreachable!(),
            };
            region.assign_advice(
                || format!("assign key{}", i),
                self.keys[i],
                offset,
                || Ok(value),
            )?;
            diff_is_zero_chip.assign(region, offset, Some(diff))?;
        }

        region.assign_advice(|| "aux1", self.auxs[0], offset, || Ok(row.aux1))?;
        region.assign_advice(|| "aux2", self.auxs[1], offset, || Ok(row.aux2))?;

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
        Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load(&mut layouter)?;
        config.assign(layouter, self.randomness, &self.rw_map)?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bus_mapping::mock::BlockData;
    use bus_mapping::operation::{
        MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
    };
    use eth_types::{
        address, bytecode,
        evm_types::{MemoryAddress, StackAddress},
        geth_types::GethData,
        Word,
    };
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::dev::MockProver;
    use mock::TestContext;
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

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
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

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
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
                address!("0x0000000000000000000000000000000000000001"),
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
                address!("0x0000000000000000000000000000000000000001"),
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
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );

        test_state_circuit_ok!(
            12,
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
            14,
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
            14,
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
            14,
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
            16,
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
            16,
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
            15,
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
            14,
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
            14,
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

        // Create a custom tx setting Gas to
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let stack_ops = builder.block.container.sorted_stack();
        let memory_ops = builder.block.container.sorted_memory();
        let storage_ops = builder.block.container.sorted_storage();

        test_state_circuit_ok!(
            14,
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
