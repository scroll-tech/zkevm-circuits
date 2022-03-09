use crate::{
    evm_circuit::{util::math_gadget::generate_lagrange_base_polynomial, witness::RwMap},
    gadget::{
        is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
        monotone::{MonotoneChip, MonotoneConfig},
        Variable,
    },
};
use bus_mapping::operation::{MemoryOp, Operation, OperationContainer, StackOp, StorageOp};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use crate::evm_circuit::witness::Rw;
use pairing::arithmetic::FieldExt;

/*
Example state table:

| q_target | address | rw_counter | value | flag | padding | storage_key | value_prev |
-------------------------------------------------------------------------------------------
|    1     |    0    |       0        |  0    |   1  |    0    |             |            |   // init row (write value 0)
|    2     |    0    |       12       |  12   |   1  |    0    |             |            |
|    2     |    0    |       24       |  12   |   0  |    0    |             |            |
|    2     |    1    |       0        |  0    |   1  |    0    |             |            |   // init row (write value 0)
|    2     |    1    |       2        |  12   |   0  |    0    |             |            |
|    2     |         |                |       |      |    1    |             |            |   // padding
|    2     |         |                |       |      |    1    |             |            |   // padding
|    1     |    0    |       3        |  4    |   1  |    0    |             |            |
|    3     |    0    |       17       |  32   |   1  |    0    |             |            |
|    3     |    0    |       89       |  32   |   0  |    0    |             |            |
|    3     |    1    |       48       |  32   |   1  |    0    |             |            |
|    3     |    1    |       49       |  32   |   0  |    0    |             |            |
|    3     |         |                |       |      |    1    |             |            |   // padding
|    1     |    1    |       55       |  32   |   1  |    0    |      5      |     0      |   // first storage op at the new address has to be write
|    4     |    1    |       56       |  33   |   1  |    0    |      8      |     32     |
|    4     |         |                |       |      |    1    |             |            |   // padding
*/

// q_target:
// 1 - first row of either target (Note: only the first row, not all init rows)
// 2 - memory
// 3 - stack
// 4 - storage

// address presents memory address, stack pointer, and account address for
// memory, stack, and storage ops respectively two columns are not displayed:
// address_diff and storage_key_diff (needed to check whether the address or
// storage_key changed) storage_key and value_prev are needed for storage ops
// only padding specifies whether the row is just a padding to fill all the rows
// that are intended for a particular target

/*
Example bus mapping:
// TODO: this is going to change

| target | address | rw_counter | value | storage_key | value_prev | flag |
-------------------------------------------------------------------------------
|    2   |    0    |       12       |  12   |             |            |  1   |
|    2   |    0    |       24       |  12   |             |            |  0   |
|    2   |    1    |       2        |  12   |             |            |  0   |
|    1   |    0    |       3        |  4    |             |            |  1   |
|    3   |    0    |       17       |  32   |             |            |  1   |
|    3   |    0    |       89       |  32   |             |            |  0   |
|    3   |    1    |       48       |  32   |             |            |  1   |
|    3   |    1    |       49       |  32   |             |            |  0   |
*/

const EMPTY_TAG: usize = 0;
const START_TAG: usize = 1;
const MEMORY_TAG: usize = 2;
const STACK_TAG: usize = 3;
const STORAGE_TAG: usize = 4;

/// A mapping derived from witnessed memory operations.
/// TODO: The complete version of this mapping will involve storage, stack,
/// and opcode details as well.
#[derive(Clone, Debug)]
pub(crate) struct BusMapping<F: FieldExt> {
    rw_counter: Variable<F, F>,
    target: Variable<F, F>,
    flag: Variable<F, F>,
    address: Variable<F, F>,
    value: Variable<F, F>,
    storage_key: Variable<F, F>,
    value_prev: Variable<F, F>,
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
    const MEMORY_ROWS_MAX: usize,
    const MEMORY_ADDRESS_MAX: usize,
    const STACK_ROWS_MAX: usize,
    const STACK_ADDRESS_MAX: usize,
    const STORAGE_ROWS_MAX: usize,
> {
    q_target: Column<Fixed>,
    address: Column<Advice>, /* used for memory address, stack pointer, and
                              * account address (for storage) */
    address_diff_inv: Column<Advice>,
    rw_counter: Column<Advice>,
    value: Column<Advice>,
    flag: Column<Advice>,
    padding: Column<Advice>,
    storage_key: Column<Advice>,
    storage_key_diff_inv: Column<Advice>,
    value_prev: Column<Advice>,
    rw_counter_table: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
    memory_value_table: Column<Fixed>,
    address_diff_is_zero: IsZeroConfig<F>,
    address_monotone: MonotoneConfig,
    padding_monotone: MonotoneConfig,
    storage_key_diff_is_zero: IsZeroConfig<F>,
}

impl<
        F: Field,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ROWS_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ROWS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const STORAGE_ROWS_MAX: usize,
    >
    Config<
        F,
        SANITY_CHECK,
        RW_COUNTER_MAX,
        MEMORY_ROWS_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ROWS_MAX,
        STACK_ADDRESS_MAX,
        STORAGE_ROWS_MAX,
    >
{
    /// Set up custom gates and lookup arguments for this configuration.
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_target = meta.fixed_column();
        let address = meta.advice_column();
        let address_diff_inv = meta.advice_column();
        let rw_counter = meta.advice_column();
        let value = meta.advice_column();
        let flag = meta.advice_column();
        let padding = meta.advice_column();
        let storage_key = meta.advice_column();
        let storage_key_diff_inv = meta.advice_column();
        let value_prev = meta.advice_column();
        let rw_counter_table = meta.fixed_column();
        let memory_address_table_zero = meta.fixed_column();
        let stack_address_table_zero = meta.fixed_column();
        let memory_value_table = meta.fixed_column();

        let one = Expression::Constant(F::from(1));

        let q_memory_first = |meta: &mut VirtualCells<F>| {
            // For first memory row it holds q_target_cur = START_TAG and q_target_next
            // = MEMORY_TAG.
            let q_target_cur = meta.query_fixed(q_target, Rotation::cur());
            let q_target_next = meta.query_fixed(q_target, Rotation::next());
            generate_lagrange_base_polynomial(q_target_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(
                    q_target_next,
                    MEMORY_TAG,
                    EMPTY_TAG..=STORAGE_TAG,
                )
        };

        let q_memory_not_first = |meta: &mut VirtualCells<F>| {
            let q_target = meta.query_fixed(q_target, Rotation::cur());
            generate_lagrange_base_polynomial(q_target, MEMORY_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        let q_stack_first = |meta: &mut VirtualCells<F>| {
            let q_target_cur = meta.query_fixed(q_target, Rotation::cur());
            let q_target_next = meta.query_fixed(q_target, Rotation::next());

            generate_lagrange_base_polynomial(q_target_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(
                    q_target_next,
                    STACK_TAG,
                    EMPTY_TAG..=STORAGE_TAG,
                )
        };

        let q_stack_not_first = |meta: &mut VirtualCells<F>| {
            let q_target = meta.query_fixed(q_target, Rotation::cur());
            generate_lagrange_base_polynomial(q_target, STACK_TAG, EMPTY_TAG..=STORAGE_TAG)
        };
        let q_storage_first = |meta: &mut VirtualCells<F>| {
            let q_target_cur = meta.query_fixed(q_target, Rotation::cur());
            let q_target_next = meta.query_fixed(q_target, Rotation::next());
            generate_lagrange_base_polynomial(q_target_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(
                    q_target_next,
                    STORAGE_TAG,
                    EMPTY_TAG..=STORAGE_TAG,
                )
        };
        let q_storage_not_first = |meta: &mut VirtualCells<F>| {
            let q_target = meta.query_fixed(q_target, Rotation::cur());
            generate_lagrange_base_polynomial(q_target, STORAGE_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        let address_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let padding = meta.query_advice(padding, Rotation::cur());
                let is_not_padding = one.clone() - padding;
                let q_target = meta.query_fixed(q_target, Rotation::cur());
                let q_not_first = q_target.clone() * (q_target - one.clone());

                q_not_first * is_not_padding
            },
            |meta| {
                let address_cur = meta.query_advice(address, Rotation::cur());
                let address_prev = meta.query_advice(address, Rotation::prev());
                address_cur - address_prev
            },
            address_diff_inv,
        );

        // Only one monotone gadget is used for memory and stack (with
        // MEMORY_ADDRESS_MAX as it is bigger)
        let address_monotone = MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::configure(
            meta,
            |meta| {
                let padding = meta.query_advice(padding, Rotation::cur());
                let is_not_padding = one.clone() - padding;
                // Since q_memory_not_first and q_stack_non_first are
                // mutually exclusive, q_not_first is binary.
                let q_not_first = q_memory_not_first(meta) + q_stack_not_first(meta);

                q_not_first * is_not_padding
            },
            address,
        );

        // Padding monotonicity could be checked using gates (as padding only
        // takes values 0 and 1), but it's much slower than using a
        // lookup.
        let padding_monotone = MonotoneChip::<F, 1, true, false>::configure(
            meta,
            |meta| q_memory_not_first(meta) + q_stack_not_first(meta),
            padding,
        );

        // A gate for the first row (does not need Rotation::prev).
        meta.create_gate("First memory row operation", |meta| {
            let value = meta.query_advice(value, Rotation::cur());
            let flag = meta.query_advice(flag, Rotation::cur());
            let q_read = one.clone() - flag;
            let q_memory_first = q_memory_first(meta);

            // read value must be 0
            vec![q_memory_first * q_read * value]
        });

        meta.create_gate("Memory operation + padding", |meta| {
            // if is_read:
            //      if address_cur == address_prev:
            //          value == prev_value
            //      else:
            //          value == 0
            let q_memory_not_first = q_memory_not_first(meta);
            let address_diff = {
                let address_prev = meta.query_advice(address, Rotation::prev());
                let address_cur = meta.query_advice(address, Rotation::cur());
                address_cur - address_prev
            };

            let value_cur = meta.query_advice(value, Rotation::cur());
            let flag = meta.query_advice(flag, Rotation::cur());

            // flag == 0 or 1
            // (flag) * (1 - flag)
            let bool_check_flag = flag.clone() * (one.clone() - flag.clone());

            // If flag == 0 (read), and rw_counter != 0, value_prev ==
            // value_cur
            let value_prev = meta.query_advice(value, Rotation::prev());
            let q_read = one.clone() - flag;

            let q_target = meta.query_fixed(q_target, Rotation::cur());
            let padding = meta.query_advice(padding, Rotation::cur());
            let bool_check_padding = padding.clone() * (one.clone() - padding);

            vec![
                q_memory_not_first.clone() * bool_check_flag, // flag is either 0 or 1
                // if address changes, read value should be 0
                q_memory_not_first.clone() * address_diff * q_read.clone() * value_cur.clone(),
                // or else, read value should be the same as the previous value
                q_memory_not_first
                    * address_diff_is_zero.is_zero_expression.clone()
                    * q_read
                    * (value_cur - value_prev),
                q_target * bool_check_padding, // padding is 0 or 1
            ]
        });

        // We don't require first stack op to be write as this is enforced by
        // evm circuit.

        meta.create_gate("Stack operation", |meta| {
            let q_stack_not_first = q_stack_not_first(meta);
            let value_cur = meta.query_advice(value, Rotation::cur());
            let flag = meta.query_advice(flag, Rotation::cur());

            // flag == 0 or 1
            // (flag) * (1 - flag)
            let bool_check_flag = flag.clone() * (one.clone() - flag.clone());

            // If flag == 0 (read), and rw_counter != 0, value_prev == value_cur
            let value_prev = meta.query_advice(value, Rotation::prev());
            let q_read = one.clone() - flag;
            // when addresses changes, we don't require the operation is write as this is
            // enforced by evm circuit

            vec![
                q_stack_not_first.clone() * bool_check_flag, // flag is either 0 or 1
                q_stack_not_first * q_read * (value_cur - value_prev), /* when reading, the
                                                              * value is the same as
                                                              * at the previous op */
            ]
        });

        // rw_counter monotonicity is checked for memory and stack when
        // address_cur == address_prev. (Recall that operations are
        // ordered first by address, and then by rw_counter.)
        meta.lookup_any("rw counter monotonicity", |meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let padding = meta.query_advice(padding, Rotation::cur());
            let is_not_padding = one.clone() - padding;
            let q_not_first = q_memory_not_first(meta) + q_stack_not_first(meta);

            vec![(
                q_not_first
                    * is_not_padding
                    * address_diff_is_zero.clone().is_zero_expression
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        // Memory address is in the allowed range.
        meta.lookup_any("Memory address in allowed range", |meta| {
            let q_memory = q_memory_first(meta) + q_memory_not_first(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let memory_address_table_zero =
                meta.query_fixed(memory_address_table_zero, Rotation::cur());

            vec![(q_memory * address_cur, memory_address_table_zero)]
        });

        // Stack address is in the allowed range.
        meta.lookup_any("Stack address in allowed range", |meta| {
            let q_stack = q_stack_first(meta) + q_stack_not_first(meta);
            let address_cur = meta.query_advice(address, Rotation::cur());
            let stack_address_table_zero =
                meta.query_fixed(stack_address_table_zero, Rotation::cur());

            vec![(q_stack * address_cur, stack_address_table_zero)]
        });

        // rw_counter is in the allowed range:
        meta.lookup_any("Global Counter in allowed range", |meta| {
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());

            vec![(rw_counter, rw_counter_table)]
        });

        // Memory value (for non-first rows) is in the allowed range.
        // Memory first row value doesn't need to be checked - it is checked
        // above where memory init row value has to be 0.
        meta.lookup_any("Memory value in allowed range", |meta| {
            let q_memory_not_first = q_memory_not_first(meta);
            let value = meta.query_advice(value, Rotation::cur());
            let memory_value_table = meta.query_fixed(memory_value_table, Rotation::cur());

            vec![(q_memory_not_first * value, memory_value_table)]
        });

        let storage_key_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let padding = meta.query_advice(padding, Rotation::cur());
                let is_not_padding = one.clone() - padding;

                let q_target = meta.query_fixed(q_target, Rotation::cur());
                let q_not_first = q_target.clone() * (q_target - one.clone());

                q_not_first * is_not_padding
            },
            |meta| {
                let storage_key_cur = meta.query_advice(storage_key, Rotation::cur());
                let storage_key_prev = meta.query_advice(storage_key, Rotation::prev());
                storage_key_cur - storage_key_prev
            },
            storage_key_diff_inv,
        );

        meta.create_gate("First storage row operation", |meta| {
            let q_storage_first = q_storage_first(meta);

            let flag = meta.query_advice(flag, Rotation::cur());
            let q_read = one.clone() - flag;

            vec![
                q_storage_first * q_read, /* first storage op has to be
                                           * write (flag = 1) */
            ]
        });

        meta.create_gate("Storage operation", |meta| {
            let q_storage_not_first = q_storage_not_first(meta);
            let address_diff = {
                let address_prev = meta.query_advice(address, Rotation::prev());
                let address_cur = meta.query_advice(address, Rotation::cur());
                address_cur - address_prev
            };

            let storage_key_diff = {
                let storage_key_prev =
                    meta.query_advice(storage_key, Rotation::prev());
                let storage_key_cur =
                    meta.query_advice(storage_key, Rotation::cur());
                storage_key_cur - storage_key_prev
            };

            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev_cur = meta.query_advice(value_prev, Rotation::cur());
            let value_prev_prev =
                meta.query_advice(value_prev, Rotation::prev());
            let flag = meta.query_advice(flag, Rotation::cur());

            // flag == 0 or 1
            // (flag) * (1 - flag)
            let bool_check_flag = flag.clone() * (one.clone() - flag.clone());

            // If flag == 0 (read), and rw_counter != 0, value_prev == value_cur
            let value_previous = meta.query_advice(value, Rotation::prev());
            let q_read = one.clone() - flag.clone();

            let padding = meta.query_advice(padding, Rotation::cur());
            let is_not_padding = one.clone() - padding;

            vec![
                q_storage_not_first.clone() * address_diff * q_read.clone(), // when address changes, the flag is 1 (write)
                q_storage_not_first.clone() * storage_key_diff * q_read.clone(), // when storage_key_diff changes, the flag is 1 (write)
                q_storage_not_first.clone() * bool_check_flag, // flag is either 0 or 1
                q_storage_not_first.clone()
                    * q_read.clone()
                    * (value_cur - value_previous.clone()), // when reading, the value is the same as at the previous op
                // Note that this last constraint needs to hold only when address and storage key don't change,
                // but we don't need to check this as the first operation at new address and
                // new storage key always has to be write - that means q_read is 1 only when
                // the address and storage key doesn't change.
                is_not_padding.clone()
                    * flag
                    * q_storage_not_first.clone()
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (value_prev_cur.clone() - value_previous),
                is_not_padding
                    * q_read
                    * q_storage_not_first
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (value_prev_cur - value_prev_prev),
            ]
        });

        // rw_counter monotonicity is checked for storage when address_cur
        // == address_prev and storage_key_cur = storage_key_prev.
        // (Recall that storage operations are ordered first by account address,
        // then by storage_key, and finally by rw_counter.)

        meta.lookup_any("Global Counter in allowed range", |meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let padding = meta.query_advice(padding, Rotation::cur());
            let is_not_padding = one.clone() - padding;
            let q_storage_not_first = q_storage_not_first(meta);

            vec![(
                q_storage_not_first
                    * is_not_padding
                    * address_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        // TODO: monotone address for storage

        Config {
            q_target,
            address,
            address_diff_inv,
            rw_counter,
            value,
            flag,
            padding,
            storage_key,
            storage_key_diff_inv,
            value_prev,
            rw_counter_table,
            memory_address_table_zero,
            stack_address_table_zero,
            memory_value_table,
            address_diff_is_zero,
            address_monotone,
            padding_monotone,
            storage_key_diff_is_zero,
        }
    }

    /// Load lookup table / other fixed constants for this configuration.
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter
            .assign_region(
                || "global counter table",
                |mut region| {
                    for idx in 0..=RW_COUNTER_MAX {
                        region.assign_fixed(
                            || "global counter table",
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

    fn assign_memory_ops(
        &self,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Rw>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut offset = offset;
        let offset_limit = offset + MEMORY_ROWS_MAX;

        for (index, oper) in ops.iter().enumerate() {
            if !matches!(oper, Rw::Memory { .. }) {
                panic!("expect memory operation");
            }
            let row = oper.table_assignment(randomness);

            let address = row.key3;
            let address_prev = if index > 0 {
                ops[index - 1].table_assignment(randomness).key3
            } else {
                F::zero()
            };

            if SANITY_CHECK && address > F::from(MEMORY_ADDRESS_MAX as u64) {
                panic!(
                    "memory address out of range {:?} > {}",
                    address, MEMORY_ADDRESS_MAX
                );
            }

            let target = if index == 0 { START_TAG } else { MEMORY_TAG };
            if offset >= offset_limit {
                panic!("too many memory operations {} > {}", offset, offset_limit);
            }
            let bus_mapping = self.assign_op(
                region,
                offset,
                address,
                row.rw_counter,
                row.value,
                row.is_write,
                F::from(target as u64),
                F::zero(),
                F::zero(),
            )?;
            bus_mappings.push(bus_mapping);

            address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;
            offset += 1;
        }
        self.pad_rows(
            region,
            ops.is_empty(),
            offset,
            offset_limit,
            MEMORY_TAG as usize,
        )?;

        Ok(bus_mappings)
    }

    fn assign_stack_ops(
        &self,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Rw>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        if ops.len() > STACK_ROWS_MAX {
            panic!("too many stack operations");
        }
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut offset = offset;
        let offset_limit = offset + STACK_ROWS_MAX;
        for (index, oper) in ops.iter().enumerate() {
            if !matches!(oper, Rw::Stack { .. }) {
                panic!("expect stack operation");
            }
            let row = oper.table_assignment(randomness);
            let address = row.key3;
            let address_prev = if index > 0 {
                ops[index - 1].table_assignment(randomness).key3
            } else {
                F::zero()
            };

            if SANITY_CHECK && address > F::from(STACK_ADDRESS_MAX as u64) {
                panic!(
                    "stack address out of range {:?} > {}",
                    address, STACK_ADDRESS_MAX as u64
                );
            }

            let target = if index > 0 {
                STACK_TAG // 3
            } else {
                START_TAG // 1
            };

            let bus_mapping = self.assign_op(
                region,
                offset,
                address,
                row.rw_counter,
                row.value,
                row.is_write,
                F::from(target as u64),
                F::zero(),
                F::zero(),
            )?;
            bus_mappings.push(bus_mapping);

            address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;

            offset += 1;
        }

        self.pad_rows(
            region,
            ops.is_empty(),
            offset,
            offset_limit,
            STACK_TAG as usize,
        )?;

        Ok(bus_mappings)
    }

    fn assign_storage_ops(
        &self,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Rw>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        storage_key_diff_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        if ops.len() > STORAGE_ROWS_MAX {
            panic!("too many storage operations");
        }
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let mut offset = offset;
        let offset_limit = offset + STORAGE_ROWS_MAX;
        for (index, oper) in ops.iter().enumerate() {
            if !matches!(oper, Rw::AccountStorage { .. }) {
                panic!("expect stack operation");
            }

            let row = oper.table_assignment(randomness);

            let target = if index > 0 { STORAGE_TAG } else { START_TAG };
            let address = row.key2;
            let storage_key = row.key3;
            let (address_prev, storage_key_prev) = if index > 0 {
                let prev_row = ops[index - 1].table_assignment(randomness);
                (prev_row.key2, prev_row.key3)
            } else {
                (F::zero(), F::zero())
            };

            let bus_mapping = self.assign_op(
                region,
                offset,
                row.key2,
                row.rw_counter,
                row.value,
                row.is_write,
                F::from(target as u64),
                row.key3,
                row.value_prev,
            )?;
            bus_mappings.push(bus_mapping);

            address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;

            storage_key_diff_is_zero_chip.assign(
                region,
                offset,
                Some(storage_key - storage_key_prev),
            )?;

            offset += 1;
        }

        self.pad_rows(
            region,
            ops.is_empty(),
            offset,
            offset_limit,
            STORAGE_TAG as usize,
        )?;

        Ok(bus_mappings)
    }

    fn pad_rows(
        &self,
        region: &mut Region<F>,
        need_pad_start_row: bool,
        start_offset: usize,
        end_offset: usize,
        target: usize,
    ) -> Result<(), Error> {
        // We pad all remaining rows to avoid the check at the first unused row.
        // Without padding, (address_cur - address_prev) would not be zero at
        // the first unused row and some checks would be triggered.

        for i in start_offset..end_offset {
            let target = if need_pad_start_row && i == start_offset {
                START_TAG
            } else {
                target
            };
            region.assign_fixed(|| "target", self.q_target, i, || Ok(F::from(target as u64)))?;
            region.assign_advice(|| "padding", self.padding, i, || Ok(F::one()))?;
            region.assign_advice(|| "memory", self.flag, i, || Ok(F::one()))?;
        }

        Ok(())
    }

    /// Assign cells.
    pub(crate) fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        randomness: F,
        memory_ops: Vec<Rw>,
        stack_ops: Vec<Rw>,
        storage_ops: Vec<Rw>,
    ) -> Result<Vec<BusMapping<F>>, Error> {
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();

        let address_diff_is_zero_chip = IsZeroChip::construct(self.address_diff_is_zero.clone());

        let memory_address_monotone_chip =
            MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::construct(
                self.address_monotone.clone(),
            );
        memory_address_monotone_chip.load(&mut layouter)?;

        let padding_monotone_chip =
            MonotoneChip::<F, 1, true, false>::construct(self.padding_monotone.clone());
        padding_monotone_chip.load(&mut layouter)?;

        let storage_key_diff_is_zero_chip =
            IsZeroChip::construct(self.storage_key_diff_is_zero.clone());

        layouter.assign_region(
            || "State operations",
            |mut region| {
                let mut offset = 0;

                let memory_mappings = self.assign_memory_ops(
                    &mut region,
                    randomness,
                    memory_ops.clone(),
                    &address_diff_is_zero_chip,
                    offset,
                );
                bus_mappings.extend(memory_mappings.unwrap());
                offset += MEMORY_ROWS_MAX;

                let stack_mappings = self.assign_stack_ops(
                    &mut region,
                    randomness,
                    stack_ops.clone(),
                    &address_diff_is_zero_chip,
                    offset,
                );
                bus_mappings.extend(stack_mappings.unwrap());
                offset += STACK_ROWS_MAX;

                let storage_mappings = self.assign_storage_ops(
                    &mut region,
                    randomness,
                    storage_ops.clone(),
                    &address_diff_is_zero_chip,
                    &storage_key_diff_is_zero_chip,
                    offset,
                );
                bus_mappings.extend(storage_mappings.unwrap());

                Ok(bus_mappings.clone())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_op(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: F,
        rw_counter: F,
        value: F,
        flag: F,
        target: F,
        storage_key: F,
        value_prev: F,
    ) -> Result<BusMapping<F>, Error> {
        let address = {
            let cell = region.assign_advice(|| "address", self.address, offset, || Ok(address))?;
            Variable::<F, F>::new(cell, Some(address))
        };

        if SANITY_CHECK && rw_counter > F::from(RW_COUNTER_MAX as u64) {
            panic!("rw_counter out of range");
        }
        let rw_counter = {
            let cell = region.assign_advice(
                || "global counter",
                self.rw_counter,
                offset,
                || Ok(rw_counter),
            )?;

            Variable::<F, F>::new(cell, Some(rw_counter))
        };

        let value = {
            let cell = region.assign_advice(|| "value", self.value, offset, || Ok(value))?;

            Variable::<F, F>::new(cell, Some(value))
        };

        let storage_key = {
            let cell = region.assign_advice(
                || "storage key",
                self.storage_key,
                offset,
                || Ok(storage_key),
            )?;

            Variable::<F, F>::new(cell, Some(storage_key))
        };

        let value_prev = {
            let cell = region.assign_advice(
                || "value prev",
                self.value_prev,
                offset,
                || Ok(value_prev),
            )?;

            Variable::<F, F>::new(cell, Some(value_prev))
        };

        let flag = {
            let cell = region.assign_advice(|| "flag", self.flag, offset, || Ok(flag))?;

            Variable::<F, F>::new(cell, Some(flag))
        };

        let target = {
            let cell = region.assign_fixed(|| "target", self.q_target, offset, || Ok(target))?;
            Variable::<F, F>::new(cell, Some(target))
        };

        Ok(BusMapping {
            rw_counter,
            target,
            flag,
            address,
            value,
            storage_key,
            value_prev,
        })
    }
}

/// State Circuit struct.
#[derive(Default)]
pub struct StateCircuit<
    F: FieldExt,
    const SANITY_CHECK: bool,
    const RW_COUNTER_MAX: usize,
    const MEMORY_ROWS_MAX: usize,
    const MEMORY_ADDRESS_MAX: usize,
    const STACK_ROWS_MAX: usize,
    const STACK_ADDRESS_MAX: usize,
    const STORAGE_ROWS_MAX: usize,
> {
    /// randomness used in linear combination
    pub randomness: F,
    /// Memory Operations
    pub memory_ops: Vec<Rw>,
    /// Stack Operations
    pub stack_ops: Vec<Rw>,
    /// Storage Operations
    pub storage_ops: Vec<Rw>,
}

impl<
        F: FieldExt,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ROWS_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ROWS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const STORAGE_ROWS_MAX: usize,
    >
    StateCircuit<
        F,
        SANITY_CHECK,
        RW_COUNTER_MAX,
        MEMORY_ROWS_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ROWS_MAX,
        STACK_ADDRESS_MAX,
        STORAGE_ROWS_MAX,
    >
{
    /// Use rw_map to build a StateCircuit instance
    pub fn new_from_rw_map(randomness: F, rw_map: &RwMap) -> Self {
        Self {
            randomness,
            memory_ops: rw_map.sorted_memory_rw(),
            stack_ops: rw_map.sorted_stack_rw(),
            storage_ops: rw_map.sorted_storage_rw(),
        }
    }
    /// Use memory_ops, stack_ops, storage_ops to build a StateCircuit instance.
    /// This method should be replaced with `new_from_rw_map` later.
    pub fn new(
        randomness: F,
        memory_ops: Vec<Operation<MemoryOp>>,
        stack_ops: Vec<Operation<StackOp>>,
        storage_ops: Vec<Operation<StorageOp>>,
    ) -> Self {
        let rw_map = RwMap::from(&OperationContainer {
            memory: memory_ops,
            stack: stack_ops,
            storage: storage_ops,
            ..Default::default()
        });
        Self::new_from_rw_map(randomness, &rw_map)
    }
}

impl<
        F: Field,
        const SANITY_CHECK: bool,
        const RW_COUNTER_MAX: usize,
        const MEMORY_ROWS_MAX: usize,
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ROWS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const STORAGE_ROWS_MAX: usize,
    > Circuit<F>
    for StateCircuit<
        F,
        SANITY_CHECK,
        RW_COUNTER_MAX,
        MEMORY_ROWS_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ROWS_MAX,
        STACK_ADDRESS_MAX,
        STORAGE_ROWS_MAX,
    >
{
    type Config = Config<
        F,
        SANITY_CHECK,
        RW_COUNTER_MAX,
        MEMORY_ROWS_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ROWS_MAX,
        STACK_ADDRESS_MAX,
        STORAGE_ROWS_MAX,
    >;
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
        config.assign(
            layouter,
            self.randomness,
            self.memory_ops.clone(),
            self.stack_ops.clone(),
            self.storage_ops.clone(),
        )?;

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bus_mapping::operation::{MemoryOp, Operation, RWCounter, StackOp, StorageOp, RW};
    use eth_types::evm_types::{MemoryAddress, StackAddress};
    use eth_types::{address, bytecode, Word};
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::dev::MockProver;
    use pairing::bn256::Fr;

    macro_rules! test_state_circuit_ok {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr, $result:expr) => {{
            let circuit = StateCircuit::<
                Fr,
                true,
                $rw_counter_max,
                $memory_rows_max,
                $memory_address_max,
                $stack_rows_max,
                $stack_address_max,
                $storage_rows_max,
            >::new(Fr::rand(), $memory_ops, $stack_ops, $storage_ops);

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
            let verify_result = prover.verify();
            assert!(verify_result.is_ok(), "verify err: {:#?}", verify_result);
        }};
    }

    macro_rules! test_state_circuit_error {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr) => {{
            let circuit = StateCircuit::<
                Fr,
                false,
                $rw_counter_max,
                $memory_rows_max,
                $memory_address_max,
                $stack_rows_max,
                $stack_address_max,
                $storage_rows_max,
            >::new(Fr::rand(), $memory_ops, $stack_ops, $storage_ops);

            let prover = MockProver::<Fr>::run($k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn state_circuit() {
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
            RWCounter::from(17),
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
            14,
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
            #[start]
            PUSH1(0x40)
            MLOAD
            STOP
        };
        let block = bus_mapping::mock::BlockData::new_from_geth_data(
            mock::new_single_tx_trace_code(&bytecode).unwrap(),
        );
        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

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
