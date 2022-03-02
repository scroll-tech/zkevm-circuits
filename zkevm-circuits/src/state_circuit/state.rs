use crate::{
    evm_circuit::{
        table::RwTableTag,
        util::{
            constraint_builder::BaseConstraintBuilder,
            math_gadget::{generate_lagrange_base_polynomial, RangeCheckGadget},
        },
        witness::{RwMap, RwRow},
    },
    gadget::{
        is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
        monotone::{MonotoneChip, MonotoneConfig},
        Variable,
    },
    util::Expr,
};
use bus_mapping::operation::{MemoryOp, Operation, OperationContainer, StackOp, StorageOp};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;

use crate::evm_circuit::witness::Rw;
use pairing::arithmetic::FieldExt;

/*
Example state table:

|            |          |       |    keys(4)  |key2_limbs(8)|   key4_bytes(32)   |                |
| rw_counter | is_write | value | tag  | ...  | ...  | ...  |      |      |      |  storage_key   |
-------------------------------------------------------------------------------------------------------
|     0      |     1    |  0    |  1   |      |      |      |      |      |      |                |   // init row (write value 0)
|     12     |     1    |  12   |  2   |      |      |      |      |      |      |                |
|     24     |     0    |  12   |  2   |      |      |      |      |      |      |                |
|     0      |     1    |  0    |  2   |      |      |      |      |      |      |                |   // init row (write value 0)
|     2      |     0    |  12   |  2   |      |      |      |      |      |      |                |
|            |          |       |  2   |      |      |      |      |      |      |                |   // padding
|            |          |       |  2   |      |      |      |      |      |      |                |   // padding
|     3      |     1    |  4    |  1   |      |      |      |      |      |      |                |
|     17     |     1    |  32   |  3   |      |      |      |      |      |      |                |
|     89     |     0    |  32   |  3   |      |      |      |      |      |      |                |
|     48     |     1    |  32   |  3   |      |      |      |      |      |      |                |
|     49     |     0    |  32   |  3   |      |      |      |      |      |      |                |
|            |          |       |  3   |      |      |      |      |      |      |                |   // padding
|     55     |     1    |  32   |  1   |      |      |      |      |      |      |         5      |   // first storage op at the new address has to be write
|     56     |     1    |  33   |  4   |      |      |      |  <RLC storageKey>  |         8      |
|            |          |       |  4   |      |      |      |      |      |      |                |   // padding
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

// const MAX_KEY0: u = 10
// const MAX_KEY1 = 2**16 - 1 // Maximum number of calls in a block
// const MAX_KEY3 = 2**40 - 1 //   Maximum value for Memory Address

const MAX_DEGREE: usize = 15;

/// A mapping derived from witnessed memory operations.
/// TODO: The complete version of this mapping will involve storage, stack,
/// and opcode details as well.
#[derive(Clone, Debug)]
pub(crate) struct BusMapping<F: FieldExt> {
    rw_counter: Variable<F, F>,
    target: Variable<F, F>,
    is_write: Variable<F, F>,
    address: Variable<F, F>,
    value: Variable<F, F>,
    storage_key: Variable<F, F>,
}

struct AssignRet<F: FieldExt>(usize, Vec<BusMapping<F>>);

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
    rw_counter: Column<Advice>,
    is_write: Column<Advice>,
    keys: [Column<Advice>; 5],
    key2_limbs: [Column<Advice>; 8],
    key4_bytes: [Column<Advice>; 32],
    value: Column<Advice>,
    auxs: [Column<Advice>; 2],

    // helper cols here
    s_enable: Column<Fixed>,
    address_diff_inv: Column<Advice>,
    account_addr_diff_inv: Column<Advice>,
    storage_key_diff_inv: Column<Advice>,

    // helper chips here
    address_diff_is_zero: IsZeroConfig<F>,      //check key3
    account_addr_diff_is_zero: IsZeroConfig<F>, //check key2
    storage_key_diff_is_zero: IsZeroConfig<F>,
    address_monotone: MonotoneConfig,

    // range tables here, TODO: organize them to a single struct?
    rw_counter_table: Column<Fixed>,
    memory_address_table_zero: Column<Fixed>,
    stack_address_table_zero: Column<Fixed>,
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
        let key2_limbs = [(); 8].map(|_| meta.advice_column());
        let key4_bytes = [(); 32].map(|_| meta.advice_column());
        let auxs = [(); 2].map(|_| meta.advice_column());
        /*let dummy = meta.advice_column();
        let key2_limbs = [dummy; 8];
        let key4_bytes = [dummy; 32];
        let auxs = [dummy; 2];*/

        let s_enable = meta.fixed_column();

        let value = meta.advice_column();

        // would be used for both address and account_addr
        let address_diff_inv = meta.advice_column();
        let account_addr_diff_inv = meta.advice_column();
        let storage_key_diff_inv = meta.advice_column();

        let rw_counter_table = meta.fixed_column();
        let memory_address_table_zero = meta.fixed_column();
        let stack_address_table_zero = meta.fixed_column();
        let memory_value_table = meta.fixed_column();

        let new_cb = || BaseConstraintBuilder::<F>::new(MAX_DEGREE);

        let tag = keys[0];
        let call_index = keys[1];
        let address = keys[3];
        let account_addr = keys[2];
        let storage_key = keys[4];

        let one = Expression::Constant(F::from(1));

        let q_memory_first = |meta: &mut VirtualCells<F>| {
            // For first memory row it holds tag_cur = START_TAG and tag_next
            // = MEMORY_TAG.
            let tag_cur = meta.query_advice(tag, Rotation::cur());
            let tag_next = meta.query_advice(tag, Rotation::next());
            generate_lagrange_base_polynomial(tag_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(tag_next, MEMORY_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        let q_memory_not_first = |meta: &mut VirtualCells<F>| {
            let tag = meta.query_advice(tag, Rotation::cur());
            generate_lagrange_base_polynomial(tag, MEMORY_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        let q_stack_first = |meta: &mut VirtualCells<F>| {
            let tag_cur = meta.query_advice(tag, Rotation::cur());
            let tag_next = meta.query_advice(tag, Rotation::next());

            generate_lagrange_base_polynomial(tag_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(tag_next, STACK_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        let q_stack_not_first = |meta: &mut VirtualCells<F>| {
            let tag = meta.query_advice(tag, Rotation::cur());
            generate_lagrange_base_polynomial(tag, STACK_TAG, EMPTY_TAG..=STORAGE_TAG)
        };
        let q_storage_first = |meta: &mut VirtualCells<F>| {
            let tag_cur = meta.query_advice(tag, Rotation::cur());
            let tag_next = meta.query_advice(tag, Rotation::next());
            generate_lagrange_base_polynomial(tag_cur, START_TAG, EMPTY_TAG..=STORAGE_TAG)
                * generate_lagrange_base_polynomial(tag_next, STORAGE_TAG, EMPTY_TAG..=STORAGE_TAG)
        };
        let q_storage_not_first = |meta: &mut VirtualCells<F>| {
            let tag = meta.query_advice(tag, Rotation::cur());
            generate_lagrange_base_polynomial(tag, STORAGE_TAG, EMPTY_TAG..=STORAGE_TAG)
        };

        /*
           try to detect both address and account_addr's diff here, because one of them
           should be always 0, ONLY USE THIS CHIP FOR STACK/MEMORY/STORAGE
        */
        let address_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let tag = meta.query_advice(tag, Rotation::cur());
                let q_not_first = tag.clone() * (tag - one.clone());

                q_not_first * meta.query_fixed(s_enable, Rotation::cur())
            },
            |meta| {
                let address_cur = meta.query_advice(address, Rotation::cur());
                let address_prev = meta.query_advice(address, Rotation::prev());
                address_cur - address_prev
            },
            address_diff_inv,
        );
        let address_diff_is_zero_exp = address_diff_is_zero.is_zero_expression.clone();

        let account_addr_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let tag = meta.query_advice(tag, Rotation::cur());
                let q_not_first = tag.clone() * (tag - one.clone());

                q_not_first * meta.query_fixed(s_enable, Rotation::cur())
            },
            |meta| {
                let account_addr_cur = meta.query_advice(account_addr, Rotation::cur());
                let account_addr_prev = meta.query_advice(account_addr, Rotation::prev());
                account_addr_cur - account_addr_prev
            },
            account_addr_diff_inv,
        );
        let _account_addr_diff_is_zero_expr = account_addr_diff_is_zero.is_zero_expression.clone();
        let storage_key_diff_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                let tag = meta.query_advice(tag, Rotation::cur());
                let q_not_first = tag.clone() * (tag - one.clone());

                q_not_first * meta.query_fixed(s_enable, Rotation::cur())
            },
            |meta| {
                let storage_key_cur = meta.query_advice(storage_key, Rotation::cur());
                let storage_key_prev = meta.query_advice(storage_key, Rotation::prev());
                storage_key_cur - storage_key_prev
            },
            storage_key_diff_inv,
        );
        let _storage_key_diff_is_zero_exp = storage_key_diff_is_zero.is_zero_expression.clone();

        // Only one monotone gadget is used for memory and stack (with
        // MEMORY_ADDRESS_MAX as it is bigger)
        let address_monotone = MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::configure(
            meta,
            |meta| {
                // Since q_memory_not_first and q_stack_non_first are
                // mutually exclusive, q_not_first is binary.
                let q_not_first = q_memory_not_first(meta) + q_stack_not_first(meta);

                q_not_first * meta.query_fixed(s_enable, Rotation::cur())
            },
            address,
        );

        meta.create_gate("General constraints", |meta| {
            let mut cb = new_cb();
            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            cb.condition(s_enable, |cb| {
                cb.require_boolean("is_write should be boolean", is_write.clone())
            });

            cb.require_in_set(
                "tag in RwTableTag range",
                meta.query_advice(tag, Rotation::cur()),
                RwTableTag::iter().map(|x| x.expr()).collect(),
            );
            cb.constraints
        });

        // meta.lookup("0 <= call index < 2^16", );
        // meta.lookup("0 <= call id in range", );

        // A gate for the first row (does not need Rotation::prev).
        meta.create_gate("First memory row operation", |meta| {
            let value = meta.query_advice(value, Rotation::cur());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;
            let q_memory_first = q_memory_first(meta);

            // read value must be 0
            vec![meta.query_fixed(s_enable, Rotation::cur()) * q_memory_first * q_read * value]
        });

        meta.create_gate("Memory operation + padding", |meta| {
            let mut cb = new_cb();
            // if is_read:
            //      if address_cur == address_prev:
            //          value == prev_value
            //      else:
            //          value == 0
            let q_memory_not_first = q_memory_not_first(meta);

            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev = meta.query_advice(value, Rotation::prev());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;
            let address_prev = meta.query_advice(address, Rotation::prev());
            let address_cur = meta.query_advice(address, Rotation::cur());

            let address_diff = address_cur - address_prev;
            let value_diff = value_cur.clone() - value_prev;
            cb.require_zero(
                "if address changes, read value should be 0",
                address_diff * q_read.clone() * value_cur,
            );
            cb.require_zero(
                "if address does not change, read value should be the same as the previous value",
                address_diff_is_zero_exp.clone() * q_read * value_diff,
            );

            cb.gate(s_enable * q_memory_not_first)
        });

        // We don't require first stack op to be write as this is enforced by
        // evm circuit.

        meta.create_gate("Stack operation", |meta| {
            let mut cb = new_cb();
            let q_stack_not_first = q_stack_not_first(meta);

            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_prev = meta.query_advice(value, Rotation::prev());
            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;

            // If is_write == 0 (read), and rw_counter != 0, value_prev == value_cur
            // when addresses changes, we don't require the operation is write as this is
            // enforced by evm circuit
            cb.require_zero(
                "when reading, the value is the same as at the previous op",
                q_read * (value_cur - value_prev),
            );
            cb.gate(s_enable * q_stack_not_first)
        });

        // rw_counter monotonicity is checked for memory and stack when
        // address_cur == address_prev. (Recall that operations are
        // ordered first by address, and then by rw_counter.)
        meta.lookup_any("rw counter monotonicity", |meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let q_not_first = q_memory_not_first(meta) + q_stack_not_first(meta);

            vec![(
                q_not_first
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

        meta.create_gate("First storage row operation", |meta| {
            let q_storage_first = q_storage_first(meta);

            let is_write = meta.query_advice(is_write, Rotation::cur());
            let q_read = one.clone() - is_write;

            vec![
                meta.query_fixed(s_enable, Rotation::cur()) *
                q_storage_first * q_read, /* first storage op has to be
                                           * write (is_write = 1) */
            ]
        });

        meta.create_gate("Storage operation", |meta| {
            let mut cb = new_cb();
            let q_storage_not_first = q_storage_not_first(meta);

            let address_prev = meta.query_advice(address, Rotation::prev());
            let address_cur = meta.query_advice(address, Rotation::cur());
            let storage_key_prev = meta.query_advice(storage_key, Rotation::prev());
            let storage_key_cur = meta.query_advice(storage_key, Rotation::cur());

            let value_cur = meta.query_advice(value, Rotation::cur());
            let value_previous = meta.query_advice(value, Rotation::prev());

            let is_write = meta.query_advice(is_write, Rotation::cur());

            let q_read = one.clone() - is_write;

            let s_enable = meta.query_fixed(s_enable, Rotation::cur());
            cb.condition(q_read, |cb| {
                cb.require_equal(
                    "if address changes, is_write == true",
                    address_cur,
                    address_prev,
                );
                cb.require_equal(
                    "if storage_key changes, is_write == true",
                    storage_key_cur,
                    storage_key_prev,
                );
                cb.require_equal(
                    "when reading, the value is the same as at the previous op",
                    value_cur,
                    value_previous,
                )
            });
            cb.gate(s_enable * q_storage_not_first)
        });

        // rw_counter monotonicity is checked for storage when address_cur
        // == address_prev and storage_key_cur = storage_key_prev.
        // (Recall that storage operations are ordered first by account address,
        // then by storage_key, and finally by rw_counter.)

        meta.lookup_any("Global Counter in allowed range", |meta| {
            let rw_counter_table = meta.query_fixed(rw_counter_table, Rotation::cur());
            let rw_counter_prev = meta.query_advice(rw_counter, Rotation::prev());
            let rw_counter = meta.query_advice(rw_counter, Rotation::cur());
            let q_storage_not_first = q_storage_not_first(meta);

            vec![(
                q_storage_not_first
                    * account_addr_diff_is_zero.clone().is_zero_expression
                    * storage_key_diff_is_zero.clone().is_zero_expression
                    * (rw_counter - rw_counter_prev - one.clone()), /*
                                                                     * - 1 because it needs to
                                                                     *   be strictly monotone */
                rw_counter_table,
            )]
        });

        // TODO: monotone address for storage

        Config {
            rw_counter,
            value,
            is_write,
            keys,
            key2_limbs,
            key4_bytes,
            auxs,
            s_enable,
            address_diff_inv,
            account_addr_diff_inv,
            storage_key_diff_inv,

            rw_counter_table,
            memory_address_table_zero,
            stack_address_table_zero,
            memory_value_table,
            address_diff_is_zero,
            account_addr_diff_is_zero,
            address_monotone,
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

    #[allow(clippy::too_many_arguments)]
    fn assign_single_type_rows(
        &self,
        region: &mut Region<F>,
        randomness: F,
        ops: Vec<Rw>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        account_addr_diff_is_zero_chip: &IsZeroChip<F>,
        storage_key_diff_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
    ) -> Result<AssignRet<F>, Error> {
        if offset + ops.len() > ROWS_MAX {
            panic!("too many storage operations");
        }
        let mut bus_mappings: Vec<BusMapping<F>> = Vec::new();
        let mut offset = offset;
        for (index, oper) in ops.iter().enumerate() {
            let row = oper.table_assignment(randomness);
            let row_prev = if index == 0 {
                RwRow::default()
            } else {
                ops[index - 1].table_assignment(randomness)
            };
            let is_init_row = index == 0;
            let bus_mapping = self.assign_row(
                region,
                offset,
                is_init_row,
                row,
                row_prev,
                address_diff_is_zero_chip,
                account_addr_diff_is_zero_chip,
                storage_key_diff_is_zero_chip,
            )?;
            bus_mappings.push(bus_mapping);
            offset += 1;
        }
        Ok(AssignRet::<_>(offset, bus_mappings))
    }

    fn pad_rows(
        &self,
        region: &mut Region<F>,
        start_offset: usize,
        end_offset: usize,
    ) -> Result<(), Error> {
        // We pad all remaining rows to avoid the check at the first unused row.
        // Without padding, (address_cur - address_prev) would not be zero at
        // the first unused row and some checks would be triggered.

        for i in start_offset..end_offset {
            region.assign_advice(|| "target", self.tag(), i, || Ok(F::from(START_TAG as u64)))?;
            region.assign_advice(|| "memory", self.is_write, i, || Ok(F::one()))?;
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
        let account_addr_diff_is_zero_chip =
            IsZeroChip::construct(self.account_addr_diff_is_zero.clone());

        let memory_address_monotone_chip =
            MonotoneChip::<F, MEMORY_ADDRESS_MAX, true, false>::construct(
                self.address_monotone.clone(),
            );
        memory_address_monotone_chip.load(&mut layouter)?;

        let storage_key_diff_is_zero_chip =
            IsZeroChip::construct(self.storage_key_diff_is_zero.clone());

        layouter.assign_region(
            || "State operations",
            |mut region| {
                let mut offset = 0;

                let memory_mappings = self
                    .assign_single_type_rows(
                        &mut region,
                        randomness,
                        memory_ops.clone(),
                        &address_diff_is_zero_chip,
                        &account_addr_diff_is_zero_chip,
                        &storage_key_diff_is_zero_chip,
                        offset,
                    )
                    .unwrap();
                bus_mappings.extend(memory_mappings.1);
                offset = memory_mappings.0;

                let stack_mappings = self
                    .assign_single_type_rows(
                        &mut region,
                        randomness,
                        stack_ops.clone(),
                        &address_diff_is_zero_chip,
                        &account_addr_diff_is_zero_chip,
                        &storage_key_diff_is_zero_chip,
                        offset,
                    )
                    .unwrap();
                bus_mappings.extend(stack_mappings.1);
                offset = stack_mappings.0;

                let storage_mappings = self
                    .assign_single_type_rows(
                        &mut region,
                        randomness,
                        storage_ops.clone(),
                        &address_diff_is_zero_chip,
                        &account_addr_diff_is_zero_chip,
                        &storage_key_diff_is_zero_chip,
                        offset,
                    )
                    .unwrap();
                bus_mappings.extend(storage_mappings.1);
                offset = storage_mappings.0;

                self.pad_rows(&mut region, offset, ROWS_MAX)?;

                // enable all rows
                for i in 0..ROWS_MAX {
                    region.assign_fixed(|| "enable row", self.s_enable, i, || Ok(F::one()))?;
                }

                Ok(bus_mappings.clone())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        is_init_row: bool,
        row: RwRow<F>,
        row_prev: RwRow<F>,
        address_diff_is_zero_chip: &IsZeroChip<F>,
        account_addr_diff_is_zero_chip: &IsZeroChip<F>,
        storage_key_diff_is_zero_chip: &IsZeroChip<F>,
    ) -> Result<BusMapping<F>, Error> {
        let account_address = row.key2;
        let account_address_prev = row_prev.key2;
        let address = row.key3;
        let address_prev = row_prev.key3;
        let rw_counter = row.rw_counter;
        let value = row.value;
        let is_write = row.is_write;
        // TODO: use same tag later
        let target = if is_init_row {
            F::from(START_TAG as u64)
        } else {
            row.tag
        };
        let storage_key = row.key4;
        let storage_key_prev = row_prev.key4;

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

        let _account_addr_cell = region.assign_advice(
            || "account_address/key2",
            self.account_addr(),
            offset,
            || Ok(account_address),
        )?;
        let address_cell =
            region.assign_advice(|| "address", self.address(), offset, || Ok(address))?;
        let rw_counter_cell = region.assign_advice(
            || "global counter",
            self.rw_counter,
            offset,
            || Ok(rw_counter),
        )?;
        let value_cell = region.assign_advice(|| "value", self.value, offset, || Ok(value))?;
        let storage_key_cell = region.assign_advice(
            || "storage key",
            self.storage_key(),
            offset,
            || Ok(storage_key),
        )?;
        let is_write_cell =
            region.assign_advice(|| "is_write", self.is_write, offset, || Ok(is_write))?;
        let target_cell = region.assign_advice(|| "target", self.tag(), offset, || Ok(target))?;

        address_diff_is_zero_chip.assign(region, offset, Some(address - address_prev))?;
        account_addr_diff_is_zero_chip.assign(
            region,
            offset,
            Some(account_address - account_address_prev),
        )?;
        storage_key_diff_is_zero_chip.assign(
            region,
            offset,
            Some(storage_key - storage_key_prev),
        )?;

        Ok(BusMapping {
            rw_counter: Variable::<F, F>::new(rw_counter_cell, Some(rw_counter)),
            target: Variable::<F, F>::new(target_cell, Some(target)),
            is_write: Variable::<F, F>::new(is_write_cell, Some(is_write)),
            address: Variable::<F, F>::new(address_cell, Some(address)),
            value: Variable::<F, F>::new(value_cell, Some(value)),
            storage_key: Variable::<F, F>::new(storage_key_cell, Some(storage_key)),
        })
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
        const MEMORY_ADDRESS_MAX: usize,
        const STACK_ADDRESS_MAX: usize,
        const ROWS_MAX: usize,
    >
    StateCircuit<F, SANITY_CHECK, RW_COUNTER_MAX, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX, ROWS_MAX>
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
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
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
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
            >::new(Fr::rand(), $memory_ops, $stack_ops, $storage_ops);

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
            RWCounter::from(17),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(302),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
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
                Word::from(0),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(20),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(0), /* Fails because not the same
                                * as value in the previous row - note: this
                                * is WRITE. */
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
