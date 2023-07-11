use super::{constraint_builder::ConstrainBuilderCommon, CachedRegion};
use crate::{
    evm_circuit::{
        param::{N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        util::{
            and,
            constraint_builder::EVMConstraintBuilder,
            from_bytes,
            math_gadget::{
                AddWordsGadget, ConstantDivisionGadget, IsZeroGadget, LtGadget, MinMaxGadget,
                RangeCheckGadget,
            },
            not, or, select, sum, Cell, CellType, MemoryAddress,
        },
    },
    util::Expr,
};
use array_init::array_init;
use eth_types::{
    evm_types::{GasCost, MAX_EXPANDED_MEMORY_ADDRESS},
    Field, ToLittleEndian, U256,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Value,
    plonk::{Error, Expression},
};
use itertools::Itertools;

/// Decodes the usable part of an address stored in a Word
pub(crate) mod address_low {
    use crate::evm_circuit::{
        param::N_BYTES_MEMORY_ADDRESS,
        util::{from_bytes, Word},
    };
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(address: &Word<F>) -> Expression<F> {
        from_bytes::expr(&address.cells[..N_BYTES_MEMORY_ADDRESS])
    }

    pub(crate) fn value(address: [u8; 32]) -> u64 {
        let mut bytes = [0; 8];
        bytes[..N_BYTES_MEMORY_ADDRESS].copy_from_slice(&address[..N_BYTES_MEMORY_ADDRESS]);
        u64::from_le_bytes(bytes)
    }
}

/// The sum of bytes of the address that are unused for most calculations on the
/// address
pub(crate) mod address_high {
    use crate::evm_circuit::{
        param::N_BYTES_MEMORY_ADDRESS,
        util::{from_bytes, Word},
    };
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(address: &Word<F>) -> Expression<F> {
        from_bytes::expr(&address.cells[N_BYTES_MEMORY_ADDRESS..])
    }

    pub(crate) fn value<F: Field>(address: [u8; 32]) -> F {
        from_bytes::value::<F>(&address[N_BYTES_MEMORY_ADDRESS..])
    }
}

/// Memory address trait to adapt for right and Uint overflow cases.
pub(crate) trait CommonMemoryAddressGadget<F: FieldExt> {
    fn construct_self(cb: &mut EVMConstraintBuilder<F>) -> Self;

    /// Return the memory address (offset + length).
    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        memory_offset: U256,
        memory_length: U256,
    ) -> Result<u64, Error>;

    /// Return original word of memory offset.
    fn offset_rlc(&self) -> Expression<F>;

    /// Return original word of memory length.
    fn length_rlc(&self) -> Expression<F>;

    /// Return valid memory length of Uint64.
    fn length(&self) -> Expression<F>;

    /// Return valid memory offset plus length.
    fn address(&self) -> Expression<F>;
}

/// Convert the dynamic memory offset and length from random linear combination
/// to integer. It handles the "no expansion" feature by setting the
/// `memory_offset_bytes` to zero when `memory_length` is zero. In this case,
/// the RLC value for `memory_offset` need not match the bytes.
#[derive(Clone, Debug)]
pub(crate) struct MemoryAddressGadget<F> {
    memory_offset: Cell<F>,
    memory_offset_bytes: MemoryAddress<F>,
    memory_length: MemoryAddress<F>,
    memory_length_is_zero: IsZeroGadget<F>,
}

impl<F: Field> CommonMemoryAddressGadget<F> for MemoryAddressGadget<F> {
    fn construct_self(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();
        Self::construct(cb, offset, length)
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        memory_offset: U256,
        memory_length: U256,
    ) -> Result<u64, Error> {
        let memory_offset_bytes = memory_offset.to_le_bytes();
        let memory_length_bytes = memory_length.to_le_bytes();
        let memory_length_is_zero = memory_length.is_zero();
        self.memory_offset.assign(
            region,
            offset,
            region.word_rlc(U256::from_little_endian(&memory_offset_bytes)),
        )?;
        self.memory_offset_bytes.assign(
            region,
            offset,
            Some(if memory_length_is_zero {
                [0; 5]
            } else {
                memory_offset_bytes[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap()
            }),
        )?;
        self.memory_length.assign(
            region,
            offset,
            Some(
                memory_length_bytes[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.memory_length_is_zero
            .assign(region, offset, sum::value(&memory_length_bytes))?;
        Ok(if memory_length_is_zero {
            0
        } else {
            address_low::value(memory_offset_bytes) + address_low::value(memory_length_bytes)
        })
    }

    fn offset_rlc(&self) -> Expression<F> {
        self.memory_offset.expr()
    }

    fn length_rlc(&self) -> Expression<F> {
        self.memory_length.expr()
    }

    fn length(&self) -> Expression<F> {
        from_bytes::expr(&self.memory_length.cells)
    }

    fn address(&self) -> Expression<F> {
        self.offset() + self.length()
    }
}

impl<F: Field> MemoryAddressGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        memory_offset: Cell<F>,
        memory_length: MemoryAddress<F>,
    ) -> Self {
        debug_assert_eq!(
            CellType::StoragePhase2,
            cb.curr.cell_manager.columns()[memory_offset.cell_column_index].cell_type
        );
        let memory_length_is_zero =
            IsZeroGadget::construct(cb, "", sum::expr(&memory_length.cells));
        let memory_offset_bytes = cb.query_word_rlc();

        let has_length = 1.expr() - memory_length_is_zero.expr();
        cb.condition(has_length, |cb| {
            cb.require_equal(
                "Offset decomposition into 5 bytes",
                memory_offset_bytes.expr(),
                memory_offset.expr(),
            );
        });

        Self {
            memory_offset,
            memory_offset_bytes,
            memory_length,
            memory_length_is_zero,
        }
    }

    pub(crate) fn has_length(&self) -> Expression<F> {
        1.expr() - self.memory_length_is_zero.expr()
    }

    pub(crate) fn offset(&self) -> Expression<F> {
        self.has_length() * from_bytes::expr(&self.memory_offset_bytes.cells)
    }
}

/// Check if memory offset plus length is within range or Uint overflow.
/// The sum of memory offset and length should also be less than or equal to
/// `0x1FFFFFFFE0` (which is less than `u64::MAX - 31`).
/// Reference go-ethereum code as:
/// . [calcMemSize64WithUint](https://github.com/ethereum/go-ethereum/blob/db18293c32f6dc5d6886e5e68ab8bfd12e33cad6/core/vm/common.go#L37)
/// . [memoryGasCost](https://github.com/ethereum/go-ethereum/blob/db18293c32f6dc5d6886e5e68ab8bfd12e33cad6/core/vm/gas_table.go#L38)
/// . [toWordSize](https://github.com/ethereum/go-ethereum/blob/db18293c32f6dc5d6886e5e68ab8bfd12e33cad6/core/vm/common.go#L67)
#[derive(Clone, Debug)]
pub(crate) struct MemoryExpandedAddressGadget<F> {
    length_is_zero: IsZeroGadget<F>,
    offset_length_sum: AddWordsGadget<F, 2, false>,
    sum_lt_cap: LtGadget<F, N_BYTES_U64>,
    sum_within_u64: IsZeroGadget<F>,
}

impl<F: Field> CommonMemoryAddressGadget<F> for MemoryExpandedAddressGadget<F> {
    fn construct_self(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let offset = cb.query_word_rlc();
        let length = cb.query_word_rlc();
        let sum = cb.query_word_rlc();

        let sum_lt_cap = LtGadget::construct(
            cb,
            from_bytes::expr(&sum.cells[..N_BYTES_U64]),
            (MAX_EXPANDED_MEMORY_ADDRESS + 1).expr(),
        );

        let sum_overflow_hi = sum::expr(&sum.cells[N_BYTES_U64..]);
        let sum_within_u64 = IsZeroGadget::construct(cb, "", sum_overflow_hi);

        let length_is_zero = IsZeroGadget::construct(cb, "", sum::expr(&length.cells));
        let offset_length_sum = AddWordsGadget::construct(cb, [offset, length], sum);

        Self {
            length_is_zero,
            offset_length_sum,
            sum_lt_cap,
            sum_within_u64,
        }
    }

    fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        memory_offset: U256,
        memory_length: U256,
    ) -> Result<u64, Error> {
        let length_bytes = memory_length
            .to_le_bytes()
            .iter()
            .fold(0, |acc, val| acc + u64::from(*val));
        self.length_is_zero
            .assign(region, offset, F::from(length_bytes))?;

        let (sum, sum_word_overflow) = memory_offset.overflowing_add(memory_length);
        self.offset_length_sum
            .assign(region, offset, [memory_offset, memory_length], sum)?;

        self.sum_lt_cap.assign(
            region,
            offset,
            F::from(sum.low_u64()),
            F::from(MAX_EXPANDED_MEMORY_ADDRESS + 1),
        )?;

        let sum_overflow_hi_bytes = sum.to_le_bytes()[N_BYTES_U64..]
            .iter()
            .fold(0, |acc, val| acc + u64::from(*val));
        self.sum_within_u64
            .assign(region, offset, F::from(sum_overflow_hi_bytes))?;

        let address = if length_bytes == 0
            || sum_overflow_hi_bytes != 0
            || sum_word_overflow
            || sum.low_u64() > MAX_EXPANDED_MEMORY_ADDRESS
        {
            0
        } else {
            sum.low_u64()
        };

        Ok(address)
    }

    fn offset_rlc(&self) -> Expression<F> {
        let addends = self.offset_length_sum.addends();
        addends[0].expr()
    }

    fn length_rlc(&self) -> Expression<F> {
        let addends = self.offset_length_sum.addends();
        addends[1].expr()
    }

    fn length(&self) -> Expression<F> {
        let addends = self.offset_length_sum.addends();
        select::expr(
            self.within_range(),
            from_bytes::expr(&addends[1].cells[..N_BYTES_U64]),
            0.expr(),
        )
    }

    /// Return expanded address if within range, otherwise return 0.
    fn address(&self) -> Expression<F> {
        select::expr(
            self.length_is_zero.expr(),
            0.expr(),
            select::expr(
                self.within_range(),
                from_bytes::expr(&self.offset_length_sum.sum().cells[..N_BYTES_U64]),
                0.expr(),
            ),
        )
    }
}

impl<F: Field> MemoryExpandedAddressGadget<F> {
    /// Return the valid length value corresponding to function `length`
    /// (which returns an Expression).
    pub(crate) fn length_value(memory_offset: U256, memory_length: U256) -> u64 {
        if memory_length.is_zero() {
            return 0;
        }

        memory_offset
            .checked_add(memory_length)
            .map_or(0, |address| {
                if address > MAX_EXPANDED_MEMORY_ADDRESS.into() {
                    0
                } else {
                    memory_length.as_u64()
                }
            })
    }

    /// Check if overflow.
    pub(crate) fn overflow(&self) -> Expression<F> {
        not::expr(self.within_range())
    }

    /// Check if within range.
    pub(crate) fn within_range(&self) -> Expression<F> {
        or::expr([
            self.length_is_zero.expr(),
            and::expr([
                self.sum_lt_cap.expr(),
                self.sum_within_u64.expr(),
                not::expr(self.offset_length_sum.carry().as_ref().unwrap()),
            ]),
        ])
    }
}

/// Calculates the memory size in words required for a memory access at the
/// specified address.
/// `memory_word_size = ceil(address/32) = floor((address + 31) / 32)`
#[derive(Clone, Debug)]
pub(crate) struct MemoryWordSizeGadget<F> {
    memory_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> MemoryWordSizeGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, address: Expression<F>) -> Self {
        let memory_word_size = ConstantDivisionGadget::construct(cb, address + 31.expr(), 32);

        Self { memory_word_size }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.memory_word_size.quotient()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        address: u64,
    ) -> Result<u64, Error> {
        let (quotient, _) = self
            .memory_word_size
            .assign(region, offset, (address as u128) + 31)?;
        Ok(quotient as u64)
    }
}

/// Returns (new memory size, memory gas cost) for a memory access.
/// If the memory needs to be expanded this will result in an extra gas cost.
/// This gas cost is the difference between the next and current memory costs:
/// `memory_cost = Gmem * memory_word_size + floor(memory_word_size *
/// memory_word_size / 512)`
#[derive(Clone, Debug)]
pub(crate) struct MemoryExpansionGadget<F, const N: usize, const N_BYTES_MEMORY_WORD_SIZE: usize> {
    memory_word_sizes: [MemoryWordSizeGadget<F>; N],
    max_memory_word_sizes: [MinMaxGadget<F, N_BYTES_MEMORY_WORD_SIZE>; N],
    curr_quad_memory_cost: ConstantDivisionGadget<F, N_BYTES_GAS>,
    next_quad_memory_cost: ConstantDivisionGadget<F, N_BYTES_GAS>,
    next_memory_word_size: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: Field, const N: usize, const N_BYTES_MEMORY_WORD_SIZE: usize>
    MemoryExpansionGadget<F, N, N_BYTES_MEMORY_WORD_SIZE>
{
    /// Input requirements:
    /// - `curr_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `address < 32 * 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// Output ranges:
    /// - `next_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `gas_cost <= GAS_MEM*256**MAX_MEMORY_SIZE_IN_BYTES + 256**MAX_QUAD_COST_IN_BYTES`
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        addresses: [Expression<F>; N],
    ) -> Self {
        // Calculate the memory size of the memory access
        // `address_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
        let memory_word_sizes =
            addresses.map(|address| MemoryWordSizeGadget::construct(cb, address));

        // The memory size needs to be updated if this memory access
        // requires expanding the memory.
        // `next_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
        let curr_memory_word_size = cb.curr.state.memory_word_size.expr();
        let mut next_memory_word_size = curr_memory_word_size.clone();
        let max_memory_word_sizes = array_init(|idx| {
            let max_memory_word_size = MinMaxGadget::construct(
                cb,
                next_memory_word_size.clone(),
                memory_word_sizes[idx].expr(),
            );
            next_memory_word_size = max_memory_word_size.max();
            max_memory_word_size
        });

        // Calculate the quad memory cost for the current and next memory size.
        // These quad costs will also be range limited to `<
        // 256**MAX_QUAD_COST_IN_BYTES`.
        let curr_quad_memory_cost = ConstantDivisionGadget::construct(
            cb,
            curr_memory_word_size.clone() * curr_memory_word_size.clone(),
            GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.as_u64(),
        );
        let next_quad_memory_cost = ConstantDivisionGadget::construct(
            cb,
            next_memory_word_size.clone() * next_memory_word_size.clone(),
            GasCost::MEMORY_EXPANSION_QUAD_DENOMINATOR.as_u64(),
        );

        // Calculate the gas cost for the memory expansion.
        // This gas cost is the difference between the next and current memory
        // costs. `gas_cost <=
        // GAS_MEM*256**MAX_MEMORY_SIZE_IN_BYTES + 256**MAX_QUAD_COST_IN_BYTES`
        let gas_cost = GasCost::MEMORY_EXPANSION_LINEAR_COEFF.expr()
            * (next_memory_word_size.clone() - curr_memory_word_size)
            + (next_quad_memory_cost.quotient() - curr_quad_memory_cost.quotient());

        Self {
            memory_word_sizes,
            max_memory_word_sizes,
            curr_quad_memory_cost,
            next_quad_memory_cost,
            next_memory_word_size,
            gas_cost,
        }
    }

    pub(crate) fn next_memory_word_size(&self) -> Expression<F> {
        // Return the new memory size
        self.next_memory_word_size.clone()
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        curr_memory_word_size: u64,
        addresses: [u64; N],
    ) -> Result<(u64, u64), Error> {
        // Calculate the active memory size
        let memory_word_sizes = self
            .memory_word_sizes
            .iter()
            .zip(addresses.iter())
            .map(|(memory_word_size, address)| memory_word_size.assign(region, offset, *address))
            .collect::<Result<Vec<_>, _>>()?;

        // Calculate the next memory size
        let mut next_memory_word_size = curr_memory_word_size;
        for (max_memory_word_sizes, memory_word_size) in self
            .max_memory_word_sizes
            .iter()
            .zip(memory_word_sizes.iter())
        {
            let (_, max) = max_memory_word_sizes.assign(
                region,
                offset,
                F::from(next_memory_word_size),
                F::from(*memory_word_size),
            )?;
            next_memory_word_size = max.get_lower_128() as u64;
        }

        // Calculate the quad gas cost for the memory size
        let (curr_quad_memory_cost, _) = self.curr_quad_memory_cost.assign(
            region,
            offset,
            (curr_memory_word_size as u128) * (curr_memory_word_size as u128),
        )?;
        let (next_quad_memory_cost, _) = self.next_quad_memory_cost.assign(
            region,
            offset,
            (next_memory_word_size as u128) * (next_memory_word_size as u128),
        )?;

        // Calculate the gas cost for the expansian
        let memory_cost = GasCost::MEMORY_EXPANSION_LINEAR_COEFF.as_u64()
            * (next_memory_word_size - curr_memory_word_size)
            + (next_quad_memory_cost - curr_quad_memory_cost) as u64;

        // Return the new memory size and the memory expansion gas cost
        Ok((next_memory_word_size, memory_cost))
    }
}

/// Returns (new memory size, memory gas cost) for a memory access.
/// If the memory needs to be expanded this will result in an extra gas cost.
/// This gas cost is the difference between the next and current memory costs:
/// `memory_cost = Gmem * memory_size + floor(memory_size * memory_size / 512)`
#[derive(Clone, Debug)]
pub(crate) struct MemoryCopierGasGadget<F, const GAS_COPY: GasCost> {
    word_size: MemoryWordSizeGadget<F>,
    gas_cost: Expression<F>,
    gas_cost_range_check: RangeCheckGadget<F, N_BYTES_GAS>,
}

impl<F: Field, const GAS_COPY: GasCost> MemoryCopierGasGadget<F, GAS_COPY> {
    pub const WORD_SIZE: u64 = 32u64;

    /// Input requirements:
    /// - `curr_memory_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `address < 32 * 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// Output ranges:
    /// - `next_memory_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `gas_cost <= GAS_MEM*256**MAX_MEMORY_SIZE_IN_BYTES + 256**MAX_QUAD_COST_IN_BYTES`
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        num_bytes: Expression<F>,
        memory_expansion_gas_cost: Expression<F>,
    ) -> Self {
        let word_size = MemoryWordSizeGadget::construct(cb, num_bytes);

        let gas_cost = word_size.expr() * GAS_COPY.expr() + memory_expansion_gas_cost;
        let gas_cost_range_check = RangeCheckGadget::construct(cb, gas_cost.clone());

        Self {
            word_size,
            gas_cost,
            gas_cost_range_check,
        }
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        num_bytes: u64,
        memory_expansion_gas_cost: u64,
    ) -> Result<u64, Error> {
        let word_size = self.word_size.assign(region, offset, num_bytes)?;
        let gas_cost = word_size * GAS_COPY.as_u64() + memory_expansion_gas_cost;
        self.gas_cost_range_check
            .assign(region, offset, F::from(gas_cost))?;
        // Return the memory copier gas cost
        Ok(gas_cost)
    }
}

/// Buffer reader gadget reads out bytes from a buffer given the start address
/// and the end address. This gadget also pads 0 to the end of buffer if the
/// access to the buffer is out of bound (addr >= addr_end).
#[derive(Clone, Debug)]
pub(crate) struct BufferReaderGadget<F, const MAX_BYTES: usize, const N_BYTES_MEMORY_ADDRESS: usize>
{
    /// The bytes read from buffer
    bytes: [Cell<F>; MAX_BYTES],
    /// The selectors that indicate if the corresponding byte contains real data
    /// or is padded
    selectors: [Cell<F>; MAX_BYTES],
    /// The min gadget to take the minimum of addr_start and addr_end
    min_gadget: MinMaxGadget<F, N_BYTES_MEMORY_ADDRESS>,
}

impl<F: Field, const MAX_BYTES: usize, const ADDR_SIZE_IN_BYTES: usize>
    BufferReaderGadget<F, MAX_BYTES, ADDR_SIZE_IN_BYTES>
{
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        addr_start: Expression<F>,
        addr_end: Expression<F>,
    ) -> Self {
        let bytes = array_init(|_| cb.query_byte());
        let selectors = array_init(|_| cb.query_bool());

        // Constraints on bytes and selectors
        for i in 0..MAX_BYTES {
            let selector_prev = if i == 0 {
                // First selector will always be 1
                1.expr()
            } else {
                selectors[i - 1].expr()
            };
            // selector can transit from 1 to 0 only once as [1, 1, 1, ...,
            // 0, 0, 0]
            cb.require_boolean(
                "Constrain selectors can only transit from 1 to 0",
                selector_prev - selectors[i].expr(),
            );
            cb.add_constraint(
                "bytes[i] == 0 when selectors[i] == 0",
                (1.expr() - selectors[i].expr()) * bytes[i].expr(),
            );
        }

        // Look at the data length, which can be negative, or within the buffer span, or larger.
        // Decide what is the other operand of the MinMaxGadget gadget. If the buffer is empty
        // because end <= start, compare the length to 0. Otherwise, compare to the buffer size.
        let is_empty = not::expr(&selectors[0]);
        let cap = select::expr(is_empty.expr(), 0.expr(), MAX_BYTES.expr());
        let signed_len = addr_end - addr_start;
        let min_gadget = MinMaxGadget::construct(cb, cap, signed_len);

        // If we claim that the buffer is empty, we prove that the end is at or before the start.
        //     buffer_len = max(0, signed_len) = 0
        cb.condition(is_empty.expr(), |cb| {
            cb.require_zero("addr_end <= addr_start", min_gadget.max());
        });

        // Otherwise, the buffer length equals the data length, capped at the buffer size.
        //     buffer_len = min(MAX_BYTES, signed_len)
        cb.condition(not::expr(is_empty), |cb| {
            let buffer_len = sum::expr(&selectors);
            let capped_len = min_gadget.min();

            cb.require_equal(
                "buffer length == end - start (capped)",
                buffer_len,
                capped_len,
            );
        });

        BufferReaderGadget {
            bytes,
            selectors,
            min_gadget,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        addr_start: u64,
        addr_end: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        assert_eq!(bytes.len(), MAX_BYTES);
        for (idx, ((byte_col, &byte_val), selector_col)) in self
            .bytes
            .iter()
            .zip_eq(bytes.iter())
            .zip_eq(self.selectors.iter())
            .enumerate()
        {
            let selector = (addr_start + idx as u64) < addr_end;
            selector_col.assign(region, offset, Value::known(F::from(selector as u64)))?;
            byte_col.assign(region, offset, Value::known(F::from(byte_val as u64)))?;
        }

        let is_empty = addr_start >= addr_end;
        let cap = if is_empty { 0 } else { MAX_BYTES };
        let signed_len = if is_empty {
            -F::from(addr_start - addr_end)
        } else {
            F::from(addr_end - addr_start)
        };
        self.min_gadget
            .assign(region, offset, F::from(cap as u64), signed_len)?;

        // Completeness: MinMaxGadget requires `signed_len ∈ (cap-RANGE; cap+RANGE]`, covering all
        // cases. If is_empty, signed_len ∈ (-RANGE; 0], otherwise signed_len ∈ [1; RANGE).
        Ok(())
    }

    pub(crate) fn byte(&self, idx: usize) -> Expression<F> {
        self.bytes[idx].expr()
    }

    /// Indicate whether the bytes\[idx\] is read from the buffer
    pub(crate) fn read_flag(&self, idx: usize) -> Expression<F> {
        self.selectors[idx].expr()
    }
}
