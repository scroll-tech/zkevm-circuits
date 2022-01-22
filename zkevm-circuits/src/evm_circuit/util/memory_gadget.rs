use crate::{
    evm_circuit::{
        param::{
            N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
        },
        util::{
            constraint_builder::ConstraintBuilder,
            from_bytes,
            math_gadget::IsZeroGadget,
            math_gadget::{ConstantDivisionGadget, MinMaxGadget},
            sum, Cell, MemoryAddress, Word,
        },
    },
    util::Expr,
};
use array_init::array_init;
use eth_types::evm_types::GasCost;
use eth_types::{ToLittleEndian, U256};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Expression};
use std::convert::TryInto;

/// Decodes the usable part of an address stored in a Word
pub(crate) mod address_low {
    use crate::evm_circuit::{
        param::N_BYTES_MEMORY_ADDRESS,
        util::{from_bytes, Word},
    };
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(address: &Word<F>) -> Expression<F> {
        from_bytes::expr(&address.cells[..N_BYTES_MEMORY_ADDRESS])
    }

    pub(crate) fn value(address: [u8; 32]) -> u64 {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&address[..N_BYTES_MEMORY_ADDRESS]);
        u64::from_le_bytes(bytes)
    }
}

/// The sum of bytes of the address that are unused for most calculations on the
/// address
pub(crate) mod address_high {
    use crate::evm_circuit::{
        param::N_BYTES_MEMORY_ADDRESS,
        util::{sum, Word},
    };
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(address: &Word<F>) -> Expression<F> {
        sum::expr(&address.cells[N_BYTES_MEMORY_ADDRESS..])
    }

    pub(crate) fn value<F: FieldExt>(address: [u8; 32]) -> F {
        sum::value::<F>(&address[N_BYTES_MEMORY_ADDRESS..])
    }
}

/// Convert the dynamic memory offset and length from random linear combiation
/// to integer. It handles the "no expansion" feature when length is zero.
#[derive(Clone, Debug)]
pub(crate) struct MemoryAddressGadget<F> {
    memory_offset: Cell<F>,
    memory_offset_bytes: MemoryAddress<F>,
    memory_length: MemoryAddress<F>,
    memory_length_is_zero: IsZeroGadget<F>,
}

impl<F: FieldExt> MemoryAddressGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        memory_offset: Cell<F>,
        memory_length: MemoryAddress<F>,
    ) -> Self {
        let memory_length_is_zero =
            IsZeroGadget::construct(cb, sum::expr(&memory_length.cells));
        let memory_offset_bytes = cb.query_rlc();

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

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        memory_offset: U256,
        memory_length: U256,
        randomness: F,
    ) -> Result<u64, Error> {
        let memory_offset_bytes = memory_offset.to_le_bytes();
        let memory_length_bytes = memory_length.to_le_bytes();
        let memory_length_is_zero = memory_length.is_zero();
        self.memory_offset.assign(
            region,
            offset,
            Some(Word::random_linear_combine(memory_offset_bytes, randomness)),
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
        self.memory_length_is_zero.assign(
            region,
            offset,
            sum::value(&memory_length_bytes),
        )?;
        Ok(if memory_length_is_zero {
            0
        } else {
            address_low::value(memory_offset_bytes)
                + address_low::value(memory_length_bytes)
        })
    }

    pub(crate) fn offset(&self) -> Expression<F> {
        (1.expr() - self.memory_length_is_zero.expr())
            * from_bytes::expr(&self.memory_offset_bytes.cells)
    }

    pub(crate) fn length(&self) -> Expression<F> {
        from_bytes::expr(&self.memory_length.cells)
    }

    pub(crate) fn address(&self) -> Expression<F> {
        self.offset() + self.length()
    }
}

/// Calculates the memory size in words required for a memory access at the
/// specified address.
/// `memory_word_size = ceil(address/32) = floor((address + 31) / 32)`
#[derive(Clone, Debug)]
pub(crate) struct MemoryWordSizeGadget<F> {
    memory_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: FieldExt> MemoryWordSizeGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        address: Expression<F>,
    ) -> Self {
        let memory_word_size =
            ConstantDivisionGadget::construct(cb, address + 31.expr(), 32);

        Self { memory_word_size }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.memory_word_size.quotient()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: u64,
    ) -> Result<u64, Error> {
        let (quotient, _) = self.memory_word_size.assign(
            region,
            offset,
            (address as u128) + 31,
        )?;
        Ok(quotient as u64)
    }
}

/// Returns (new memory size, memory gas cost) for a memory access.
/// If the memory needs to be expanded this will result in an extra gas cost.
/// This gas cost is the difference between the next and current memory costs:
/// `memory_cost = Gmem * memory_word_size + floor(memory_word_size *
/// memory_word_size / 512)`
#[derive(Clone, Debug)]
pub(crate) struct MemoryExpansionGadget<
    F,
    const N: usize,
    const N_BYTES_MEMORY_WORD_SIZE: usize,
> {
    memory_word_sizes: [MemoryWordSizeGadget<F>; N],
    max_memory_word_sizes: [MinMaxGadget<F, N_BYTES_MEMORY_WORD_SIZE>; N],
    curr_quad_memory_cost: ConstantDivisionGadget<F, N_BYTES_GAS>,
    next_quad_memory_cost: ConstantDivisionGadget<F, N_BYTES_GAS>,
    next_memory_word_size: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: FieldExt, const N: usize, const N_BYTES_MEMORY_WORD_SIZE: usize>
    MemoryExpansionGadget<F, N, N_BYTES_MEMORY_WORD_SIZE>
{
    /// Input requirements:
    /// - `curr_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `address < 32 * 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// Output ranges:
    /// - `next_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
    /// - `gas_cost <= GAS_MEM*256**MAX_MEMORY_SIZE_IN_BYTES +
    ///   256**MAX_QUAD_COST_IN_BYTES`
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        curr_memory_word_size: Expression<F>,
        addresses: [Expression<F>; N],
    ) -> Self {
        // Calculate the memory size of the memory access
        // `address_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
        let memory_word_sizes = addresses
            .map(|address| MemoryWordSizeGadget::construct(cb, address));

        // The memory size needs to be updated if this memory access
        // requires expanding the memory.
        // `next_memory_word_size < 256**MAX_MEMORY_SIZE_IN_BYTES`
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
            + (next_quad_memory_cost.quotient()
                - curr_quad_memory_cost.quotient());

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
        region: &mut Region<'_, F>,
        offset: usize,
        curr_memory_word_size: u64,
        addresses: [u64; N],
    ) -> Result<(u64, u64), Error> {
        // Calculate the active memory size
        let memory_word_sizes = self
            .memory_word_sizes
            .iter()
            .zip(addresses.iter())
            .map(|(memory_word_size, address)| {
                memory_word_size.assign(region, offset, *address)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Calculate the next memory size
        let mut next_memory_word_size = curr_memory_word_size as u64;
        for (max_memory_word_sizes, memory_word_size) in self
            .max_memory_word_sizes
            .iter()
            .zip(memory_word_sizes.iter())
        {
            let (_, max) = max_memory_word_sizes.assign(
                region,
                offset,
                F::from(next_memory_word_size as u64),
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
            * (next_memory_word_size - curr_memory_word_size as u64)
            + (next_quad_memory_cost - curr_quad_memory_cost) as u64;

        // Return the new memory size and the memory expansion gas cost
        Ok((next_memory_word_size, memory_cost))
    }
}
