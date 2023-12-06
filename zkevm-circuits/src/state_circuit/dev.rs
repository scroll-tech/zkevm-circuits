pub use super::StateCircuit;

use crate::{
    state_circuit::{StateCircuitConfig, StateCircuitConfigArgs},
    table::{MptTable, RwTable, UXTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};

impl<F: Field> Circuit<F> for StateCircuit<F>
where
    F: Field,
{
    type Config = (StateCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rw_table = RwTable::construct(meta);
        let mpt_table = MptTable::construct(meta);
        let u8_table = UXTable::construct(meta);
        let u10_table = UXTable::construct(meta);
        let u16_table = UXTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    rw_table,
                    mpt_table,
                    u8_table,
                    u10_table,
                    u16_table,
                    challenges,
                },
            )
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        config.mpt_table.load(
            &mut layouter,
            &self.updates,
            self.n_rows,
            challenges.evm_word(),
        )?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum AdviceColumn {
    IsWrite,
    Address,
    AddressLimb0,
    AddressLimb1,
    _StorageKeyLo,
    _StorageKeyHi,
    StorageKeyLimb0,
    _StorageKeyLimb1,
    StorageKeyByte0,
    StorageKeyByte1,
    ValueLo,
    ValueHi,
    ValuePrevLo,
    ValuePrevHi,
    RwCounter,
    RwCounterLimb0,
    RwCounterLimb1,
    Tag,
    TagBit0,
    TagBit1,
    TagBit2,
    TagBit3,
    LimbIndexBit0, // most significant bit
    LimbIndexBit1,
    LimbIndexBit2,
    LimbIndexBit3,
    LimbIndexBit4, // least significant bit
    InitialValueLo,
    InitialValueHi,
    IsZero, // committed_value and value are 0
    // NonEmptyWitness is the BatchedIsZero chip witness that contains the
    // inverse of the non-zero value if any in [committed_value, value]
    NonEmptyWitness,
}

impl AdviceColumn {
    pub fn value<F: Field>(&self, config: &StateCircuitConfig<F>) -> Column<Advice> {
        match self {
            Self::IsWrite => config.rw_table.is_write,
            Self::Address => config.rw_table.address,
            Self::AddressLimb0 => config.sort_keys.address.limbs[0],
            Self::AddressLimb1 => config.sort_keys.address.limbs[1],
            Self::_StorageKeyLo => config.rw_table.storage_key.lo(),
            Self::_StorageKeyHi => config.rw_table.storage_key.hi(),
            Self::StorageKeyLimb0 => config.sort_keys.storage_key.limbs[0],
            Self::_StorageKeyLimb1 => config.sort_keys.storage_key.limbs[1],
            Self::StorageKeyByte0 => config.sort_keys.storage_key.limbs[0],
            Self::StorageKeyByte1 => config.sort_keys.storage_key.limbs[1],
            Self::ValueLo => config.rw_table.value.lo(),
            Self::ValueHi => config.rw_table.value.hi(),
            Self::ValuePrevLo => config.rw_table.value_prev.lo(),
            Self::ValuePrevHi => config.rw_table.value_prev.hi(),
            Self::RwCounter => config.rw_table.rw_counter,
            Self::RwCounterLimb0 => config.sort_keys.rw_counter.limbs[0],
            Self::RwCounterLimb1 => config.sort_keys.rw_counter.limbs[1],
            Self::Tag => config.rw_table.tag,
            Self::TagBit0 => config.sort_keys.tag.bits[0],
            Self::TagBit1 => config.sort_keys.tag.bits[1],
            Self::TagBit2 => config.sort_keys.tag.bits[2],
            Self::TagBit3 => config.sort_keys.tag.bits[3],
            Self::LimbIndexBit0 => config.lexicographic_ordering.first_different_limb.bits[0],
            Self::LimbIndexBit1 => config.lexicographic_ordering.first_different_limb.bits[1],
            Self::LimbIndexBit2 => config.lexicographic_ordering.first_different_limb.bits[2],
            Self::LimbIndexBit3 => config.lexicographic_ordering.first_different_limb.bits[3],
            Self::LimbIndexBit4 => config.lexicographic_ordering.first_different_limb.bits[4],
            Self::InitialValueLo => config.initial_value.lo(),
            Self::InitialValueHi => config.initial_value.hi(),
            Self::IsZero => config.is_non_exist.is_zero,
            Self::NonEmptyWitness => config.is_non_exist.nonempty_witness,
        }
    }
}
