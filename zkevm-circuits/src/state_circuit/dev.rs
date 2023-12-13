pub use super::StateCircuit;

use crate::{
    state_circuit::{StateCircuitConfig, StateCircuitConfigArgs},
    table::{MptTable, RwTable},
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
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    rw_table,
                    mpt_table,
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
    StorageKey,
    StorageKeyByte0,
    StorageKeyByte1,
    Value,
    ValuePrev,
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
    InitialValue,
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
            Self::StorageKey => config.rw_table.storage_key,
            Self::StorageKeyByte0 => config.sort_keys.storage_key.bytes[0],
            Self::StorageKeyByte1 => config.sort_keys.storage_key.bytes[1],
            Self::Value => config.rw_table.value,
            Self::ValuePrev => config.rw_table.value_prev,
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
            Self::InitialValue => config.initial_value,
            Self::IsZero => config.is_non_exist.is_zero,
            Self::NonEmptyWitness => config.is_non_exist.nonempty_witness,
        }
    }
}
