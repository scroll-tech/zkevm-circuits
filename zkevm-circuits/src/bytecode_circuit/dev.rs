pub use super::circuit::BytecodeCircuit;

use crate::{
    bytecode_circuit::circuit::BytecodeCircuitConfigArgs,
    table::{BytecodeTable, KeccakTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

#[cfg(feature = "poseidon-codehash")]
use super::circuit::to_poseidon_hash::{
    ToHashBlockBytecodeCircuitConfigArgs, ToHashBlockCircuitConfig, HASHBLOCK_BYTES_IN_FIELD,
};

#[cfg(feature = "poseidon-codehash")]
use crate::table::PoseidonTable;
#[cfg(feature = "poseidon-codehash")]
/// alias for circuit config
pub type CircuitConfig<F> = ToHashBlockCircuitConfig<F, HASHBLOCK_BYTES_IN_FIELD>;
#[cfg(not(feature = "poseidon-codehash"))]
/// alias for circuit config
pub type CircuitConfig<F> = super::circuit::BytecodeCircuitConfig<F>;

impl<F: Field> Circuit<F> for BytecodeCircuit<F> {
    type Config = (CircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let bytecode_table = BytecodeTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        #[cfg(feature = "poseidon-codehash")]
        let poseidon_table = PoseidonTable::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            let args = BytecodeCircuitConfigArgs {
                bytecode_table,
                keccak_table,
                challenges,
            };
            #[cfg(feature = "poseidon-codehash")]
            let args = ToHashBlockBytecodeCircuitConfigArgs {
                base_args: args,
                poseidon_table,
            };

            CircuitConfig::new(meta, args)
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        config.keccak_table.dev_load(
            &mut layouter,
            self.bytecodes.iter().map(|b| &b.bytes),
            &challenges,
        )?;
        #[cfg(feature = "poseidon-codehash")]
        config
            .poseidon_table
            .dev_load(&mut layouter, self.bytecodes.iter().map(|b| &b.bytes))?;
        self.synthesize_sub(&config, &challenges, &mut layouter)?;
        Ok(())
    }
}
