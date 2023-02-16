use super::bytecode_unroller::{unroll, UnrolledBytecode};
#[cfg(feature = "poseidon-codehash")]
use super::circuit::to_poseidon_hash::{
    ToHashBlockBytecodeCircuitConfigArgs, ToHashBlockCircuitConfig, HASHBLOCK_BYTES_IN_FIELD,
};
#[cfg(not(feature = "poseidon-codehash"))]
use super::circuit::BytecodeCircuitConfig;
use super::circuit::{BytecodeCircuit, BytecodeCircuitConfigArgs};
#[cfg(feature = "poseidon-codehash")]
use crate::table::PoseidonTable;
use crate::table::{BytecodeTable, KeccakTable};
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
use log::error;

#[cfg(feature = "poseidon-codehash")]
///alias for circuit config
pub type CircuitConfig<F> = ToHashBlockCircuitConfig<F, HASHBLOCK_BYTES_IN_FIELD>;
#[cfg(not(feature = "poseidon-codehash"))]
///alias for circuit config
pub type CircuitConfig<F> = BytecodeCircuitConfig<F>;

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
        config.poseidon_table.dev_load(
            &mut layouter,
            self.bytecodes.iter().map(|b| &b.bytes),
            &challenges,
        )?;

        self.synthesize_sub(&config, &challenges, &mut layouter)?;
        Ok(())
    }
}

impl<F: Field> BytecodeCircuit<F> {
    /// Verify that the selected bytecode fulfills the circuit
    pub fn verify_raw(k: u32, bytecodes: Vec<Vec<u8>>) {
        let unrolled: Vec<_> = bytecodes.iter().map(|b| unroll(b.clone())).collect();
        Self::verify(k, unrolled, true);
    }

    pub(crate) fn verify(k: u32, bytecodes: Vec<UnrolledBytecode<F>>, success: bool) {
        let circuit = BytecodeCircuit::<F>::new(bytecodes, 2usize.pow(k));

        let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
        let result = prover.verify();
        if let Err(failures) = &result {
            for failure in failures.iter() {
                error!("{}", failure);
            }
        }
        assert_eq!(result.is_ok(), success);
    }
}

/// Test bytecode circuit with unrolled bytecode
pub fn test_bytecode_circuit_unrolled<F: Field>(
    k: u32,
    bytecodes: Vec<UnrolledBytecode<F>>,
    success: bool,
) {
    let circuit = BytecodeCircuit::<F>::new(bytecodes, 2usize.pow(k));

    let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
    let result = prover.verify_par();
    if let Err(failures) = &result {
        for failure in failures.iter() {
            error!("{}", failure);
        }
    }
    let error_msg = if success { "valid" } else { "invalid" };
    assert_eq!(result.is_ok(), success, "proof must be {}", error_msg);
}
