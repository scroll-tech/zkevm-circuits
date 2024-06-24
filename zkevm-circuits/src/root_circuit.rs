//! The Root circuit implementation.
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::serde::SerdeObject,
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use maingate::MainGateInstructions;
use snark_verifier::{util::arithmetic::MultiMillerLoop, verifier::plonk::PlonkProtocol};
use std::iter;

mod aggregation;

#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use self::RootCircuit as TestRootCircuit;

pub use aggregation::{
    aggregate, AggregationConfig, EccChip, Halo2Loader, KzgAs, KzgDk, KzgSvk,
    PlonkSuccinctVerifier, PlonkVerifier, PoseidonTranscript, Snark, SnarkWitness, BITS, LIMBS,
};
pub use snark_verifier::system::halo2::{compile, Config};

#[cfg(any(feature = "test", test))]
pub use aggregation::TestAggregationCircuit;

/// RootCircuit for aggregating SuperCircuit into a much smaller proof.
#[derive(Clone)]
pub struct RootCircuit<'a, M: MultiMillerLoop> {
    svk: KzgSvk<M>,
    snark: SnarkWitness<'a, M::G1Affine>,
    instance: Vec<M::Scalar>,
}

impl<'a, M: MultiMillerLoop> RootCircuit<'a, M>
where
    M::G1Affine: SerdeObject,
    M::G2Affine: SerdeObject,
{
    /// Create a `RootCircuit` with accumulator computed given a `SuperCircuit`
    /// proof and its instance. Returns `None` if given proof is invalid.
    pub fn new(
        params: &ParamsKZG<M>,
        super_circuit_protocol: &'a PlonkProtocol<M::G1Affine>,
        super_circuit_instances: Value<&'a Vec<Vec<M::Scalar>>>,
        super_circuit_proof: Value<&'a [u8]>,
    ) -> Result<Self, snark_verifier::Error> {
        let num_instances = super_circuit_protocol.num_instance.iter().sum::<usize>() + 4 * LIMBS;
        let instance = {
            let mut instance = Ok(vec![M::Scalar::zero(); num_instances]);
            super_circuit_instances
                .as_ref()
                .zip(super_circuit_proof.as_ref())
                .map(|(super_circuit_instances, super_circuit_proof)| {
                    let snark = Snark::new(
                        super_circuit_protocol,
                        super_circuit_instances,
                        super_circuit_proof,
                    );
                    instance = aggregate::<M>(params, [snark]).map(|accumulator_limbs| {
                        iter::empty()
                            // Propagate `SuperCircuit`'s instance
                            .chain(super_circuit_instances.iter().flatten().cloned())
                            // Output aggregated accumulator limbs
                            .chain(accumulator_limbs)
                            .collect_vec()
                    });
                });
            instance?
        };
        debug_assert_eq!(instance.len(), num_instances);

        Ok(Self {
            svk: KzgSvk::<M>::new(params.get_g()[0]),
            snark: SnarkWitness::new(
                super_circuit_protocol,
                super_circuit_instances,
                super_circuit_proof,
            ),
            instance,
        })
    }

    /// Returns accumulator indices in instance columns, which will be in
    /// the last `4 * LIMBS` rows of instance column in `MainGate`.
    pub fn accumulator_indices(&self) -> Vec<(usize, usize)> {
        let offset = self.snark.protocol().num_instance.iter().sum::<usize>();
        (offset..).map(|idx| (0, idx)).take(4 * LIMBS).collect()
    }

    /// Returns number of instance
    pub fn num_instance(&self) -> Vec<usize> {
        vec![self.snark.protocol().num_instance.iter().sum::<usize>() + 4 * LIMBS]
    }

    /// Returns instance
    pub fn instance(&self) -> Vec<Vec<M::Scalar>> {
        vec![self.instance.clone()]
    }
}

impl<'a, M: MultiMillerLoop> Circuit<M::Scalar> for RootCircuit<'a, M> {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snark: self.snark.without_witnesses(),
            instance: vec![M::Scalar::zero(); self.instance.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<M::Scalar>) -> Self::Config {
        AggregationConfig::configure::<M::G1Affine>(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<M::Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;
        let (instance, accumulator_limbs) =
            config.aggregate::<M>(&mut layouter, &self.svk, [self.snark])?;

        // Constrain equality to instance values
        let main_gate = config.main_gate();
        for (row, limb) in instance
            .into_iter()
            .flatten()
            .flatten()
            .chain(accumulator_limbs)
            .enumerate()
        {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }

        Ok(())
    }
}
