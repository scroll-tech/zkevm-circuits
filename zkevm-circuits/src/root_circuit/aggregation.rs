use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::{
        group::prime::PrimeCurveAffine, pairing::Engine, serde::SerdeObject, CurveAffine,
    },
    plonk::{Circuit, ConstraintSystem, Error},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::{rngs::StdRng, SeedableRng};
use snark_verifier::{
    loader::{
        self,
        halo2::{
            halo2_wrong_ecc::{self, integer::rns::Rns, maingate::*, EccConfig},
            Scalar,
        },
        native::NativeLoader,
    },
    pcs::{
        kzg::{self, *},
        AccumulationDecider, AccumulationScheme, AccumulationSchemeProver,
    },
    system::halo2::transcript,
    util::arithmetic::{fe_to_limbs, FieldExt, MultiMillerLoop},
    verifier::{self, plonk::PlonkProtocol, SnarkVerifier},
};
use std::{io, iter, rc::Rc};

/// Number of limbs to decompose a elliptic curve base field element into.
pub const LIMBS: usize = 4;
/// Number of bits of each decomposed limb.
pub const BITS: usize = 68;

/// KZG accumulation scheme with GWC19 multiopen.
pub type KzgAs<M> = kzg::KzgAs<M, Gwc19>;
/// KZG succinct verifying key
pub type KzgSvk<M> = KzgSuccinctVerifyingKey<<M as Engine>::G1Affine>;
/// KZG deciding key
pub type KzgDk<M> = KzgDecidingKey<M>;
/// Plonk succinct verifier with `KzgAs`
pub type PlonkSuccinctVerifier<M> = verifier::plonk::PlonkSuccinctVerifier<KzgAs<M>>;
/// Plonk verifier with `KzgAs` and `LimbsEncoding<LIMBS, BITS>`.
pub type PlonkVerifier<M> = verifier::plonk::PlonkVerifier<KzgAs<M>, LimbsEncoding<LIMBS, BITS>>;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;

/// `BaseFieldEccChip` with hardcoded `LIMBS` and `BITS` serving as `EccChip`
/// for `Halo2Loader`.
pub type EccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;
/// `Halo2Loader` with hardcoded `EccChip`.
pub type Halo2Loader<'a, C> = loader::halo2::Halo2Loader<'a, C, EccChip<C>>;
/// `PoseidonTranscript` with hardcoded parameter with 128-bits security.
pub type PoseidonTranscript<C, S> =
    transcript::halo2::PoseidonTranscript<C, NativeLoader, S, T, RATE, R_F, R_P>;

/// Snark contains the minimal information for verification
#[derive(Clone, Copy)]
pub struct Snark<'a, C: CurveAffine> {
    protocol: &'a PlonkProtocol<C>,
    instances: &'a Vec<Vec<C::Scalar>>,
    proof: &'a [u8],
}

impl<'a, C: CurveAffine> Snark<'a, C> {
    /// Construct `Snark` with each field.
    pub fn new(
        protocol: &'a PlonkProtocol<C>,
        instances: &'a Vec<Vec<C::Scalar>>,
        proof: &'a [u8],
    ) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }
}

impl<'a, C: CurveAffine> From<Snark<'a, C>> for SnarkWitness<'a, C> {
    fn from(snark: Snark<'a, C>) -> Self {
        Self {
            protocol: snark.protocol,
            instances: Value::known(snark.instances),
            proof: Value::known(snark.proof),
        }
    }
}

/// SnarkWitness
#[derive(Clone, Copy)]
pub struct SnarkWitness<'a, C: CurveAffine> {
    protocol: &'a PlonkProtocol<C>,
    instances: Value<&'a Vec<Vec<C::Scalar>>>,
    proof: Value<&'a [u8]>,
}

impl<'a, C: CurveAffine> SnarkWitness<'a, C> {
    /// Construct `SnarkWitness` with each field.
    pub fn new(
        protocol: &'a PlonkProtocol<C>,
        instances: Value<&'a Vec<Vec<C::Scalar>>>,
        proof: Value<&'a [u8]>,
    ) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }

    /// Returns `SnarkWitness` with all witness as `Value::unknown()`.
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol,
            instances: Value::unknown(),
            proof: Value::unknown(),
        }
    }

    /// Returns protocol as reference.
    pub fn protocol(&self) -> &PlonkProtocol<C> {
        self.protocol
    }

    /// Returns proof as reference.
    pub fn proof(&self) -> Value<&[u8]> {
        self.proof
    }

    fn loaded_instances<'b>(
        &self,
        loader: &Rc<Halo2Loader<'b, C>>,
    ) -> Vec<Vec<Scalar<'b, C, EccChip<C>>>> {
        self.instances
            .transpose_vec(self.protocol.num_instance.len())
            .into_iter()
            .zip(self.protocol.num_instance.iter())
            .map(|(instances, num_instance)| {
                instances
                    .transpose_vec(*num_instance)
                    .into_iter()
                    .map(|instance| loader.assign_scalar(instance.copied()))
                    .collect_vec()
            })
            .collect_vec()
    }
}

/// Aggregation configuration.
#[derive(Clone)]
pub struct AggregationConfig {
    /// MainGateConfig
    pub main_gate_config: MainGateConfig,
    /// RangeConfig
    pub range_config: RangeConfig,
}

impl AggregationConfig {
    /// Configure for `MainGate` and `RangeChip` with corresponding fixed lookup
    /// table.
    pub fn configure<C: CurveAffine>(meta: &mut ConstraintSystem<C::Scalar>) -> Self {
        let main_gate_config = MainGate::<C::Scalar>::configure(meta);
        let range_config = RangeChip::<C::Scalar>::configure(
            meta,
            &main_gate_config,
            vec![BITS / LIMBS],
            Rns::<C::Base, C::Scalar, LIMBS, BITS>::construct().overflow_lengths(),
        );
        Self {
            main_gate_config,
            range_config,
        }
    }

    /// Returns `MainGate`.
    pub fn main_gate<F: FieldExt>(&self) -> MainGate<F> {
        MainGate::new(self.main_gate_config.clone())
    }

    /// Returns `RangeChip`.
    pub fn range_chip<F: FieldExt>(&self) -> RangeChip<F> {
        RangeChip::new(self.range_config.clone())
    }

    /// Returns `EccChip`.
    pub fn ecc_chip<C: CurveAffine>(&self) -> EccChip<C> {
        EccChip::new(EccConfig::new(
            self.range_config.clone(),
            self.main_gate_config.clone(),
        ))
    }

    /// Load fixed lookup table for `RangeChip`
    pub fn load_table<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.range_chip().load_table(layouter)
    }

    /// Aggregate snarks into a single accumulator and decompose it into
    /// `4 * LIMBS` limbs.
    /// Returns assigned instances of snarks and aggregated accumulator limbs.
    #[allow(clippy::type_complexity)]
    pub fn aggregate<'a, M: MultiMillerLoop>(
        &self,
        layouter: &mut impl Layouter<M::Scalar>,
        svk: &KzgSvk<M>,
        snarks: impl IntoIterator<Item = SnarkWitness<'a, M::G1Affine>>,
    ) -> Result<
        (
            Vec<Vec<Vec<AssignedCell<M::Scalar, M::Scalar>>>>,
            Vec<AssignedCell<M::Scalar, M::Scalar>>,
        ),
        Error,
    > {
        type PoseidonTranscript<'a, C, S> =
            transcript::halo2::PoseidonTranscript<C, Rc<Halo2Loader<'a, C>>, S, T, RATE, R_F, R_P>;
        let snarks = snarks.into_iter().collect_vec();
        layouter.assign_region(
            || "Aggregate snarks",
            |mut region| {
                // annotate advices columns of `main_gate`. We can't annotate fixed_columns of
                // `main_gate` bcs there is no methods exported.
                for (i, col) in self.main_gate_config.advices().iter().enumerate() {
                    region.name_column(|| format!("ROOT_main_gate_{}", i), *col);
                }

                let ctx = RegionCtx::new(region, 0);

                let ecc_chip = self.ecc_chip::<M::G1Affine>();
                let loader = Halo2Loader::new(ecc_chip, ctx);

                // Verify the cheap part and get accumulator (left-hand and right-hand side of
                // pairing) of individual proof.
                let (instances, accumulators) = snarks
                    .iter()
                    .map(|snark| {
                        let protocol = snark.protocol.loaded(&loader);
                        let instances = snark.loaded_instances(&loader);
                        let mut transcript = PoseidonTranscript::new(&loader, snark.proof());
                        let proof = PlonkSuccinctVerifier::<M>::read_proof(
                            svk,
                            &protocol,
                            &instances,
                            &mut transcript,
                        )
                        .unwrap();
                        let accumulators =
                            PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof)
                                .unwrap();
                        (instances, accumulators)
                    })
                    .collect_vec()
                    .into_iter()
                    .unzip::<_, _, Vec<_>, Vec<_>>();

                // Verify proof for accumulation of all accumulators into new one.
                let accumulator = {
                    let as_vk = Default::default();
                    let as_proof = Vec::new();
                    let accumulators = accumulators.into_iter().flatten().collect_vec();
                    let mut transcript =
                        PoseidonTranscript::new(&loader, Value::known(as_proof.as_slice()));
                    let proof =
                        KzgAs::<M>::read_proof(&as_vk, &accumulators, &mut transcript).unwrap();
                    KzgAs::<M>::verify(&as_vk, &accumulators, &proof).unwrap()
                };

                let instances = instances
                    .iter()
                    .map(|instances| {
                        instances
                            .iter()
                            .map(|instances| {
                                instances
                                    .iter()
                                    .map(|instance| instance.assigned().to_owned())
                                    .collect_vec()
                            })
                            .collect_vec()
                    })
                    .collect_vec();
                let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                    .iter()
                    .map(|ec_point| {
                        loader
                            .ecc_chip()
                            .assign_ec_point_to_limbs(&mut loader.ctx_mut(), ec_point.assigned())
                    })
                    .collect::<Result<Vec<_>, Error>>()?
                    .into_iter()
                    .flatten()
                    .collect();

                Ok((instances, accumulator_limbs))
            },
        )
    }
}

/// Aggregate snarks into a single accumulator and decompose it into
/// `4 * LIMBS` limbs.
/// Returns `None` if any given snarks is invalid.
pub fn aggregate<'a, M: MultiMillerLoop>(
    params: &ParamsKZG<M>,
    snarks: impl IntoIterator<Item = Snark<'a, M::G1Affine>>,
) -> Result<[M::Scalar; 4 * LIMBS], snark_verifier::Error>
where
    M::G1Affine: SerdeObject,
    M::G2Affine: SerdeObject,
{
    let svk = KzgSvk::<M>::new(params.get_g()[0]);
    let dk = KzgDk::new(svk, params.g2(), params.s_g2());

    // Use the same logic of verifier to get accumulator (left-hand and right-hand
    // side of pairing) of individual proof.
    let accumulators = snarks
        .into_iter()
        .map(|snark| {
            let mut transcript = PoseidonTranscript::new(snark.proof);
            let proof = PlonkSuccinctVerifier::<M>::read_proof(
                &svk,
                snark.protocol,
                snark.instances,
                &mut transcript,
            )?;
            for commitment in iter::empty()
                .chain(snark.protocol.preprocessed.iter())
                .chain(proof.witnesses.iter())
                .chain(proof.quotients.iter())
            {
                if bool::from(commitment.is_identity()) {
                    return Err(snark_verifier::Error::Transcript(
                        io::ErrorKind::Other,
                        "Identity point in preprocessed or proof is not yet supported".to_string(),
                    ));
                }
            }
            PlonkSuccinctVerifier::verify(&svk, snark.protocol, snark.instances, &proof)
        })
        .try_collect::<_, Vec<_>, _>()?
        .into_iter()
        .flatten()
        .collect_vec();

    // Create proof for accumulation of all accumulators into new one.
    // In our case (KZG without zero-knowledge), it's no-ops since the verifier
    // could add up the accumulators into the new one itself in circuit.
    let accumulator = {
        let as_pk = Default::default();
        let rng = StdRng::from_seed(Default::default());
        let mut transcript = PoseidonTranscript::new(Vec::new());
        let accumulator = KzgAs::<M>::create_proof(&as_pk, &accumulators, &mut transcript, rng)?;
        assert!(transcript.finalize().is_empty());
        accumulator
    };
    KzgAs::<M>::decide(&dk, accumulator.clone())?;

    let KzgAccumulator { lhs, rhs } = accumulator;
    let accumulator_limbs = [lhs, rhs]
        .into_iter()
        .flat_map(|point| {
            let coordinates = point.coordinates().unwrap();
            [*coordinates.x(), *coordinates.y()]
        })
        .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .collect_vec()
        .try_into()
        .unwrap();
    Ok(accumulator_limbs)
}

/// Aggregation circuit for testing purpose.
#[derive(Clone)]
pub struct TestAggregationCircuit<'a, M: MultiMillerLoop> {
    svk: KzgSvk<M>,
    snarks: Vec<SnarkWitness<'a, M::G1Affine>>,
    instances: Vec<M::Scalar>,
}

impl<'a, M: MultiMillerLoop> TestAggregationCircuit<'a, M>
where
    M::G1Affine: SerdeObject,
    M::G2Affine: SerdeObject,
{
    /// Create an Aggregation circuit with aggregated accumulator computed.
    /// Returns `None` if any given snark is invalid.
    pub fn new(
        params: &ParamsKZG<M>,
        snarks: impl IntoIterator<Item = Snark<'a, M::G1Affine>>,
    ) -> Result<Self, snark_verifier::Error> {
        let snarks = snarks.into_iter().collect_vec();

        let accumulator_limbs = aggregate(params, snarks.clone())?;
        let instances = iter::empty()
            // Propagate aggregated snarks' instances
            .chain(
                snarks
                    .iter()
                    .flat_map(|snark| snark.instances.clone())
                    .flatten(),
            )
            // Output aggregated accumulator
            .chain(accumulator_limbs)
            .collect_vec();

        Ok(Self {
            svk: KzgSvk::<M>::new(params.get_g()[0]),
            snarks: snarks.into_iter().map_into().collect(),
            instances,
        })
    }

    /// Returns accumulator indices in instance columns, which will be in
    /// the last 4 * LIMBS rows of MainGate's instance column.
    pub fn accumulator_indices(&self) -> Vec<(usize, usize)> {
        (self.instances.len() - 4 * LIMBS..)
            .map(|idx| (0, idx))
            .take(4 * LIMBS)
            .collect()
    }

    /// Returns number of instance
    pub fn num_instance(&self) -> Vec<usize> {
        vec![self.instances.len()]
    }

    /// Returns instances
    pub fn instances(&self) -> Vec<Vec<M::Scalar>> {
        vec![self.instances.clone()]
    }
}

impl<'a, M: MultiMillerLoop> Circuit<M::Scalar> for TestAggregationCircuit<'a, M> {
    type Config = AggregationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: vec![M::Scalar::zero(); self.instances.len()],
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
        let (instances, accumulator_limbs) =
            config.aggregate::<M>(&mut layouter, &self.svk, self.snarks.clone())?;

        // Constrain equality to instance values
        let main_gate = config.main_gate();
        for (row, limb) in instances
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

/// Contains TestAggregationCircuit to test whether aggregation is working for
/// any given inputs.
#[cfg(test)]
pub mod test {
    use crate::root_circuit::{PoseidonTranscript, Snark, TestAggregationCircuit};
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{floor_planner::V1, Layouter, Value},
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::{
            bn256::{Bn256, Fr, G1Affine},
            CurveAffine,
        },
        plonk::{
            create_proof, keygen_pk, keygen_vk, Advice, Any, Circuit, Column, ConstraintSystem,
            Error, Fixed,
        },
        poly::{
            kzg::{
                commitment::{KZGCommitmentScheme, ParamsKZG},
                multiopen::ProverGWC,
            },
            Rotation,
        },
    };
    use itertools::Itertools;
    use rand::{rngs::OsRng, RngCore};
    use snark_verifier::{
        system::halo2::{compile, Config},
        verifier::plonk::PlonkProtocol,
    };
    use std::iter;

    #[derive(Clone)]
    pub struct SnarkOwned<C: CurveAffine> {
        protocol: PlonkProtocol<C>,
        instances: Vec<Vec<C::Scalar>>,
        proof: Vec<u8>,
    }

    impl<C: CurveAffine> SnarkOwned<C> {
        pub fn new(
            protocol: PlonkProtocol<C>,
            instances: Vec<Vec<C::Scalar>>,
            proof: Vec<u8>,
        ) -> Self {
            Self {
                protocol,
                instances,
                proof,
            }
        }

        pub fn as_snark(&self) -> Snark<C> {
            Snark {
                protocol: &self.protocol,
                instances: &self.instances,
                proof: &self.proof,
            }
        }
    }

    /// Configuration for `StandardPlonk`
    #[derive(Clone)]
    pub struct StandardPlonkConfig {
        selectors: [Column<Fixed>; 5],
        wires: [Column<Advice>; 3],
    }

    impl StandardPlonkConfig {
        /// Configure for `StandardPlonk`
        pub fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
            let [w_l, w_r, w_o] = [(); 3].map(|_| meta.advice_column());
            let [q_l, q_r, q_o, q_m, q_c] = [(); 5].map(|_| meta.fixed_column());
            let pi = meta.instance_column();
            [w_l, w_r, w_o].map(|column| meta.enable_equality(column));
            meta.create_gate(
                "q_l·w_l + q_r·w_r + q_o·w_o + q_m·w_l·w_r + q_c + pi = 0",
                |meta| {
                    let [w_l, w_r, w_o] =
                        [w_l, w_r, w_o].map(|column| meta.query_advice(column, Rotation::cur()));
                    let [q_l, q_r, q_o, q_m, q_c] = [q_l, q_r, q_o, q_m, q_c]
                        .map(|column| meta.query_fixed(column, Rotation::cur()));
                    let pi = meta.query_instance(pi, Rotation::cur());
                    Some(
                        q_l * w_l.clone()
                            + q_r * w_r.clone()
                            + q_o * w_o
                            + q_m * w_l * w_r
                            + q_c
                            + pi,
                    )
                },
            );
            StandardPlonkConfig {
                selectors: [q_l, q_r, q_o, q_m, q_c],
                wires: [w_l, w_r, w_o],
            }
        }
    }

    /// Standard plonk with few assignments for testing purpose.
    #[derive(Clone, Copy)]
    pub struct StandardPlonk<F>(F);

    impl<F: FieldExt> StandardPlonk<F> {
        /// Create a `StandardPlonk` with random instnace.
        pub fn rand<R: RngCore>(mut rng: R) -> Self {
            Self(F::from(rng.next_u32() as u64))
        }

        /// Returns instances.
        pub fn instances(&self) -> Vec<Vec<F>> {
            vec![vec![self.0]]
        }
    }

    impl<F: FieldExt> Circuit<F> for StandardPlonk<F> {
        type Config = StandardPlonkConfig;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            meta.set_minimum_degree(4);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let [q_l, q_r, q_o, q_m, q_c] = config.selectors;
            let [w_l, w_r, w_o] = config.wires;
            layouter.assign_region(
                || "",
                |mut region| {
                    // Assign some non-zero values to make sure the advice/fixed columns have
                    // non-identity commitments.
                    let a = region.assign_advice(|| "", w_l, 0, || Value::known(self.0))?;
                    region.assign_fixed(|| "", q_l, 0, || Value::known(-F::one()))?;
                    a.copy_advice(|| "", &mut region, w_r, 1)?;
                    a.copy_advice(|| "", &mut region, w_o, 2)?;
                    region.assign_advice(|| "", w_l, 3, || Value::known(-F::from(5)))?;
                    for (column, idx) in [q_l, q_r, q_o, q_m, q_c].iter().zip(1..) {
                        region.assign_fixed(|| "", *column, 3, || Value::known(F::from(idx)))?;
                    }
                    Ok(())
                },
            )
        }
    }

    /// Create random `StandardPlonk` and returns `Snark`s for them.
    pub fn rand_standard_plonk_snarks(
        params: &ParamsKZG<Bn256>,
        n: usize,
    ) -> Vec<SnarkOwned<G1Affine>> {
        // Preprocess
        let (pk, protocol) = {
            let standard_plonk = StandardPlonk(Fr::zero());
            let vk = keygen_vk(params, &standard_plonk).unwrap();
            let pk = keygen_pk(params, vk, &standard_plonk).unwrap();
            let protocol = compile(
                params,
                pk.get_vk(),
                Config::kzg().with_num_instance(
                    standard_plonk
                        .instances()
                        .iter()
                        .map(|instances| instances.len())
                        .collect(),
                ),
            );
            (pk, protocol)
        };

        // Create snarks
        iter::repeat_with(move || {
            let standard_plonk = StandardPlonk::<Fr>::rand(OsRng);
            let instances = standard_plonk.instances();
            let proof = {
                let mut transcript = PoseidonTranscript::new(Vec::new());
                create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
                    params,
                    &pk,
                    &[standard_plonk],
                    &[&instances.iter().map(Vec::as_slice).collect_vec()],
                    OsRng,
                    &mut transcript,
                )
                .unwrap();
                transcript.finalize()
            };
            SnarkOwned::new(protocol.clone(), instances, proof)
        })
        .take(n)
        .collect()
    }

    #[ignore = "not supported with QUERY_INSTANCE enabled in halo2_proofs"]
    #[test]
    fn test_standard_plonk_aggregation() {
        let params = ParamsKZG::<Bn256>::setup(8, OsRng);

        // Create Aggregation circuit and compute aggregated accumulator
        let snarks = rand_standard_plonk_snarks(&params, 2);
        let aggregation =
            TestAggregationCircuit::<Bn256>::new(&params, snarks.iter().map(SnarkOwned::as_snark))
                .unwrap();
        let instances = aggregation.instances();
        assert_eq!(
            MockProver::run(21, &aggregation, instances)
                .unwrap()
                .verify_par(),
            Ok(())
        );
    }

    #[ignore = "not supported with QUERY_INSTANCE enabled in halo2_proofs"]
    #[test]
    fn test_standard_plonk_aggregation_unmatched_instance() {
        let params = ParamsKZG::<Bn256>::setup(8, OsRng);

        // Create Aggregation circuit and compute aggregated accumulator
        let snarks = rand_standard_plonk_snarks(&params, 2);
        let aggregation =
            TestAggregationCircuit::<Bn256>::new(&params, snarks.iter().map(SnarkOwned::as_snark))
                .unwrap();
        let mut instances = aggregation.instances();
        // Change the propagated inner snark's instance
        instances[0][0] += Fr::one();
        // Then expect the verification to fail
        assert_eq!(
            MockProver::run(21, &aggregation, instances)
                .unwrap()
                .verify_par(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "Aggregate snarks").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                }
            ])
        );
    }
}
