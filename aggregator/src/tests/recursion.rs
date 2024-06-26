
use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine},
        group::ff::Field,
    },
    poly::{commitment::ParamsProver, Rotation},
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Selector, Circuit, Error, ConstraintSystem, ProvingKey, VerifyingKey},
};
use snark_verifier_sdk::{
    gen_pk, gen_snark_shplonk, verify_snark_shplonk, 
    types::{PoseidonTranscript, Plonk, POSEIDON_SPEC},
    Snark, CircuitExt,
};
use snark_verifier::{
    loader::{
        halo2::halo2_ecc::halo2_base as sv_halo2_base,
        native::NativeLoader,
    },
    verifier::{PlonkProof, PlonkVerifier},
};
use sv_halo2_base::utils::fs::gen_srs;
use std::fs;

use ark_std::{end_timer, start_timer, test_rng};
use crate::{
    param::ConfigParams as AggregationConfigParams,
    recursion::*,
};

#[derive(Clone, Default)]
pub struct Square(Fr);

impl Circuit<Fr> for Square {
    type Config = Selector;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let q = meta.selector();
        let i = meta.instance_column();
        meta.create_gate("square", |meta| {
            let q = meta.query_selector(q);
            let [i, i_w] = [0, 1].map(|rotation| meta.query_instance(i, Rotation(rotation)));
            Some(q * (i.clone() * i - i_w))
        });
        q
    }

    fn synthesize(
        &self,
        q: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(|| "", |mut region| q.enable(&mut region, 0))
    }
}

impl CircuitExt<Fr> for Square {
    fn num_instance(&self) -> Vec<usize> {
        vec![2]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![self.0, self.0.square()]]
    }
}

impl StateTransition for Square {
    type Input = [Fr;1];

    fn new(state: Self::Input) -> Self {
        Self(state[0])
    }

    fn state_transition(&self) -> Self::Input {
        [self.0.square()]
    }
}

#[test]
fn test_recursive_last() {

    let app_params = gen_srs(3);
    let recursion_config: AggregationConfigParams =
        serde_json::from_reader(fs::File::open("configs/verify_circuit.config").unwrap()).unwrap();
    let k = recursion_config.degree;
    let recursion_params = gen_srs(k);

    let app = Square::default();
    let app_pk = gen_pk(&app_params, &app, None);

    let pk_time = start_timer!(|| "Generate recursion pk");
    let recursion_pk = gen_recursion_pk::<Square, _, 1>(
        &recursion_params,
        &app_params,
        app_pk.get_vk(),
        &mut test_rng,
    );
    end_timer!(pk_time);

    let mut rng = test_rng();
    let app_snark = gen_snark_shplonk(
        &app_params, 
        &app_pk, 
        app, 
        &mut rng, 
        None::<String>,
    ).unwrap();
    let init_snark = initial_recursion_snark::<_, 1>(
        &recursion_params, 
        &recursion_pk.get_vk(), 
        &mut test_rng,
    );

    let recursion = RecursionCircuit::new(
        &recursion_params,
        app_snark,
        init_snark,
        test_rng(),
        [Fr::from(4u64)],
        [Fr::from(2u64)],
        0,
    );    
    let pf_time = start_timer!(|| "Generate full recursive snark");

    let snark = gen_snark_shplonk(
        &recursion_params, 
        &recursion_pk, 
        recursion, 
        &mut rng, 
        None::<String>,
    ).unwrap();

    end_timer!(pf_time);
    //assert_eq!(final_state, Fr::from(2u64).pow(&[1 << num_round, 0, 0, 0]));

    let accept = {
        use snark_verifier::pcs::kzg::{Gwc19, Kzg};
        type Pcs = Kzg<Bn256, Gwc19>;
        let svk = recursion_params.get_g()[0].into();
        let dk = (recursion_params.g2(), recursion_params.s_g2()).into();
        let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
        let proof = Plonk::<Pcs>::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript);
        Plonk::verify(&svk, &dk, &snark.protocol, &snark.instances, &proof)
    };
    assert!(accept)
}
