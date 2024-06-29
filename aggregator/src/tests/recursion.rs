
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
    type Input = Fr;
    type Circuit = Self;

    fn new(state: Self::Input) -> Self {
        Self(state)
    }

    fn num_transition_instance() -> usize {1}

    fn state_transition(&self, _: usize) -> Self::Input {
        self.0.square()
    }
}

#[test]
fn test_recursion_circuit() {

    let app_params = gen_srs(3);
    let recursion_config: AggregationConfigParams =
        serde_json::from_reader(fs::File::open("configs/verify_circuit.config").unwrap()).unwrap();
    let k = recursion_config.degree;
    let recursion_params = gen_srs(k);

    let app = Square::default();
    let app_pk = gen_pk(&app_params, &app, None);
    let mut rng = test_rng();

    let pk_time = start_timer!(|| "Generate recursion pk");
    let recursion_pk = gen_recursion_pk::<Square>(
        &recursion_params,
        &app_params,
        app_pk.get_vk(),
        &mut rng,
        None,
    );
    end_timer!(pk_time);

    
    let init_state = Fr::from(2u64);
    let app = Square::new(init_state);
    let next_state = app.state_transition(0);
    let app_snark = gen_snark_shplonk(
        &app_params, 
        &app_pk, 
        app, 
        &mut rng, 
        None::<String>,
    ).unwrap();
    let init_snark = initial_recursion_snark::<Square>(
        &recursion_params, 
        Some(&recursion_pk.get_vk()), 
        &mut rng,
    );
    
    let recursion = RecursionCircuit::<Square>::new(
        &recursion_params,
        app_snark,
        init_snark,
        test_rng(),
        &[init_state],
        &[next_state],
        0,
    );    
    let pf_time = start_timer!(|| "Generate first recursive snark");

    let snark = gen_snark_shplonk(
        &recursion_params, 
        &recursion_pk, 
        recursion, 
        &mut rng, 
        None::<String>,
    ).unwrap();

    end_timer!(pf_time);
    //assert_eq!(final_state, Fr::from(2u64).pow(&[1 << num_round, 0, 0, 0]));

    assert!(verify_snark_shplonk::<RecursionCircuit<Square>>(
        &recursion_params,
        snark.clone(),
        recursion_pk.get_vk()
    ));

    let app = Square::new(next_state);
    let next_state = app.state_transition(1);
    let app_snark = gen_snark_shplonk(
        &app_params, 
        &app_pk, 
        app, 
        &mut rng, 
        None::<String>,
    ).unwrap();
    
    let recursion = RecursionCircuit::<Square>::new(
        &recursion_params,
        app_snark,
        snark,
        test_rng(),
        &[init_state],
        &[next_state],
        1,
    );
 
    let pf_time = start_timer!(|| "Generate next recursive snark");

    let snark = gen_snark_shplonk(
        &recursion_params, 
        &recursion_pk, 
        recursion, 
        &mut rng, 
        None::<String>,
    ).unwrap();

    end_timer!(pf_time);

    assert!(verify_snark_shplonk::<RecursionCircuit<Square>>(
        &recursion_params,
        snark,
        recursion_pk.get_vk()
    ));

}
