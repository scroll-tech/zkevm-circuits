use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
    SerdeFormat,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base as sv_halo2_base;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};
use std::fs;
use sv_halo2_base::utils::fs::gen_srs;

use crate::{param::ConfigParams as AggregationConfigParams, recursion::*};
use ark_std::{end_timer, start_timer, test_rng};

fn test_recursion_impl<App>(app_degree: u32, init_state: Fr, mut add_inst: Vec<Vec<Fr>>)
where
    App: CircuitExt<Fr> + StateTransition<Input = Fr> + Default,
{
    let app_params = gen_srs(app_degree);
    let recursion_config: AggregationConfigParams =
        serde_json::from_reader(fs::File::open("configs/verify_circuit.config").unwrap()).unwrap();
    let k = recursion_config.degree;
    let recursion_params = gen_srs(k);

    let app = App::default();
    let app_pk = gen_pk(&app_params, &app, None);
    let mut rng = test_rng();

    let pk_time = start_timer!(|| "Generate recursion pk");
    // this is the pk from default app and dummy self-snark
    let recursion_pk = gen_recursion_pk::<App>(
        &recursion_params,
        &app_params,
        app_pk.get_vk(),
        &mut rng,
        None,
    );
    end_timer!(pk_time);

    let app = App::new(init_state);
    let next_state = app.state_transition(0);
    let app_snark = gen_snark_shplonk(&app_params, &app_pk, app, &mut rng, None::<String>)
        .expect("Snark generated successfully");
    let init_snark =
        initial_recursion_snark::<App>(&recursion_params, Some(recursion_pk.get_vk()), &mut rng);

    // gen inst for first round
    add_inst[0].insert(0, next_state);

    let recursion = RecursionCircuit::<App>::new(
        &recursion_params,
        app_snark,
        init_snark,
        test_rng(),
        &[init_state],
        &add_inst[0],
        0,
    );

    let pk_time = start_timer!(|| "Generate secondary recursion pk for test");
    {
        let r_pk_2 = gen_pk(&recursion_params, &recursion, None);
        assert_eq!(
            r_pk_2.get_vk().to_bytes(SerdeFormat::RawBytesUnchecked),
            recursion_pk
                .get_vk()
                .to_bytes(SerdeFormat::RawBytesUnchecked),
        );
    }
    end_timer!(pk_time);

    let pf_time = start_timer!(|| "Generate first recursive snark");

    let snark = gen_snark_shplonk(
        &recursion_params,
        &recursion_pk,
        recursion,
        &mut rng,
        None::<String>,
    )
    .expect("Snark generated successfully");

    end_timer!(pf_time);
    //assert_eq!(final_state, Fr::from(2u64).pow(&[1 << num_round, 0, 0, 0]));

    assert!(verify_snark_shplonk::<RecursionCircuit<App>>(
        &recursion_params,
        snark.clone(),
        recursion_pk.get_vk()
    ));

    let app = App::new(next_state);
    let next_state = app.state_transition(1);
    let app_snark = gen_snark_shplonk(&app_params, &app_pk, app, &mut rng, None::<String>)
        .expect("Snark generated successfully");

    // gen inst for first round
    add_inst[1].insert(0, next_state);

    let recursion = RecursionCircuit::<App>::new(
        &recursion_params,
        app_snark,
        snark,
        test_rng(),
        &[init_state],
        &add_inst[1],
        1,
    );

    let pk_time = start_timer!(|| "Generate thrid recursion pk for test");
    {
        let r_pk_3 = gen_pk(&recursion_params, &recursion, None);
        assert_eq!(
            r_pk_3.get_vk().to_bytes(SerdeFormat::RawBytesUnchecked),
            recursion_pk
                .get_vk()
                .to_bytes(SerdeFormat::RawBytesUnchecked),
        );
    }
    end_timer!(pk_time);

    let pf_time = start_timer!(|| "Generate next recursive snark");

    let snark = gen_snark_shplonk(
        &recursion_params,
        &recursion_pk,
        recursion,
        &mut rng,
        None::<String>,
    )
    .expect("Snark generated successfully");

    end_timer!(pf_time);

    assert!(verify_snark_shplonk::<RecursionCircuit<App>>(
        &recursion_params,
        snark,
        recursion_pk.get_vk()
    ));
}

#[test]
fn test_recursion_circuit() {
    #[derive(Clone, Default)]
    struct Square(Fr);

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

        fn num_transition_instance() -> usize {
            1
        }

        fn state_transition(&self, _: usize) -> Self::Input {
            self.0.square()
        }
    }

    test_recursion_impl::<Square>(3, Fr::from(2u64), vec![Vec::new(), Vec::new()])
}

#[test]
fn test_recursion_add_inst() {
    #[derive(Clone, Default)]
    struct Square(Fr);

    impl Circuit<Fr> for Square {
        type Config = (Selector, Column<Advice>, Column<Instance>);
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
            let s = meta.fixed_column();
            meta.enable_constant(s);
            let a = meta.advice_column();
            meta.enable_equality(a);
            meta.enable_equality(i);
            (q, a, i)
        }

        fn synthesize(
            &self,
            (q, a, i): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    q.enable(&mut region, 0)?;
                    q.enable(&mut region, 1)?;
                    region.assign_advice_from_instance(|| "copy inst (3)", i, 3, a, 0)?;
                    region.assign_advice_from_constant(
                        || "fix inst to 42",
                        a,
                        0,
                        Fr::from(42u64),
                    )?;
                    Ok(())
                },
            )
        }
    }

    impl CircuitExt<Fr> for Square {
        fn num_instance(&self) -> Vec<usize> {
            vec![4]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![
                self.0,
                self.0.square(),
                self.0.square().square(),
                Fr::from(42u64),
            ]]
        }
    }

    impl StateTransition for Square {
        type Input = Fr;
        type Circuit = Self;

        fn new(state: Self::Input) -> Self {
            Self(state)
        }

        fn num_additional_instance() -> usize {
            2
        }

        fn num_transition_instance() -> usize {
            1
        }

        fn state_transition(&self, _: usize) -> Self::Input {
            self.0.square()
        }
    }

    test_recursion_impl::<Square>(
        4,
        Fr::from(2u64),
        vec![
            vec![Fr::from(16u64), Fr::from(42u64)],
            vec![Fr::from(256u64), Fr::from(42u64)],
        ],
    )
}