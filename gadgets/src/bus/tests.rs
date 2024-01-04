use crate::util::{query_expression, Expr};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Challenge, Circuit, Column, ConstraintSystem, Error, Fixed, SecondPhase},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::{
    bus_builder::*,
    bus_chip::*,
    bus_codec::{BusCodecExpr, BusCodecVal},
    bus_lookup::BusLookupChip,
    bus_port::*,
    Field,
};

#[test]
fn test_bus() {
    test_circuit();
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    enabled: Column<Fixed>,
    bus_config: BusConfig,
    bus_lookup: BusLookupChip<F>,
    port2: PortChip<F>,
    rand: Challenge,
    _marker: PhantomData<F>,
}

#[derive(Default, Clone)]
struct TestCircuit<F: Field> {
    n_rows: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        cs.advice_column(); // Bypass illogical validation.
        cs.advice_column_in(SecondPhase);

        let enabled = cs.fixed_column();
        let enabled_expr = query_expression(cs, |cs| cs.query_fixed(enabled, Rotation::cur()));

        let rand = cs.challenge_usable_after(SecondPhase);
        let rand_expr = query_expression(cs, |cs| cs.query_challenge(rand));
        let mut bus_builder = BusBuilder::new(BusCodecExpr::new(rand_expr));

        let message = vec![2.expr()];

        // Circuit 1 sends values dynamically.
        let bus_lookup =
            BusLookupChip::connect(cs, &mut bus_builder, enabled_expr.clone(), message.clone());

        // Circuit 2 receives one value per row.
        let port2 = PortChip::connect(cs, &mut bus_builder, enabled_expr, BusOp::receive(message));

        // Global bus connection.
        let bus_config = BusConfig::new(cs, &bus_builder.build());

        TestCircuitConfig {
            enabled,
            bus_config,
            bus_lookup,
            port2,
            rand,
            _marker: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let rand = layouter.get_challenge(config.rand);

        layouter.assign_region(
            || "witness",
            |mut region| {
                for offset in 0..self.n_rows {
                    region.assign_fixed(
                        || "Port_enable",
                        config.enabled,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }

                let mut bus_assigner = BusAssigner::new(BusCodecVal::new(rand), self.n_rows);

                // Circuit 2 receives one message per row.
                {
                    // First pass: run circuit steps.
                    for offset in 0..self.n_rows {
                        // Do normal circuit assignment logic, and obtain a message.
                        let message = vec![F::from(2)];

                        // Assign an operation to the port of this circuit, and to the shared bus.
                        config
                            .port2
                            .assign(&mut bus_assigner, offset, BusOp::receive(message));
                    }
                }

                // Circuit 1 sends a message on some row.
                {
                    // Do normal circuit assignment logic, and obtain a message.
                    let message = vec![F::from(2)];

                    // The bus assigner counted `n_rows` messages from Circuit 2.
                    assert_eq!(
                        bus_assigner.op_counter().count_receives(&message),
                        self.n_rows as isize,
                    );

                    // Provide an entry of the table to the bus.
                    let offset = 3; // can be anywhere.
                    config.bus_lookup.assign(
                        &mut region,
                        &mut bus_assigner,
                        offset,
                        message.clone(),
                    )?;

                    // The bus assigner counted that all lookups were satisfied.
                    assert_eq!(bus_assigner.op_counter().count_receives(&message), 0,);
                }

                // Final pass: assign the bus witnesses.
                bus_assigner.finish_ports(&mut region);

                config
                    .bus_config
                    .assign(&mut region, self.n_rows, bus_assigner.terms())?;

                Ok(())
            },
        )
    }
}

fn test_circuit() {
    let circuit = TestCircuit::<Fr> {
        n_rows: 10,
        _marker: PhantomData,
    };
    let k = 10;
    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par()
}
