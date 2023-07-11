//! Tests the RLC gates

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{rlc::RlcConfig, util::rlc};

#[derive(Default, Debug, Clone, Copy)]
struct ArithTestCircuit {
    f1: Fr,
    f2: Fr,
    f3: Fr,
    f4: Fr,
    f5: Fr,
    f6: Fr,
    f7: Fr,
}

impl Circuit<Fr> for ArithTestCircuit {
    type Config = RlcConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        RlcConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "test field circuit",
            |mut region| {
                let mut offset = 0;

                let f1 = config.load_private(&mut region, &self.f1, &mut offset)?;
                let f2 = config.load_private(&mut region, &self.f2, &mut offset)?;
                let f3 = config.load_private(&mut region, &self.f3, &mut offset)?;
                let f4 = config.load_private(&mut region, &self.f4, &mut offset)?;
                let f5 = config.load_private(&mut region, &self.f5, &mut offset)?;
                let f6 = config.load_private(&mut region, &self.f6, &mut offset)?;
                let f7 = config.load_private(&mut region, &self.f7, &mut offset)?;

                // unit test: addition
                {
                    let f3_rec = config.add(&mut region, &f1, &f2, &mut offset)?;
                    region.constrain_equal(f3.cell(), f3_rec.cell())?;
                }
                // unit test: subtraction
                {
                    let f2_rec = config.sub(&mut region, &f3, &f1, &mut offset)?;
                    region.constrain_equal(f2.cell(), f2_rec.cell())?;
                }

                // unit test: multiplication
                {
                    let f4_rec = config.mul(&mut region, &f1, &f2, &mut offset)?;
                    region.constrain_equal(f4.cell(), f4_rec.cell())?;
                }
                // unit test: mul_add
                {
                    let f5_rec = config.mul_add(&mut region, &f1, &f2, &f3, &mut offset)?;
                    region.constrain_equal(f5.cell(), f5_rec.cell())?;
                }
                // unit test: rlc
                {
                    let f6_rec = config.rlc(&mut region, &[f1, f2, f3, f4], &f5, &mut offset)?;
                    region.constrain_equal(f6.cell(), f6_rec.cell())?;
                }
                // unit test: enforce_zero
                {
                    config.enforce_zero(&mut region, &f7, &mut offset)?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_field_ops() {
    let k = 10;

    let f1 = Fr::from(3);
    let f2 = Fr::from(4);
    let f3 = f1 + f2;
    let f4 = f1 * f2;
    let f5 = f1 * f2 + f3;
    let f6 = rlc(&[f1, f2, f3, f4], &f5);
    let f7 = Fr::zero();

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3,
            f4,
            f5,
            f6,
            f7,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3: Fr::zero(),
            f4,
            f5,
            f6,
            f7,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3,
            f4: Fr::zero(),
            f5,
            f6,
            f7,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3,
            f4,
            f5: Fr::zero(),
            f6,
            f7,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3,
            f4,
            f5,
            f6: Fr::zero(),
            f7,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    {
        let circuit = ArithTestCircuit {
            f1,
            f2,
            f3,
            f4,
            f5,
            f6,
            f7: Fr::one(),
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
