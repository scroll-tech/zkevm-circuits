//! Tests the RLC gates

use ark_std::test_rng;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::RngCore;
use zkevm_circuits::util::Challenges;

use crate::{aggregation::RlcConfig, util::rlc};

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
        let challenges = Challenges::construct(meta);
        RlcConfig::configure(meta, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut rng = test_rng();

        let mut first_pass = true;
        layouter.assign_region(
            || "test field circuit",
            |mut region| -> Result<(), Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                config.init(&mut region)?;

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
                // unit test: enforce_zero
                {
                    config.enforce_zero(&mut region, &f7)?;
                }
                // unit test: not gate
                {
                    let zero = config.load_private(&mut region, &Fr::zero(), &mut offset)?;
                    let one = config.not(&mut region, &zero, &mut offset)?;
                    let zero_rec = config.not(&mut region, &one, &mut offset)?;

                    zero.value().map(|&x| assert_eq!(x, Fr::zero()));
                    one.value().map(|&x| assert_eq!(x, Fr::one()));
                    zero_rec.value().map(|&x| assert_eq!(x, Fr::zero()));
                }
                // unit test: conditional select gate
                {
                    let zero = config.load_private(&mut region, &Fr::zero(), &mut offset)?;
                    let one = config.not(&mut region, &zero, &mut offset)?;

                    let f2_rec = config.select(&mut region, &f1, &f2, &zero, &mut offset)?;
                    region.constrain_equal(f2.cell(), f2_rec.cell())?;

                    let f1_rec = config.select(&mut region, &f1, &f2, &one, &mut offset)?;
                    region.constrain_equal(f1.cell(), f1_rec.cell())?;
                }

                let inputs = vec![f1, f2, f3, f4];

                // unit test: rlc
                {
                    let f6_rec = config.rlc(&mut region, &inputs, &f5, &mut offset)?;
                    region.constrain_equal(f6.cell(), f6_rec.cell())?;
                }
                // unit test: rlc with flags
                {
                    let zero = config.load_private(&mut region, &Fr::zero(), &mut offset)?;
                    let one = config.not(&mut region, &zero, &mut offset)?;

                    let flag = [one.clone(), one.clone(), one.clone(), one.clone()];
                    let f6_rec =
                        config.rlc_with_flag(&mut region, &inputs, &f5, &flag, &mut offset)?;
                    region.constrain_equal(f6.cell(), f6_rec.cell())?;

                    let flag = [one.clone(), one.clone(), one, zero];
                    let res = rlc(&[self.f1, self.f2, self.f3], &self.f5);
                    let res = config.load_private(&mut region, &res, &mut offset)?;
                    let res_rec =
                        config.rlc_with_flag(&mut region, &inputs, &f5, &flag, &mut offset)?;
                    region.constrain_equal(res.cell(), res_rec.cell())?;
                }
                // unit test: decomposition
                {
                    for _ in 0..10 {
                        let tmp = Fr::random(&mut rng);
                        let tmp = config.load_private(&mut region, &tmp, &mut offset)?;
                        config.decomposition(&mut region, &tmp, &mut offset)?;
                    }
                }
                // unit test: is smaller than
                {
                    for _ in 0..10 {
                        let a = Fr::from(rng.next_u64());
                        let b = Fr::from(rng.next_u64());
                        let c = if a < b { Fr::one() } else { Fr::zero() };
                        let a = config.load_private(&mut region, &a, &mut offset)?;
                        let b = config.load_private(&mut region, &b, &mut offset)?;
                        let c = config.load_private(&mut region, &c, &mut offset)?;
                        let c_rec = config.is_smaller_than(&mut region, &a, &b, &mut offset)?;
                        region.constrain_equal(c.cell(), c_rec.cell())?;
                    }

                    // equality check
                    let a = Fr::from(rng.next_u64());
                    let b = a;
                    let c = Fr::zero();
                    let a = config.load_private(&mut region, &a, &mut offset)?;
                    let b = config.load_private(&mut region, &b, &mut offset)?;
                    let c = config.load_private(&mut region, &c, &mut offset)?;
                    let c_rec = config.is_smaller_than(&mut region, &a, &b, &mut offset)?;
                    region.constrain_equal(c.cell(), c_rec.cell())?;
                }

                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_field_ops() {
    let k = 16;

    let f1 = Fr::from(3);
    let f2 = Fr::from(4);
    let f3 = f1 + f2; // 7
    let f4 = f1 * f2; // 12
    let f5 = f1 * f2 + f3; // 19
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
