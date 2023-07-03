use num_bigint::BigUint;
use misc_precompiled_circuit::circuits::range::{
    RangeCheckConfig,
    RangeCheckChip,
};
use misc_precompiled_circuit::value_for_assign;

use halo2_proofs::{
    halo2curves::bn256::Fr,
    circuit::{Chip, Layouter, Region, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error
    },
};

use misc_precompiled_circuit::circuits::modexp::{
    ModExpChip,
    ModExpConfig,
    Number,
    Limb,
};

/// !
#[derive(Clone, Debug)]
pub struct HelperChipConfig {
    limb: Column<Advice>
}

/// !
#[derive(Clone, Debug)]
pub struct HelperChip {
    config: HelperChipConfig
}

impl Chip<Fr> for HelperChip {
    type Config = HelperChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl HelperChip {
    fn new(config: HelperChipConfig) -> Self {
        HelperChip{
            config,
        }
    }

    fn configure(cs: &mut ConstraintSystem<Fr>) -> HelperChipConfig {
        let limb= cs.advice_column();
        cs.enable_equality(limb);
        HelperChipConfig {
            limb,
        }
    }

    fn assign_base(
        &self,
        _region: &mut Region<Fr>,
        _offset: &mut usize,
        base: &BigUint,
    ) -> Result<Number<Fr>, Error> {
        Ok(Number::from_bn(base))
    }

    fn assign_exp(
        &self,
        _region: &mut Region<Fr>,
        _offset: &mut usize,
        exp: &BigUint,
    ) -> Result<Number<Fr>, Error> {
        Ok(Number::from_bn(exp))
    }



    fn assign_modulus(
        &self,
        _region: &mut Region<Fr>,
        _offset: &mut usize,
        modulus: &BigUint,
    ) -> Result<Number<Fr>, Error> {
        Ok(Number::from_bn(modulus))
    }

    fn assign_results(
        &self,
        region: &mut Region<Fr>,
        offset: &mut usize,
        result: &BigUint,
    ) -> Result<Number<Fr>, Error> {
        let n = Number::from_bn(result);
        let mut cells = vec![];
        for i in 0..4 {
            let c = region.assign_advice(
                || format!("assign input"),
                self.config.limb,
                *offset + i,
                || value_for_assign!(n.limbs[i].value)
            )?;
            cells.push(Some(c));
            *offset = *offset + 1;
        }
        let n = Number {
            limbs: [
                Limb::new(cells[0].clone(), n.limbs[0].value),
                Limb::new(cells[1].clone(), n.limbs[1].value),
                Limb::new(cells[2].clone(), n.limbs[2].value),
                Limb::new(cells[3].clone(), n.limbs[3].value),
            ]
        };
        Ok(n)
    }

}

#[derive(Clone, Debug, Default)]
struct TestCircuit {
    base: BigUint,
    exp: BigUint,
    modulus: BigUint,
}

#[derive(Clone, Debug)]
struct TestConfig {
    modexpconfig: ModExpConfig,
    helperconfig: HelperChipConfig,
    rangecheckconfig: RangeCheckConfig,
}

impl Circuit<Fr> for TestCircuit {
    type Config = TestConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let rangecheckconfig = RangeCheckChip::<Fr>::configure(meta);
        Self::Config {
           modexpconfig: ModExpChip::<Fr>::configure(meta, &rangecheckconfig),
           helperconfig: HelperChip::configure(meta),
           rangecheckconfig,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let modexpchip = ModExpChip::<Fr>::new(config.clone().modexpconfig);
        let helperchip = HelperChip::new(config.clone().helperconfig);
        let mut range_chip = RangeCheckChip::<Fr>::new(config.clone().rangecheckconfig);
        layouter.assign_region(
            || "assign mod mult",
            |mut region| {
                range_chip.initialize(&mut region)?;
                let mut offset = 0;
                let base = helperchip.assign_base(&mut region, &mut offset, &self.base)?;
                let exp = helperchip.assign_exp(&mut region, &mut offset, &self.exp)?;
                let modulus = helperchip.assign_modulus(&mut region, &mut offset, &self.modulus)?;
                let bn_rem = self.base.clone().modpow(&self.exp, &self.modulus);
                let result = helperchip.assign_results(&mut region, &mut offset, &bn_rem)?;
                let rem = modexpchip.mod_exp(&mut region, &mut range_chip, &mut offset, &base, &exp, &modulus)?;
                for i in 0..4 {
                    //println!("rem is {:?}, result is {:?}", &rem.limbs[i].value, &result.limbs[i].value);
                    //println!("rem cell is {:?}, result cell is {:?}", &rem.limbs[i].cell, &result.limbs[i].cell);
                    region.constrain_equal(
                        rem.limbs[i].clone().cell.unwrap().cell(),
                        result.limbs[i].clone().cell.unwrap().cell()
                    )?;
                }
                Ok(())
            }
        )?;
        Ok(())
    }
}

/* 
#[test]
fn test_modexp_circuit_00() {
    let base = BigUint::from(1u128 << 100);
    let exp = BigUint::from(2u128 << 100);
    let modulus = BigUint::from(7u128);
    let test_circuit = TestCircuit {base, exp, modulus} ;
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_modexp_circuit_01() {
    let base = BigUint::from(1u128);
    let exp = BigUint::from(2u128);
    let modulus = BigUint::from(7u128);
    let test_circuit = TestCircuit {base, exp, modulus} ;
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
#[test]
fn test_modexp_circuit_02() {
    let base = BigUint::from(2u128);
    let exp = BigUint::from(2u128);
    let modulus = BigUint::from(7u128);
    let test_circuit = TestCircuit {base, exp, modulus} ;
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
*/