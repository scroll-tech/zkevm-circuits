
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error
    },
};

use eth_types::{Field, Word};
use bus_mapping::circuit_input_builder::ModExpEvent;
use crate::{
    table::ModExpTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};

//use misc_precompiled_circuit::value_for_assign;
use misc_precompiled_circuit::circuits::{
    range::{
        RangeCheckConfig,
        RangeCheckChip,
    },
    modexp::{
        ModExpChip,
        ModExpConfig,
        Number,
        Limb,
    },
};

#[derive(Clone, Debug)]
struct ModExpCircuitConfig {
    modexp_config: ModExpConfig,
    rangecheck_config: RangeCheckConfig,
    modexp_table: ModExpTable,
}

impl<F :Field> SubCircuitConfig<F> for ModExpCircuitConfig {
    type ConfigArgs = ModExpTable;

    /// Return a new ModExpCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        modexp_table: Self::ConfigArgs,
    ) -> Self {
        let rangecheck_config = RangeCheckChip::configure(meta);
        let modexp_config = ModExpChip::configure(meta, &rangecheck_config);
        Self {
            rangecheck_config,
            modexp_config,
            modexp_table,
        }
    }
}

impl ModExpCircuitConfig {

    pub(crate) fn assign_group<F :Field>(
        &self,
        region: &mut Region<F>,
        table_offset: usize,
        mut calc_offset: usize,
        event: &ModExpEvent,
        modexp_chip: &ModExpChip<F>,
        range_check_chip: &mut RangeCheckChip<F>,
    ) -> Result<usize, Error> {
        
        let base = self.assign_value(region, table_offset, self.modexp_table.base, &event.base)?;
        let exp = self.assign_value(region, table_offset, self.modexp_table.exp, &event.exponent)?;
        let modulus = self.assign_value(region, table_offset, self.modexp_table.modulus, &event.modulus)?;

        let ret = modexp_chip.mod_exp(region, range_check_chip, &mut calc_offset, &base, &exp, &modulus)?;
        for i in 0..4 {

            region.assign_fixed(
                || format!("modexp table head {}", table_offset+i),
                self.modexp_table.q_head,
                table_offset + i,
                || Value::known(if i == 0 {F::one()} else {F::zero()}),
            )?;

            ret.limbs[i].cell.clone()
            .expect("should has assigned after modexp")
            .copy_advice(
                ||"copy to result limbs", 
                region, 
                self.modexp_table.result, 
                table_offset + i
            )?;
        }
        Ok(calc_offset)
    }

    fn assign_value<F :Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        col: Column<Advice>,
        value: &Word,
    ) -> Result<Number<F>, Error> {
        
        let limbs_v = ModExpTable::split_u256_108bit_limbs(value);
        let native_v = ModExpTable::native_u256(value);
        let mut limbs = Vec::new();

        for i in 0..3 {
            let fv = F::from_u128(limbs_v[i]);
            let c = region.assign_advice(
                || "assign modexp limb", 
                col, 
                offset + i, 
                || Value::known(fv),
            )?;
            limbs.push(Limb::new(Some(c), fv));
        }
        let c = region.assign_advice(
            || "assign modexp native", 
            col, 
            offset + 3, 
            || Value::known(native_v),
        )?;
        limbs.push(Limb::new(Some(c), native_v));
        Ok(Number {limbs: limbs.try_into().expect("just 4 pushes")})
    }

}


const MODEXPCONFIG_EACH_CHIP_ROWS : usize = 9291;

#[derive(Clone, Debug, Default)]
struct ModExpCircuit<F: Field>(Vec<ModExpEvent>, std::marker::PhantomData<F>);

impl<F: Field> SubCircuit<F> for ModExpCircuit<F> {
    type Config = ModExpCircuitConfig;

    fn unusable_rows() -> usize {
        // No column queried at more than 4 distinct rotations, so returns 8 as
        // minimum unusable rows.
        8
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {

        let event_limit = block.circuits_params.max_keccak_rows / MODEXPCONFIG_EACH_CHIP_ROWS;
        let mut exp_events = block.modexp_events.clone();
        assert!(exp_events.len() <= event_limit, 
            "no enough rows for modexp circuit, expected {}, limit {}",
            exp_events.len(),
            event_limit,
        );

        exp_events.resize(event_limit, Default::default());
        Self(exp_events, Default::default())
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            block.modexp_events.len() * MODEXPCONFIG_EACH_CHIP_ROWS,
            (block.modexp_events.len() * MODEXPCONFIG_EACH_CHIP_ROWS).max(block.circuits_params.max_keccak_rows),
        )
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {

        let modexp_chip = ModExpChip::new(config.modexp_config.clone());
        let mut range_chip = RangeCheckChip::new(config.rangecheck_config.clone());

        layouter.assign_region(
            || "modexp circuit",
            |mut region| {

                range_chip.initialize(&mut region)?;
                let mut calc_offset = 0;
                for (n, event) in self.0.iter().enumerate(){
                    calc_offset = config.assign_group(
                        &mut region, 
                        n*4, 
                        calc_offset, 
                        event, 
                        &modexp_chip, 
                        &mut range_chip
                    )?;
                }
                Ok(())
            },
        )?;

        config.modexp_table.fill_blank(layouter)

    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::{
        halo2curves::bn256::Fr,
        circuit::SimpleFloorPlanner,
        plonk::{Circuit, ConstraintSystem},
    };    
    use crate::util::MockChallenges;

    impl Circuit<Fr> for ModExpCircuit<Fr> {
        type Config = (ModExpCircuitConfig, MockChallenges);
        type FloorPlanner = SimpleFloorPlanner;
    
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
    
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let modexp_table = ModExpTable::construct(meta);
            let challenge = MockChallenges::construct(meta);
            (
                <ModExpCircuitConfig as SubCircuitConfig<Fr>>::new(meta, modexp_table),
                challenge,
            )
        }
    
        fn synthesize(
            &self,
            (config, challenge): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let challenges = challenge.values(&mut layouter);
            <Self as SubCircuit<Fr>>::synthesize_sub(
                &self, 
                &config,
                &challenges,
                &mut layouter
            )
        }
    }

    #[test]
    fn test_modexp_circuit_00() {
        let base = Word::from(1u128);
        let exp = Word::from(2u128);
        let modulus = Word::from(7u128);
        let (_, result) = base.pow(exp).div_mod(modulus);
        let event1 = ModExpEvent {base, exponent: exp, modulus, result};
        let test_circuit = ModExpCircuit (vec![event1], Default::default());
        let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
    
    #[test]
    fn test_modexp_circuit_01() {
        let base = Word::from(1u128);
        let exp = Word::from(2u128);
        let modulus = Word::from(7u128);
        let (_, result) = base.pow(exp).div_mod(modulus);
        let event1 = ModExpEvent {base, exponent: exp, modulus, result};
        let test_circuit = ModExpCircuit (vec![event1], Default::default());
        let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
    #[test]
    fn test_modexp_circuit_02() {
        let base = Word::from(2u128);
        let exp = Word::from(2u128);
        let modulus = Word::from(7u128);
        let (_, result) = base.pow(exp).div_mod(modulus);
        let event1 = ModExpEvent {base, exponent: exp, modulus, result};
        let test_circuit = ModExpCircuit (vec![event1], Default::default());
        let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
    

}
