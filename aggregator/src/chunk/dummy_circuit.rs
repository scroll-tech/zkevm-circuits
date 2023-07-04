use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base;

use crate::ChunkHash;

#[derive(Clone)]
pub struct DummyChunkHashCircuit {
    dummy_chunk: ChunkHash,
}

impl DummyChunkHashCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(dummy_chunk: ChunkHash) -> Self {
        Self { dummy_chunk }
    }

    pub(crate) fn instance(&self) -> Vec<Fr> {
        self.dummy_chunk
            .public_input_hash()
            .as_bytes()
            .iter()
            .map(|&x| Fr::from(x as u64))
            .collect()
    }
}

#[derive(Clone)]
pub struct DummyChunkHashCircuitConfig {
    /// Instance for public input; stores
    /// - batch_public_input_hash (32 elements)
    instance: Column<Instance>,
    /// Advice column to store the public input
    advice: Column<Advice>,
}

impl Circuit<Fr> for DummyChunkHashCircuit {
    type Config = DummyChunkHashCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Instance column stores public input column
        // - the batch public input hash
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // Advice column also stores public input column
        // - the batch public input hash
        let advice = meta.advice_column();
        meta.enable_equality(advice);

        Self::Config { instance, advice }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut cells = vec![];
        layouter.assign_region(
            || "dummy chunk circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                for (index, element) in self.instance().iter().enumerate() {
                    cells.push(region.assign_advice(
                        || "public input",
                        config.advice,
                        index,
                        || Value::known(*element),
                    )?);
                }

                Ok(())
            },
        )?;

        for (index, element) in cells.iter().enumerate() {
            layouter.constrain_instance(element.cell(), config.instance, index)?;
        }

        Ok(())
    }
}
