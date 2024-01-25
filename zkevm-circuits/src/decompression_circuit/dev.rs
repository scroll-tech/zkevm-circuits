use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    decompression_circuit::{
        DecompressionCircuit, DecompressionCircuitConfig, DecompressionCircuitConfigArgs,
    },
    table::{
        decompression::LiteralsHeaderTable, BitwiseOpTable, KeccakTable, Pow2Table, RangeTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

impl<F: Field> Circuit<F> for DecompressionCircuit<F> {
    type Config = (DecompressionCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        let bitwise_op_table = BitwiseOpTable::construct(meta);
        let range4 = RangeTable::construct(meta);
        let range8 = RangeTable::construct(meta);
        let range16 = RangeTable::construct(meta);
        let range64 = RangeTable::construct(meta);
        let range128 = RangeTable::construct(meta);
        let range256 = RangeTable::construct(meta);
        let pow2_table = Pow2Table::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let literals_header_table = LiteralsHeaderTable::construct(
            meta,
            bitwise_op_table,
            range4,
            range8,
            range16,
            range64,
        );

        let config = DecompressionCircuitConfig::new(
            meta,
            DecompressionCircuitConfigArgs {
                challenges: challenge_exprs,
                literals_header_table,
                range8,
                range128,
                range256,
                pow2_table,
                keccak_table,
            },
        );
        log::debug!("meta.degree() = {}", meta.degree());

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = &config.1.values(&layouter);
        self.synthesize_sub(&config.0, challenges, &mut layouter)
    }
}
