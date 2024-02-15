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
        decompression::{
            BitstringAccumulationTable, DecodedLiteralsTable, FseTable, HuffmanCodesTable,
            LiteralsHeaderTable,
        },
        BitwiseOpTable, KeccakTable, Pow2Table, PowOfRandTable, RangeTable,
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
        let pow_rand_table = PowOfRandTable::construct(meta, &challenge_exprs);
        let fse_table = FseTable::construct(meta, bitwise_op_table, pow2_table, range8, range256);
        let huffman_codes_table = HuffmanCodesTable::construct(meta, pow2_table, range256);
        let bs_acc_table = BitstringAccumulationTable::construct(meta);
        let literals_header_table = LiteralsHeaderTable::construct(
            meta,
            bitwise_op_table,
            range4,
            range8,
            range16,
            range64,
        );
        let decoded_literals_table =
            DecodedLiteralsTable::construct(meta, challenge_exprs.clone(), range256);

        let config = DecompressionCircuitConfig::new(
            meta,
            DecompressionCircuitConfigArgs {
                challenges: challenge_exprs,
                fse_table,
                huffman_codes_table,
                bs_acc_table,
                literals_header_table,
                decoded_literals_table,
                bitwise_op_table,
                range4,
                range8,
                range16,
                range64,
                range128,
                range256,
                pow2_table,
                keccak_table,
                pow_rand_table,
            },
        );

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = &config.1.values(&layouter);

        config.0.bitwise_op_table.load(&mut layouter)?;
        config.0.range4.load(&mut layouter)?;
        config.0.range8.load(&mut layouter)?;
        config.0.range16.load(&mut layouter)?;
        config.0.range64.load(&mut layouter)?;
        config.0.range128.load(&mut layouter)?;
        config.0.range256.load(&mut layouter)?;
        config.0.tag_rom_table.load(&mut layouter)?;
        config.0.pow_rand_table.assign(&mut layouter, challenges)?;
        config.0.block_type_rom_table.load(&mut layouter)?;
        config.0.pow2_table.load(&mut layouter)?;
        config.0.literals_header_rom_table.load(&mut layouter)?;

        self.synthesize_sub(&config.0, challenges, &mut layouter)
    }
}
