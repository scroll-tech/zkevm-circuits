// Added until this is used by another component
#![allow(dead_code)]
use super::BYTES_PER_WORD;
use crate::permutation::tables::RangeCheckConfig;
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use std::convert::TryInto;

pub type Byte = u8;
pub type AssignedByte<F> = AssignedCell<F, F>;
pub type AssignedWord<F> = AssignedCell<F, F>;

#[derive(Debug, Clone)]
/// Gets 8 Advice columns with the 8bytes to form the word + the final word
/// value of the composed bytes at the end.
pub(crate) struct WordBuilderConfig<F> {
    q_enable: Selector,
    bytes: [Column<Advice>; BYTES_PER_WORD],
    word: Column<Advice>,
    byte_table: RangeCheckConfig<F, 255>,
}

impl<F: Field> WordBuilderConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        bytes: [Column<Advice>; BYTES_PER_WORD],
        word: Column<Advice>,
        byte_table: RangeCheckConfig<F, 255>,
    ) -> WordBuilderConfig<F> {
        let q_enable = meta.complex_selector();

        // Enable equality for all byte cells.
        bytes.iter().for_each(|&byte| meta.enable_equality(byte));
        meta.enable_equality(word);

        bytes.iter().for_each(|&byte| {
            meta.lookup("Range check for word byte", |meta| {
                let q_enable = meta.query_selector(q_enable);

                vec![(
                    q_enable * meta.query_advice(byte, Rotation::cur()),
                    byte_table.range,
                )]
            });
        });

        meta.create_gate("Build Word", |meta| {
            let q_enable = meta.query_selector(q_enable);

            // Running sum to construct a u64 word with 8 u8 bytes shifted by it's position.
            let bytes_sum: Expression<F> = bytes
                .iter()
                .map(|&column| meta.query_advice(column, Rotation::cur()))
                .enumerate()
                .map(|(idx, byte_expr)| {
                    Expression::Constant(F::from(1u64 << (idx * 8))) * byte_expr
                })
                .reduce(|acc, byte_shifted| acc + byte_shifted)
                // Unwrapping is safe here as we recieve an array that contails all elements.
                .unwrap();

            let word = meta.query_advice(word, Rotation::cur());

            vec![q_enable * (bytes_sum - word)]
        });
        Self {
            q_enable,
            bytes,
            word,
            byte_table,
        }
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.byte_table.load(layouter)
    }

    pub(crate) fn assign_bytes(
        &self,
        layouter: &mut impl Layouter<F>,
        bytes: [AssignedByte<F>; BYTES_PER_WORD],
    ) -> Result<AssignedWord<F>, Error> {
        layouter.assign_region(
            || "Word construction",
            |mut region| {
                let offset = 0;
                self.q_enable.enable(&mut region, offset)?;
                // Copy bytes to byte columns
                let byte_cells: [AssignedByte<F>; BYTES_PER_WORD] = bytes
                    .iter()
                    .zip(self.bytes.iter())
                    .map(|(byte, &byte_col)| {
                        byte.copy_advice(|| "Copy byte", &mut region, byte_col, offset)
                    })
                    .collect::<Result<Vec<AssignedByte<F>>, Error>>()?
                    .try_into()
                    .unwrap();

                // Compute the word formed by the bytes and assign it into the last column of
                // the bytes
                let word_scalar = byte_cells
                    .iter()
                    .enumerate()
                    .map(|(idx, byte_cell)| {
                        F::from(1u64 << (idx * 8)) * byte_cell.value().unwrap_or(&F::zero())
                    })
                    .reduce(|acc, byte_shifted| acc + byte_shifted)
                    // Unwrapping is safe here as we recieve an array that contails all elements.
                    .unwrap();

                region.assign_advice(
                    || "Assign byte-constructed Word",
                    self.word,
                    offset,
                    || Ok(word_scalar),
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::{
            metadata::{Column as MetaColumn, Region},
            FailureLocation, MockProver, VerifyFailure,
        },
        plonk::{Advice, Any, Circuit},
    };
    use pairing::bn256::Fr;
    //use pretty_assertions::assert_eq;

    #[test]
    fn test_word_construction_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            bytes: [F; BYTES_PER_WORD],
            word: F,
        }

        #[derive(Clone)]
        struct MyConfig<F> {
            word_build_conf: WordBuilderConfig<F>,
            bytes: [Column<Advice>; BYTES_PER_WORD],
            word: Column<Advice>,
        }

        impl<F: Field> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                // Create WordBuilderConfig
                let table = RangeCheckConfig::<F, 255>::configure(meta);
                let bytes: [Column<Advice>; BYTES_PER_WORD] = (0..BYTES_PER_WORD)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column);
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                let word = meta.advice_column();
                meta.enable_equality(word);
                let word_build_conf = WordBuilderConfig::configure(meta, bytes, word, table);

                // Create a MyConfig instance with all the extra columns needed
                // for testing purposes
                let bytes: [Column<Advice>; BYTES_PER_WORD] = (0..BYTES_PER_WORD)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column);
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let word = meta.advice_column();
                meta.enable_equality(word);

                MyConfig {
                    word_build_conf,
                    bytes,
                    word,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.word_build_conf.byte_table.load(&mut layouter)?;
                let bytes = layouter.assign_region(
                    || "Wittnes of word's bytes",
                    |mut region| {
                        let bytes: [AssignedCell<F, F>; BYTES_PER_WORD] = {
                            let mut state: Vec<AssignedCell<F, F>> =
                                Vec::with_capacity(BYTES_PER_WORD);
                            for (idx, val) in self.bytes.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.bytes[idx],
                                    0,
                                    || Ok(*val),
                                )?;
                                state.push(cell)
                            }
                            state.try_into().unwrap()
                        };
                        Ok(bytes)
                    },
                )?;

                let circuit_word = config.word_build_conf.assign_bytes(&mut layouter, bytes)?;

                // Add equality constrain between the obtained word from the circuit and the
                // witnessed one.
                layouter.assign_region(
                    || "Constraint word to be equal to the test announced one",
                    |mut region| {
                        let announced_word = region.assign_advice(
                            || "Add test word",
                            config.word,
                            0,
                            || Ok(self.word),
                        )?;
                        region.constrain_equal(circuit_word.cell(), announced_word.cell())
                    },
                )?;
                Ok(())
            }
        }

        // Test that the circuit works when we provide correct witnesses.
        {
            let bytes = [
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
            ];
            let word = Fr::from(2947526575u64);

            let circuit = MyCircuit::<Fr> { bytes, word };

            // Test without public inputs
            let prover = MockProver::<Fr>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }

        // Test that if we pass a byte greater than 255 the lookup will cause the
        // circuit to fail.
        {
            let bytes = [
                Fr::from(0x100u64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
            ];
            let word = Fr::from(68730990511u64);

            let circuit = MyCircuit::<Fr> { bytes, word };

            // Test without public inputs
            let prover = MockProver::<Fr>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(
                prover.verify(),
                Err(vec![
                    VerifyFailure::Lookup {
                        name: "Range check for word byte",
                        lookup_index: 0,
                        location: FailureLocation::InRegion {
                            region: Region::from((2, "Word construction")),
                            offset: 0
                        }
                    },
                    VerifyFailure::Permutation {
                        column: MetaColumn::from((Any::Advice, 8)),
                        row: 0
                    },
                    VerifyFailure::Permutation {
                        column: MetaColumn::from((Any::Advice, 17)),
                        row: 0
                    }
                ])
            )
        }

        // Test that if the bytes are not equivalent to the announced word, the circuit
        // fails.
        {
            let bytes = [
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::from(0xafu64),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
                Fr::zero(),
            ];
            let word = Fr::from(2947526574u64);

            let circuit = MyCircuit::<Fr> { bytes, word };

            // Test without public inputs
            let prover = MockProver::<Fr>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(
                prover.verify(),
                Err(vec![
                    VerifyFailure::Permutation {
                        column: MetaColumn::from((Any::Advice, 8)),
                        row: 0
                    },
                    VerifyFailure::Permutation {
                        column: MetaColumn::from((Any::Advice, 17)),
                        row: 0
                    }
                ])
            )
        }
    }
}
