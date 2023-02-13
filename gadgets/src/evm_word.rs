//! An EVM word (256 bits) is represented as a linear combination of 32 bytes:
//! `encode(word) = b_0 + r * b_1 + ... + r^{31} * b_{31}`,
//! where `word` is a 256-bit word, b_i's are bytes, and `r` is a random factor.
//! This helper returns an expression of `encode(word)`.
//!
//! In the zkevm circuit, this `encode(word)` expression will not be directly
//! looked up. Instead, it will be folded into the bus mapping lookup.

use crate::Variable;
use digest::{FixedOutput, Input};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use sha3::{Digest, Keccak256};

#[cfg(test)]
use halo2_proofs::circuit::Layouter;

// TODO: Move into crate-level `constants` file.
/// r = hash([0, 1, ..., 255])
pub fn r<F: Field>() -> F {
    let mut hasher = Keccak256::new();
    for byte in 0..=u8::MAX {
        hasher.process(&[byte]);
    }
    let mut r = [0; 64];
    r[..32].copy_from_slice(hasher.fixed_result().as_slice());
    F::from_bytes_wide(&r)
}

/// Returns encoding of big-endian representation of a 256-bit word.
pub fn encode<F: Field>(vals: impl Iterator<Item = u8>, r: F) -> F {
    vals.fold(F::zero(), |acc, val| {
        let byte = F::from(val as u64);
        acc * r + byte
    })
}

/// A 256-bit word represented in the circuit as 32 bytes.
pub struct Word<F: Field>([Variable<u8, F>; 32]);

#[allow(dead_code)]
/// Configuration structure used to constraint. generate and assign an EVM Word
/// inside a circuit.
#[derive(Clone, Debug)]
pub struct WordConfig<F: Field> {
    /// Randomness used to compress the word encoding.
    r: F,
    /// Selector to toggle the word encoding gate.
    // TODO: This may be replaced by a synthetic selector.
    q_encode: Selector,
    /// Advice columns used to witness the byte representation of the word.
    bytes: [Column<Advice>; 32],
    /// Fixed column containing all possible 8-bit values. This is used in
    /// a lookup argument to range-constrain each byte.
    byte_lookup: Column<Fixed>,
    /// Expression representing `encode(word)`.
    encode_word_expr: Expression<F>,
}

impl<F: Field> WordConfig<F> {
    /// Sets up the configuration of the config by creating the required columns
    /// & selectors and defining the constraints that take part when using a
    /// Word.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        r: F,
        q_encode: Selector,
        bytes: [Column<Advice>; 32],
        byte_lookup: Column<Fixed>,
    ) -> Self {
        // Expression representing `encode(word)`.
        let mut encode_word_expr = Expression::Constant(F::zero());

        // Lookup each byte in the witnessed word representation to
        // range-constrain it to 8 bits.
        for byte in bytes.iter().rev() {
            meta.lookup_any("Word byte for range", |meta| {
                let q_encode = meta.query_selector(q_encode);
                let r = Expression::Constant(r);
                let byte = meta.query_advice(*byte, Rotation::cur());
                let byte_lookup = meta.query_fixed(byte_lookup, Rotation::cur());

                // Update encode_word_expr.
                encode_word_expr = encode_word_expr.clone() * r + byte.clone();

                vec![(q_encode * byte, byte_lookup)]
            });
        }

        Self {
            r,
            q_encode,
            bytes,
            byte_lookup,
            encode_word_expr,
        }
    }

    /// Loads the 8-bit lookup table.
    /// NB: This is only used in tests, since the zkevm circuit will load a
    /// global 8-bit table.
    #[cfg(test)]
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "8-bit table",
            |mut meta| {
                for byte in 0..=u8::MAX {
                    meta.assign_fixed(
                        || format!("load {}", byte),
                        self.byte_lookup,
                        byte.into(),
                        || Value::known(F::from(byte as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    /// Assigns the byte decomposition of a word to the `bytes` advice columns.
    pub fn assign_word(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        word: [Value<u8>; 32],
    ) -> Result<Word<F>, Error> {
        let mut bytes: Vec<Variable<u8, F>> = Vec::with_capacity(32);

        for (idx, (byte, column)) in word.iter().zip(self.bytes.iter()).enumerate() {
            // TODO: We will likely enable this selector outside of the helper.
            self.q_encode.enable(region, offset)?;

            let byte_field_elem = byte.map(|byte| F::from(byte as u64));
            let cell = region.assign_advice(
                || format!("assign byte {}", idx),
                *column,
                offset,
                || byte_field_elem,
            )?;

            bytes.push(Variable::new(cell, *byte));
        }

        Ok(Word(bytes.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        arithmetic::Field as Halo2Field,
        circuit::SimpleFloorPlanner,
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::{bn256::Fr as Fp, group::ff::PrimeField},
        plonk::{Circuit, Instance},
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::marker::PhantomData;

    #[test]
    fn evm_word() {
        #[derive(Default)]
        struct MyCircuit<F: Field> {
            word: [Value<u8>; 32],
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for MyCircuit<F> {
            // Introduce an additional instance column here to test lookups
            // with public inputs. This is analogous to the bus mapping
            // commitment which will be provided as public inputs.
            type Config = (WordConfig<F>, Column<Instance>);
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let r = r();

                let q_encode = meta.complex_selector();

                let bytes: [Column<Advice>; 32] = (0..32)
                    .map(|_| meta.advice_column())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let byte_lookup = meta.fixed_column();

                let config = WordConfig::configure(meta, r, q_encode, bytes, byte_lookup);

                let pub_inputs = meta.instance_column();

                // Make sure each encoded word has been committed to in the
                // public inputs.
                meta.lookup_any("Encoded word / Pub inputs", |meta| {
                    let q_encode = meta.query_selector(q_encode);
                    let pub_inputs = meta.query_instance(pub_inputs, Rotation::cur());

                    let encode_word = config.clone().encode_word_expr;

                    vec![(q_encode * encode_word, pub_inputs)]
                });

                (config, pub_inputs)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.0.load(&mut layouter)?;

                layouter.assign_region(
                    || "assign word",
                    |mut region| {
                        let offset = 0;
                        config.0.assign_word(&mut region, offset, self.word)
                    },
                )?;

                Ok(())
            }
        }

        {
            let rng = XorShiftRng::from_seed([
                0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
                0xbc, 0xe5,
            ]);
            let word = Fp::random(rng);
            let circuit = MyCircuit::<Fp> {
                word: word
                    .to_repr()
                    .iter()
                    .map(|b| Value::known(*b))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                _marker: PhantomData,
            };

            // Test without public inputs
            let prover = MockProver::<Fp>::run(9, &circuit, vec![vec![]]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::Lookup {
                    name: "Encoded word / Pub inputs",
                    lookup_index: 32,
                    location: FailureLocation::InRegion {
                        region: halo2_proofs::dev::metadata::Region::from((
                            1,
                            "assign word".to_string()
                        )),
                        offset: 0
                    }
                }])
            );

            // Calculate word commitment and use it as public input.
            let encoded: Fp = encode(word.to_repr().iter().rev().cloned(), r());
            let prover = MockProver::<Fp>::run(9, &circuit, vec![vec![encoded]]).unwrap();
            prover.assert_satisfied_par()
        }
    }
}
