use crate::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Any, Assigned, Column, ConstraintSystem, Error},
};
use std::convert::TryInto;

mod compression;
mod gates;
mod message_schedule;
mod spread_table;
mod util;

use compression::*;
use gates::*;
use message_schedule::*;
use spread_table::*;
use util::*;

const ROUNDS: usize = 64;
const STATE: usize = 8;

#[allow(clippy::unreadable_literal)]
pub(crate) const ROUND_CONSTANTS: [u32; ROUNDS] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; STATE] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

#[derive(Clone, Copy, Debug, Default)]
/// A word in a `Table16` message block.
// TODO: Make the internals of this struct private.
pub struct BlockWord(pub Value<u32>);

#[derive(Clone, Debug)]
/// Little-endian bits (up to 64 bits)
pub struct Bits<const LEN: usize>([bool; LEN]);

impl<const LEN: usize> Bits<LEN> {
    fn spread<const SPREAD: usize>(&self) -> [bool; SPREAD] {
        spread_bits(self.0)
    }
}

impl<const LEN: usize> std::ops::Deref for Bits<LEN> {
    type Target = [bool; LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> From<[bool; LEN]> for Bits<LEN> {
    fn from(bits: [bool; LEN]) -> Self {
        Self(bits)
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for [bool; LEN] {
    fn from(bits: &Bits<LEN>) -> Self {
        bits.0
    }
}

impl<F: Field, const LEN: usize> From<&Bits<LEN>> for Assigned<F> {
    fn from(bits: &Bits<LEN>) -> Assigned<F> {
        assert!(LEN <= 64);
        F::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<16>> for u16 {
    fn from(bits: &Bits<16>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<16> {
    fn from(int: u16) -> Bits<16> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

impl From<&Bits<32>> for u32 {
    fn from(bits: &Bits<32>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<32> {
    fn from(int: u32) -> Bits<32> {
        Bits(i2lebsp::<32>(int.into()))
    }
}

/// Assigned bits
#[derive(Clone, Debug)]
pub struct AssignedBits<F: Field, const LEN: usize>(pub AssignedCell<Bits<LEN>, F>);

impl<F: Field, const LEN: usize> std::ops::Deref for AssignedBits<F, LEN> {
    type Target = AssignedCell<Bits<LEN>, F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: Field, const LEN: usize> AssignedBits<F, LEN> {
    fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<T>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
        <T as TryInto<[bool; LEN]>>::Error: std::fmt::Debug,
    {
        let value: Value<[bool; LEN]> = value.map(|v| v.try_into().unwrap());
        let value: Value<Bits<LEN>> = value.map(|v| v.into());

        let column: Column<Any> = column.into();
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: Field> AssignedBits<F, 16> {
    fn value_u16(&self) -> Value<u16> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<16>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: Field> AssignedBits<F, 32> {
    fn value_u32(&self) -> Value<u32> {
        self.value().map(|v| v.into())
    }

    fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Value<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Value<Bits<32>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice(_) => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone()
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

/// Configuration for a [`Table16Chip`].
#[derive(Clone, Debug)]
pub struct Table16Config {
    lookup: SpreadTableConfig,
    message_schedule: MessageScheduleConfig,
    compression: CompressionConfig,
}

impl Table16Config {
    pub(crate) fn initialize<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state_assigned: [RoundWordDense<F>; STATE],
    ) -> Result<State<F>, Error> {
        self.compression.initialize(layouter, init_state_assigned)
    }

    pub(crate) fn compress<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: State<F>,
        w_halves: [(AssignedBits<F, 16>, AssignedBits<F, 16>); ROUNDS],
    ) -> Result<State<F>, Error> {
        self.compression
            .compress(layouter, initialized_state, w_halves)
    }

    pub(crate) fn digest<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        final_state: State<F>,
        initialized_state: State<F>,
    ) -> Result<[RoundWordDense<F>; STATE], Error> {
        self.compression
            .digest(layouter, final_state, initialized_state)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn message_process<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        input: [BlockWord; crate::BLOCK_SIZE],
    ) -> Result<[(AssignedBits<F, 16>, AssignedBits<F, 16>); ROUNDS], Error> {
        let (_, w_halves) = self.message_schedule.process(layouter, input)?;
        Ok(w_halves)
    }
}

/// A chip that implements SHA-256 with a maximum lookup table size of $2^16$.
#[derive(Clone, Debug)]
pub struct Table16Chip {
    config: Table16Config,
}

impl<F: Field> Chip<F> for Table16Chip {
    type Config = Table16Config;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl Table16Chip {
    /// Reconstructs this chip from the given config.
    pub fn construct<F: Field>(config: <Self as Chip<F>>::Config) -> Self {
        Self { config }
    }

    /// Configures a circuit to include this chip.
    pub fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> <Self as Chip<F>>::Config {
        // Columns required by this chip:
        let message_schedule = meta.advice_column();
        let extras = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        // - Three advice columns to interact with the lookup table.
        let input_tag = meta.advice_column();
        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        let lookup = SpreadTableChip::configure(meta, input_tag, input_dense, input_spread);
        let lookup_inputs = lookup.input.clone();

        // Rename these here for ease of matching the gates to the specification.
        let _a_0 = lookup_inputs.tag;
        let a_1 = lookup_inputs.dense;
        let a_2 = lookup_inputs.spread;
        let a_3 = extras[0];
        let a_4 = extras[1];
        let a_5 = message_schedule;
        let a_6 = extras[2];
        let a_7 = extras[3];
        let a_8 = extras[4];
        let _a_9 = extras[5];

        // Add all advice columns to permutation
        for column in [a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8].iter() {
            meta.enable_equality(*column);
        }

        let compression =
            CompressionConfig::configure(meta, lookup_inputs.clone(), message_schedule, extras);

        let message_schedule =
            MessageScheduleConfig::configure(meta, lookup_inputs, message_schedule, extras);

        Table16Config {
            lookup,
            message_schedule,
            compression,
        }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load<F: Field>(
        config: Table16Config,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup, layouter)
    }
}

/// composite of states in table16
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Table16State<F: Field> {
    /// working state (with spread assignment) for compression rounds
    Compress(Box<State<F>>),
    /// the dense state only carry hi-lo 16bit assigned cell used in digest and next block
    Dense([RoundWordDense<F>; STATE]),
}

impl<F: Field> super::Sha256Instructions<F> for Table16Chip {
    type State = Table16State<F>;
    type BlockWord = BlockWord;

    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error> {
        <Self as Chip<F>>::config(self)
            .compression
            .initialize_with_iv(layouter, IV)
            .map(Box::new)
            .map(Table16State::Compress)
    }

    fn initialization(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state: &Self::State,
    ) -> Result<Self::State, Error> {
        let dense_state = match init_state.clone() {
            Table16State::Compress(s) => {
                let (a, b, c, d, e, f, g, h) = s.decompose();
                [
                    a.into_dense(),
                    b.into_dense(),
                    c.into_dense(),
                    d,
                    e.into_dense(),
                    f.into_dense(),
                    g.into_dense(),
                    h,
                ]
            }
            Table16State::Dense(s) => s,
        };

        <Self as Chip<F>>::config(self)
            .compression
            .initialize(layouter, dense_state)
            .map(Box::new)
            .map(Table16State::Compress)
    }

    // Given an initialized state and an input message block, compress the
    // message block and return the final state.
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; super::BLOCK_SIZE],
    ) -> Result<Self::State, Error> {
        let config = <Self as Chip<F>>::config(self);
        let (_, w_halves) = config.message_schedule.process(layouter, input)?;

        let init_working_state = match initialized_state {
            Table16State::Compress(s) => s.as_ref().clone(),
            _ => panic!("unexpected state type"),
        };

        let final_state =
            config
                .compression
                .compress(layouter, init_working_state.clone(), w_halves)?;

        config
            .compression
            .digest(layouter, final_state, init_working_state)
            .map(Table16State::Dense)
    }

    fn digest(
        &self,
        _layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; super::DIGEST_SIZE], Error> {
        let digest_state = match state {
            Table16State::Dense(s) => s.clone(),
            _ => panic!("unexpected state type"),
        };

        Ok(digest_state.map(|s| s.value()).map(BlockWord))
    }
}

/// Common assignment patterns used by Table16 regions.
trait Table16Assignment<F: Field> {
    /// Assign cells for general spread computation used in sigma, ch, ch_neg, maj gates
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn assign_spread_outputs(
        &self,
        region: &mut Region<'_, F>,
        lookup: &SpreadInputs,
        a_3: Column<Advice>,
        row: usize,
        r_0_even: Value<[bool; 16]>,
        r_0_odd: Value<[bool; 16]>,
        r_1_even: Value<[bool; 16]>,
        r_1_odd: Value<[bool; 16]>,
    ) -> Result<
        (
            (AssignedBits<F, 16>, AssignedBits<F, 16>),
            (AssignedBits<F, 16>, AssignedBits<F, 16>),
        ),
        Error,
    > {
        // Lookup R_0^{even}, R_0^{odd}, R_1^{even}, R_1^{odd}
        let r_0_even = SpreadVar::with_lookup(
            region,
            lookup,
            row - 1,
            r_0_even.map(SpreadWord::<16, 32>::new),
        )?;
        let r_0_odd =
            SpreadVar::with_lookup(region, lookup, row, r_0_odd.map(SpreadWord::<16, 32>::new))?;
        let r_1_even = SpreadVar::with_lookup(
            region,
            lookup,
            row + 1,
            r_1_even.map(SpreadWord::<16, 32>::new),
        )?;
        let r_1_odd = SpreadVar::with_lookup(
            region,
            lookup,
            row + 2,
            r_1_odd.map(SpreadWord::<16, 32>::new),
        )?;

        // Assign and copy R_1^{odd}
        r_1_odd
            .spread
            .copy_advice(|| "Assign and copy R_1^{odd}", region, a_3, row)?;

        Ok((
            (r_0_even.dense, r_1_even.dense),
            (r_0_odd.dense, r_1_odd.dense),
        ))
    }

    /// Assign outputs of sigma gates
    #[allow(clippy::too_many_arguments)]
    fn assign_sigma_outputs(
        &self,
        region: &mut Region<'_, F>,
        lookup: &SpreadInputs,
        a_3: Column<Advice>,
        row: usize,
        r_0_even: Value<[bool; 16]>,
        r_0_odd: Value<[bool; 16]>,
        r_1_even: Value<[bool; 16]>,
        r_1_odd: Value<[bool; 16]>,
    ) -> Result<(AssignedBits<F, 16>, AssignedBits<F, 16>), Error> {
        let (even, _odd) = self.assign_spread_outputs(
            region, lookup, a_3, row, r_0_even, r_0_odd, r_1_even, r_1_odd,
        )?;

        Ok(even)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{Sha256, BLOCK_SIZE},
        message_schedule::msg_schedule_test_input,
        Table16Chip, Table16Config,
    };
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use halo2curves::pasta::pallas;

    struct MyCircuit {
        repeated: usize,
    }

    impl Circuit<pallas::Base> for MyCircuit {
        type Config = Table16Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            Table16Chip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let table16_chip = Table16Chip::construct::<pallas::Base>(config.clone());
            Table16Chip::load(config, &mut layouter)?;

            // Test vector: "abc"
            let test_input = msg_schedule_test_input();

            // Create a message of <repeated> blocks
            let mut input = Vec::with_capacity(self.repeated * BLOCK_SIZE);
            for _ in 0..self.repeated {
                input.extend_from_slice(&test_input);
            }

            let _digest = Sha256::digest(
                table16_chip,
                layouter.namespace(|| format!("'abc' * {}", self.repeated)),
                &input,
            )?;
            //println!("{:#x?}", digest);

            Ok(())
        }
    }

    #[test]
    fn table16_circuit() {
        let circuit = MyCircuit { repeated: 31 };
        let prover = match MockProver::<_>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    #[cfg(feature = "dev-graph")]
    fn print_table16_circuit() {
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("sha-256-table16-chip-layout.png", (1024, 3480)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("16-bit Table SHA-256 Chip", ("sans-serif", 60))
            .unwrap();

        let circuit = MyCircuit { repeated: 2 };
        halo2_proofs::dev::CircuitLayout::default()
            .render::<pallas::Base, _, _>(13, &circuit, &root)
            .unwrap();

        let prover = match MockProver::<_>::run(13, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
