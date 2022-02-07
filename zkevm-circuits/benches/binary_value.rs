use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use halo2::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};

use pairing::{arithmetic::FieldExt, bn256::Fr as Fp};

#[derive(Copy, Clone, Debug)]
struct MemoryAddress<F: FieldExt>(F);

/// Global counter
#[derive(Copy, Clone, Debug)]
struct GlobalCounter(usize);

#[derive(Copy, Clone, Debug)]
struct Value<F: FieldExt>(F);

#[derive(Clone, Debug)]
enum ReadWrite<F: FieldExt> {
    // flag == 0
    Read(GlobalCounter, Value<F>),
    // flag == 1
    Write(GlobalCounter, Value<F>),
}

impl<F: FieldExt> ReadWrite<F> {
    fn global_counter(&self) -> GlobalCounter {
        match self {
            Self::Read(global_counter, _) | Self::Write(global_counter, _) => *global_counter,
        }
    }

    fn value(&self) -> Value<F> {
        match self {
            Self::Read(_, value) | Self::Write(_, value) => *value,
        }
    }

    fn flag(&self) -> bool {
        match self {
            Self::Read(..) => false,
            Self::Write(..) => true,
        }
    }
}

#[derive(Clone, Debug)]
/// All the read/write operations that happen at this address.
pub(crate) struct MemoryOp<F: FieldExt> {
    address: MemoryAddress<F>,
    global_counters: Vec<Option<ReadWrite<F>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Config<F: FieldExt, const LOOKUP: bool> {
    q_target: Column<Fixed>,
    address: Column<Advice>,
    global_counter: Column<Advice>,
    value: Column<Advice>,
    flag: Column<Advice>,
    binary_table: Column<Fixed>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const LOOKUP: bool> Config<F, LOOKUP> {
    /// Set up custom gates and lookup arguments for this configuration.
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_target = meta.fixed_column();
        let address = meta.advice_column();
        let global_counter = meta.advice_column();
        let value = meta.advice_column();
        let flag = meta.advice_column();
        let binary_table = meta.fixed_column();

        if LOOKUP {
            meta.lookup_any(|meta| {
                let q_target = meta.query_fixed(q_target, Rotation::cur());
                let flag = meta.query_advice(flag, Rotation::cur());
                let binary_table = meta.query_fixed(binary_table, Rotation::cur());

                vec![(q_target * flag, binary_table)]
            });
        } else {
            meta.create_gate("Memory operation", |meta| {
                let q_target = meta.query_fixed(q_target, Rotation::cur());
                let flag = meta.query_advice(flag, Rotation::cur());

                // flag == 0 or 1
                // (flag) * (1 - flag)
                let bool_check_flag = {
                    let one = Expression::Constant(F::one());
                    flag.clone() * (one - flag)
                };

                vec![q_target * bool_check_flag]
            });
        }

        Config {
            q_target,
            address,
            global_counter,
            value,
            flag,
            binary_table,
            _marker: PhantomData,
        }
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "binary table",
            |mut region| {
                for idx in 0..=1 {
                    region.assign_fixed(
                        || "binary table",
                        self.binary_table,
                        idx,
                        || Ok(F::from(idx as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    /// Assign cells.
    pub(crate) fn assign(&self, mut layouter: impl Layouter<F>, ops: Vec<MemoryOp<F>>) {
        layouter
            .assign_region(
                || "Memory operations",
                |mut region| {
                    let mut offset = 0;

                    for (_index, op) in ops.iter().enumerate() {
                        let address = op.address;

                        self.init(&mut region, offset, address)?;
                        region.assign_fixed(
                            || "Memory selector",
                            self.q_target,
                            offset,
                            || Ok(F::one()),
                        )?;

                        // Increase offset by 1 after initialising.
                        offset += 1;

                        for global_counter in op.global_counters.iter() {
                            self.assign_per_counter(&mut region, offset, address, global_counter);

                            region.assign_fixed(
                                || "Memory selector",
                                self.q_target,
                                offset,
                                || Ok(F::one()),
                            )?;
                            offset += 1;
                        }
                    }

                    Ok(())
                },
            )
            .ok();
    }

    /// Initialise first row for a new operation.
    fn init(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: MemoryAddress<F>,
    ) -> Result<(), Error> {
        // Assign `address`
        region.assign_advice(|| "init address", self.address, offset, || Ok(address.0))?;

        // Assign `global_counter`
        region.assign_advice(
            || "init global counter",
            self.global_counter,
            offset,
            || Ok(F::zero()),
        )?;

        // Assign `value`
        region.assign_advice(|| "init value", self.value, offset, || Ok(F::zero()))?;

        // Assign memory_flag
        region.assign_advice(|| "init memory", self.flag, offset, || Ok(F::one()))?;

        Ok(())
    }

    /// Assign cells for each global counter in an operation.
    fn assign_per_counter(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        address: MemoryAddress<F>,
        read_write: &Option<ReadWrite<F>>,
    ) {
        region
            .assign_advice(|| "address", self.address, offset, || Ok(address.0))
            .ok();

        let value = read_write
            .as_ref()
            .map(|read_write| read_write.global_counter().0);
        let field_elem = value.map(|value| F::from(value as u64));

        region
            .assign_advice(
                || "global counter",
                self.global_counter,
                offset,
                || field_elem.ok_or(Error::Synthesis),
            )
            .ok();

        // Assign `value`
        let value = read_write.as_ref().map(|read_write| read_write.value().0);
        region
            .assign_advice(
                || "value",
                self.value,
                offset,
                || value.ok_or(Error::Synthesis),
            )
            .ok();

        let value = read_write.as_ref().map(|read_write| read_write.flag());
        let field_elem = value.map(|value| F::from(value as u64));
        region
            .assign_advice(
                || "flag",
                self.flag,
                offset,
                || field_elem.ok_or(Error::Synthesis),
            )
            .ok();
    }
}

macro_rules! test_state_circuit {
    ($lookup:expr) => {{
        #[derive(Default)]
        struct MemoryCircuit<F: FieldExt, const LOOKUP: bool> {
            ops: Vec<MemoryOp<F>>,
            _marker: PhantomData<F>,
        }

        impl<F: FieldExt, const LOOKUP: bool> Circuit<F> for MemoryCircuit<F, LOOKUP> {
            type Config = Config<F, LOOKUP>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                Config::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.load(&mut layouter)?;
                config.assign(layouter, self.ops.clone());

                Ok(())
            }
        }

        let mut ops = vec![];
        for _i in 0..10000 {
            let op = MemoryOp {
                address: MemoryAddress(Fp::zero()),
                global_counters: vec![
                    Some(ReadWrite::Write(GlobalCounter(12), Value(Fp::from(12)))),
                    Some(ReadWrite::Read(GlobalCounter(24), Value(Fp::from(12)))),
                ],
            };
            ops.push(op);
        }

        let circuit = MemoryCircuit::<Fp, $lookup> {
            ops,
            _marker: PhantomData,
        };

        let prover = MockProver::<Fp>::run(7, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }};
}

// measuring the value being binary with lookup table (containing 0 and 1) and
// with gate
fn binary() {
    test_state_circuit!(true); // with lookup
                               // test_state_circuit!(false); // with gate
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("checking binary values", |b| b.iter(binary));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
