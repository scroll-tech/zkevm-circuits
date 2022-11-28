use super::bytecode_unroller::{unroll, Config, UnrolledBytecode};
use crate::table::{BytecodeTable, KeccakTable};
use crate::util::Challenges;
use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

/// BytecodeCircuitTester
#[derive(Default)]
pub struct BytecodeCircuitTester<F: Field> {
    bytecodes: Vec<UnrolledBytecode<F>>,
    size: usize,
}

impl<F: Field> BytecodeCircuitTester<F> {
    /// new BytecodeCircuitTester
    pub fn new(bytecodes: Vec<UnrolledBytecode<F>>, size: usize) -> Self {
        BytecodeCircuitTester { bytecodes, size }
    }
}

impl<F: Field> Circuit<F> for BytecodeCircuitTester<F> {
    type Config = (Config<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let bytecode_table = BytecodeTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            Config::configure(meta, bytecode_table, keccak_table, challenges)
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);

        config.load(&mut layouter)?;
        config.keccak_table.dev_load(
            &mut layouter,
            self.bytecodes.iter().map(|b| &b.bytes),
            &challenges,
        )?;
        config.assign_internal(
            &mut layouter,
            self.size,
            &self.bytecodes,
            &challenges,
            false,
        )?;
        Ok(())
    }
}

impl<F: Field> BytecodeCircuitTester<F> {
    /// Verify that the selected bytecode fulfills the circuit
    pub fn verify_raw(k: u32, bytecodes: Vec<Vec<u8>>) {
        let unrolled: Vec<_> = bytecodes.iter().map(|b| unroll(b.clone())).collect();
        Self::verify(k, unrolled, true);
    }

    pub(crate) fn verify(k: u32, bytecodes: Vec<UnrolledBytecode<F>>, success: bool) {
        let circuit = BytecodeCircuitTester::<F> {
            bytecodes,
            size: 2usize.pow(k),
        };

        let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
        let result = prover.verify();
        if let Err(failures) = &result {
            for failure in failures.iter() {
                println!("{}", failure);
            }
        }
        assert_eq!(result.is_ok(), success);
    }
}

/// Test bytecode circuit with raw bytecode
pub fn test_bytecode_circuit<F: Field>(k: u32, bytecodes: Vec<Vec<u8>>) {
    let unrolled: Vec<_> = bytecodes.iter().map(|b| unroll::<F>(b.clone())).collect();
    test_bytecode_circuit_unrolled(k, unrolled, true);
}

/// Test bytecode circuit with unrolled bytecode
pub fn test_bytecode_circuit_unrolled<F: Field>(
    k: u32,
    bytecodes: Vec<UnrolledBytecode<F>>,
    success: bool,
) {
    let k = k + 3;
    let circuit = BytecodeCircuitTester::<F> {
        bytecodes,
        size: 2usize.pow(k),
    };

    let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
    let result = prover.verify_par();
    if let Err(failures) = &result {
        for failure in failures.iter() {
            println!("{}", failure);
        }
    }
    assert_eq!(result.is_ok(), success);
}
