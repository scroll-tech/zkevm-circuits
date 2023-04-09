//! Common utility traits and functions.
use std::collections::BTreeSet;

use bus_mapping::evm::OpcodeId;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{Challenge, ConstraintSystem, Error, Expression, FirstPhase, VirtualCells},
};
use keccak256::plain::Keccak;

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use crate::{evm_circuit::util::rlc, table::TxLogFieldTag, witness};
use eth_types::{Field, ToAddress, Word};
pub use ethers_core::types::{Address, U256};
pub use gadgets::util::Expr;

pub(crate) fn query_expression<F: FieldExt, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

pub(crate) fn random_linear_combine_word<F: FieldExt>(bytes: [u8; 32], randomness: F) -> F {
    rlc::value(&bytes, randomness)
}

pub(crate) fn rlc_be_bytes<F: Field>(bytes: &[u8], rand: Value<F>) -> Value<F> {
    rand.map(|rand| {
        bytes
            .iter()
            .fold(F::zero(), |acc, byte| acc * rand + F::from(*byte as u64))
    })
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    evm_word: T,
    keccak_input: T,
    lookup_input: T,
}

/// ..
#[derive(Default, Clone, Copy, Debug)]
pub struct MockChallenges {
    evm_word: u64,
    keccak_input: u64,
    lookup_input: u64,
}

impl MockChallenges {
    /// ..
    pub fn construct<F: FieldExt>(_meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            evm_word: 0x100,
            keccak_input: 0x100,
            lookup_input: 0x100,
        }
    }
    /// ..
    pub fn exprs<F: FieldExt>(&self, _meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        Challenges {
            evm_word: Expression::Constant(F::from(self.evm_word)),
            keccak_input: Expression::Constant(F::from(self.keccak_input)),
            lookup_input: Expression::Constant(F::from(self.lookup_input)),
        }
    }
    /// ..
    pub fn values<F: FieldExt>(&self, _layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: Value::known(F::from(self.evm_word)),
            keccak_input: Value::known(F::from(self.keccak_input)),
            lookup_input: Value::known(F::from(self.lookup_input)),
        }
    }
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(any(not(feature = "onephase"), feature = "test", test))]
        let _dummy_cols = [
            meta.advice_column(),
            meta.advice_column_in(halo2_proofs::plonk::SecondPhase),
            meta.advice_column_in(halo2_proofs::plonk::ThirdPhase),
        ];

        Self {
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [evm_word, keccak_input, lookup_input] = query_expression(meta, |meta| {
            [self.evm_word, self.keccak_input, self.lookup_input]
                .map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: FieldExt>(&self, layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: layouter.get_challenge(self.evm_word),
            keccak_input: layouter.get_challenge(self.keccak_input),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `evm_word`.
    pub fn evm_word(&self) -> T {
        self.evm_word.clone()
    }

    /// Returns challenge of `keccak_input`.
    pub fn keccak_input(&self) -> T {
        self.keccak_input.clone()
    }

    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [&self.evm_word, &self.keccak_input, &self.lookup_input]
    }

    /// ..
    pub fn mock(evm_word: T, keccak_input: T, lookup_input: T) -> Self {
        Self {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }

    /// Returns powers of randomness for word RLC encoding
    pub fn evm_word_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.evm_word.clone())
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.keccak_input.clone())
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}

pub(crate) fn build_tx_log_address(index: u64, field_tag: TxLogFieldTag, log_id: u64) -> Address {
    (U256::from(index) + (U256::from(field_tag as u64) << 32) + (U256::from(log_id) << 48))
        .to_address()
}

pub(crate) fn build_tx_log_expression<F: Field>(
    index: Expression<F>,
    field_tag: Expression<F>,
    log_id: Expression<F>,
) -> Expression<F> {
    index + (1u64 << 32).expr() * field_tag + ((1u64 << 48).expr()) * log_id
}

/// SubCircuit is a circuit that performs the verification of a specific part of
/// the full Ethereum block verification.  The SubCircuit's interact with each
/// other via lookup tables and/or shared public inputs.  This type must contain
/// all the inputs required to synthesize this circuit (and the contained
/// table(s) if any).
pub trait SubCircuit<F: Field> {
    /// Configuration of the SubCircuit.
    type Config: SubCircuitConfig<F>;

    /// Create a new SubCircuit from a witness Block
    fn new_from_block(block: &witness::Block<F>) -> Self;

    /// Returns the instance columns required for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        vec![]
    }
    /// Assign only the columns used by this sub-circuit.  This includes the
    /// columns that belong to the exposed lookup table contained within, if
    /// any; and excludes external tables that this sub-circuit does lookups
    /// to.
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error>;

    /// Return the minimum number of rows required to prove the block.
    /// Row numbers without/with padding are both returned.
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize);
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// Ceiling of log_2(n)
pub fn log2_ceil(n: usize) -> u32 {
    u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
}

pub(crate) fn keccak(msg: &[u8]) -> Word {
    let mut keccak = Keccak::default();
    keccak.update(msg);
    Word::from_big_endian(keccak.digest().as_slice())
}

pub(crate) fn is_push(byte: u8) -> bool {
    OpcodeId::from(byte).is_push()
}

pub(crate) fn get_push_size(byte: u8) -> u64 {
    if is_push(byte) {
        byte as u64 - OpcodeId::PUSH1.as_u64() + 1
    } else {
        0u64
    }
}

/// Using values like this will make it easier to debug...
pub const DEFAULT_RAND: u128 = 0x10000;

#[derive(Debug)]
pub(crate) struct CircuitStats {
    num_constraints: usize,
    num_fixed_columns: usize,
    num_lookups: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_selectors: usize,
    num_simple_selectors: usize,
    num_permutation_columns: usize,
    degree: usize,
    num_challenges: usize,
    max_phase: u8,
    num_rotation: usize,
    min_rotation: i32,
    max_rotation: i32,
    num_verification_ecmul: usize,
}

pub(crate) fn circuit_stats<F: Field>(meta: &ConstraintSystem<F>) -> CircuitStats {
    let rotations = meta
        .advice_queries
        .iter()
        .map(|(_, q)| q.0)
        .collect::<BTreeSet<i32>>();
    CircuitStats {
        num_constraints: meta
            .gates()
            .iter()
            .map(|g| g.polynomials().len())
            .sum::<usize>(),
        num_fixed_columns: meta.num_fixed_columns,
        num_lookups: meta.lookups.len(),
        num_advice_columns: meta.num_advice_columns,
        num_instance_columns: meta.num_instance_columns,
        num_selectors: meta.num_selectors,
        num_simple_selectors: meta.num_simple_selectors,
        num_permutation_columns: meta.permutation.columns.len(),
        degree: meta.degree(),
        num_challenges: meta.num_challenges(),
        max_phase: meta.max_phase(),
        num_rotation: rotations.len(),
        min_rotation: rotations.first().cloned().unwrap_or_default(),
        max_rotation: rotations.last().cloned().unwrap_or_default(),
        // TODO: add permutation related ecmuls
        num_verification_ecmul: meta.num_advice_columns + 3 * meta.lookups.len() + rotations.len(),
    }
}
