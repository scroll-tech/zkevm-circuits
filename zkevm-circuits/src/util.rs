//! Common utility traits and functions.
use std::collections::BTreeSet;

use bus_mapping::evm::OpcodeId;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Challenge, Circuit, ConstraintSystem, Error, Expression, FirstPhase, VirtualCells},
};

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;
use sha3::Digest;

use crate::{evm_circuit::util::rlc, table::TxLogFieldTag, witness};
use eth_types::{ToAddress, Word};
pub use ethers_core::types::{Address, U256};
pub use gadgets::util::Expr;

/// A wrapper of is_zero in gadgets which gives is_zero at any rotation
pub mod is_zero;

/// The field used in circuits. We only support bn254fr now.
pub trait Field = gadgets::Field + halo2_base::utils::ScalarField;

pub(crate) fn query_expression<F: Field, T>(
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

pub(crate) fn random_linear_combine_word<F: Field>(bytes: [u8; 32], randomness: F) -> F {
    rlc::value(&bytes, randomness)
}

pub(crate) fn rlc_be_bytes<F: Field>(bytes: &[u8], rand: Value<F>) -> Value<F> {
    rand.map(|rand| {
        bytes
            .iter()
            .fold(F::zero(), |acc, byte| acc * rand + F::from(*byte as u64))
    })
}

/// Wrap multiple challenges:
/// `construct`: the default construct route to provide all challenges used in `SuperCircuit`.
/// `construct_p1`: construct challenge up to second phase
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    evm_word: T,
    keccak_input: T,
    lookup_input: Option<T>,
}

/// ..
#[derive(Default, Clone, Copy, Debug)]
pub struct MockChallenges {
    evm_word: u64,
    keccak_input: u64,
    lookup_input: Option<u64>,
}

impl MockChallenges {
    /// ..
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            lookup_input: Some(0x100),
            ..Self::construct_p1(meta)
        }
    }
    /// ..
    pub fn construct_p1<F: Field>(_meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            evm_word: 0x100,
            keccak_input: 0x101,
            lookup_input: None,
        }
    }
    /// ..
    pub fn exprs<F: Field>(&self, _meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        Challenges {
            evm_word: Expression::Constant(F::from(self.evm_word)),
            keccak_input: Expression::Constant(F::from(self.keccak_input)),
            lookup_input: self.lookup_input.map(|c| Expression::Constant(F::from(c))),
        }
    }
    /// ..
    pub fn values<F: Field>(&self, _layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: Value::known(F::from(self.evm_word)),
            keccak_input: Value::known(F::from(self.keccak_input)),
            lookup_input: self.lookup_input.map(|c| Value::known(F::from(c))),
        }
    }
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges only to secondary phases.
    pub fn construct_p1<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(any(not(feature = "onephase"), feature = "test", test))]
        let _dummy_cols = [
            meta.advice_column(),
            meta.advice_column_in(halo2_proofs::plonk::SecondPhase),
        ];

        Self {
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: None,
        }
    }

    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(any(not(feature = "onephase"), feature = "test", test))]
        let _dummy_cols = [
            meta.advice_column(),
            meta.advice_column_in(halo2_proofs::plonk::SecondPhase),
            meta.advice_column_in(halo2_proofs::plonk::ThirdPhase),
        ];

        Self {
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: Some(meta.challenge_usable_after(SecondPhase)),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: Field>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [evm_word, keccak_input] = query_expression(meta, |meta| {
            [self.evm_word, self.keccak_input].map(|challenge| meta.query_challenge(challenge))
        });
        let lookup_input = self
            .lookup_input
            .map(|c| query_expression(meta, |meta| meta.query_challenge(c)));
        Challenges {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: Field>(&self, layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: layouter.get_challenge(self.evm_word),
            keccak_input: layouter.get_challenge(self.keccak_input),
            lookup_input: self.lookup_input.map(|c| layouter.get_challenge(c)),
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
        self.lookup_input
            .as_ref()
            .expect("created for supercircuit")
            .clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [
            &self.evm_word,
            &self.keccak_input,
            self.lookup_input
                .as_ref()
                .expect("created for supercircuit"),
        ]
    }

    /// ..
    pub fn mock(evm_word: T, keccak_input: T, lookup_input: T) -> Self {
        Self {
            evm_word,
            keccak_input,
            lookup_input: Some(lookup_input),
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
        Self::powers_of(
            self.lookup_input
                .as_ref()
                .expect("created for supercircuit")
                .clone(),
        )
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

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        256
    }

    /// Create a new SubCircuit from a witness Block
    fn new_from_block(block: &witness::Block) -> Self;

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
    fn min_num_rows_block(block: &witness::Block) -> (usize, usize);
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// Ceiling of log_2(n)
/// `log2_ceil(0)` returns 0.
pub fn log2_ceil(n: usize) -> u32 {
    (u32::BITS - (n as u32).leading_zeros()) - u32::from(n.is_power_of_two())
}

pub(crate) fn keccak(msg: &[u8]) -> Word {
    Word::from_big_endian(sha3::Keccak256::digest(msg).as_slice())
}

pub(crate) fn is_push_with_data(byte: u8) -> bool {
    OpcodeId::from(byte).is_push_with_data()
}

pub(crate) fn get_push_size(byte: u8) -> u64 {
    if is_push_with_data(byte) {
        byte as u64 - OpcodeId::PUSH0.as_u64()
    } else {
        0u64
    }
}

/// Basic stats of circuit config
#[derive(Debug)]
pub struct CircuitStats {
    num_constraints: usize,
    num_fixed_columns: usize,
    num_lookups: usize,
    num_advice_columns: usize,
    num_instance_columns: usize,
    num_selectors: usize,
    num_simple_selectors: usize,
    num_permutation_columns: usize,
    num_vk_commitment: usize,
    degree: usize,
    blinding_factors: usize,
    num_challenges: usize,
    max_phase: u8,
    num_rotation: usize,
    min_rotation: i32,
    max_rotation: i32,
    num_verification_ecmul: usize,
}

/// Basic stats of circuit config
pub fn circuit_stats<F: Field>(meta: &ConstraintSystem<F>) -> CircuitStats {
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
        num_vk_commitment: meta.num_fixed_columns
            + meta.num_selectors
            + meta.permutation.columns.len(),
        degree: meta.degree(),
        blinding_factors: meta.blinding_factors(),
        num_challenges: meta.num_challenges(),
        max_phase: meta.max_phase(),
        num_rotation: rotations.len(),
        min_rotation: rotations.first().cloned().unwrap_or_default(),
        max_rotation: rotations.last().cloned().unwrap_or_default(),
        num_verification_ecmul: meta.num_advice_columns
            + meta.num_instance_columns
            + meta.permutation.columns.len()
            + meta.num_selectors
            + meta.num_fixed_columns
            + 3 * meta.lookups.len()
            + rotations.len(),
    }
}

/// Returns number of unusable rows of the Circuit.
/// The minimum unusable rows of a circuit is currently 6, where
/// - 3 comes from minimum number of distinct queries to permutation argument witness column
/// - 1 comes from queries at x_3 during multiopen
/// - 1 comes as slight defense against off-by-one errors
/// - 1 comes from reservation for last row for grand-product boundary check, hence not copy-able or
///   lookup-able. Note this 1 is not considered in [`ConstraintSystem::blinding_factors`], so below
///   we need to add an extra 1.
///
/// For circuit with column queried at more than 3 distinct rotation, we can
/// calculate the unusable rows as (x - 3) + 6 where x is the number of distinct
/// rotation.
pub(crate) fn unusable_rows<F: Field, C: Circuit<F>>() -> usize {
    let mut cs = ConstraintSystem::default();
    C::configure(&mut cs);

    cs.blinding_factors() + 1
}

/// The function of this algorithm： Split a vec into two subsets such that
/// the sums of the two subsets are as close as possible。
pub(crate) fn find_two_closest_subset(vec: &[i32]) -> (Vec<i32>, Vec<i32>) {
    let total_sum: i32 = vec.iter().sum();
    let n = vec.len();

    // dp[i][j]：indicates whether it is possible to achieve a sum of j using the first i elements.
    let mut dp = vec![vec![false; (total_sum / 2 + 1) as usize]; n + 1];

    // initialization: first sum zero can be always reached.
    for i in 0..=n {
        dp[i][0] = true;
    }

    // fill dp table
    for i in 1..=n {
        for j in 1..=(total_sum / 2) as usize {
            if j >= vec[i - 1] as usize {
                dp[i][j] = dp[i - 1][j] || dp[i - 1][j - vec[i - 1] as usize];
            } else {
                dp[i][j] = dp[i - 1][j];
            }
        }
    }

    // find closest sum
    let mut sum1 = 0;
    for j in (0..=(total_sum / 2) as usize).rev() {
        if dp[n][j] {
            sum1 = j as i32;
            break;
        }
    }

    // construct two sub set
    let mut subset1 = Vec::new();
    let mut subset2 = Vec::new();
    let mut current_sum = sum1;
    for i in (1..=n).rev() {
        if current_sum >= vec[i - 1] && dp[i - 1][current_sum as usize - vec[i - 1] as usize] {
            subset1.push(vec[i - 1]);
            current_sum -= vec[i - 1];
        } else {
            subset2.push(vec[i - 1]);
        }
    }

    (subset1, subset2)
}

// tests for algorithm of `find_two_closest_subset`
#[test]
fn test_find_two_closest_subset() {
    let mut nums = vec![80, 100, 10, 20];
    let (set1, set2) = find_two_closest_subset(&nums);
    // set1's sum: 100, set2's sum: 110, diff = 10
    assert_eq!(set1, [20, 80]);
    assert_eq!(set2, [10, 100]);

    nums = vec![80, 20, 50, 110, 32];
    let (set1, set2) = find_two_closest_subset(&nums);
    // set1's sum: 142, set2's sum: 150, diff = 8
    assert_eq!(set1, [32, 110]);
    assert_eq!(set2, [50, 20, 80]);

    nums = vec![1, 5, 11, 5, 10];
    let (set1, set2) = find_two_closest_subset(&nums);
    // set1's sum: 16, set2's sum: 16, diff = 0
    assert_eq!(set1, [10, 5, 1]);
    assert_eq!(set2, [11, 5]);

    nums = vec![1, 5, 11, 5, 10, 20, 4];
    let (set1, set2) = find_two_closest_subset(&nums);
    // set1's sum: 27, set2's sum: 29, diff = 2
    assert_eq!(set1, [10, 5, 11, 1]);
    assert_eq!(set2, [4, 20, 5]);
}
