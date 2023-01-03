//! Common utility traits and functions.
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::table::TxLogFieldTag;
use crate::witness;
use eth_types::{Field, ToAddress};
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
    crate::evm_circuit::util::Word::random_linear_combine(bytes, randomness)
}

pub(crate) fn rlc_be_bytes<F: Field>(bytes: &[u8], rand: Value<F>) -> Value<F> {
    rand.map(|rand| {
        bytes
            .iter()
            .fold(F::zero(), |acc, byte| acc * rand + F::from(*byte as u64))
    })
}

/// Query N instances at current rotation and return their expressions.  This
/// function is used to get the power of randomness (passed as
/// instances) in our tests.
pub fn power_of_randomness_from_instance<F: FieldExt, const N: usize>(
    meta: &mut ConstraintSystem<F>,
) -> [Expression<F>; N] {
    // This gate is used just to get the array of expressions from the power of
    // randomness instance column, so that later on we don't need to query
    // columns everywhere, and can pass the power of randomness array
    // expression everywhere.  The gate itself doesn't add any constraints.

    let columns = [(); N].map(|_| meta.instance_column());
    query_expression(meta, |meta| {
        columns.map(|column| meta.query_instance(column, Rotation::cur()))
    })
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = u128> {
    evm_word: T,
    keccak_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: FieldExt>(_meta: &mut ConstraintSystem<F>) -> Self {
        //#[cfg(test)]
        //let _dummy_col = meta.advice_column();

        Self {
            evm_word: DEFAULT_RAND,
            keccak_input: DEFAULT_RAND,
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: FieldExt>(&self, _meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [evm_word, keccak_input] = [self.evm_word, self.keccak_input]
            .map(|challenge| Expression::Constant(F::from_u128(challenge)));
        Challenges {
            evm_word,
            keccak_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: FieldExt>(&self, _layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: Value::known(F::from_u128(self.evm_word)),
            keccak_input: Value::known(F::from_u128(self.keccak_input)),
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

    /// ..
    pub fn mock(evm_word: T, keccak_input: T) -> Self {
        Self {
            evm_word,
            keccak_input,
        }
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness for word RLC encoding
    pub fn evm_word_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        std::iter::successors(self.evm_word.clone().into(), |power| {
            (self.evm_word.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
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
}

/// SubCircuit configuration
pub trait SubCircuitConfig<F: Field> {
    /// Config constructor arguments
    type ConfigArgs;

    /// Type constructor
    fn new(meta: &mut ConstraintSystem<F>, args: Self::ConfigArgs) -> Self;
}

/// the magic number is `echo 'zkevm-circuits' | hexdump`
pub const DEFAULT_RAND: u128 = 0x10000; //0x6b7a76652d6d6963637269757374u128;
