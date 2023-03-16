//! Testing utilities

use crate::{
    evm_circuit::EvmCircuit,
    state_circuit::StateCircuit,
    util::{log2_ceil, SubCircuit},
    witness::{Block, Rw},
};
use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use eth_types::geth_types::GethData;

use halo2_proofs::circuit::Value;
use halo2_proofs::dev::{unwrap_value, MockProver};
use halo2_proofs::halo2curves::bn256::Fr;
use mock::TestContext;

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
}

#[allow(clippy::type_complexity)]
/// Struct used to easily generate tests for EVM &| State circuits being able to
/// customize all of the steps involved in the testing itself.
///
/// By default, the tests run through `prover.assert_satisfied_par()` but the
/// builder pattern provides functions that allow to pass different functions
/// that the prover should execute when verifying the CTB correctness.
///
/// The CTB also includes a mechanism to receive calls that will modify the
/// block produced from the [`TestContext`] and apply them before starting to
/// compute the proof.
///
/// ## Example:
/// ```rust, no_run
/// use eth_types::geth_types::Account;
/// use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256, word};
/// use mock::{TestContext, MOCK_ACCOUNTS, gwei, eth};
/// use zkevm_circuits::test_util::CircuitTestBuilder;
///     let code = bytecode! {
/// // [ADDRESS, STOP]
///     PUSH32(word!("
/// 3000000000000000000000000000000000000000000000000000000000000000"))
///     PUSH1(0)
///     MSTORE
///
///     PUSH1(2)
///     PUSH1(0)
///     RETURN
/// };
/// let ctx = TestContext::<1, 1>::new(
///     None,
///     |accs| {
///         accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
///     },
///     |mut txs, _accs| {
///         txs[0]
///             .from(MOCK_ACCOUNTS[0])
///             .gas_price(gwei(2))
///             .gas(Word::from(0x10000))
///             .value(eth(2))
///             .input(code.into());
///     },
///     |block, _tx| block.number(0xcafeu64),
/// )
/// .unwrap();
///
/// CircuitTestBuilder::new_from_test_ctx(ctx)
///     .block_modifier(Box::new(|block| block.circuits_params.max_evm_rows = (1 << 18) - 100))
///     .state_checks(Box::new(|prover, evm_rows, lookup_rows| assert!(prover.verify_at_rows_par(evm_rows.iter().cloned(), lookup_rows.iter().cloned()).is_err())))
///     .run();
/// ```
pub struct CircuitTestBuilder<const NACC: usize, const NTX: usize> {
    test_ctx: Option<TestContext<NACC, NTX>>,
    circuits_params: Option<CircuitsParams>,
    block: Option<Block<Fr>>,
    evm_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    state_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    block_modifiers: Vec<Box<dyn Fn(&mut Block<Fr>)>>,
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// Generates an empty/set to default `CircuitTestBuilder`.
    fn empty() -> Self {
        CircuitTestBuilder {
            test_ctx: None,
            circuits_params: None,
            block: None,
            evm_checks: Box::new(|prover, gate_rows, lookup_rows| {
                assert_eq!(prover.verify_at_rows_par(
                    gate_rows.iter().cloned(),
                    lookup_rows.iter().cloned(),
                ), Ok(()));
            }),
            state_checks: Box::new(|prover, gate_rows, lookup_rows| {
                assert_eq!(prover.verify_at_rows_par(
                    gate_rows.iter().cloned(),
                    lookup_rows.iter().cloned(),
                ), Ok(()));
            }),
            block_modifiers: vec![],
        }
    }

    /// Generates a CTBC from a [`TestContext`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_test_ctx(ctx: TestContext<NACC, NTX>) -> Self {
        Self::empty().test_ctx(ctx)
    }

    /// Generates a CTBC from a [`Block`] passed with all the other fields
    /// set to [`Default`].
    pub fn new_from_block(block: Block<Fr>) -> Self {
        Self::empty().block(block)
    }

    /// Allows to produce a [`TestContext`] which will serve as the generator of
    /// the Block.
    pub fn test_ctx(mut self, ctx: TestContext<NACC, NTX>) -> Self {
        self.test_ctx = Some(ctx);
        self
    }

    /// Allows to pass a non-default [`CircuitsParams`] to the builder.
    /// This means that we can increase for example, the `max_rws` or `max_txs`.
    pub fn params(mut self, params: CircuitsParams) -> Self {
        assert!(
            self.block.is_none(),
            "circuit_params already provided in the block"
        );
        self.circuits_params = Some(params);
        self
    }

    /// Allows to pass a [`Block`] already built to the constructor.
    pub fn block(mut self, block: Block<Fr>) -> Self {
        self.block = Some(block);
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide checks different than the default ones for the State
    /// Circuit verification.
    pub fn state_checks(
        mut self,
        state_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    ) -> Self {
        self.state_checks = state_checks;
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide checks different than the default ones for the EVM
    /// Circuit verification.
    pub fn evm_checks(
        mut self,
        evm_checks: Box<dyn Fn(MockProver<Fr>, &Vec<usize>, &Vec<usize>)>,
    ) -> Self {
        self.evm_checks = evm_checks;
        self
    }

    #[allow(clippy::type_complexity)]
    /// Allows to provide modifier functions for the [`Block`] that will be
    /// generated within this builder.
    ///
    /// That removes the need in a lot of tests to build the block outside of
    /// the builder because they need to modify something particular.
    pub fn block_modifier(mut self, modifier: Box<dyn Fn(&mut Block<Fr>)>) -> Self {
        self.block_modifiers.push(modifier);
        self
    }
}

impl<const NACC: usize, const NTX: usize> CircuitTestBuilder<NACC, NTX> {
    /// Triggers the `CircuitTestBuilder` to convert the [`TestContext`] if any,
    /// into a [`Block`] and apply the default or provided block_modifiers or
    /// circuit checks to the provers generated for the State and EVM circuits.
    pub fn run(self) {
        let params = if let Some(block) = self.block.as_ref() {
            block.circuits_params
        } else {
            self.circuits_params.unwrap_or_default()
        };
        log::debug!("params in CircuitTestBuilder: {:?}", params);

        let block: Block<Fr> = if self.block.is_some() {
            self.block.unwrap()
        } else if self.test_ctx.is_some() {
            let block: GethData = self.test_ctx.unwrap().into();
            let mut builder = BlockData::new_from_geth_data_with_params(block.clone(), params)
                .new_circuit_input_builder();
            builder
                .handle_block(&block.eth_block, &block.geth_traces)
                .unwrap();
            // Build a witness block from trace result.
            let mut block =
                crate::witness::block_convert(&builder.block, &builder.code_db).unwrap();

            for modifier_fn in self.block_modifiers {
                modifier_fn.as_ref()(&mut block);
            }
            block
        } else {
            panic!("No attribute to build a block was passed to the CircuitTestBuilder")
        };

        const NUM_BLINDING_ROWS: usize = 64;
        // Run evm circuit test
        {
            let k = block.get_test_degree();
            let (active_gate_rows, active_lookup_rows) = EvmCircuit::<Fr>::get_active_rows(&block);

            let circuit = EvmCircuit::get_test_cicuit_from_block(block.clone());
            let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

            self.evm_checks.as_ref()(prover, &active_gate_rows, &active_lookup_rows)
        }

        // Run state circuit test
        {
            let rows_needed = StateCircuit::<Fr>::min_num_rows_block(&block).1;
            let k = log2_ceil(rows_needed + NUM_BLINDING_ROWS);
            let state_circuit = StateCircuit::<Fr>::new(block.rws, params.max_rws);
            let instance = state_circuit.instance();
            let prover = MockProver::<Fr>::run(k, &state_circuit, instance).unwrap();
            // Skip verification of Start rows to accelerate testing
            let non_start_rows_len = state_circuit
                .rows
                .iter()
                .filter(|rw| !matches!(rw, Rw::Start { .. }))
                .count();
            let rows = (params.max_rws - non_start_rows_len..params.max_rws)
                .into_iter()
                .collect();

            self.state_checks.as_ref()(prover, &rows, &rows);
        }
    }
}

/// Escape the type safety of Value in tests.
pub fn escape_value<T>(v: Value<T>) -> Option<T> {
    if v.is_none() {
        None
    } else {
        Some(unwrap_value(v))
    }
}
