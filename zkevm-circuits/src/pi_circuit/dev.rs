use super::*;

// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[derive(Default, Clone)]
pub struct PiTestCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    pub PiCircuit<F>,
);

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> SubCircuit<F>
    for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = PiCircuitConfig<F>;

    fn unusable_rows() -> usize {
        PiCircuit::<F>::unusable_rows()
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        Self(PiCircuit::new_from_block(block))
    }

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        PiCircuit::min_num_rows_block(block)
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        self.0.instance()
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        panic!("use PiCircuit for embedding instead");
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    block_table,
                    tx_table,
                },
            ),
            Challenges::construct(meta),
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
