use super::*;

// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[derive(Clone)]
pub struct PiTestCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
>(pub PiCircuit<F>);

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    Default for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    fn default() -> Self {
        Self(PiCircuit::<F> {
            public_data: PublicData {
                max_txs: MAX_TXS,
                max_calldata: MAX_CALLDATA,
                max_inner_blocks: MAX_INNER_BLOCKS,
                chain_id: 0,
                start_l1_queue_index: 0,
                transactions: vec![],
                prev_state_root: H256::zero(),
                next_state_root: H256::zero(),
                withdraw_trie_root: H256::zero(),
                block_ctxs: Default::default(),
            },
            connections: Default::default(),
            tx_value_cells: Default::default(),
            _marker: PhantomData,
        })
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    SubCircuit<F> for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        Self(PiCircuit::new_from_block(block))
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

    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        assert_eq!(block.circuits_params.max_txs, MAX_TXS);
        assert_eq!(block.circuits_params.max_calldata, MAX_CALLDATA);

        PiCircuit::min_num_rows_block(block)
    }
}

impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    Circuit<F> for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    block_table,
                    keccak_table,
                    tx_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);

        // assign tx table
        let tx_value_cells = config.tx_table.load(
            &mut layouter,
            &self.0.public_data.transactions,
            self.0.public_data.max_txs,
            self.0.public_data.max_calldata,
            self.0.public_data.chain_id,
            &challenges,
        )?;
        // assign keccak table
        let data_bytes = self.0.public_data.data_bytes();
        let pi_bytes = self
            .0
            .public_data
            .pi_bytes(self.0.public_data.get_data_hash());
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&data_bytes, &pi_bytes], &challenges)?;

        self.0.import_tx_values(tx_value_cells);
        self.0.synthesize_sub(&config, &challenges, &mut layouter)?;

        Ok(())
    }
}
