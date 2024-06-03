use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::{
        util::{Expr},
        param::N_BYTES_U64, table::{FixedTableTag, Lookup}, util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::{IsZeroGadget, LtGadget},
            U64Word, Word,
        }
    }, table::BlockContextFieldTag, util::{Expr, Field}
};
use eth_types::{
    forks::{HardforkId, SCROLL_DEVNET_CHAIN_ID, SCROLL_MAINNET_CHAIN_ID}, utils::is_precompiled, Address, ToLittleEndian, ToScalar, U256,
};
use bus_mapping::{
    circuit_input_builder::{TxL1Fee, TX_L1_COMMIT_EXTRA_COST, TX_L1_FEE_PRECISION},
    l2_predeployed::l1_gas_price_oracle,
};
//use eth_types::{ToLittleEndian, ToScalar, U256};
use gadgets::util::not;
use halo2_proofs::{circuit::Value, plonk::{Error, Expression}};


#[derive(Clone, Debug)]
pub(crate) struct CurieGadget<F> {
    /// Scroll chains have non-zero curie hard fork block number
    is_scoll_chain: IsZeroGadget<F>,
    is_before_curie: LtGadget<F, 8>, // block num is u64
    chain_id: Cell<F>,
    /// The block height at which curie hard fork happens
    curie_fork_block_num: Cell<F>,
}

impl<F: Field> CurieGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        block_number: Expr<F>,
    ) -> Self {

        let chain_id = cb.query_cell();
        // Lookup block table with chain_id
        cb.block_lookup(
            BlockContextFieldTag::ChainId.expr(),
            block_number.expr(),
            chain_id.expr(),
        );

        // TODO: refactor
        // is_scoll_chain means (chain_id - 534352) * (chain_id - 222222) == 0
        let is_scroll_chain = IsZeroGadget::construct(cb, 
            (chain_id.expr() - SCROLL_MAINNET_CHAIN_ID.expr())
            * (chain_id.expr() - SCROLL_DEVNET_CHAIN_ID.expr()));


        // For Scroll Networks (mainnet, testnet, devnet),
        // curie_fork_block_num should be pre-defined.
        // For other chain ids, it should be 0.
        let curie_fork_block_num = cb.query_cell();
        cb.condition(is_scroll_chain.expr(), |cb| {
            cb.add_lookup(
            "Hardfork lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ChainFork.expr(),
                values: [
                    (HardforkId::Curie as u64).expr(),
                    chain_id.expr(),
                    curie_fork_block_num.expr(),
                ],
            },
        );});
        cb.condition(not::expr(is_scroll_chain.expr()), |cb| {
            cb.require_zero("enable curie since genesis", curie_fork_block_num.expr());
        });

        
        let is_before_curie = LtGadget::construct(
            cb,
            cb.curr.state.block_number.expr(),
            curie_fork_block_num.expr(),
        );
        Self {
            is_before_curie,
            is_scoll_chain: is_scroll_chain,
            chain_id,
            curie_fork_block_num,
        }
    }
    
    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        chain_id: u64,
        block_number: u64,
    )-> Result<(), Error> {
        self.chain_id
            .assign(region, offset, Value::known(F::from(chain_id)))?;
        self.is_scoll_chain.assign(region, offset, 
            (F::from(chain_id) - F::from(SCROLL_MAINNET_CHAIN_ID)
            *(F::from(chain_id) - F::from(SCROLL_DEVNET_CHAIN_ID))))?;
        let curie_fork_block_num =
            bus_mapping::circuit_input_builder::curie::get_curie_fork_block(chain_id);
        self.curie_fork_block_num.assign(
            region,
            offset,
            Value::known(F::from(curie_fork_block_num)),
        )?;
        self.is_before_curie.assign(
            region,
            offset,
            F::from(block_number),
            F::from(curie_fork_block_num),
        )?;
        Ok(())
    }
}