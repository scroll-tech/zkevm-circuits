// Adapted from https://github.com/scroll-tech/go-ethereum/blob/8dc419a70b94f5ca185dcf818a48a3bd2eefc392/consensus/misc/curie.go

use eth_types::{
    utils::{hash_code, hash_code_keccak},
    ToWord, Word,
};

use crate::{
    l2_predeployed::l1_gas_price_oracle,
    operation::{AccountField, AccountOp, StorageOp, RW},
    Error,
};

use super::{CircuitInputStateRef, ExecStep};

/// Get curie fork block height
pub fn get_curie_fork_block(chain_id: u64) -> u64 {
    for (fork, fork_chain_id, fork_blk) in eth_types::forks::hardfork_heights() {
        if fork == eth_types::forks::HardforkId::Curie && chain_id == fork_chain_id {
            return fork_blk;
        }
    }
    0
}

/// Whether this blk has enabled curie fork
pub fn is_curie_enabled(chain_id: u64, blk: u64) -> bool {
    blk >= get_curie_fork_block(chain_id)
}

/// Whether this blk is the hardfork height of curie
pub fn is_curie_fork_block(chain_id: u64, blk: u64) -> bool {
    let result = blk == get_curie_fork_block(chain_id);
    if result {
        log::info!("curie fork: chain id {chain_id} block {blk}");
    }
    result
}

/// Insert needed rws for the contract upgrade
/// Num of rws: 7
pub fn apply_curie(state: &mut CircuitInputStateRef, step: &mut ExecStep) -> Result<(), Error> {
    // The chunk should not includes other txs.
    let v1_codesize = l1_gas_price_oracle::V1_BYTECODE.len();
    let v1_codehash = hash_code(&l1_gas_price_oracle::V1_BYTECODE);
    let v1_keccak_codehash = hash_code_keccak(&l1_gas_price_oracle::V1_BYTECODE);
    log::debug!("l1_oracle poseidon codehash {:?}", v1_codehash);
    log::debug!("l1_oracle keccak codehash {:?}", v1_keccak_codehash);
    let v2_codesize = l1_gas_price_oracle::V2_BYTECODE.len();
    let v2_codehash = hash_code(&l1_gas_price_oracle::V2_BYTECODE);
    let v2_keccak_codehash = hash_code_keccak(&l1_gas_price_oracle::V2_BYTECODE);

    state.push_op(
        step,
        RW::WRITE,
        AccountOp {
            address: *l1_gas_price_oracle::ADDRESS,
            field: AccountField::CodeHash,
            value_prev: v1_codehash.to_word(),
            value: v2_codehash.to_word(),
        },
    )?;
    state.push_op(
        step,
        RW::WRITE,
        AccountOp {
            address: *l1_gas_price_oracle::ADDRESS,
            field: AccountField::KeccakCodeHash,
            value_prev: v1_keccak_codehash.to_word(),
            value: v2_keccak_codehash.to_word(),
        },
    )?;
    state.push_op(
        step,
        RW::WRITE,
        AccountOp {
            address: *l1_gas_price_oracle::ADDRESS,
            field: AccountField::CodeSize,
            value_prev: v1_codesize.to_word(),
            value: v2_codesize.to_word(),
        },
    )?;

    for (slot, value) in [
        (*l1_gas_price_oracle::IS_CURIE_SLOT, Word::from(1)),
        (*l1_gas_price_oracle::L1_BLOB_BASEFEE_SLOT, Word::from(1)),
        (
            *l1_gas_price_oracle::COMMIT_SCALAR_SLOT,
            *l1_gas_price_oracle::INITIAL_COMMIT_SCALAR,
        ),
        (
            *l1_gas_price_oracle::BLOB_SCALAR_SLOT,
            *l1_gas_price_oracle::INITIAL_BLOB_SCALAR,
        ),
    ] {
        state.push_op(
            step,
            RW::WRITE,
            StorageOp::new(
                *l1_gas_price_oracle::ADDRESS,
                slot,
                value,
                Word::from(0),
                0,
                Word::zero(),
            ),
        )?;
    }

    Ok(())
}
