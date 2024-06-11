#![allow(missing_docs)]
use crate::exp_circuit::param::OFFSET_INCREMENT;
use bus_mapping::circuit_input_builder::{CircuitsParams, PrecompileEcParams};
use halo2_proofs::halo2curves::bn256::Fr;

use super::SuperCircuit;

////// params for Super Circuit of degree = 20 ////////////
pub const MAX_TXS: usize = 100;
pub const MAX_INNER_BLOCKS: usize = 100;
pub const MAX_EXP_STEPS: usize = 10_000;
pub const MAX_CALLDATA: usize = 350_000;
pub const MAX_RLP_ROWS: usize = 800_000;
pub const MAX_BYTECODE: usize = 1_000_000;
pub const MAX_MPT_ROWS: usize = 1_000_000;
pub const MAX_KECCAK_ROWS: usize = 1_000_000;
//pub const MAX_SHA256_ROWS: usize = 1_000_000;
pub const MAX_POSEIDON_ROWS: usize = 1_000_000;
pub const MAX_VERTICAL_ROWS: usize = 1_000_000;
pub const MAX_RWS: usize = 1_000_000;
pub const MAX_PRECOMPILE_EC_ADD: usize = 50;
pub const MAX_PRECOMPILE_EC_MUL: usize = 50;
pub const MAX_PRECOMPILE_EC_PAIRING: usize = 2;

/// default params for super circuit
pub fn get_super_circuit_params() -> CircuitsParams {
    CircuitsParams {
        max_evm_rows: MAX_RWS,
        max_rws: MAX_RWS,
        max_copy_rows: MAX_RWS,
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_bytecode: MAX_BYTECODE,
        max_inner_blocks: MAX_INNER_BLOCKS,
        max_keccak_rows: MAX_KECCAK_ROWS,
        max_poseidon_rows: MAX_POSEIDON_ROWS,
        max_vertical_circuit_rows: MAX_VERTICAL_ROWS,
        max_exp_steps: MAX_EXP_STEPS,
        max_mpt_rows: MAX_MPT_ROWS,
        max_rlp_rows: MAX_RLP_ROWS,
        max_ec_ops: PrecompileEcParams {
            ec_add: MAX_PRECOMPILE_EC_ADD,
            ec_mul: MAX_PRECOMPILE_EC_MUL,
            ec_pairing: MAX_PRECOMPILE_EC_PAIRING,
        },
    }
}

/// The super circuit used for mainnet
pub type ScrollSuperCircuit = SuperCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, 0x100>;

/// Capacity for each subcircuit
pub fn get_sub_circuit_limit_and_confidence() -> Vec<(usize, f64)> {
    // Change it to 0.99?
    let default_confidence = 0.95;
    [
        (MAX_RWS, default_confidence),                          // evm
        (MAX_RWS, default_confidence),                          // state
        (MAX_BYTECODE, default_confidence),                     // bytecode
        (MAX_RWS, default_confidence),                          // copy
        (MAX_KECCAK_ROWS, default_confidence),                  // keccak
        (MAX_KECCAK_ROWS, default_confidence),                  // sha256
        (MAX_VERTICAL_ROWS, default_confidence),                // tx
        (MAX_CALLDATA, default_confidence),                     // rlp
        (OFFSET_INCREMENT * MAX_EXP_STEPS, default_confidence), // exp
        (MAX_KECCAK_ROWS, default_confidence),                  // modexp
        (MAX_RWS, default_confidence),                          // pi
        (MAX_POSEIDON_ROWS, default_confidence),                // poseidon
        (MAX_VERTICAL_ROWS, default_confidence),                // sig
        (MAX_VERTICAL_ROWS, 1.0),                               // ecc
        #[cfg(feature = "scroll")]
        (MAX_MPT_ROWS, default_confidence), // mpt
    ]
    .to_vec()
}
