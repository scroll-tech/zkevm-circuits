mod proof;

pub use proof::{
    gen_and_verify_batch_proofs, gen_and_verify_chunk_proofs, gen_and_verify_normal_and_evm_proofs,
};

pub const ASSETS_DIR: &str = "./test_assets";
pub const PARAMS_DIR: &str = "./test_params";
