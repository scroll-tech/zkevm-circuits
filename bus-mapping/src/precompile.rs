//! precompile helpers

use eth_types::Address;
use revm_precompile::{Precompile, Precompiles};

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    Precompiles::latest()
        .get(address.as_fixed_bytes())
        .is_some()
}

pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    let Some(Precompile::Standard(precompile_fn)) = Precompiles::latest()
        .get(address.as_fixed_bytes())  else {
        panic!("calling non-exist precompiled contract address")
    };

    match precompile_fn(input, gas) {
        Ok((gas_cost, return_value)) => (return_value, gas_cost),
        Err(_) => (vec![], gas),
    }
}
