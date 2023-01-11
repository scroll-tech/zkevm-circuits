//! precompile helpers

use eth_types::Address;
use fp_evm::{
    Context, ExitError, ExitReason, ExitSucceed, Precompile, PrecompileFailure, PrecompileHandle,
    PrecompileOutput, Transfer,
};
use pallet_evm_precompile_blake2::Blake2F;
use pallet_evm_precompile_bn128::{Bn128Add, Bn128Mul, Bn128Pairing};
use pallet_evm_precompile_modexp::Modexp;
use pallet_evm_precompile_simple::{ECRecover, Identity, Ripemd160, Sha256};

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    address.0[0..19] == [0u8; 19] && (1..=9).contains(&address.0[19])
}

pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    match address.as_bytes()[19] {
        0x01 => execute::<ECRecover>(input, gas),
        0x02 => execute::<Sha256>(input, gas),
        0x03 => execute::<Ripemd160>(input, gas),
        0x04 => execute::<Identity>(input, gas),
        0x05 => execute::<Modexp>(input, gas),
        0x06 => execute::<Bn128Add>(input, gas),
        0x07 => execute::<Bn128Mul>(input, gas),
        0x08 => execute::<Bn128Pairing>(input, gas),
        0x09 => execute::<Blake2F>(input, gas),
        _ => panic!("calling non-exist precompiled contract address"),
    }
}

fn execute<T: Precompile>(input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    let mut handler = Handler::new(input, gas);
    match T::execute(&mut handler) {
        Ok(PrecompileOutput {
            exit_status,
            output,
        }) => {
            assert_eq!(exit_status, ExitSucceed::Returned);
            (output, handler.gas_cost)
        }
        Err(failure) => {
            match failure {
                // invalid input, consume all gas and return empty
                PrecompileFailure::Error { .. } => (vec![], gas),
                _ => unreachable!("{:?} should not happen in precompiled contract", failure),
            }
        }
    }
}

struct Handler<'a> {
    input: &'a [u8],
    gas_cost: u64,
    available_gas: u64,
}

impl<'a> Handler<'a> {
    fn new(input: &'a [u8], gas: u64) -> Self {
        Self {
            input,
            gas_cost: 0,
            available_gas: gas,
        }
    }
}

impl<'a> PrecompileHandle for Handler<'a> {
    fn call(
        &mut self,
        _to: primitive_types_12::H160,
        _transfer: Option<Transfer>,
        _input: Vec<u8>,
        _gas_limit: Option<u64>,
        _is_static: bool,
        _context: &Context,
    ) -> (ExitReason, Vec<u8>) {
        unreachable!("we don't use this")
    }

    fn record_cost(&mut self, delta: u64) -> Result<(), ExitError> {
        self.gas_cost += delta;
        debug_assert!(
            self.gas_cost <= self.available_gas,
            "exceeded available gas"
        );
        Ok(())
    }

    fn remaining_gas(&self) -> u64 {
        self.available_gas - self.gas_cost
    }

    fn log(
        &mut self,
        _: primitive_types_12::H160,
        _: Vec<primitive_types_12::H256>,
        _: Vec<u8>,
    ) -> Result<(), ExitError> {
        unreachable!("we don't use this")
    }

    fn code_address(&self) -> primitive_types_12::H160 {
        unreachable!("we don't use this")
    }

    fn input(&self) -> &[u8] {
        self.input
    }

    fn context(&self) -> &Context {
        unreachable!("we don't use this")
    }

    fn is_static(&self) -> bool {
        unreachable!("we don't use this")
    }

    fn gas_limit(&self) -> Option<u64> {
        Some(self.available_gas)
    }
}
