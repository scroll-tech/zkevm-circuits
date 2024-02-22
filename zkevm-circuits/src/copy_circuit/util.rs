use crate::{evm_circuit::util::rlc, util::word};
use bus_mapping::circuit_input_builder::NumberOrHash;
use eth_types::Field;
use halo2_proofs::circuit::Value;

/// Encode the type `NumberOrHash` into a field element
pub fn number_or_hash_to_field<F: Field>(v: &NumberOrHash, challenge: Value<F>) -> Value<F> {
    match v {
        NumberOrHash::Number(n) => Value::known(F::from(*n as u64)),
        NumberOrHash::Hash(h) => {
            // since code hash in the bytecode table is represented in
            // the little-endian form, we reverse the big-endian bytes
            // of H256.
            let le_bytes = {
                let mut b = h.to_fixed_bytes();
                b.reverse();
                b
            };
            challenge.map(|challenge| {
                rlc::value(
                    &le_bytes,
                    if cfg!(feature = "poseidon-codehash") {
                        0x100u64.into()
                    } else {
                        challenge
                    },
                )
            })
        }
    }
}

/// Encode the type `NumberOrHash` into a field element
pub fn number_or_hash_to_word<F: Field>(v: &NumberOrHash) -> word::Word<Value<F>> {
    match v {
        NumberOrHash::Number(n) => word::Word::from(*n as u64).into_value(),
        NumberOrHash::Hash(h) => word::Word::from(*h).into_value(),
    }
}
