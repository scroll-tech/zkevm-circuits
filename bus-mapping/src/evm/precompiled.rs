use eth_types::evm_types::Memory;
use eth_types::Address;

pub fn execute_precompiled(address: &Address, input: &[u8]) -> Memory {
    (match address.as_bytes()[19] {
        0x01 => ec_recover,
        0x02 => sha2_256,
        0x03 => ripemd_160,
        0x04 => identity,
        0x05 => modexp,
        0x06 => ec_add,
        0x07 => ec_mul,
        0x08 => ec_pairing,
        _ => panic!("calling non-exist precompiled contract address"),
    })(input)
}

fn ec_recover(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn sha2_256(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ripemd_160(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn identity(input: &[u8]) -> Memory {
    Memory::from(input.to_vec())
}

fn modexp(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ec_add(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ec_mul(_input: &[u8]) -> Memory {
    unimplemented!()
}

fn ec_pairing(_input: &[u8]) -> Memory {
    unimplemented!()
}
