use anyhow::Result;
use eth_types::{Bytes, U256};
use sha3::Digest;
use std::cell::RefCell;

thread_local! {
    /// dirty hack to enable normalization
    pub static ENABLE_NORMALIZE: RefCell<bool> = RefCell::new(true);
}

/// encodes an abi call (e.g. "f(uint) 1")
pub fn encode_funccall(spec: &str) -> Result<Bytes> {
    use ethers_core::abi::{Function, Param, ParamType, StateMutability, Token};

    // split parts into `func_name` ([`func_params`]) `args`

    let tokens: Vec<_> = spec.split(' ').collect();
    let func = tokens[0];
    let args = &tokens[1..];

    let func_name_params: Vec<_> = func
        .split([',', '(', ')'])
        .filter(|s| !s.is_empty())
        .collect();
    let func_name = func_name_params[0];
    let func_params = if func_name_params.len() == 1 {
        vec![]
    } else {
        func_name_params[1..func_name_params.len()].to_vec()
    };
    // transform func_params and args into the appropriate types

    let map_type = |t| match t {
        "uint" => ParamType::Uint(256),
        "uint256" => ParamType::Uint(256),
        "bool" => ParamType::Bool,
        _ => panic!("unimplemented abi type {t:?}"),
    };

    let encode_type = |t, v: &str| match t {
        ParamType::Uint(256) => {
            if let Some(hex) = v.strip_prefix("0x") {
                let split_idx = if hex.len() > 64 { hex.len() - 64 } else { 0 };
                U256::from_str_radix(&hex[split_idx..], 16).map(Token::Uint)
            } else {
                U256::from_str_radix(v, 10).map(Token::Uint)
            }
        }
        ParamType::Bool => match v.to_lowercase().as_str() {
            "true" | "0x01" => Ok(Token::Bool(true)),
            "false" | "0x00" => Ok(Token::Bool(false)),
            _ => panic!("unexpected boolean '{v}'"),
        },
        _ => unimplemented!(),
    };

    let func_params: Vec<_> = func_params
        .iter()
        .enumerate()
        .map(|(n, t)| Param {
            name: format!("p{n}"),
            kind: map_type(t),
            internal_type: None,
        })
        .collect();

    let args: Vec<Token> = func_params
        .iter()
        .zip(args)
        .map(|(typ, val)| encode_type(typ.kind.clone(), val))
        .collect::<std::result::Result<_, _>>()?;

    // generate and return calldata

    #[allow(deprecated)]
    let func = Function {
        name: func_name.to_string(),
        inputs: func_params,
        outputs: vec![],
        state_mutability: StateMutability::Payable,
        constant: Some(false),
    };
    let bytes: Vec<u8> = if !ENABLE_NORMALIZE.with_borrow(|b| *b) {
        let encoded_params = ethers_core::abi::encode(&args);
        let short_signature: Vec<u8> = sha3::Keccak256::digest(tokens[0])[0..4].to_vec();
        let bytes: Vec<u8> = short_signature.into_iter().chain(encoded_params).collect();
        bytes
    } else {
        func.encode_input(&args)?
    };

    Ok(Bytes::from(bytes))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_abi_encoding() -> Result<()> {
        // matches with https://raw.githubusercontent.com/ethereum-lists/4bytes/master/with_parameter_names/b3de648b
        assert_eq!(
            hex::encode(encode_funccall("f(uint) 4")?),
            "b3de648b0000000000000000000000000000000000000000000000000000000000000004"
        );
        assert_eq!(
            hex::encode(encode_funccall("f(uint) 0x04")?),
            "b3de648b0000000000000000000000000000000000000000000000000000000000000004"
        );
        encode_funccall("doReenter()")?;
        Ok(())
    }
}
