use std::collections::HashMap;

use crate::abi;
use crate::Compiler;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use eth_types::evm_types::OpcodeId;
use eth_types::{Address, Bytes, H256, U256};
use log::debug;

type Label = String;

/// returns the element as an address
pub fn parse_address(as_str: &str) -> Result<Address> {
    let hex = as_str.strip_prefix("0x").unwrap_or(as_str);
    Ok(Address::from_slice(
        &hex::decode(hex).context("parse_address")?,
    ))
}

/// returns the element as a to address
pub fn parse_to_address(as_str: &str) -> Result<Option<Address>> {
    if as_str.trim().is_empty() {
        return Ok(None);
    }
    parse_address(as_str).map(|x| Ok(Some(x)))?
}

/// returns the element as an array of bytes
pub fn parse_bytes(as_str: &str) -> Result<Bytes> {
    let hex = as_str.strip_prefix("0x").unwrap_or(as_str);
    Ok(Bytes::from(hex::decode(hex).context("parse_bytes")?))
}

/// converts list of tagged values string into a map
/// if there's no tags, an entry with an empty tag and the full string is
/// returned
fn decompose_tags(expr: &str) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    let mut it = expr.trim();
    if it.is_empty() {
        tags.insert("".to_string(), "".to_string());
    } else {
        while !it.is_empty() {
            if it.starts_with(':') {
                let tag = &it[..it.find(&[' ', '\n']).expect("unable to find end tag")];
                it = &it[tag.len() + 1..];
                let value_len = if tag == ":yul" || tag == ":solidity" || tag == ":asm" {
                    it.len()
                } else {
                    it.find(':').unwrap_or(it.len())
                };
                tags.insert(tag.to_string(), it[..value_len].trim().to_string());
                it = &it[value_len..];
            } else {
                tags.insert("".to_string(), it.trim().to_string());
                it = &it[it.len()..]
            }
        }
    }
    tags
}

/// returns the element as calldata bytes, supports 0x, :raw, :abi, :yul and
/// { LLL }
pub fn parse_calldata(compiler: &mut Compiler, as_str: &str) -> Result<(Bytes, Option<Label>)> {
    let tags = decompose_tags(as_str);
    let label = tags.get(":label").cloned();

    if let Some(notag) = tags.get("") {
        let notag = notag.trim();
        if notag.is_empty() {
            Ok((Bytes::default(), label))
        } else if notag.starts_with('{') {
            Ok((compiler.lll(notag)?, label))
        } else if let Some(hex) = notag.strip_prefix("0x") {
            Ok((Bytes::from(hex::decode(hex)?), label))
        } else {
            bail!("do not know what to do with calldata (1): '{:?}'", as_str);
        }
    } else if let Some(raw) = tags.get(":raw") {
        if let Some(hex) = raw.strip_prefix("0x") {
            Ok((Bytes::from(hex::decode(hex)?), label))
        } else {
            bail!("bad encoded calldata (3) {:?}", as_str)
        }
    } else if let Some(abi) = tags.get(":abi") {
        Ok((abi::encode_funccall(abi)?, label))
    } else if let Some(yul) = tags.get(":yul") {
        Ok((compiler.yul(yul)?, label))
    } else {
        bail!(
            "do not know what to do with calldata: (2) {:?} '{:?}'",
            tags,
            as_str
        )
    }
}

/// parse entry as code, can be 0x, :raw or { LLL }
pub fn parse_code(compiler: &mut Compiler, as_str: &str) -> Result<Bytes> {
    let tags = decompose_tags(as_str);

    let mut code = if let Some(notag) = tags.get("") {
        if let Some(hex) = notag.strip_prefix("0x") {
            Bytes::from(hex::decode(hex)?)
        } else if notag.starts_with('{') {
            compiler.lll(notag)?
        } else if notag.trim().is_empty() {
            Bytes::default()
        } else {
            bail!(
                "do not know what to do with code(1) {:?} '{}'",
                as_str,
                notag
            );
        }
    } else if let Some(raw) = tags.get(":raw") {
        if let Some(hex) = raw.strip_prefix("0x") {
            Bytes::from(hex::decode(hex)?)
        } else {
            bail!("do not know what to do with code(3) '{:?}'", as_str);
        }
    } else if let Some(yul) = tags.get(":yul") {
        compiler.yul(yul)?
    } else if let Some(solidity) = tags.get(":solidity") {
        debug!("SOLIDITY: >>>{}<<< => {:?}", solidity, as_str);
        compiler.solidity(solidity)?
    } else if let Some(asm) = tags.get(":asm") {
        compiler.asm(asm)?
    } else {
        bail!("do not know what to do with code(2) '{:?}'", as_str);
    };

    // TODO: remote the finish with STOP if does not finish with it when fixed
    if !code.0.is_empty() && code.0[code.0.len() - 1] != OpcodeId::STOP.as_u8() {
        let mut code_stop = Vec::new();
        code_stop.extend_from_slice(&code.0);
        code_stop.push(OpcodeId::STOP.as_u8());
        code = Bytes::from(code_stop);
    }

    Ok(code)
}

/// parse a hash entry
pub fn parse_hash(value: &str) -> Result<H256> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    Ok(H256::from_slice(&hex::decode(hex).context("parse_hash")?))
}

/// parse an uint256 entry
pub fn parse_u256(as_str: &str) -> Result<U256> {
    if let Some(stripped) = as_str.strip_prefix("0x") {
        Ok(U256::from_str_radix(stripped, 16)?)
    } else if as_str
        .to_lowercase()
        .contains(['a', 'b', 'c', 'd', 'e', 'f'])
    {
        Ok(U256::from_str_radix(as_str, 16)?)
    } else {
        Ok(U256::from_str_radix(as_str, 10)?)
    }
}

/// parse u64 entry
#[allow(clippy::cast_sign_loss)]
pub fn parse_u64(as_str: &str) -> Result<u64> {
    if let Some(stripped) = as_str.strip_prefix("0x") {
        Ok(U256::from_str_radix(stripped, 16)?.as_u64())
    } else {
        Ok(U256::from_str_radix(as_str, 10)?.as_u64())
    }
}
