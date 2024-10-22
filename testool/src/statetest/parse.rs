use crate::{abi, compiler::Compiler};
use anyhow::{bail, Context, Result};
use eth_types::{address, AccessList, AccessListItem, Address, Bytes, H256, U256};
use log::debug;
use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, str::FromStr, sync::LazyLock};

type Label = String;

/// Raw access list to parse
pub type RawAccessList = Vec<RawAccessListItem>;

/// Raw access list item to parse
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawAccessListItem {
    address: String,
    storage_keys: Vec<String>,
}

impl RawAccessListItem {
    pub fn new(address: String, storage_keys: Vec<String>) -> Self {
        Self {
            address,
            storage_keys,
        }
    }
}

/// parsed calldata
#[derive(Debug)]
pub struct Calldata {
    pub data: Bytes,
    pub label: Option<Label>,
    pub access_list: Option<AccessList>,
}

impl Calldata {
    fn new(data: Bytes, label: Option<Label>, access_list: Option<AccessList>) -> Self {
        Self {
            data,
            label,
            access_list,
        }
    }
}

static YUL_FRAGMENT_PARSER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\s*(?P<version>\w+)?\s*(?P<version2>\w+)*\s*(?P<code>\{[\S\s]*)"#).unwrap()
});

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
                let tag = &it[..it.find([' ', '\n']).expect("unable to find end tag")];
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
pub fn parse_calldata(
    compiler: &Compiler,
    data: &str,
    raw_access_list: &Option<RawAccessList>,
) -> Result<Calldata> {
    let tags = decompose_tags(data);
    let label = tags.get(":label").cloned();
    let bytes = parse_call_bytes(compiler, tags).unwrap();
    let access_list = parse_access_list(raw_access_list)?;

    Ok(Calldata::new(bytes, label, access_list))
}

/// parse entry as code, can be 0x, :raw or { LLL }
pub fn parse_code(compiler: &Compiler, as_str: &str) -> Result<Bytes> {
    let tags = decompose_tags(as_str);

    let code = if let Some(notag) = tags.get("") {
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
        let (src, optimize_level, evm_version) = if yul.starts_with('{') {
            // 1 is default option: --optimize --yul-optimizations=:
            (yul.to_string(), 1, None)
        } else {
            let re = Regex::new(r"\s").unwrap();
            let mut parts = re.splitn(yul, 2);

            let version = parts.next().unwrap();
            let src = parts.next().unwrap();
            if src.starts_with("optimise") {
                let src = src.strip_prefix("optimise").unwrap_or(src).to_string();
                (src, 0, Some(version.to_string()))
            } else {
                (src.to_string(), 1, Some(version.to_string()))
            }
        };
        compiler.yul(&src, optimize_level, evm_version.as_deref())?
    } else if let Some(solidity) = tags.get(":solidity") {
        debug!(target: "testool", "SOLIDITY: >>>{}<<< => {:?}", solidity, as_str);
        compiler.solidity(solidity, None)?
    } else if let Some(asm) = tags.get(":asm") {
        compiler.asm(asm)?
    } else {
        bail!("do not know what to do with code(2) '{:?}'", as_str);
    };

    Ok(code)
}

/// parse a hash entry
pub fn parse_hash(value: &str) -> Result<H256> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() {
        return Ok(H256::zero());
    }
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

// Parse calldata to bytes
fn parse_call_bytes(compiler: &Compiler, tags: HashMap<String, String>) -> Result<Bytes> {
    if let Some(notag) = tags.get("") {
        let notag = notag.trim();
        if notag.is_empty() {
            Ok(Bytes::default())
        } else if notag.starts_with('{') {
            Ok(compiler.lll(notag).unwrap())
        } else if let Some(hex) = notag.strip_prefix("0x") {
            Ok(Bytes::from(hex::decode(hex).unwrap()))
        } else {
            bail!("do not know what to do with calldata (1): '{tags:?}'");
        }
    } else if let Some(raw) = tags.get(":raw") {
        if let Some(hex) = raw.strip_prefix("0x") {
            Ok(Bytes::from(hex::decode(hex.replace(' ', "")).unwrap()))
        } else {
            bail!("bad encoded calldata (3) {:?}", tags)
        }
    } else if let Some(abi) = tags.get(":abi") {
        Ok(abi::encode_funccall(abi).unwrap())
    } else if let Some(yul) = tags.get(":yul") {
        let caps = YUL_FRAGMENT_PARSER
            .captures(yul)
            .ok_or_else(|| anyhow::anyhow!("do not know what to do with code(4) '{:?}'", tags))?;
        Ok(compiler.yul(
            caps.name("code").unwrap().as_str(),
            1,
            caps.name("version").map(|m| m.as_str()),
        )?)
    } else {
        bail!("do not know what to do with calldata: (2) '{:?}'", tags,)
    }
}

// Parse access list
fn parse_access_list(raw_access_list: &Option<RawAccessList>) -> Result<Option<AccessList>> {
    if let Some(raw_access_list) = raw_access_list {
        let mut items = Vec::with_capacity(raw_access_list.len());
        for raw in raw_access_list {
            let storage_keys = raw
                .storage_keys
                .iter()
                .map(|key| H256::from_str(key))
                .collect::<Result<_, _>>()?;

            items.push(AccessListItem {
                address: address!(raw.address),
                storage_keys,
            });
        }

        return Ok(Some(AccessList(items)));
    }

    Ok(None)
}
