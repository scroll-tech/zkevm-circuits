use std::str::FromStr;

use anyhow::{bail, Result};
use eth_types::{bytecode::OpcodeWithData, Bytecode, GethExecTrace};
use log::{error, info};
use prettytable::Table;
use std::process::{Command, Stdio};

#[cfg(any(feature = "enable-stack", feature = "enable-storage"))]
use eth_types::U256;

#[derive(Debug, Eq, PartialEq, PartialOrd)]
pub enum MainnetFork {
    Shanghai = 15,
    Merge = 14,
    GrayGlacier = 13,
    ArrowGlacier = 12,
    Altair = 11,
    London = 10,
    Berlin = 9,
    MuirGlacier = 8,
    Istanbul = 7,
    Constantinople = 6,
    Byzantium = 5,
    SpuriousDragon = 4,
    TangerineWhistle = 3,
    Homestead = 2,
    Frontier = 1,
}

#[cfg(feature = "shanghai")]
pub const TEST_FORK: MainnetFork = MainnetFork::Shanghai;
#[cfg(not(feature = "shanghai"))]
pub const TEST_FORK: MainnetFork = MainnetFork::Merge;

impl FromStr for MainnetFork {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Shanghai" => Self::Shanghai,
            "Merge" => Self::Merge,
            "Gray Glacier" => Self::GrayGlacier,
            "Arrow Glacier" => Self::ArrowGlacier,
            "Altair" => Self::Altair,
            "London" => Self::London,
            "Berlin" => Self::Berlin,
            "Muir Glacier" => Self::MuirGlacier,
            "Istanbul" => Self::Istanbul,
            "ConstantinopleFix" => Self::Constantinople,
            "Constantinople" => Self::Constantinople,
            "Byzantium" => Self::Byzantium,
            "Spurious Dragon" => Self::SpuriousDragon,
            "TangeringWhistle" => Self::TangerineWhistle,
            "EIP158" => Self::TangerineWhistle,
            "Homestead" => Self::Homestead,
            "Frontier" => Self::Frontier,
            _ => bail!(format!("Unknown network '{s}'")),
        })
    }
}

impl MainnetFork {
    pub fn in_network_range(expect: &[String]) -> Result<bool, anyhow::Error> {
        let in_network = if expect.is_empty() {
            true
        } else {
            let mut in_network = false;
            for network in expect {
                if let Some(network) = network.strip_prefix(">=") {
                    if crate::utils::TEST_FORK >= crate::utils::MainnetFork::from_str(network)? {
                        in_network = true;
                    }
                } else if let Some(network) = network.strip_prefix('<') {
                    if crate::utils::TEST_FORK < crate::utils::MainnetFork::from_str(network)? {
                        in_network = true;
                    }
                } else if crate::utils::TEST_FORK == crate::utils::MainnetFork::from_str(network)? {
                    in_network = true;
                }
            }
            in_network
        };

        Ok(in_network)
    }
}

pub fn print_trace(trace: GethExecTrace) -> Result<()> {
    #[cfg(any(feature = "enable-stack", feature = "enable-storage"))]
    fn u256_to_str(u: &U256) -> String {
        if *u > U256::from_str("0x1000000000000000").unwrap() {
            format!("0x{u:x}")
        } else {
            u.to_string()
        }
    }
    #[cfg(feature = "enable-storage")]
    fn kv(storage: std::collections::HashMap<U256, U256>) -> Vec<String> {
        let mut keys: Vec<_> = storage.keys().collect();
        keys.sort();
        keys.iter()
            .map(|k| format!("{}: {}", u256_to_str(k), u256_to_str(&storage[k])))
            .collect()
    }
    fn split(strs: Vec<String>, len: usize) -> String {
        let mut out = String::new();
        let mut current_len = 0;
        let mut it = strs.iter();
        let mut current = it.next();

        while let Some(v) = current {
            let mut count = 1usize;
            current = it.next();
            while current == Some(v) {
                count += 1;
                current = it.next();
            }

            let item = if count == 1 {
                v.to_string()
            } else {
                format!("{v}[{count}]")
            };

            if current_len > len {
                current_len = 0;
                out.push('\n');
            } else if current_len > 0 {
                out.push_str(", ");
            }
            out.push_str(&item);
            current_len += item.len();
        }
        out
    }

    let mut table = Table::new();
    table.add_row(row![
        "PC", "OP", "GAS", "GAS_COST", "DEPTH", "ERR", "STACK", "MEMORY", "STORAGE"
    ]);
    for step in trace.struct_logs {
        #[cfg(feature = "enable-stack")]
        let stack = step.stack.0.iter().map(u256_to_str).collect();
        #[cfg(not(feature = "enable-stack"))]
        let stack = vec![];

        #[cfg(feature = "enable-memory")]
        let memory = step.memory.0.iter().map(ToString::to_string).collect();
        #[cfg(not(feature = "enable-memory"))]
        let memory = vec![];

        #[cfg(feature = "enable-storage")]
        let storage = kv(step.storage.0);
        #[cfg(not(feature = "enable-storage"))]
        let storage = vec![];

        table.add_row(row![
            format!("{}", step.pc.0),
            format!("{:?}", step.op),
            format!("{}", step.gas.0),
            format!("{}", step.gas_cost.0),
            format!("{}", step.depth),
            step.error.map(|e| e.error()).unwrap_or(""),
            split(stack, 30),
            split(memory, 30),
            split(storage, 30)
        ]);
    }

    error!("FAILED: {:?}", trace.failed);
    info!("GAS: {:?}", trace.gas);
    table.printstd();

    Ok(())
}

pub fn current_git_commit() -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    let git_hash = git_hash[..7].to_string();
    Ok(git_hash)
}

pub fn current_submodule_git_commit() -> Result<String> {
    let git_cmd = Command::new("git")
        .args(["ls-tree", "HEAD"])
        .stdout(Stdio::piped())
        .output()?;

    match String::from_utf8(git_cmd.stdout)?
        .lines()
        .filter_map(|l| l.strip_suffix("\ttests").and_then(|l| l.split(' ').nth(2)))
        .next()
    {
        Some(git_hash) => Ok(git_hash.to_string()),
        None => bail!("unknown submodule hash"),
    }
}

pub fn bytecode_of(code: &str) -> anyhow::Result<Bytecode> {
    let bytecode = if let Ok(bytes) = hex::decode(code) {
        let bytecode = Bytecode::from(bytes.clone());
        if log::log_enabled!(log::Level::Info) {
            for op in bytecode.iter() {
                info!("{}", op.to_string());
            }
        }
        bytecode
    } else {
        let mut bytecode = Bytecode::default();
        for op in code.split(',') {
            let op = OpcodeWithData::from_str(op.trim()).unwrap();
            bytecode.append_op(op);
        }
        bytecode
    };
    Ok(bytecode)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn networks() {
        assert!(MainnetFork::in_network_range(&[String::from(">=Istanbul")])
            .expect("can parse network"));
    }
}

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
}
