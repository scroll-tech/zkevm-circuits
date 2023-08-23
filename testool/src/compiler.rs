#![allow(clippy::map_entry)]

use anyhow::{bail, Context, Result};
use eth_types::{bytecode, Bytecode, Bytes, H256};
use keccak256::plain::Keccak;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    sync::Mutex,
};

struct Cache {
    entries: HashMap<H256, Bytes>,
    path: PathBuf,
}

impl Cache {
    pub fn new(path: PathBuf) -> Result<Self> {
        let entries = if let Ok(mut file) = std::fs::File::open(&path) {
            let h256 = |s| H256::from_slice(&hex::decode(s).expect("cache load h256"));
            let bytes = |s| Bytes::from(hex::decode(s).expect("cache load value"));

            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            buf.lines()
                .filter(|l| l.len() > 1)
                .map(|l| l.split_once('=').unwrap())
                .map(|(k, v)| (h256(k), bytes(v)))
                .collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, entries })
    }

    pub fn get(&self, src: &str) -> Option<&Bytes> {
        self.entries.get(&Self::hash(src))
    }

    pub fn insert(&mut self, src: &str, bytecode: Bytes) -> Result<()> {
        let code_hash = Self::hash(src);

        if !self.entries.contains_key(&code_hash) {
            let entry = format!("{}={}\n", hex::encode(code_hash), hex::encode(&bytecode));
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .append(true)
                .open(&self.path)?
                .write_all(entry.as_bytes())?;

            self.entries.insert(code_hash, bytecode);
        }

        Ok(())
    }

    fn hash(src: &str) -> H256 {
        let mut hash = Keccak::default();
        hash.update(src.as_bytes());
        H256::from_slice(&hash.digest())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CompilerInput {
    language: Language,
    settings: CompilerSettings,
    sources: HashMap<String, Source>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum Language {
    Solidity,
    Yul,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompilerSettings {
    optimizer: Optimizer,
    evm_version: String,
    output_selection: HashMap<String, HashMap<String, Vec<String>>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Optimizer {
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Source {
    content: String,
}

impl CompilerInput {
    pub fn new_default(language: Language, src: &str, evm_version: Option<&str>) -> Self {
        let mut sources = HashMap::new();
        sources.insert(
            "stdin".to_string(),
            Source {
                content: src.to_string(),
            },
        );
        CompilerInput {
            language,
            settings: CompilerSettings::new_default(evm_version),
            sources,
        }
    }
}

impl CompilerSettings {
    fn new_default(evm_version: Option<&str>) -> Self {
        let mut output_selection = HashMap::new();
        let mut selection = HashMap::new();
        selection.insert("*".to_string(), vec!["evm.bytecode".to_string()]);
        output_selection.insert("*".to_string(), selection);
        CompilerSettings {
            evm_version: evm_version.unwrap_or("berlin").to_string(),
            optimizer: Default::default(),
            output_selection,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompilationResult {
    contracts: HashMap<String, HashMap<String, Contract>>,
    errors: Vec<CompilationError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Contract {
    evm: Evm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Evm {
    bytecode: BytecodeResult,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BytecodeResult {
    object: String,
    opcodes: String,
    source_map: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompilationError {
    component: String,
    error_code: String,
    formatted_message: String,
    message: String,
    severity: Severity,
    #[serde(rename = "type")]
    error_type: String,
    source_location: Option<SourceLocation>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SourceLocation {
    end: i32,
    file: String,
    start: i32,
}

#[derive(Default)]
pub struct Compiler {
    cache: Option<Mutex<Cache>>,
    compile: bool,
}

impl Compiler {
    pub fn new(compile: bool, cache_path: Option<PathBuf>) -> Result<Self> {
        let cache = cache_path.map(Cache::new).transpose()?.map(Mutex::new);
        Ok(Compiler { compile, cache })
    }

    /// the concurrency level of the exec is controlled by rayon parallelism
    fn exec(args: &[&str], stdin: &str) -> Result<String> {
        let mut child = Command::new("docker")
            .args(args)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        child
            .stdin
            .as_mut()
            .context("failed to open stdin")?
            .write_all(stdin.as_bytes())?;

        let output = child.wait_with_output()?;

        if output.status.success() {
            let raw_output = String::from_utf8(output.stdout)?;
            Ok(raw_output)
        } else {
            let err = String::from_utf8(output.stderr)?;
            bail!(
                "docker {:?} failed {:?} when compiling >>>{:?}<<<",
                args,
                err,
                stdin
            )
        }
    }

    /// compiles ASM code
    pub fn asm(&self, src: &str) -> Result<Bytes> {
        let mut bytecode = Bytecode::default();
        for op in src.split(';') {
            let op = match bytecode::OpcodeWithData::from_str(op.trim()) {
                Ok(op) => op,
                Err(err) => bail!("unable to process asm entry {}: {:?}", op, err),
            };
            bytecode.append_op(op);
        }
        let bytes = Bytes::from(bytecode.code().to_vec());
        Ok(bytes)
    }

    /// compiles LLL code
    pub fn lll(&self, src: &str) -> Result<Bytes> {
        if let Some(bytecode) = self
            .cache
            .as_ref()
            .and_then(|c| c.lock().unwrap().get(src).cloned())
        {
            return Ok(bytecode);
        }
        if !self.compile {
            bail!("No way to compile LLLC for '{}'", src)
        }

        let stdout = Self::exec(&["run", "-i", "--rm", "lllc"], src)?;
        let bytecode = Bytes::from(hex::decode(stdout.trim())?);

        if let Some(ref cache) = self.cache {
            cache.lock().unwrap().insert(src, bytecode.clone())?;
        }

        Ok(bytecode)
    }

    /// compiles YUL code
    pub fn yul(&self, src: &str, evm_version: Option<&str>) -> Result<Bytes> {
        self.solc(Language::Yul, src, evm_version)
    }

    /// compiles Solidity code
    pub fn solidity(&self, src: &str, evm_version: Option<&str>) -> Result<Bytes> {
        self.solc(Language::Solidity, src, evm_version)
    }

    fn solc(&self, language: Language, src: &str, evm_version: Option<&str>) -> Result<Bytes> {
        if let Some(bytecode) = self
            .cache
            .as_ref()
            .and_then(|c| c.lock().unwrap().get(src).cloned())
        {
            return Ok(bytecode);
        }
        if !self.compile {
            bail!("No way to compile {:?} for '{}'", language, src)
        }
        let compiler_input = CompilerInput::new_default(language, src, evm_version);

        let stdout = Self::exec(
            &["run", "-i", "--rm", "solc", "--standard-json", "-"],
            serde_json::to_string(&compiler_input).unwrap().as_str(),
        )?;
        let mut compilation_result: CompilationResult = serde_json::from_str(&stdout)
            .map_err(|e| {
                println!("---\n{language:?}\n{src}\n{evm_version:?}\n{e:?}\n{stdout}\n-----")
            })
            .unwrap();
        let bytecode = compilation_result
            .contracts
            .remove("stdin")
            .expect("should have stdin")
            .into_iter()
            .next()
            .expect("should have one contract")
            .1
            .evm
            .bytecode
            .object;

        let bytecode = Bytes::from(hex::decode(bytecode)?);

        if let Some(ref cache) = self.cache {
            cache.lock().unwrap().insert(src, bytecode.clone())?;
        }

        Ok(bytecode)
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(not(feature = "ignore-test-docker"))]
    fn test_docker_lll() -> anyhow::Result<()> {
        let out = super::Compiler::new(true, None)?.lll(
            "[[0]] (+ 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 4)",
        )?;
        assert_eq!(
            hex::encode(out),
            "60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500"
        );
        Ok(())
    }
    #[test]
    #[cfg(not(feature = "ignore-test-docker"))]
    fn test_docker_yul() -> anyhow::Result<()> {
        let out = super::Compiler::new(true, None)?.yul(
            r#"
{
    function power(base, exponent) -> result
    {
        result := 1
        for { let i := 0 } lt(i, exponent) { i := add(i, 1) }
        {
            result := mul(result, base)
        }
    }
}
            "#,
        )?;
        assert_eq!(
            hex::encode(out),
            "6020565b8381101560195782820291506001810190506003565b5092915050565b"
        );
        Ok(())
    }
    #[test]
    #[cfg(not(feature = "ignore-test-docker"))]
    fn test_docker_solidity() -> anyhow::Result<()> {
        let out = super::Compiler::new(true, None)?.solidity("contract A{}")?;
        assert_eq!(
            hex::encode(out),
            "6080604052348015600f57600080fd5b50603c80601d6000396000f3fe6080604052600080fdfea164736f6c637828302e382e31332d646576656c6f702e323032322e352e31312b636f6d6d69742e61626161356330650030"
        );
        Ok(())
    }
}
