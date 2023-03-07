use anyhow::{anyhow, bail, Context};
use eth_types::{geth_types::Account, Address, Bytes, Word, H256, U256};
use ethers_core::k256::ecdsa::SigningKey;
use ethers_core::utils::secret_key_to_address;
use std::{collections::HashMap, str::FromStr};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Env {
    pub current_base_fee: U256,
    pub current_coinbase: Address,
    pub current_difficulty: U256,
    pub current_gas_limit: u64,
    pub current_number: u64,
    pub current_timestamp: u64,
    pub previous_hash: H256,
}

#[derive(PartialEq, Eq, Default, Debug, Clone)]
pub struct AccountMatch {
    pub address: Address,
    pub balance: Option<U256>,
    pub code: Option<Bytes>,
    pub nonce: Option<U256>,
    pub storage: HashMap<U256, U256>,
}

impl TryInto<Account> for AccountMatch {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Account, Self::Error> {
        Ok(Account {
            address: self.address,
            balance: self.balance.context("balance")?,
            code: self.code.context("code")?,
            nonce: self.nonce.context("nonce")?,
            storage: self.storage,
        })
    }
}

pub type StateTestResult = HashMap<Address, AccountMatch>;

#[derive(PartialEq, Clone, Eq, Debug)]
pub struct StateTest {
    pub path: String,
    pub id: String,
    pub env: Env,
    pub secret_key: Bytes,
    pub from: Address,
    pub to: Option<Address>,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub nonce: U256,
    pub value: U256,
    pub data: Bytes,
    pub pre: HashMap<Address, Account>,
    pub result: StateTestResult,
    pub exception: bool,
}

impl std::fmt::Display for StateTest {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let max_len = 100;

        let format = |v: &str, k: &str| -> String {
            let mut text = String::new();
            let k = if k.is_empty() {
                k.to_string()
            } else {
                format!("{} :", k)
            };
            let max_len = max_len - k.len();
            for i in 0..=v.len() / max_len {
                if i == 0 && !k.is_empty() {
                    text.push_str(&k);
                } else {
                    let padding: String = " ".repeat(k.len());
                    text.push_str(&padding);
                }
                text.push_str(&v[i * max_len..std::cmp::min((i + 1) * max_len, v.len())]);
                text.push('\n');
            }
            text
        };

        use prettytable::Table;
        let mut table = Table::new();
        if !self.id.is_empty() {
            table.add_row(row!["id", self.id]);
        }
        if !self.path.is_empty() {
            table.add_row(row!["path", self.path]);
        }
        table.add_row(row!["coinbase", format!("{:?}", self.env.current_coinbase)]);

        table.add_row(row![
            "difficulty",
            format!("{}", self.env.current_difficulty)
        ]);
        table.add_row(row!["number", format!("{}", self.env.current_number)]);
        table.add_row(row!["timestamp", format!("{}", self.env.current_timestamp)]);
        table.add_row(row!["prev_hash", format!("{:?}", self.env.previous_hash)]);
        table.add_row(row!["sk", hex::encode(&self.secret_key)]);
        table.add_row(row!["from", format!("{:?}", self.from)]);
        table.add_row(row!["to", format!("{:?}", self.to)]);
        table.add_row(row!["gas_limit", format!("{}", self.gas_limit)]);
        table.add_row(row!["gas_price", format!("{}", self.gas_price)]);
        table.add_row(row!["nonce", format!("{}", self.nonce)]);
        table.add_row(row!["value", format!("{}", self.value)]);
        table.add_row(row!["data", format(&hex::encode(&self.data), "")]);
        table.add_row(row!["exception", self.exception]);

        let mut addrs: Vec<_> = self.pre.keys().collect();
        addrs.extend(self.result.keys());
        addrs.sort();
        addrs.dedup();
        for addr in addrs {
            let mut state = HashMap::new();
            if let Some(pre) = self.pre.get(addr) {
                state.insert("balance".to_string(), format!("{}", pre.balance));
                state.insert("nonce".to_string(), format!("{}", pre.nonce));
                state.insert("code".to_string(), hex::encode(&pre.code).to_string());
                for (key, value) in &pre.storage {
                    let (k, v) = (format!("slot {}", key), format!("{}", value));
                    state.insert(k, v);
                }
            }
            if let Some(result) = self.result.get(addr) {
                let none = String::from("∅");
                if let Some(balance) = result.balance {
                    let pre = state.get("balance").unwrap_or(&none);
                    let text = format!("{} → {}", pre, balance);
                    state.insert("balance".to_string(), text);
                }
                if let Some(code) = &result.code {
                    let pre = state.get("code").unwrap_or(&none);
                    let text = format!("{} → {}", pre, code);
                    state.insert("code".to_string(), text);
                }
                if let Some(nonce) = &result.nonce {
                    let pre = state.get("nonce").unwrap_or(&none);
                    let text = format!("{} → {}", pre, nonce);
                    state.insert("nonce".to_string(), text);
                }
                for (key, value) in &result.storage {
                    let (k, v) = (format!("slot {}", key), format!("{}", value));
                    let pre = state.get(&k).unwrap_or(&none);
                    let text = format!("{} → {}", pre, v);
                    state.insert(k, text);
                }
            }
            let mut text = String::new();
            let mut keys: Vec<_> = state.keys().collect();
            keys.sort();
            for k in keys {
                text.push_str(&format(state.get(k).unwrap(), k));
            }
            table.add_row(row![format!("{:?}", addr), text]);
        }
        write!(f, "{}", table)?;

        Ok(())
    }
}

impl StateTest {
    pub fn parse_oneline_spec(tx: &str) -> anyhow::Result<StateTest> {
        // call;calldata;value;gas addr;code;balance;slot1:val1;slot2:val2
        // create;calldata;value;gas addr;code;balance;slot1:val1;slot2:val2

        let parse_u256 = |s: &str| {
            if s.is_empty() {
                Ok(Word::zero())
            } else if let Some(hex) = s.strip_prefix("0x") {
                Word::from_str_radix(hex, 16)
            } else {
                Word::from_str_radix(s, 10)
            }
        };

        let mut param = tx.split(' ');

        // parse tx parameters
        let mut tx = param
            .next()
            .ok_or_else(|| anyhow!("bad params"))?
            .split(';');
        let is_create = {
            match tx
                .next()
                .ok_or_else(|| anyhow!("no call or create specified"))?
            {
                "call" => false,
                "create" => true,
                _ => bail!("no call or create specified"),
            }
        };
        let data = hex::decode(tx.next().unwrap_or(""))?;
        let value = parse_u256(tx.next().unwrap_or("0"))?;
        let gas_limit = u64::from_str(tx.next().unwrap_or("10000000"))?;
        let secret_key = Bytes::from(&[1u8; 32]);
        let from = secret_key_to_address(&SigningKey::from_bytes(&secret_key.to_vec())?);

        let mut pre = HashMap::<Address, Account>::new();

        // setup tx.origin (from) account
        pre.insert(
            from,
            Account {
                address: from,
                nonce: U256::zero(),
                balance: U256::from(10).pow(18.into()),
                code: Bytes::default(),
                storage: HashMap::new(),
            },
        );

        // parse rest accounts
        let mut to = None;
        for account in param {
            let mut account = account.split(';');

            // parse address, code, balance
            let address = account
                .next()
                .ok_or_else(|| anyhow!("Invalid account"))?
                .replace("0x", "");
            let address = format!("{:0>40}", address);
            let address = Address::from_str(&address)?;
            if !is_create && to.is_none() {
                to = Some(address);
            }
            let code = crate::utils::bytecode_of(account.next().unwrap_or(""))?;
            let balance = Word::from_str(account.next().unwrap_or("0"))?;
            let mut storage = HashMap::<U256, U256>::new();

            // parse storage (if any)
            for key_value in account {
                let (key, value) = key_value
                    .split_once(':')
                    .ok_or_else(|| anyhow!("Invalid storage spec"))?;
                storage.insert(parse_u256(key)?, parse_u256(value)?);
            }
            pre.insert(
                address,
                Account {
                    address,
                    nonce: U256::one(),
                    code: Bytes::from(code.code()),
                    balance,
                    storage,
                },
            );
        }

        let state_test = StateTest {
            path: String::default(),
            id: String::default(),
            env: Env {
                current_base_fee: U256::from(1),
                current_coinbase: Address::default(),
                current_difficulty: U256::default(),
                current_gas_limit: 16000000,
                current_number: 1,
                current_timestamp: 1,
                previous_hash: H256::default(),
            },
            secret_key,
            from,
            to,
            gas_limit,
            gas_price: U256::one(),
            nonce: U256::zero(),
            value,
            data: data.into(),
            pre,
            result: HashMap::new(),
            exception: false,
        };

        Ok(state_test)
    }
}
