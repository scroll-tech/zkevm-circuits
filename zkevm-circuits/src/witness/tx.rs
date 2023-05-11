use crate::{
    evm_circuit::{step::ExecutionState, util::rlc},
    table::TxContextFieldTag,
    util::{rlc_be_bytes, Challenges},
    witness::{
        rlp_fsm::SmState,
        DataTable, Format,
        Format::{TxHashEip155, TxHashEip1559, TxHashPreEip155, TxSignEip155, TxSignPreEip155},
        RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTable, RlpTag, State,
        State::DecodeTagStart,
        StateMachine,
        Tag::{EndList, EndVector},
    },
};
use bus_mapping::{
    circuit_input_builder,
    circuit_input_builder::{get_dummy_tx, get_dummy_tx_hash},
};
use eth_types::{
    geth_types::TxTypes,
    sign_types::{biguint_to_32bytes_le, ct_option_ok_or, recover_pk, SignData, SECP256K1_Q},
    Address, Error, Field, Signature, ToBigEndian, ToLittleEndian, ToScalar, ToWord, Word, H256,
};
use ethers_core::{
    types::TransactionRequest,
    utils::{
        keccak256,
        rlp::{Encodable, RlpStream},
    },
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::{group::ff::PrimeField, secp256k1},
};
use mock::MockTransaction;
use num::Integer;
use num_bigint::BigUint;
use std::collections::BTreeMap;

use super::{step::step_convert, Call, ExecStep};

/// Transaction in a witness block
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// The block number in which this tx is included in
    pub block_number: u64,
    /// The transaction identifier in the block
    pub id: usize,
    /// The hash of the transaction
    pub hash: H256,
    /// The type of the transaction
    pub tx_type: TxTypes,
    /// The sender account nonce of the transaction
    pub nonce: u64,
    /// The gas limit of the transaction
    pub gas: u64,
    /// The gas price
    pub gas_price: Word,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Option<Address>,
    /// Whether it's a create transaction
    pub is_create: bool,
    /// The ether amount of the transaction
    pub value: Word,
    /// The call data
    pub call_data: Vec<u8>,
    /// The call data length
    pub call_data_length: usize,
    /// The gas cost for transaction call data
    pub call_data_gas_cost: u64,
    /// Chain ID as per EIP-155.
    pub chain_id: u64,
    /// Rlp-encoded bytes of unsigned tx
    pub rlp_unsigned: Vec<u8>,
    /// Rlp-encoded bytes of unsigned tx
    pub rlp_signed: Vec<u8>,
    /// "v" value of the transaction signature
    pub v: u64,
    /// "r" value of the transaction signature
    pub r: Word,
    /// "s" value of the transaction signature
    pub s: Word,
    /// The calls made in the transaction
    pub calls: Vec<Call>,
    /// The steps executioned in the transaction
    pub steps: Vec<ExecStep>,
}

impl Transaction {
    /// Assignments for tx table, split into tx_data (all fields except
    /// calldata) and tx_calldata
    /// Return a fixed dummy tx for chain_id
    pub fn dummy(chain_id: u64) -> Self {
        let (dummy_tx, dummy_sig) = get_dummy_tx(chain_id);
        let dummy_tx_hash = get_dummy_tx_hash(chain_id);
        let rlp_signed = dummy_tx.rlp_signed(&dummy_sig).to_vec();
        let rlp_unsigned = dummy_tx.rlp().to_vec();

        Self {
            block_number: 0, // FIXME
            id: 0,           // need to be changed to correct value
            caller_address: Address::zero(),
            callee_address: Some(Address::zero()),
            is_create: false, // callee_address != None
            chain_id,
            v: dummy_sig.v,
            r: dummy_sig.r,
            s: dummy_sig.s,
            rlp_signed,
            rlp_unsigned,
            hash: dummy_tx_hash,

            ..Default::default()
        }
    }
    /// Sign data
    pub fn sign_data(&self) -> Result<SignData, Error> {
        let sig_r_le = self.r.to_le_bytes();
        let sig_s_le = self.s.to_le_bytes();
        let sig_r = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_r_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let sig_s = ct_option_ok_or(
            secp256k1::Fq::from_repr(sig_s_le),
            Error::Signature(libsecp256k1::Error::InvalidSignature),
        )?;
        let msg = self.rlp_unsigned.clone().into();
        let msg_hash = keccak256(&self.rlp_unsigned);
        let v = ((self.v + 1) % 2) as u8;
        let pk = recover_pk(v, &self.r, &self.s, &msg_hash)?;
        // msg_hash = msg_hash % q
        let msg_hash = BigUint::from_bytes_be(msg_hash.as_slice());
        let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
        let msg_hash_le = biguint_to_32bytes_le(msg_hash);
        let msg_hash = ct_option_ok_or(
            secp256k1::Fq::from_repr(msg_hash_le),
            libsecp256k1::Error::InvalidMessage,
        )?;
        Ok(SignData {
            signature: (sig_r, sig_s),
            pk,
            msg,
            msg_hash,
        })
    }

    /// Assignments for tx table
    pub fn table_assignments_fixed<F: Field>(
        &self,
        challenges: Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let rlp_signed_hash = H256(keccak256(&self.rlp_signed));
        if self.hash != rlp_signed_hash {
            log::debug!(
                "assign a non-legacy tx (hash = {}, rlp_signed_hash = {}) in tx table",
                self.hash,
                rlp_signed_hash
            );
        }
        let tx_hash_be_bytes = rlp_signed_hash.to_fixed_bytes();
        let tx_sign_hash_be_bytes = keccak256(&self.rlp_unsigned);

        let ret = vec![
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Nonce as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.nonce)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Gas as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.gas)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::GasPrice as u64)),
                Value::known(F::zero()),
                challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&self.gas_price.to_le_bytes(), challenge)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallerAddress as u64)),
                Value::known(F::zero()),
                Value::known(self.caller_address.to_scalar().unwrap()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CalleeAddress as u64)),
                Value::known(F::zero()),
                Value::known(
                    self.callee_address
                        .unwrap_or(Address::zero())
                        .to_scalar()
                        .unwrap(),
                ),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::IsCreate as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.is_create as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::Value as u64)),
                Value::known(F::zero()),
                challenges
                    .evm_word()
                    .map(|challenge| rlc::value(&self.value.to_le_bytes(), challenge)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallDataLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.call_data_length as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::CallDataGasCost as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.call_data_gas_cost)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigV as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.v)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigR as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.r.to_be_bytes(), challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::SigS as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.s.to_be_bytes(), challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.rlp_unsigned.len() as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignRLC as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.rlp_unsigned, challenges.keccak_input()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxSignHash as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&tx_sign_hash_be_bytes, challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHashLength as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.rlp_signed.len() as u64)),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHashRLC as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&self.rlp_signed, challenges.keccak_input()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::TxHash as u64)),
                Value::known(F::zero()),
                rlc_be_bytes(&tx_hash_be_bytes, challenges.evm_word()),
            ],
            [
                Value::known(F::from(self.id as u64)),
                Value::known(F::from(TxContextFieldTag::BlockNumber as u64)),
                Value::known(F::zero()),
                Value::known(F::from(self.block_number)),
            ],
        ];

        ret
    }

    /// Assignments for tx table
    pub fn table_assignments_dyn<F: Field>(
        &self,
        _challenges: Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        self.call_data
            .iter()
            .enumerate()
            .map(|(idx, byte)| {
                [
                    Value::known(F::from(self.id as u64)),
                    Value::known(F::from(TxContextFieldTag::CallData as u64)),
                    Value::known(F::from(idx as u64)),
                    Value::known(F::from(*byte as u64)),
                ]
            })
            .collect()
    }

    #[cfg(test)]
    fn new_from_rlp_bytes(tx_type: TxTypes, bytes: Vec<u8>) -> Self {
        Self {
            tx_type,
            rlp_signed: bytes,
            ..Default::default()
        }
    }
}

impl<F: Field> RlpFsmWitnessGen<F> for Transaction {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>> {
        let (hash_format, sign_format) = match self.tx_type {
            TxTypes::Eip155 => (TxHashEip155, TxSignEip155),
            TxTypes::PreEip155 => (TxHashPreEip155, TxSignPreEip155),
            TxTypes::Eip1559 => (TxHashEip1559, TxHashEip1559),
            TxTypes::Eip2930 => {
                unimplemented!("eip1559 not supported now")
            }
        };

        let gen_witness = |tx_id: u64,
                           format: Format,
                           rlp_bytes: &[u8],
                           challenges: &Challenges<Value<F>>|
         -> Vec<RlpFsmWitnessRow<F>> {
            let mut witness = vec![];
            let rom_table = format.rom_table_rows();
            let keccak_rand = challenges.keccak_input();
            let word_rand = challenges.evm_word();
            let rlp_bytes_rlc = rlp_bytes
                .iter()
                .scan(Value::known(F::zero()), |rlc, &byte| {
                    *rlc = *rlc * keccak_rand + Value::known(F::from(byte as u64));

                    Some(*rlc)
                })
                .collect::<Vec<_>>();
            let mut cur = SmState {
                tag: rom_table[0].tag,
                state: DecodeTagStart,
                tag_idx: 0,
                tag_length: 0,
                tag_value_acc: Value::known(F::zero()),
                byte_idx: 0,
                depth: 0,
            };
            // TODO: what's the reason that cur_rom_row is of type `vector`.
            // At the beginning of parsing tag we actually do not know the next tag
            // only after we finished parsing the current tag, then we can know
            let mut cur_rom_row = vec![0];
            let mut remaining_bytes = vec![];
            let mut witness_table_idx = 0;

            // This map keeps track
            // - the last row in the witness table of each parsed tag,
            // - the row in the rom table of each parsed tag.
            // And this map is used to fill the tag_next column in the witness table
            let mut tag_rom_row_map = BTreeMap::new();
            let mut is_output;
            let mut is_none;
            let mut rlp_tag;
            let mut lb_len = 0;

            loop {
                // default behavior
                is_none = false;
                is_output = false;
                rlp_tag = RlpTag::Tag(cur.tag);

                let mut next = cur.clone();
                match cur.state {
                    DecodeTagStart => {
                        if cur.tag.is_end() {
                            // assertions
                            assert_eq!(
                                remaining_bytes
                                    .pop()
                                    .expect("remaining_bytes shall not be empty"),
                                0
                            );
                            if cur.depth == 1 {
                                assert_eq!(cur.byte_idx, rlp_bytes.len() - 1);
                                is_output = true;
                                rlp_tag = RlpTag::RLC;
                                cur.tag_value_acc = rlp_bytes_rlc[cur.byte_idx];
                            }

                            // state transitions
                            next.depth = cur.depth - 1;
                        } else {
                            let byte_value = rlp_bytes[cur.byte_idx];
                            next.byte_idx = cur.byte_idx + 1;
                            if let Some(rem) = remaining_bytes.last_mut() {
                                // read one more byte
                                *rem = *rem - 1;
                            }
                            if byte_value < 0x80 {
                                // assertions
                                assert!(!cur.tag.is_list());
                                is_output = true;
                                cur.tag_value_acc = Value::known(F::from(byte_value as u64));

                                // state transitions
                                next.state = DecodeTagStart;
                            } else if byte_value == 0x80 {
                                // assertions
                                assert!(!cur.tag.is_list());
                                is_output = true;
                                is_none = true;
                                cur.tag_value_acc = Value::known(F::zero());

                                // state transitions
                                next.state = DecodeTagStart;
                            } else if byte_value < 0xb8 {
                                // assertions
                                assert!(!cur.tag.is_list());

                                // state transitions
                                next.tag_idx = 1;
                                next.tag_length = (byte_value - 0x80) as usize;
                                next.tag_value_acc =
                                    Value::known(F::from(rlp_bytes[next.byte_idx] as u64));
                                next.state = State::Bytes;
                            } else if byte_value < 0xc0 {
                                // assertions
                                assert!(!cur.tag.is_list());

                                // state transitions
                                next.tag_idx = 1;
                                next.tag_length = (byte_value - 0xb7) as usize;
                                lb_len = rlp_bytes[next.byte_idx] as usize;
                                next.tag_value_acc = Value::known(F::from(lb_len as u64));
                                next.state = State::LongBytes;
                            } else if byte_value < 0xf8 {
                                // assertions
                                assert!(cur.tag.is_begin());
                                if cur.depth == 0 {
                                    is_output = true;
                                    rlp_tag = RlpTag::Len;
                                    cur.tag_value_acc = Value::known(F::from(
                                        (cur.byte_idx + 1 + usize::from(byte_value - 0xc0)) as u64,
                                    )); // +1 because byte_idx starts from 0.
                                }

                                // state transitions
                                if let Some(rem) = remaining_bytes.last_mut() {
                                    *rem = *rem - usize::from(byte_value - 0xc0);
                                }
                                remaining_bytes.push(usize::from(byte_value - 0xc0));
                                next.depth = cur.depth + 1;
                                next.state = DecodeTagStart;
                            } else {
                                // assertions
                                assert!(cur.tag.is_begin());
                                // TODO: assert first leading byte is non-zero

                                next.tag_idx = 1;
                                next.tag_length = (byte_value - 0xf7) as usize;
                                lb_len = rlp_bytes[next.byte_idx] as usize;
                                next.tag_value_acc = Value::known(F::from(lb_len as u64));
                                next.state = State::LongList;
                            }
                        }
                    }
                    State::Bytes => {
                        next.byte_idx = cur.byte_idx + 1;
                        if let Some(rem) = remaining_bytes.last_mut() {
                            *rem = *rem - 1;
                        }
                        if cur.tag_idx < cur.tag_length {
                            // state transitions
                            let b = if cur.tag_length < 32 {
                                Value::known(F::from(256_u64))
                            } else if cur.tag_length == 32 {
                                word_rand
                            } else {
                                keccak_rand
                            };
                            next.tag_idx = cur.tag_idx + 1;
                            next.tag_value_acc = cur.tag_value_acc * b
                                + Value::known(F::from(rlp_bytes[next.byte_idx] as u64));
                        } else {
                            // assertions
                            is_output = true;

                            // state transitions
                            next.state = DecodeTagStart;
                        }
                    }
                    State::LongBytes => {
                        next.byte_idx = cur.byte_idx + 1;
                        if let Some(rem) = remaining_bytes.last_mut() {
                            *rem = *rem - 1;
                        }

                        if cur.tag_idx < cur.tag_length {
                            // state transitions
                            next.tag_idx = cur.tag_idx + 1;
                            lb_len = lb_len * 256 + usize::from(rlp_bytes[next.byte_idx]);
                            next.tag_value_acc = Value::known(F::from(lb_len as u64));
                        } else {
                            // we're dealing with case cur.tag_idx == cur.tag_length

                            // state transitions
                            next.tag_idx = 1;
                            next.tag_length = lb_len;
                            next.tag_value_acc =
                                Value::known(F::from(u64::from(rlp_bytes[next.byte_idx])));
                            next.state = State::Bytes;
                        }
                    }
                    State::LongList => {
                        next.byte_idx = cur.byte_idx + 1;
                        if let Some(rem) = remaining_bytes.last_mut() {
                            // read one more byte
                            *rem = *rem - 1;
                        }
                        if cur.tag_idx < cur.tag_length {
                            next.tag_idx = cur.tag_idx + 1;
                            lb_len = lb_len * 256 + usize::from(rlp_bytes[next.byte_idx]);
                            next.tag_value_acc = Value::known(F::from(lb_len as u64));
                        } else {
                            if cur.depth == 0 {
                                assert_eq!(lb_len + 1, rlp_bytes.len() - cur.byte_idx);
                            }
                            if let Some(rem) = remaining_bytes.last_mut() {
                                *rem = *rem - lb_len;
                            }
                            remaining_bytes.push(lb_len);
                            next.depth = cur.depth + 1;
                            next.state = DecodeTagStart;
                        }
                    }
                    State::End => {
                        unreachable!()
                    }
                }

                if next.state == DecodeTagStart {
                    println!(
                        "tag: {:?} {:?} {:?} {}",
                        cur.tag, cur.tag_value_acc, cur_rom_row, cur.byte_idx
                    );
                    // we finished parsing current tag
                    let row = if cur_rom_row.len() == 1 {
                        cur_rom_row[0]
                    } else if cur_rom_row.len() == 2 {
                        // only cur_rom_row[0].tag_next is EndVector.
                        assert_eq!(rom_table[cur_rom_row[0]].tag_next, EndVector);

                        let rem = remaining_bytes.last().expect("");
                        if *rem == 0 {
                            // we have finished parsing the vector.
                            cur_rom_row[0]
                        } else {
                            // we have not finished parsing the vector.
                            cur_rom_row[1]
                        }
                    } else {
                        unreachable!()
                    };

                    assert_eq!(cur.tag, rom_table[row].tag);

                    tag_rom_row_map.insert(witness_table_idx, row);
                    next.tag = rom_table[row].tag_next;
                    cur_rom_row = rom_table[row].tag_next_idx.clone();
                }

                witness.push(RlpFsmWitnessRow {
                    rlp_table: RlpTable {
                        tx_id,
                        format,
                        rlp_tag,
                        tag_value_acc: cur.tag_value_acc,
                        is_output,
                        is_none,
                    },
                    state_machine: StateMachine {
                        state: cur.state,
                        tag: cur.tag,
                        tag_next: Default::default(),
                        byte_idx: cur.byte_idx,
                        byte_rev_idx: rlp_bytes.len() - cur.byte_idx,
                        byte_value: rlp_bytes[cur.byte_idx],
                        tag_idx: cur.tag_idx,
                        tag_length: cur.tag_length,
                        depth: cur.depth,
                        bytes_rlc: rlp_bytes_rlc[cur.byte_idx],
                    },
                });
                witness_table_idx += 1;

                if cur.tag == EndList && next.depth == 1 {
                    break;
                }
                cur = next;
            }
            // filling up the `tag_next` col of the witness table
            let mut idx = 0;
            for (witness_idx, rom_table_row) in tag_rom_row_map {
                while idx <= witness_idx {
                    witness[idx].state_machine.tag_next = rom_table[rom_table_row].tag_next;
                    idx = idx + 1;
                }
            }

            witness
        };

        let hash_wit = gen_witness(self.id as u64, hash_format, &self.rlp_signed, challenges);
        // let sign_wit = gen_witness(self.id as u64, sign_format, &self.rlp_unsigned, challenges);

        // [hash_wit, sign_wit].concat()
        hash_wit
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<DataTable<F>> {
        let tx_id = self.id as u64;
        let r = challenges.keccak_input();

        let (hash_format, sign_format) = match self.tx_type {
            TxTypes::Eip155 => (TxHashEip155, TxSignEip155),
            TxTypes::PreEip155 => (TxHashPreEip155, TxSignPreEip155),
            TxTypes::Eip1559 => {
                unimplemented!("eip1559 not supported now")
            }
            TxTypes::Eip2930 => {
                unimplemented!("eip1559 not supported now")
            }
        };

        let get_table = |rlp_bytes: &Vec<u8>, format: Format| {
            let n = rlp_bytes.len();
            rlp_bytes
                .into_iter()
                .enumerate()
                .scan(Value::known(F::zero()), |rlc, (i, &byte_value)| {
                    *rlc = *rlc * r + Value::known(F::from(byte_value as u64));
                    Some(DataTable {
                        tx_id,
                        format,
                        byte_idx: i + 1,
                        byte_rev_idx: n - i,
                        byte_value,
                        bytes_rlc: *rlc,
                    })
                })
                .collect::<Vec<_>>()
        };

        let hash_table = get_table(&self.rlp_signed, hash_format);
        let sign_table = get_table(&self.rlp_unsigned, sign_format);

        [hash_table, sign_table].concat()
    }
}

/// Signed transaction in a witness block
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    /// Transaction data.
    pub tx: Transaction,
    /// ECDSA signature on the transaction.
    pub signature: Signature,
}

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        todo!()
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        todo!()
    }
}

impl From<MockTransaction> for Transaction {
    fn from(mock_tx: MockTransaction) -> Self {
        let is_create = mock_tx.to.is_none();
        let sig = Signature {
            r: mock_tx.r.expect("tx expected to be signed"),
            s: mock_tx.s.expect("tx expected to be signed"),
            v: mock_tx.v.expect("tx expected to be signed").as_u64(),
        };
        let (rlp_unsigned, rlp_signed) = {
            let mut legacy_tx = TransactionRequest::new()
                .from(mock_tx.from.address())
                .nonce(mock_tx.nonce)
                .gas_price(mock_tx.gas_price)
                .gas(mock_tx.gas)
                .value(mock_tx.value)
                .data(mock_tx.input.clone())
                .chain_id(mock_tx.chain_id.as_u64());
            if !is_create {
                legacy_tx = legacy_tx.to(mock_tx.to.as_ref().map(|to| to.address()).unwrap());
            }

            let unsigned = legacy_tx.rlp().to_vec();

            let signed = legacy_tx.rlp_signed(&sig).to_vec();

            (unsigned, signed)
        };
        Self {
            block_number: 1,
            id: mock_tx.transaction_index.as_usize(),
            hash: mock_tx.hash.unwrap_or_default(),
            tx_type: TxTypes::Eip155,
            nonce: mock_tx.nonce.as_u64(),
            gas: mock_tx.gas.as_u64(),
            gas_price: mock_tx.gas_price,
            caller_address: mock_tx.from.address(),
            callee_address: mock_tx.to.as_ref().map(|to| to.address()),
            is_create,
            value: mock_tx.value,
            call_data: mock_tx.input.to_vec(),
            call_data_length: mock_tx.input.len(),
            call_data_gas_cost: mock_tx
                .input
                .iter()
                .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
            chain_id: mock_tx.chain_id.as_u64(),
            rlp_unsigned,
            rlp_signed,
            v: sig.v,
            r: sig.r,
            s: sig.s,
            calls: vec![],
            steps: vec![],
        }
    }
}
impl From<MockTransaction> for SignedTransaction {
    fn from(mock_tx: MockTransaction) -> Self {
        SignedTransaction::from(&Transaction::from(mock_tx))
    }
}

pub(super) fn tx_convert(
    tx: &circuit_input_builder::Transaction,
    id: usize,
    chain_id: u64,
    next_block_num: u64,
) -> Transaction {
    debug_assert_eq!(
        chain_id, tx.chain_id,
        "block.chain_id = {}, tx.chain_id = {}",
        chain_id, tx.chain_id
    );
    let callee_address = if tx.is_create() { None } else { Some(tx.to) };

    Transaction {
        block_number: tx.block_num,
        id,
        hash: tx.hash, // NOTE that if tx is not of legacy type, then tx.hash does not equal to
        // keccak(rlp_signed)
        tx_type: tx.tx_type,
        nonce: tx.nonce,
        gas: tx.gas,
        gas_price: tx.gas_price,
        caller_address: tx.from,
        callee_address,
        is_create: tx.is_create(),
        value: tx.value,
        call_data: tx.input.clone(),
        call_data_length: tx.input.len(),
        call_data_gas_cost: tx
            .input
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 }),
        chain_id,
        rlp_unsigned: tx.rlp_unsigned_bytes.clone(),
        rlp_signed: tx.rlp_bytes.clone(),
        v: tx.signature.v,
        r: tx.signature.r,
        s: tx.signature.s,
        calls: tx
            .calls()
            .iter()
            .map(|call| Call {
                id: call.call_id,
                is_root: call.is_root,
                is_create: call.is_create(),
                code_hash: call.code_hash.to_word(),
                rw_counter_end_of_reversion: call.rw_counter_end_of_reversion,
                caller_id: call.caller_id,
                depth: call.depth,
                caller_address: call.caller_address,
                callee_address: call.address,
                call_data_offset: call.call_data_offset,
                call_data_length: call.call_data_length,
                return_data_offset: call.return_data_offset,
                return_data_length: call.return_data_length,
                value: call.value,
                is_success: call.is_success,
                is_persistent: call.is_persistent,
                is_static: call.is_static,
            })
            .collect(),
        steps: tx
            .steps()
            .iter()
            .map(|step| step_convert(step, tx.block_num))
            .chain({
                let rw_counter = tx.steps().last().unwrap().rwc.0 + 9 - (id == 1) as usize;
                debug_assert!(next_block_num >= tx.block_num);
                let end_inner_block_steps = (tx.block_num..next_block_num)
                    .map(|block_num| ExecStep {
                        rw_counter,
                        execution_state: ExecutionState::EndInnerBlock,
                        block_num,
                        ..Default::default()
                    })
                    .collect::<Vec<ExecStep>>();
                log::trace!("end_inner_block_steps {:?}", end_inner_block_steps);
                end_inner_block_steps
            })
            .collect(),
    }
}

impl From<&Transaction> for SignedTransaction {
    fn from(tx: &Transaction) -> Self {
        Self {
            tx: tx.clone(),
            signature: Signature {
                v: tx.v,
                r: tx.r,
                s: tx.s,
            },
        }
    }
}

mod tests {
    use crate::{
        util::Challenges,
        witness::{tx::tx_convert, RlpFsmWitnessGen, Transaction},
    };
    use eth_types::geth_types::TxTypes;
    use ethers_core::utils::rlp::{Decodable, Rlp};
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

    #[test]
    fn test_rlp() {
        // get eip155
    }

    #[test]
    fn test_rlp_eip1559() {
        use ethers_core::types::Transaction as EthTransaction;
        // the tx is downloaded from https://etherscan.io/getRawTx?tx=0x1c5bd618bdbc575f71bfe0a54f09bca2997bbf6d90d4f371a509b05e2b3124e3
        let raw_tx_rlp_bytes = hex::decode("02f901e901833c3139842b27f14d86012309ce540083055ca8945f65f7b609678448494de4c87521cdf6cef1e93280b8e4fa558b7100000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000016a217dedfacdf9c23edb84b57154f26a15848e60000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000028cad80bb7cf17e27c4c8f893f7945f65f7b609678448494de4c87521cdf6cef1e932e1a0d2dc2a0881b05440a4908cf506b4871b1f7eaa46ea0c5dfdcda5f52bc17164a4f8599495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef842a0ba03decd934aae936605e9d437c401439ec4cefbad5795e0965100f929fe339ca0b36e2afa1a25492257090107ad99d079032e543c8dd1ffcd44cf14a96d3015ac80a0821193127789b107351f670025dd3b862f5836e5155f627a29741a251e8d28e8a07ea1e82b1bf6f29c5d0f1e4024acdb698086ac40c353704d7d5e301fb916f2e3")
            .expect("decode tx's hex shall not fail");

        let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
            .expect("decode tx's rlp bytes shall not fail");

        let tx = Transaction::new_from_rlp_bytes(TxTypes::Eip1559, raw_tx_rlp_bytes);
        let mock_challenges = Challenges::mock(
            Value::known(Fr::from(0x100)),
            Value::known(Fr::from(0x100)),
            Value::known(Fr::from(0x100)),
        );
        let witness_table = tx.gen_sm_witness(&mock_challenges);
    }
}
