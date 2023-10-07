use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::circuit::Value;

use crate::{evm_circuit::util::rlc, table::BytecodeFieldTag, util::Challenges};

/// Bytecode
#[derive(Clone, Debug)]
pub struct Bytecode {
    /// Hash of bytecode
    pub hash: Word,
    /// Raw bytes
    pub bytes: Vec<u8>,
}

impl Bytecode {
    /// Assignments for bytecode table
    pub fn table_assignments<F: Field>(
        &self,
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 6]> {
        let n = 1 + self.bytes.len();
        let mut rows = Vec::with_capacity(n);
        let hash = if cfg!(feature = "poseidon-codehash") {
            challenges
                .evm_word()
                .map(|_challenge| rlc::value(&self.hash.to_le_bytes(), F::from(256u64)))
            //Value::known(rlc::value(&self.hash.to_le_bytes(), F::from(256u64)))
        } else {
            challenges
                .evm_word()
                .map(|challenge| rlc::value(&self.hash.to_le_bytes(), challenge))
        };

        rows.push([
            hash,
            Value::known(F::from(BytecodeFieldTag::Header as u64)),
            Value::known(F::zero()),
            Value::known(F::zero()),
            Value::known(F::from(self.bytes.len() as u64)),
            Value::known(F::zero()),
        ]);

        let mut push_rlc = Value::known(F::zero());

        let mut push_data_left = 0;
        for (idx, byte) in self.bytes.iter().enumerate() {
            let is_code = push_data_left == 0;

            if is_code {
                // push_data_left will be > 0 only if it is a push opcode
                push_data_left = OpcodeId::from(*byte).data_len();

                // Calculate the RLC of the upcoming push data, if any.
                // Set the RLC result for all rows of the instruction, or 0.
                let start = idx + 1;
                let end = (start + push_data_left).min(self.bytes.len());
                push_rlc = Self::make_push_rlc(challenges.evm_word(), &self.bytes[start..end]);
            } else {
                push_data_left -= 1;
            }

            rows.push([
                hash,
                Value::known(F::from(BytecodeFieldTag::Byte as u64)),
                Value::known(F::from(idx as u64)),
                Value::known(F::from(is_code as u64)),
                Value::known(F::from(*byte as u64)),
                push_rlc,
            ])
        }
        rows
    }

    /// Return the RLC (LE order) of a bytecode slice.
    fn make_push_rlc<F: Field>(rand: Value<F>, rows: &[u8]) -> Value<F> {
        let mut acc = Value::known(F::zero());
        for byte in rows {
            acc = acc * rand + Value::known(F::from(*byte as u64));
        }
        acc
    }

    /// get byte value and is_code pair
    fn get(&self, dest: usize) -> (u8, bool, Option<(usize, usize)>) {
        let mut push_range = None;
        let mut push_data_left = 0;
        for (idx, byte) in self.bytes.iter().enumerate() {
            let mut is_code = true;
            if push_data_left > 0 {
                is_code = false;
                push_data_left -= 1;
            } else if (OpcodeId::PUSH0.as_u8()..=OpcodeId::PUSH32.as_u8()).contains(byte) {
                push_data_left = *byte as usize - OpcodeId::PUSH0.as_u8() as usize;
                push_range = Some((idx + 1, push_data_left));
            } else {
                push_range = None;
            }

            if idx == dest {
                return (*byte, is_code, push_range);
            }
        }

        // here dest > bytecodes len
        panic!("can not find byte in the bytecodes list")
    }

    /// Return (byte, is_code, push_rlc) at index `dest`
    pub fn get_byte_row<F: Field>(
        &self,
        dest: usize,
        challenges: &Challenges<Value<F>>,
    ) -> (u8, bool, Value<F>) {
        let (byte, is_code, push_range) = self.get(dest);

        let push_rlc = match push_range {
            None => Value::known(F::zero()),

            Some((start, length)) => {
                let end = (start + length).min(self.bytes.len());
                Self::make_push_rlc(challenges.evm_word(), &self.bytes[start..end])
            }
        };

        (byte, is_code, push_rlc)
    }
}
