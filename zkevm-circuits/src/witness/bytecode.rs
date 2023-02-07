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
    ) -> Vec<[Value<F>; 5]> {
        let n = 1 + self.bytes.len();
        let mut rows = Vec::with_capacity(n);
        let hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(&self.hash.to_le_bytes(), challenge));

        rows.push([
            hash,
            Value::known(F::from(BytecodeFieldTag::Header as u64)),
            Value::known(F::zero()),
            Value::known(F::zero()),
            Value::known(F::from(self.bytes.len() as u64)),
        ]);

        let mut push_data_left = 0;
        for (idx, byte) in self.bytes.iter().enumerate() {
            let is_code = push_data_left == 0;

            push_data_left = if is_code {
                // push_data_left will be > 0 only if it is a push opcode
                OpcodeId::from(*byte).data_len()
            } else {
                push_data_left - 1
            };

            rows.push([
                hash,
                Value::known(F::from(BytecodeFieldTag::Byte as u64)),
                Value::known(F::from(idx as u64)),
                Value::known(F::from(is_code as u64)),
                Value::known(F::from(*byte as u64)),
            ])
        }
        rows
    }

    /// get byte value and is_code pair
    pub fn get(&self, dest: usize) -> [u8; 2] {
        let mut push_data_left = 0;
        for (idx, byte) in self.bytes.iter().enumerate() {
            let mut is_code = true;
            if push_data_left > 0 {
                is_code = false;
                push_data_left -= 1;
            } else if (OpcodeId::PUSH1.as_u8()..=OpcodeId::PUSH32.as_u8()).contains(byte) {
                push_data_left = *byte as usize - (OpcodeId::PUSH1.as_u8() - 1) as usize;
            }

            if idx == dest {
                return [*byte, is_code as u8];
            }
        }

        // here dest > bytecodes len
        panic!("can not find byte in the bytecodes list")
    }
}
