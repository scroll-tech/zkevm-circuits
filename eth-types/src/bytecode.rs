//! EVM byte code generator

use crate::{evm_types::OpcodeId, Bytes, ToWord, Word};
use std::{collections::HashMap, str::FromStr};

/// Error type for Bytecode related failures
#[derive(Debug)]
pub enum Error {
    /// Serde de/serialization error.
    InvalidAsmError(String),
}

/// Helper struct that represents a single element in a bytecode.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BytecodeElement {
    /// The byte value of the element.
    pub value: u8,
    /// Whether the element is an opcode or push data byte.
    pub is_code: bool,
}

/// EVM Bytecode
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Bytecode {
    /// Vector for bytecode elements.
    pub code: Vec<BytecodeElement>,
    num_opcodes: usize,
    markers: HashMap<String, usize>,
}

impl From<Bytecode> for Bytes {
    fn from(code: Bytecode) -> Self {
        code.code
            .iter()
            .map(|e| e.value)
            .collect::<Vec<u8>>()
            .into()
    }
}

impl Bytecode {
    /// Build not checked bytecode
    pub fn from_raw_unchecked(input: Vec<u8>) -> Self {
        Self {
            code: input
                .iter()
                .map(|b| BytecodeElement {
                    value: *b,
                    is_code: true,
                })
                .collect(),
            markers: HashMap::new(),
            num_opcodes: 0,
        }
    }

    /// Get the code
    pub fn code(&self) -> Vec<u8> {
        self.code.iter().map(|b| b.value).collect()
    }

    /// Get the bytecode element at an index.
    pub fn get(&self, index: usize) -> Option<BytecodeElement> {
        self.code.get(index).cloned()
    }

    /// Get the generated code
    pub fn to_vec(&self) -> Vec<u8> {
        self.code.iter().map(|e| e.value).collect()
    }

    /// Append
    pub fn append(&mut self, other: &Bytecode) {
        self.code.extend_from_slice(&other.code);
        for (key, val) in other.markers.iter() {
            self.insert_marker(key, self.num_opcodes + val);
        }
        self.num_opcodes += other.num_opcodes;
    }

    /// Write op
    pub fn write_op(&mut self, op: OpcodeId) -> &mut Self {
        self.write_op_internal(op.as_u8())
    }

    fn write_op_internal(&mut self, op: u8) -> &mut Self {
        self.num_opcodes += 1;
        self.write(op, true)
    }

    /// Write byte
    pub fn write(&mut self, value: u8, is_code: bool) -> &mut Self {
        self.code.push(BytecodeElement { value, is_code });
        self
    }

    /// Push, value is useless for `PUSH0`
    pub fn push<T: ToWord>(&mut self, n: u8, value: T) -> &mut Self {
        debug_assert!((..=32).contains(&n), "invalid push");
        let value = value.to_word();

        // Write the op code
        self.write_op((OpcodeId::push_n(n)).expect("valid push size"));

        let mut bytes = [0u8; 32];
        value.to_little_endian(&mut bytes);
        // Write the bytes MSB to LSB
        for i in 0..n {
            self.write(bytes[(n - 1 - i) as usize], false);
        }
        // Check if the full value could be pushed
        for byte in bytes.iter().skip(n as usize) {
            debug_assert!(*byte == 0u8, "value too big for PUSH{n}: {value}");
        }
        self
    }

    /// Add marker
    pub fn add_marker(&mut self, marker: String) -> &mut Self {
        self.insert_marker(&marker, self.num_opcodes);
        self
    }

    /// Insert marker
    pub fn insert_marker(&mut self, marker: &str, pos: usize) {
        debug_assert!(
            !self.markers.contains_key(marker),
            "marker already used: {marker}"
        );
        self.markers.insert(marker.to_string(), pos);
    }

    /// Get the position of a marker
    pub fn get_pos(&self, marker: &str) -> usize {
        *self
            .markers
            .get(&marker.to_string())
            .unwrap_or_else(|| panic!("marker '{marker}' not found"))
    }

    /// Setup state
    pub fn setup_state(&mut self) -> &mut Self {
        self.append(&crate::bytecode! {
            PUSH1(0x80u64) // value
            PUSH1(0x40u64) // offset
            MSTORE
        });
        self
    }

    /// Generate the diassembly
    pub fn disasm(&self) -> String {
        let mut asm = String::new();
        for op in self.iter() {
            asm.push_str(&op.to_string());
            asm.push('\n');
        }
        asm
    }

    /// Append asm
    pub fn append_asm(&mut self, op: &str) -> Result<(), Error> {
        match OpcodeWithData::from_str(op)? {
            OpcodeWithData::Opcode(op) => self.write_op(op),
            OpcodeWithData::PushWithData(n, value) => self.push(n, value),
        };
        Ok(())
    }

    /// Append an opcode
    pub fn append_op(&mut self, op: OpcodeWithData) -> &mut Self {
        match op {
            OpcodeWithData::Opcode(opcode) => {
                self.write_op(opcode);
            }
            OpcodeWithData::PushWithData(n, word) => {
                self.push(n, word);
            }
        }
        self
    }

    /// create iterator
    pub fn iter(&self) -> BytecodeIterator<'_> {
        BytecodeIterator(self.code.iter())
    }

    /// JUMPDEST opcode
    pub fn op_jumpdest(&mut self) -> usize {
        self.write_op(OpcodeId::JUMPDEST);
        self.code.len()
    }
}

/// An ASM entry
#[derive(Clone, PartialEq, Eq)]
pub enum OpcodeWithData {
    /// A `PUSH0` or non-push opcode
    Opcode(OpcodeId),
    /// A `PUSH1` .. `PUSH32` opcode
    PushWithData(u8, Word),
}

impl OpcodeWithData {
    /// get the opcode
    pub fn opcode(&self) -> OpcodeId {
        match self {
            OpcodeWithData::Opcode(op) => *op,
            OpcodeWithData::PushWithData(n, _) => OpcodeId::push_n(*n).expect("valid push size"),
        }
    }
}

impl FromStr for OpcodeWithData {
    type Err = Error;

    #[allow(clippy::manual_range_contains)]
    fn from_str(op: &str) -> Result<Self, Self::Err> {
        let err = || Error::InvalidAsmError(op.to_string());

        if let Some(push) = op.strip_prefix("PUSH") {
            let n_value: Vec<_> = push.splitn(3, ['(', ')']).collect();
            let n = n_value[0].parse::<u8>().map_err(|_| err())?;
            if n > 32 {
                return Err(err());
            }

            // Parse `PUSH0` below only for shanghai (otherwise as an invalid opcode).
            if n > 0 {
                let value = if n_value[1].starts_with("0x") {
                    Word::from_str_radix(&n_value[1][2..], 16)
                } else {
                    Word::from_str_radix(n_value[1], 10)
                }
                .map_err(|_| err())?;

                return Ok(OpcodeWithData::PushWithData(n, value));
            }
        }

        let opcode = OpcodeId::from_str(op).map_err(|_| err())?;
        Ok(OpcodeWithData::Opcode(opcode))
    }
}

impl ToString for OpcodeWithData {
    fn to_string(&self) -> String {
        match self {
            OpcodeWithData::Opcode(opcode) => format!("{opcode:?}"),
            OpcodeWithData::PushWithData(n, word) => format!("PUSH{n}({word})"),
        }
    }
}

/// Iterator over the bytecode to retrieve individual opcodes
pub struct BytecodeIterator<'a>(std::slice::Iter<'a, BytecodeElement>);
impl<'a> Iterator for BytecodeIterator<'a> {
    type Item = OpcodeWithData;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|byte| {
            let op = OpcodeId::from(byte.value);
            let n = op.data_len();
            if n > 0 {
                assert!(op.is_push_with_data());

                let mut value = vec![0u8; n];
                for value_byte in value.iter_mut() {
                    *value_byte = self.0.next().unwrap().value;
                }

                OpcodeWithData::PushWithData(n as u8, Word::from(value.as_slice()))
            } else {
                OpcodeWithData::Opcode(op)
            }
        })
    }
}

impl From<Vec<u8>> for Bytecode {
    fn from(input: Vec<u8>) -> Self {
        let mut code = Bytecode::default();

        let mut input_iter = input.iter();
        while let Some(byte) = input_iter.next() {
            let op = OpcodeId::from(*byte);
            code.write_op(op);
            if op.is_push_with_data() {
                let n = op.postfix().expect("opcode with postfix");
                for _ in 0..n {
                    match input_iter.next() {
                        Some(v) => {
                            code.write(*v, false);
                        }
                        None => {
                            // out of boundary is allowed
                            // see also: https://github.com/ethereum/go-ethereum/blob/997f1c4f0abcd78f645e6e7ced6db4b42ad59c9d/core/vm/analysis.go#L65
                            break;
                        }
                    }
                }
            }
        }

        code
    }
}

/// EVM code macro
#[macro_export]
macro_rules! bytecode {
    ($($args:tt)*) => {{
        let mut code = $crate::bytecode::Bytecode::default();
        $crate::bytecode_internal!(code, $($args)*);
        code
    }};
}

#[macro_export]
#[doc(hidden)]
macro_rules! bytecode_internal {
    // Nothing left to do
    ($code:ident, ) => {};
    // PUSHX op codes
    ($code:ident, $x:ident ($v:expr) $($rest:tt)*) => {{
        debug_assert!($crate::evm_types::OpcodeId::$x.is_push_with_data(), "invalid push");
        let n = $crate::evm_types::OpcodeId::$x.postfix().expect("opcode with postfix");
        $code.push(n, $v);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Default opcode without any inputs
    ($code:ident, $x:ident $($rest:tt)*) => {{
        debug_assert!(!$crate::evm_types::OpcodeId::$x.is_push_with_data(), "invalid push");
        $code.write_op($crate::evm_types::OpcodeId::$x);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Marker
    ($code:ident, #[$marker:tt] $($rest:tt)*) => {{
        $code.add_marker(stringify!($marker).to_string());
        $crate::bytecode_internal!($code, $($rest)*);
    }};
    // Function calls
    ($code:ident, .$function:ident ($($args:expr),* $(,)?) $($rest:tt)*) => {{
        $code.$function($($args,)*);
        $crate::bytecode_internal!($code, $($rest)*);
    }};
}

impl Bytecode {
    /// Helper function for `PUSH0`
    pub fn op_push0(&mut self) -> &mut Self {
        self.push(0, Word::zero())
    }
}

macro_rules! impl_push_n {
    ($($push_n:ident, $n:expr)*) => {
        #[allow(missing_docs)]
        impl Bytecode {
            $(
                pub fn $push_n<T: ToWord>(&mut self, value: T) -> &mut Self {
                    self.push($n, value)
                }
            )*
        }
    };
}

impl_push_n! {
    op_push1, 1
    op_push2, 2
    op_push3, 3
    op_push4, 4
    op_push5, 5
    op_push6, 6
    op_push7, 7
    op_push8, 8
    op_push9, 9
    op_push10, 10
    op_push11, 11
    op_push12, 12
    op_push13, 13
    op_push14, 14
    op_push15, 15
    op_push16, 16
    op_push17, 17
    op_push18, 18
    op_push19, 19
    op_push20, 20
    op_push21, 21
    op_push22, 22
    op_push23, 23
    op_push24, 24
    op_push25, 25
    op_push26, 26
    op_push27, 27
    op_push28, 28
    op_push29, 29
    op_push30, 30
    op_push31, 31
    op_push32, 32
}

macro_rules! impl_other_opcodes_inner {
    ($self:ident, ) => {};
    ($self:ident, $arg:ident) => {
        $self.op_push32($arg);
    };
    ($self:ident, $arg:ident $($tail:ident)+) => {
        impl_other_opcodes_inner!($self, $($tail)*);
        $self.op_push32($arg);
    }
}

macro_rules! impl_other_opcodes {
    ($(($op:ident, $x:ident $(, $arg:ident : $arg_ty:ident)*)),* $(,)?) => {
        #[allow(missing_docs)]
        #[allow(clippy::too_many_arguments)]
        impl Bytecode {
            $(
                pub fn $op<$(
                    $arg_ty: ToWord,
                )*>(&mut self, $($arg: $arg_ty),*) -> &mut Self {
                    impl_other_opcodes_inner!(self, $($arg)*);
                    self.write_op($crate::evm_types::OpcodeId::$x)
                }
            )*
        }
    };
}

impl_other_opcodes! {
    (op_stop, STOP),
    (op_add, ADD, a: A, b: B),
    (op_mul, MUL, a: A, b: B),
    (op_sub, SUB, a: A, b: B),
    (op_div, DIV, a: A, b: B),
    (op_sdiv, SDIV, a: A, b: B),
    (op_mod, MOD, a: A, b: B),
    (op_smod, SMOD, a: A, b: B),
    (op_addmod, ADDMOD, a: A, b: B, n: N),
    (op_mulmod, MULMOD, a: A, b: B, n: N),
    (op_exp, EXP, a: A, exponent: B),
    (op_signextend, SIGNEXTEND, b: A, x: B),
    (op_lt, LT, a: A, b: B),
    (op_gt, GT, a: A, b: B),
    (op_slt, SLT, a: A, b: B),
    (op_sgt, SGT, a: A, b: B),
    (op_eq, EQ, a: A, b: B),
    (op_iszero, ISZERO, a: A),
    (op_and, AND, a: A, b: B),
    (op_or, OR, a: A, b: B),
    (op_xor, XOR, a: A, b: B),
    (op_not, NOT, a: A),
    (op_byte, BYTE, i: I, x: X),
    (op_shl, SHL, shift: S, value: V),
    (op_shr, SHR, shift: S, value: V),
    (op_sar, SAR, shift: S, value: V),
    (op_sha3, SHA3, offset: O, size: S),
    (op_address, ADDRESS),
    (op_balance, BALANCE, address: A),
    (op_origin, ORIGIN),
    (op_caller, CALLER),
    (op_callvalue, CALLVALUE),
    (op_calldataload, CALLDATALOAD, i: I),
    (op_calldatasize, CALLDATASIZE),
    (op_calldatacopy, CALLDATACOPY, dest_offset: D, offset: B, size: C),
    (op_codesize, CODESIZE),
    (op_codecopy, CODECOPY, dest_offset: D, offset: B, size: C),
    (op_gasprice, GASPRICE),
    (op_extcodesize, EXTCODESIZE, address: A),
    (op_extcodecopy, EXTCODECOPY, address: A, dest_offset: D, offset: B, size: C),
    (op_returndatasize, RETURNDATASIZE),
    (op_returndatacopy, RETURNDATACOPY, dest_offset: D, offset: B, size: C),
    (op_extcodehash, EXTCODEHASH, address: A),
    (op_blockhash, BLOCKHASH, blocknumber: B),
    (op_coinbase, COINBASE),
    (op_timestamp, TIMESTAMP),
    (op_number, NUMBER),
    (op_prevrandao, DIFFICULTY), // alias for DIFFICULTY
    (op_difficulty, DIFFICULTY),
    (op_gaslimit, GASLIMIT),
    (op_chainid, CHAINID),
    (op_selfbalance, SELFBALANCE),
    // (op_basefee, BASEFEE), ignored
    (op_pop, POP),
    (op_mload, MLOAD, offset: O),
    (op_mstore, MSTORE, offset: O, value: V),
    (op_mstore8, MSTORE8, offset: O, value: V),
    (op_sload, SLOAD, offset: O),
    (op_sstore, SSTORE, offset: O, value: V),
    (op_jump, JUMP, counter: C),
    (op_jumpi, JUMPI, counter: C), // branch not included
    (op_pc, PC),
    (op_msize, MSIZE),
    (op_gas, GAS),
    // (op_jumpdest, JUMPDEST), manually implemented
    (op_dup1, DUP1),
    (op_dup2, DUP2),
    (op_dup3, DUP3),
    (op_dup4, DUP4),
    (op_dup5, DUP5),
    (op_dup6, DUP6),
    (op_dup7, DUP7),
    (op_dup8, DUP8),
    (op_dup9, DUP9),
    (op_dup10, DUP10),
    (op_dup11, DUP11),
    (op_dup12, DUP12),
    (op_dup13, DUP13),
    (op_dup14, DUP14),
    (op_dup15, DUP15),
    (op_dup16, DUP16),
    (op_swap1, SWAP1),
    (op_swap2, SWAP2),
    (op_swap3, SWAP3),
    (op_swap4, SWAP4),
    (op_swap5, SWAP5),
    (op_swap6, SWAP6),
    (op_swap7, SWAP7),
    (op_swap8, SWAP8),
    (op_swap9, SWAP9),
    (op_swap10, SWAP10),
    (op_swap11, SWAP11),
    (op_swap12, SWAP12),
    (op_swap13, SWAP13),
    (op_swap14, SWAP14),
    (op_swap15, SWAP15),
    (op_swap16, SWAP16),
    (op_log0, LOG0, offset: O, size: S),
    (op_log1, LOG1, offset: O, size: S, topic1: T1),
    (op_log2, LOG2, offset: O, size: S, topic1: T1, topic2: T2),
    (op_log3, LOG3, offset: O, size: S, topic1: T1, topic2: T2, topic3: T3),
    (op_log4, LOG4, offset: O, size: S, topic1: T1, topic2: T2, topic3: T3, topic4: T4),
    (op_create, CREATE, value: V, offset: O, size: S),
    (op_call, CALL, gas: G, address: A, value: V, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_callcode, CALLCODE, gas: G, address: A, value: V, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_return, RETURN, offset: O, size: S),
    (op_delegatecall, DELEGATECALL, gas: G, address: A, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_create2, CREATE2, value: V, offset: O, size: SI, salt: SA),
    (op_staticcall, STATICCALL, gas: G, address: A, args_offset: AO, args_size: AS, ret_offset: RO, ret_size: RS),
    (op_revert, REVERT, offset: O, size: S),
    // (op_invalid, INVALID), ignored
    // (op_selfdestruct, SELFDESTRUCT), ignored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bytecode;
    use std::str::FromStr;

    #[test]
    fn test_bytecode_roundtrip() {
        let code = bytecode! {
            PUSH0
            POP
            PUSH8(0x123)
            POP
            PUSH24(0x321)
            PUSH32(0x432)
            MUL
            CALLVALUE
            CALLER
            POP
            POP
            POP
            STOP
        };
        assert_eq!(Bytecode::try_from(code.to_vec()).unwrap(), code);
    }

    #[test]
    fn test_asm_disasm() {
        let code = bytecode! {
            PUSH1(5)
            PUSH2(0xa)
            MUL
            STOP
        };
        let mut code2 = Bytecode::default();
        code.iter()
            .map(|op| op.to_string())
            .map(|op| OpcodeWithData::from_str(&op).unwrap())
            .for_each(|op| {
                code2.append_op(op);
            });

        assert_eq!(code.code, code2.code);
    }

    #[cfg(feature = "shanghai")]
    #[test]
    fn test_asm_disasm_for_shanghai() {
        let code = bytecode! {
            PUSH0
            POP
            PUSH1(5)
            PUSH2(0xa)
            MUL
            STOP
        };
        let mut code2 = Bytecode::default();
        code.iter()
            .map(|op| op.to_string())
            .map(|op| OpcodeWithData::from_str(&op).unwrap())
            .for_each(|op| {
                code2.append_op(op);
            });

        assert_eq!(code.code, code2.code);
    }
}
