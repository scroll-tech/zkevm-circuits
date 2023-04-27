use std::cmp::Ordering;

use crate::evm_circuit::step::ExecutionState;
use bus_mapping::{
    circuit_input_builder::{self, CircuitsParams, ExecState},
    mock::BlockData,
};
use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData, Address, Bytecode, ToWord};
use mock::{eth, test_ctx::TestContext, MOCK_ACCOUNTS};
use strum::IntoEnumIterator;

/// Helper type to print formatted tables in MarkDown
pub(crate) struct DisplayTable<const N: usize> {
    header: [String; N],
    rows: Vec<[String; N]>,
}

impl<const N: usize> DisplayTable<N> {
    pub(crate) fn new(header: [String; N]) -> Self {
        Self {
            header,
            rows: Vec::new(),
        }
    }
    fn push_row(&mut self, row: [String; N]) {
        self.rows.push(row)
    }
    fn print_row(row: &[String; N], rows_width: &[usize; N]) {
        for (i, h) in row.iter().enumerate() {
            if i == 0 {
                print!("|");
            }
            print!(" {:width$} |", h, width = rows_width[i]);
        }
        println!();
    }
    pub(crate) fn print(&self) {
        let mut rows_width = [0; N];
        for row in std::iter::once(&self.header).chain(self.rows.iter()) {
            for (i, s) in row.iter().enumerate() {
                if s.len() > rows_width[i] {
                    rows_width[i] = s.len();
                }
            }
        }
        Self::print_row(&self.header, &rows_width);
        for (i, width) in rows_width.iter().enumerate() {
            if i == 0 {
                print!("|");
            }
            print!(" {:-<width$} |", "", width = width);
        }
        println!();
        for row in &self.rows {
            Self::print_row(row, &rows_width);
        }
    }
}

/// Generate the prefix bytecode to trigger a big amount of rw operations
pub(crate) fn bytecode_prefix_op_big_rws(opcode: OpcodeId) -> Bytecode {
    match opcode {
        OpcodeId::CODECOPY | OpcodeId::CALLDATACOPY => {
            bytecode! {
                PUSH4(0x1000) // size
                PUSH2(0x00) // offset
                PUSH2(0x00) // destOffset
            }
        }
        OpcodeId::RETURNDATACOPY => {
            bytecode! {
                PUSH1(0x00) // retLength
                PUSH1(0x00) // retOffset
                PUSH1(0x00) // argsLength
                PUSH1(0x00) // argsOffset
                PUSH1(0x00) // value
                PUSH32(MOCK_ACCOUNTS[3].to_word())
                PUSH32(0x1_0000) // gas
                CALL
                PUSH4(0x1000) // size
                PUSH2(0x00) // offset
                PUSH2(0x00) // destOffset
            }
        }
        OpcodeId::LOG0
        | OpcodeId::LOG1
        | OpcodeId::LOG2
        | OpcodeId::LOG3
        | OpcodeId::LOG4
        | OpcodeId::SHA3
        | OpcodeId::RETURN
        | OpcodeId::REVERT => bytecode! {
            PUSH4(0x1000) // size
            PUSH2(0x00) // offset
        },
        OpcodeId::EXTCODECOPY => bytecode! {
            PUSH4(0x1000) // size
            PUSH2(0x00) // offset
            PUSH2(0x00) // destOffset
            PUSH2(0x00) // address
        },
        _ => bytecode! {
            PUSH2(0x40)
            PUSH2(0x50)
        },
    }
}

struct Row {
    state: ExecutionState,
    opcode: OpcodeId,
    height: usize,
    gas_cost: u64,
    height_per_gas: f64,
}

/// This function prints to stdout a table with all the implemented states
/// and their responsible opcodes with the following stats:
/// - height: number of rows in a circuit used by the execution state
/// - gas: gas value used for the opcode execution
/// - height/gas: ratio between circuit cost and gas cost
///
/// The TestContext is as follows:
/// - `MOCK_ACCOUNTS[0]` calls `MOCK_ACCOUNTS[1]` which has a proxy code that calls
///   `MOCK_ACCOUNT[2]` which has the main code
/// - `0x0` account has a copy of the main code
/// - `MOCK_ACCOUNTS[3]` has a small code that returns a 0-memory chunk
pub(crate) fn print_circuit_stats_by_states(
    // Function to select which opcodes to analyze.  When this returns false,
    // the opcode is skipped.
    fn_filter: impl Fn(ExecutionState) -> bool,
    // Function to generate bytecode that will be prefixed to the opcode,
    // useful to set up arguments that cause worst height/gas case.
    fn_bytecode_prefix_op: impl Fn(OpcodeId) -> Bytecode,
    // Function that calculates the circuit height used by an opcode.  This function takes the
    // circuit input builder Block, the current execution state, and the step index in circuit
    // input builder tx.
    fn_height: impl Fn(&circuit_input_builder::Block, ExecutionState, usize) -> usize,
) {
    let mut implemented_states = Vec::new();
    for state in ExecutionState::iter() {
        let height = state.get_step_height_option();
        if height.is_some() {
            implemented_states.push(state);
        }
    }
    let smallcode = bytecode! {
        PUSH4(0x1000) // size
        PUSH2(0x00) // offset
        RETURN
    };
    let proxy_code = bytecode! {
        PUSH2(0x1000) // retLength
        PUSH1(0x00) // retOffset
        PUSH1(0x00) // argsLength
        PUSH1(0x00) // argsOffset
        PUSH1(0x00) // value
        PUSH32(MOCK_ACCOUNTS[2].to_word())
        PUSH32(800_000) // gas
        CALL
        STOP
    };

    let mut table = DisplayTable::new(["state", "opcode", "h", "g", "h/g"].map(|s| s.into()));
    let mut rows = vec![];
    for state in implemented_states {
        if !fn_filter(state) {
            continue;
        }
        for responsible_op in state.responsible_opcodes() {
            let opcode = responsible_op.opcode();
            let mut code = bytecode! {
                PUSH2(0x00)
                EXTCODESIZE // Warm up 0x0 address
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH1(0x00)
                PUSH2(0x00)
                PUSH2(0x10)
                PUSH2(0x20)
                PUSH2(0x30)
            };
            let bytecode_prefix_op = fn_bytecode_prefix_op(opcode);
            code.append(&bytecode_prefix_op);
            code.write_op(opcode);
            let opcode_pc = code.code.len() - 1;
            // let opcode_step_index = (proxy_code.num_opcodes - 1 + code.num_opcodes) - 1;
            code.op_stop();
            let block: GethData = TestContext::<10, 1>::new(
                None,
                |accs| {
                    accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(10));
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .balance(eth(10))
                        .code(proxy_code.clone());
                    accs[2]
                        .address(MOCK_ACCOUNTS[2])
                        .balance(eth(10))
                        .code(code.clone());
                    accs[3].address(MOCK_ACCOUNTS[3]).code(smallcode.clone());
                    accs[4].address(Address::zero()).balance(eth(10)).code(code);
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .input(vec![1, 2, 3, 4, 5, 6, 7].into());
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap()
            .into();
            let mut builder = BlockData::new_from_geth_data_with_params(
                block.clone(),
                CircuitsParams {
                    max_rws: 16_000,
                    max_copy_rows: 8_000,
                    ..CircuitsParams::default()
                },
            )
            .new_circuit_input_builder();
            builder
                .handle_block(&block.eth_block, &block.geth_traces)
                .unwrap();
            // Find the step that executed our opcode by filtering on second call (because
            // we run it via proxy) and the PC where we wrote the opcode.
            let (step_index, step) = builder.block.txs[0]
                .steps()
                .iter()
                .enumerate()
                .find(|(_, s)| s.call_index == 1 && s.pc.0 == opcode_pc)
                .unwrap();
            assert_eq!(ExecState::Op(opcode), step.exec_state);
            let height = fn_height(&builder.block, state, step_index);

            // Substract 1 to step_index to remove the `BeginTx` step, which doesn't appear
            // in the geth trace.
            let geth_step = &block.geth_traces[0].struct_logs[step_index - 1];
            assert_eq!(opcode, geth_step.op);
            let gas_cost = geth_step.gas_cost.0;
            rows.push(Row {
                state,
                opcode,
                height,
                gas_cost,
                height_per_gas: height as f64 / gas_cost as f64,
            });
        }
    }
    rows.sort_by(|a, b| {
        b.height_per_gas
            .partial_cmp(&a.height_per_gas)
            .unwrap_or(Ordering::Greater)
    });

    for row in rows.iter() {
        let row = [
            format!("{:?}", row.state),
            format!("{:?}", row.opcode),
            format!("{}", row.height),
            format!("{}", row.gas_cost),
            format!("{:1.3}", row.height_per_gas),
        ];
        table.push_row(row);
    }

    table.print();
}
