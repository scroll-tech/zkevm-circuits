use eth_types::l2_types::BlockTraceV2;
use eth_types::{bytecode, word};
use mock::test_ctx::helpers::*;
use mock::TestContext;

fn main() {
    let code = bytecode! {
        JUMPDEST
        PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000000"))
        JUMP
    };

    let ctx = TestContext::<2, 1>::new(
        None,
        account_0_code_account_1_no_code(code),
        tx_from_1_to_0,
        |block, _tx| block.number(0xcafe_u64),
    )
    .unwrap();
    let block_trace = BlockTraceV2::from(ctx.l2_trace().clone());
    serde_json::to_writer_pretty(std::io::stdout(), &block_trace).unwrap();
}
