use eth_types::l2_types::BlockTraceV2;
use eth_types::{bytecode, Bytecode};
use ethers_signers::Signer;
use mock::{eth, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

fn main() {
    let mut attacker = vec![0x5b; 24576];
    attacker[0] = 0xfe;
    let attacker = Bytecode::from(attacker);
    let caller = bytecode! {
        JUMPDEST
        PUSH0
        PUSH0
        PUSH0
        PUSH0
        PUSH0
        PUSH20(MOCK_ACCOUNTS[0])
        PUSH0
        CALL
        JUMP
    };

    let ctx = TestContext::<3, 1>::new(
        None,
        |acc| {
            acc[0].address(MOCK_ACCOUNTS[0]).code(attacker);
            acc[1].address(MOCK_ACCOUNTS[1]).code(caller);
            acc[2].address(MOCK_WALLETS[0].address()).balance(eth(10));
        },
        |mut tx, acc| {
            tx[0].from(MOCK_WALLETS[0].clone()).to(acc[1].address);
        },
        |block, _tx| block.number(0xcafe_u64),
    )
    .unwrap();
    let block_trace = BlockTraceV2::from(ctx.l2_trace().clone());
    serde_json::to_writer_pretty(std::io::stdout(), &block_trace).unwrap();
}
