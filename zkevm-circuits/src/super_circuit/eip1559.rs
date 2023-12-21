//! Helper functions for super circuit tests of EIP-1559

use super::CircuitsParams;
use eth_types::{address, l2_types::BlockTrace};
use ethers_signers::{LocalWallet, Signer};
use mock::{eth, gwei, TestContext, MOCK_CHAIN_ID};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

pub(crate) fn test_block_trace() -> BlockTrace {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let wallet_a = LocalWallet::new(&mut rng).with_chain_id(MOCK_CHAIN_ID);

    let addr_a = wallet_a.address();
    let addr_b = address!("0x0000000000000000000000000000000000001559");

    TestContext::<2, 1>::new(
        None,
        |accs| {
            accs[0].address(addr_b).balance(eth(1));
            accs[1].address(addr_a).balance(gwei(80_000));
        },
        |mut txs, _accs| {
            txs[0]
                .from(addr_a)
                .to(addr_b)
                .gas_price(gwei(2))
                .gas(30_000.into())
                .value(gwei(20_000))
                .max_fee_per_gas(gwei(2))
                .max_priority_fee_per_gas(gwei(2))
                .transaction_type(2); // Set tx type to EIP-1559.
        },
        |block, _tx| block.number(0xcafe_u64),
    )
    .unwrap()
    .l2_trace()
    .clone()
}

pub(crate) fn test_circuits_params(max_txs: usize, max_calldata: usize) -> CircuitsParams {
    CircuitsParams {
        max_txs,
        max_calldata,
        max_rws: 256,
        max_copy_rows: 256,
        max_exp_steps: 256,
        max_bytecode: 512,
        max_mpt_rows: 2049,
        max_poseidon_rows: 512,
        max_evm_rows: 0,
        max_keccak_rows: 0,
        max_inner_blocks: 1,
        max_rlp_rows: 500,
        ..Default::default()
    }
}
