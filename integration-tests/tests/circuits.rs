macro_rules! declare_tests {
    (($name:ident, $block_tag:expr),$real_prover:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_evm_circuit_block(*block_num, $real_prover).await;
            }

            #[tokio::test]
            async fn [<serial_test_state_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_state_circuit_block(*block_num, $real_prover).await;
            }

            #[tokio::test]
            async fn [<serial_test_tx_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_tx_circuit_block(*block_num, $real_prover).await;
            }

            #[tokio::test]
            async fn [<serial_test_bytecode_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_bytecode_circuit_block(*block_num, $real_prover).await;
            }

            #[tokio::test]
            async fn [<serial_test_copy_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_copy_circuit_block(*block_num, $real_prover).await;
            }
        }
    };
}

macro_rules! unroll_tests {
    ($($arg:tt),*) => {
        mod real_prover {
            use paste::paste;
            use integration_tests::integration_test_circuits::{
                test_bytecode_circuit_block, test_copy_circuit_block, test_evm_circuit_block,
                test_state_circuit_block, test_tx_circuit_block, GEN_DATA,
            };
            use integration_tests::log_init;
            $(
                declare_tests! ($arg, true) ;
            )*
        }

        mod mock_prover {
            use paste::paste;
            use integration_tests::integration_test_circuits::{
                test_bytecode_circuit_block, test_copy_circuit_block, test_evm_circuit_block,
                test_state_circuit_block, test_tx_circuit_block, GEN_DATA,
            };
            use integration_tests::log_init;
            $(
                declare_tests! ($arg, false) ;
            )*
        }
    }
}

unroll_tests!(
    (circuit_block_transfer_0, "Transfer 0"),
    (circuit_multiple_transfers_0, "Multiple transfers 0"),
    (
        circuit_erc20_openzeppelin_transfer_fail,
        "ERC20 OpenZeppelin transfer failed"
    ),
    (
        circuit_erc20_openzeppelin_transfer_succeed,
        "ERC20 OpenZeppelin transfer successful"
    ),
    (
        circuit_multiple_erc20_openzeppelin_transfers,
        "Multiple ERC20 OpenZeppelin transfers"
    )
);
