macro_rules! run_test {
    ($test_instance:expr, $block_tag:expr, $real_prover:expr) => {
        log_init();

        let mut test = $test_instance.lock().await;
        test.test_at_block_tag($block_tag, $real_prover).await;
    };
}

macro_rules! declare_tests {
    (($name:ident, $block_tag:expr),$real_prover:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                run_test! (EVM_CIRCUIT_TEST, $block_tag, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_state_ $name>]() {
                run_test! (STATE_CIRCUIT_TEST, $block_tag, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_tx_ $name>]() {
                run_test! (TX_CIRCUIT_TEST, $block_tag, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_bytecode_ $name>]() {
                run_test! (BYTECODE_CIRCUIT_TEST, $block_tag, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_copy_ $name>]() {
                run_test! (COPY_CIRCUIT_TEST, $block_tag, $real_prover);
            }

            #[tokio::test]
            async fn [<serial_test_super_ $name>]() {
                run_test! (SUPER_CIRCUIT_TEST, $block_tag, $real_prover);
            }
        }
    };
}

macro_rules! unroll_tests {
    ($($arg:tt),*) => {
        use paste::paste;
        use integration_tests::integration_test_circuits::{
            EVM_CIRCUIT_TEST,
            STATE_CIRCUIT_TEST,
            TX_CIRCUIT_TEST,
            BYTECODE_CIRCUIT_TEST,
            COPY_CIRCUIT_TEST,
            SUPER_CIRCUIT_TEST
        };
        use integration_tests::log_init;
        mod real_prover {
            use super::*;
            $(
                declare_tests! ($arg, true) ;
            )*
        }

        mod mock_prover {
            use super::*;
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
