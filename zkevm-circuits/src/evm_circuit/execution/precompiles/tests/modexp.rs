use bus_mapping::{evm::PrecompileCallArgs, precompile::PrecompileCalls};
use eth_types::{bytecode, word, ToWord};
use once_cell::sync::Lazy;

pub static TEST_VECTOR: Lazy<Vec<PrecompileCallArgs>> = Lazy::new(|| {
    vec![
        PrecompileCallArgs {
            name: "modexp success",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x1)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x1)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x63.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp success",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x66.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        PrecompileCallArgs {
            name: "modexp success with padding 0",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x65.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        // 'attempt to divide by zero',
        // /home/ubuntu/.cargo/registry/src/github.com-1ecc6299db9ec823/num-bigint-0.4.3/src/
        // biguint/division.rs:121:9 stack backtrace:
        // 0: std::panicking::begin_panic
        // 1: num_bigint::biguint::division::div_rem
        // 2: mylib::circuits::modexp::ModExpChip<F>::mod_mult
        // 3: mylib::circuits::modexp::ModExpChip<F>::mod_exp
        // 4: zkevm_circuits::modexp_circuit::ModExpCircuitConfig::assign_group
        // 5: <halo2_proofs::circuit::floor_planner::single_pass::SingleChipLayouter<F,CS> as
        // halo2_proofs::circuit::Layouter<F>>::assign_region
        // 6: <zkevm_circuits::modexp_circuit::ModExpCircuit<F> as
        // zkevm_circuits::util::SubCircuit<F>>::synthesize_sub
        // 7: <zkevm_circuits::super_circuit::SuperCircuit<halo2curves::bn256::fr::Fr,_,_,_,_> as
        // halo2_proofs::plonk::circuit::Circuit<halo2curves::bn256::fr::Fr>>::synthesize
        // 8: <halo2_proofs::circuit::floor_planner::single_pass::SimpleFloorPlanner as
        // halo2_proofs::plonk::circuit::FloorPlanner>::synthesize
        // 9: halo2_proofs::dev::MockProver<F>::run
        // 10: zkevm_circuits::super_circuit::test::test_super_circuit
        // 11: zkevm_circuits::super_circuit::test::test_super_circuit_modexp_ops_txs
        // 12: core::ops::function::FnOnce::call_once
        // 13: core::ops::function::FnOnce::call_once
        //             at
        // /rustc/dfe3fe710181738a2cb3060c23ec5efb3c68ca09/library/core/src/ops/function.rs:507:5
        //
        // PrecompileCallArgs {
        //     name: "modexp no input",
        //     setup_code: bytecode! {
        //         // just put something in memory
        //         PUSH1(0x1)
        //         PUSH1(0x00)
        //         MSTORE
        //     },
        //     call_data_offset: 0x0.into(),
        //     call_data_length: 0x0.into(),
        //     ret_offset: 0x9f.into(),
        //     ret_size: 0x01.into(),
        //     address: PrecompileCalls::Modexp.address().to_word(),
        //     ..Default::default()
        // },
        PrecompileCallArgs {
            name: "modexp success with garbage bytes",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x3)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x2)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x0800000901000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
                PUSH32(word!("0x0000000000000000000000000000000000000000000000000000000000000009"))
                PUSH1(0x80)
                MSTORE
                PUSH32(word!("0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
                PUSH1(0xA0)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0xc0.into(),
            ret_offset: 0xe0.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            ..Default::default()
        },
        // same 'attempt to divide by zero',
        // PrecompileCallArgs {
        //     name: "modexp zero modulus",
        //     setup_code: bytecode! {
        //         // Base size
        //         PUSH1(0x1)
        //         PUSH1(0x00)
        //         MSTORE
        //         // Esize
        //         PUSH1(0x2)
        //         PUSH1(0x20)
        //         MSTORE
        //         // Msize
        //         PUSH1(0x0)
        //         PUSH1(0x40)
        //         MSTORE
        //         // B, E and M
        //         PUSH32(word!("
        // 0x0800090000000000000000000000000000000000000000000000000000000000"))
        //         PUSH1(0x60)
        //         MSTORE
        //     },
        //     call_data_offset: 0x0.into(),
        //     call_data_length: 0x63.into(),
        //     ret_offset: 0x9f.into(),
        //     ret_size: 0x01.into(),
        //     address: PrecompileCalls::Modexp.address().to_word(),
        //     ..Default::default()
        // },
        // assertion failed:
        // ws[0] * cs[0] + ws[1] * cs[1] + ws[2] * cs[2]
        // + ws[3] * cs[3] + ws[4] * cs[4]
        // + ws[5] * cs[5] + ws[0] * ws[3] * cs[6]
        // + ws[1] * ws[2] * cs[7] + cs[8] == F::zero()'
        // /home/ubuntu/.cargo/git/checkouts/misc-precompiled-circuit-158c0f4ab8ae3af7/31c41ca/src/
        // circuits/mod.rs:308:9 PrecompileCallArgs {
        //     name: "modexp length in u256",
        //     setup_code: bytecode! {
        //         // Base size
        //         PUSH1(0x20)
        //         PUSH1(0x00)
        //         MSTORE
        //         // Esize
        //         PUSH1(0x20)
        //         PUSH1(0x20)
        //         MSTORE
        //         // Msize
        //         PUSH1(0x20)
        //         PUSH1(0x40)
        //         MSTORE
        //         // B, E and M
        //         PUSH32(word!("
        // 0x0000000000000000000000000000000000000000000000000000000000000008"))
        //         PUSH1(0x60)
        //         MSTORE
        //         PUSH32(word!("
        // 0x1000000000000000000000000000000000000000000000000000000000000009"))
        //         PUSH1(0x80)
        //         MSTORE
        //         PUSH32(word!("
        // 0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
        //         PUSH1(0xA0)
        //         MSTORE
        //     },
        //     call_data_offset: 0x0.into(),
        //     call_data_length: 0xc0.into(),
        //     ret_offset: 0xe0.into(),
        //     ret_size: 0x01.into(),
        //     address: PrecompileCalls::Modexp.address().to_word(),
        //     ..Default::default()
        // },
        // same above
        // PrecompileCallArgs {
        //     name: "modexp length in u256 and result wrapped",
        //     setup_code: bytecode! {
        //         // Base size
        //         PUSH1(0x20)
        //         PUSH1(0x00)
        //         MSTORE
        //         // Esize
        //         PUSH1(0x20)
        //         PUSH1(0x20)
        //         MSTORE
        //         // Msize
        //         PUSH1(0x20)
        //         PUSH1(0x40)
        //         MSTORE
        //         // B, E and M
        //         PUSH32(word!("
        // 0x0000000000000000000000000000000000000000000000000000000000000008"))
        //         PUSH1(0x60)
        //         MSTORE
        //         PUSH32(word!("
        // 0x0000000000000000000000000000000000000000000000000000000000000064"))
        //         PUSH1(0x80)
        //         MSTORE
        //         PUSH32(word!("
        // 0xfcb51a0695d8f838b1ee009b3fbf66bda078cd64590202a864a8f3e8c4315c47"))
        //         PUSH1(0xA0)
        //         MSTORE
        //     },
        //     call_data_offset: 0x0.into(),
        //     call_data_length: 0xc0.into(),
        //     ret_offset: 0xe0.into(),
        //     ret_size: 0x01.into(),
        //     address: PrecompileCalls::Modexp.address().to_word(),
        //     ..Default::default()
        // },
        PrecompileCallArgs {
            name: "modexp length too large invalid",
            setup_code: bytecode! {
                // Base size
                PUSH1(0x1)
                PUSH1(0x00)
                MSTORE
                // Esize
                PUSH1(0x1)
                PUSH1(0x20)
                MSTORE
                // Msize
                PUSH1(0x21)
                PUSH1(0x40)
                MSTORE
                // B, E and M
                PUSH32(word!("0x08090A0000000000000000000000000000000000000000000000000000000000"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x0.into(),
            call_data_length: 0x63.into(),
            ret_offset: 0x9f.into(),
            ret_size: 0x01.into(),
            address: PrecompileCalls::Modexp.address().to_word(),
            gas: 100000.into(),
            ..Default::default()
        },
    ]
});
