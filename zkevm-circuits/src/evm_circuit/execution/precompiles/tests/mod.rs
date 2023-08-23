use crate::test_util::CircuitTestBuilder;
use bus_mapping::evm::PrecompileCallArgs;
use eth_types::evm_types::OpcodeId;
use mock::TestContext;
use rayon::iter::{ParallelBridge, ParallelIterator};
use std::panic::catch_unwind;

pub mod ec_add;
pub mod ec_mul;
pub mod ec_paring;
pub mod ec_recover;
pub mod identity;
pub mod modexp;

fn test_precompile_inner<'a>(
    test_vector: impl Iterator<Item = &'a PrecompileCallArgs> + Send,
    call_kind: OpcodeId,
) {
    test_vector
        .par_bridge()
        .filter_map(|test_vector| {
            catch_unwind(|| {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            })
            .err()
            .map(|e| (test_vector.name, e))
        })
        .for_each(|(name, e)| eprintln!("test {name} failed with error: {e:?}"));
}

macro_rules! gen_test {
    ($name:ident) => {
        paste::paste! {
            #[test]
            fn [<test_ $name _call>]() {
                test_precompile_inner($name::TEST_VECTOR.iter(), OpcodeId::CALL);
            }
            #[test]
            fn [<test_ $name _callcode>]() {
                test_precompile_inner($name::TEST_VECTOR.iter(), OpcodeId::CALLCODE);
            }
            #[test]
            fn [<test_ $name _delegatecall>]() {
                test_precompile_inner($name::TEST_VECTOR.iter(), OpcodeId::DELEGATECALL);
            }
            #[test]
            fn [<test_ $name _staticcall>]() {
                test_precompile_inner($name::TEST_VECTOR.iter(), OpcodeId::STATICCALL);
            }
        }
    };
}

gen_test!(ec_add);
gen_test!(ec_mul);
gen_test!(ec_paring);
gen_test!(ec_recover);
gen_test!(identity);
gen_test!(modexp);
