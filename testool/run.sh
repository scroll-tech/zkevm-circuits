C="modexpRandomInput_d0_g0_v0"
C="ecadd_0-0_0-0_21000_0_d0_g0_v0"
C="CALLBlake2f_d4_g0_v0"

#CHECK_RW_LOOKUP=true 
FLAG=" --features=scroll"

RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits basic --suite precompile2 --inspect "${C}" 2>&1 | tee inspect.log
#RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits basic --suite precompile2 2>&1 | tee precompile2.log
#RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits basic --suite precompile 2>&1 | tee precompile.log
#RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits sc --inspect "${C}" 2>&1 | tee one_sc.log
