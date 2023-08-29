C="modexpRandomInput_d0_g0_v0"
C="ecadd_0-0_0-0_21000_0_d0_g0_v0"

#CHECK_RW_LOOKUP=true 
FLAG=" --features=scroll"

RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits basic --inspect "${C}" 2>&1 | tee one.log
#RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits sc --inspect "${C}" 2>&1 | tee one_sc.log
