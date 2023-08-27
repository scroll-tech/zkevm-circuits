#C="create2collisionNonce_d1_g0_v0"
#C="Create2OOGFromCallRefunds_d3(SStore_Call_Refund_NoOoG)_g0_v0"
#C="FailedCreateRevertsDeletion_d0_g0_v0"
#C="InitCollision_d2_g0_v0"
#C="randomStatetest650_d0_g0_v0"
C="revertRetDataSize_d0_g0_v0"

#CHECK_RW_LOOKUP=true 
FLAG=" --features=scroll"

RUST_BACKTRACE=1 RUST_LOG=trace cargo run --release $FLAG -- --circuits sc --inspect "${C}" 2>&1 | tee one.log
