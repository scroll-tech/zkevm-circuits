#!/bin/bash
set -e
#set -x

prnumber=$1
base_dir="/home/CI/CI_Prover_Benches/"
target_dir="$base_dir"PR"$1"
k=$2
circuit=$(echo $3 | awk '{ print $2 }' | tr '[:upper:]' '[:lower:]')
printf -v _date '%(%Y-%m-%d_%H:%M:%S)T' -1

case $circuit in
    "all")
        echo "To be implemented"
        exit 1
        ;;
    "evm")
        run_suffix="evm_circuit_prover"
        ;;
    "keccak")
        run_suffix="keccak_round"
        ;;
    "state")
        run_suffix="state_circuit_prover"
        ;;
    "tx")
        run_suffix="tx_circuit_prover"
        ;;
    "super")
        run_suffix="super_circuit_prover"
        ;;
    "bytecode")
        run_suffix="bytecode_circuit_prover"
        ;;
    "pi")
        run_suffix="pi_circuit_prover"
        ;;
    "exp")
        run_suffix="exp_circuit_prover"
        ;;
    "copy")
        run_suffix="copy_circuit_prover"
        ;;
    *)
        echo "No proper value"
        exit 1
        ;;
esac

cd $target_dir;
logfile=$_date--${circuit}_bench-$k.proverlog

export RUST_BACKTRACE=1
DEGREE=$k ~/.cargo/bin/cargo test --profile bench bench_${run_suffix} -p circuit-benchmarks --features benches  -- --nocapture > "$target_dir/$logfile" 2>&1

exit 0
