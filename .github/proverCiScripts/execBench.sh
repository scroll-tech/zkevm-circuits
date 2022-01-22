#!/bin/bash
set -e
#set -x

prnumber=$1
base_dir="/home/ubuntu/CI_Prover_Benches/"
target_dir="$base_dir"PR"$1"
k=$2
printf -v _date '%(%Y-%m-%d_%H:%M:%S)T' -1

cd $target_dir;
logfile=$_date--evm_bench-$k.proverlog

export PATH=$PATH:/usr/local/go/bin
DEGREE=$k ~/.cargo/bin/cargo test --profile bench bench_evm_circuit_prover -p circuit-benchmarks --features benches  -- --nocapture > "$target_dir/$logfile" 2>&1
