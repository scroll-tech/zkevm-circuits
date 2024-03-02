#!/bin/bash
#set -e 
#set -x

prnumber=$1
base_dir="/home/CI/CI_Prover_Benches/"
target_dir="$base_dir"PR"$1"

source_dir=$2

cd $source_dir && scp -r * prover:$target_dir

