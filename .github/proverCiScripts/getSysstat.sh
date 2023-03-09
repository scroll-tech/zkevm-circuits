#!/bin/bash
set -e
#set -x

prnumber=$1
base_dir="/home/CI/CI_Prover_Benches/"
target_dir="$base_dir"PR"$prnumber"

logfile=$(ls $target_dir | grep proverlog | xargs -n 1 basename)
tail -12 $target_dir/$logfile
