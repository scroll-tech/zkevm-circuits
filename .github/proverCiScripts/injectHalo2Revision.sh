#!/bin/bash
#set -e 
#set -x

prnumber=$1
base_dir="/home/CI/CI_Prover_Benches/"
target_dir="$base_dir"PR"$1"

_revision=$2

oldrev=$(egrep halo2.*rev $target_dir/Cargo.toml | awk -F\" '{ print $4 }')

for i in `find $target_dir -type f -name 'Cargo.toml'`
do
  sed -i "s/$oldrev/$_revision/g" $i
done
