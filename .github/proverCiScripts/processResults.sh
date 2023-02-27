#!/bin/bash
set -e
#set -x

prnumber=$1
label=$2
degree=$3
base_dir="/home/ubuntu/CI_Prover_Benches/"
target_dir="$base_dir"PR"$prnumber"

rm -f ~/*.stats
rm -f ~/*.proverlog
rm -f ~/*.tar.gz

scp prover:$target_dir/*proverlog ~/
scp ~/actions-runner/zkevm_circuits_prover/zkevm-circuits/zkevm-circuits/.github/proverCiScripts/sadf.sh prover:~/
ssh prover "bash -s" <<EOF
./sadf.sh
rm -f sadf.sh
EOF

scp prover:~/*.stats ~/


l=$(echo $label | tr -d '"') 
circuit=$(echo $l |  awk '{print $2}')
time=$(date +%s)
test_id=$circuit-$degree-Benchmark-PR$prnumber--$time

tar -czvf ~/$test_id.tar.gz ~/*proverlog ~/*.stats
aws s3 cp ~/$test_id.tar.gz s3://zkevm-chain-testing --profile cirunner
echo "Log file uploaded at : https://zkevm-chain-testing.s3.eu-central-1.amazonaws.com/$test_id"".tar.gz"
/usr/bin/python3 .github/proverCiScripts/benchmarks_result_reporting/reporting_main.py  "$prnumber" "$circuit" "$degree" "$test_id"

ssh prover "bash -s" <<EOF
rm -f $target_dir/*proverlog
rm -f ~/*.stats
EOF

rm -rf ~/*proverlog
rm -rf ~/*.stats
rm -rf ~/$test_id.tar.gz
