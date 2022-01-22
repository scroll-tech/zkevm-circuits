#!/bin/bash
set -e
#set -x

prnumber=$1
base_dir="/home/ubuntu/CI_Prover_Benches/"
target_dir="$base_dir"PR"$prnumber"

sar -uh > cpu.stats
sar -rh > mem.stats

sed -i -e '1,5d' cpu.stats
sed -i -e '1,5d' mem.stats
sed -i -e '$ d' cpu.stats
sed -i -e '$ d' mem.stats

minIdleCPU=$(cat cpu.stats | awk '{ print $8 }' | sed  's/%//g' | sort -n | head -1)
maxUsedCPU=$(bc <<< "scale=2; 100-$minIdleCPU")
maxMemUsed=$(cat mem.stats | awk '{ print $4 }' | sed 's/G//g' | sort -n | tail -1)

#echo $maxUsedCPU
#echo $maxMemUsed
#echo "Maximum CPU Usage at $maxUsedCPU%"
#echo "Maximum Mem Usage at ${maxMemUsed}Gb"

logfile=$(ls $target_dir | grep proverlog | xargs -n 1 basename)
tail -12 $target_dir/$logfile

echo "Maximum CPU Usage at $maxUsedCPU%"
echo "Maximum Mem Usage at ${maxMemUsed}Gb"
