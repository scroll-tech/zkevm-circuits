#!/bin/bash
#set -e 
#set -x

profile="cirunner"
provers_vpc_id="vpc-1176d875"

running_prover=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[proverbench-multiAZ] Name=instance-state-name,Values=[running] Name=network-interface.vpc-id,Values=[$provers_vpc_id] --query "Reservations[*].Instances[*][InstanceId]" --output text)

aws ec2 stop-instances --profile $profile --instance-ids $running_prover

sleep 30
