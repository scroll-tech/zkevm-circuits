#!/bin/bash

profile="cirunner"
runner_vpc_id1="vpc-8bdf97ec"
runner_vpc_id2="vpc-1176d875"
region_opt1="--region us-west-2"
region_opt2="--region us-west-1"

# Get runner status
runner1=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[jenkins1] Name=network-interface.vpc-id,Values=[$runner_vpc_id1] --query "Reservations[*].Instances[*][InstanceId]" ${region_opt1} --output text | xargs)
runner2=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[jenkins2] Name=network-interface.vpc-id,Values=[$runner_vpc_id2] --query "Reservations[*].Instances[*][InstanceId]" ${region_opt2} --output text | xargs)

while true; do
    runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner1 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt1} --output text)
    if [[ $runner_status = "stopped" ]]; then
        aws ec2 start-instances --profile $profile --instance-ids $runner1 ${region_opt1}
        break
    elif [[ $runner_status = "running" ]]; then
        sleep 120
        runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner1 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt1} --output text)
        if [[ $runner_status = "running" ]]; then
            break
        fi
    else
        sleep 30
    fi
done

while true; do
    runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner2 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt2} --output text)
    if [[ $runner_status = "stopped" ]]; then
        aws ec2 start-instances --profile $profile --instance-ids $runner2 ${region_opt2}
        break
    elif [[ $runner_status = "running" ]]; then
        sleep 120
        runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner2 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt2} --output text)
        if [[ $runner_status = "running" ]]; then
            break
        fi
    else
        sleep 30
    fi
done

exit 0
