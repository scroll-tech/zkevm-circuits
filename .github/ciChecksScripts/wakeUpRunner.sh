#!/bin/bash

profile="cirunner"
runner_vpc_id1="vpc-8bdf97ec"
runner_vpc_id2="vpc-1176d875"
region_opt="--region us-west-2"

# Get runner status
runner1=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[jenkins] Name=network-interface.vpc-id,Values=[$runner_vpc_id1] --query "Reservations[*].Instances[*][InstanceId]" ${region_opt} --output text | xargs)
runner2=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[jenkins] Name=network-interface.vpc-id,Values=[$runner_vpc_id2] --query "Reservations[*].Instances[*][InstanceId]" --output text | xargs)

{
    while true; do
        runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner1 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt} --output text)
        echo 'runner1 - '$runner_status
        if [[ $runner_status = "stopped" ]]; then
            aws ec2 start-instances --profile $profile --instance-ids $runner1 ${region_opt}
            break
        elif [[ $runner_status = "running" ]]; then
            echo 'waiting for runner1 restore'
            sleep 30
            runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner1 --query "Reservations[*].Instances[*].State.[Name]" ${region_opt} --output text)
            if [[ $runner_status = "running" ]]; then
                break
            fi
        else
            sleep 30
        fi
    done
}&
while true; do
    runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner2 --query "Reservations[*].Instances[*].State.[Name]" --output text)
    echo 'runner2 - '$runner_status
    if [[ $runner_status = "stopped" ]]; then
        aws ec2 start-instances --profile $profile --instance-ids $runner2
        break
    elif [[ $runner_status = "running" ]]; then
        echo 'waiting for runner2 restore'
        sleep 30
        runner_status=$(aws ec2 describe-instances --profile $profile --instance-ids $runner2 --query "Reservations[*].Instances[*].State.[Name]" --output text)
        if [[ $runner_status = "running" ]]; then
            break
        fi
    else
        sleep 30
    fi
done

exit 0
