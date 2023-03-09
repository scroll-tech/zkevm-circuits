#!/bin/bash
#set -e 
#set -x

profile="cirunner"
provers_vpc_id="vpc-1176d875"
dns_ipaddr=$(dig prover.cirunners.internal +short)
zone_id=$(aws route53 --profile $profile list-hosted-zones --query 'HostedZones[?Name==`cirunners.internal.`].[Id]' --output text | awk -F \/ '{ print $3 }')
route53_dir=".github/proverCiScripts/misc"

sshprover () {
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no prover "uptime"
}

# Get running provers IDs
provers_running=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[proverbench-multiAZ] Name=instance-state-name,Values=[running] Name=network-interface.vpc-id,Values=[$provers_vpc_id] --query "Reservations[*].Instances[*][InstanceId]" --output text)
provers_running_num=$(echo $provers_running | wc -w)

if [[ $provers_running_num -gt 1 ]]; then
    echo "More than 1 provers running"
    exit 1
elif [[ $provers_running_num -eq 0 ]]; then
    # Get provers IDs and start first available
    provers=$(aws ec2 describe-instances --profile $profile --filters Name=tag:Name,Values=[proverbench-multiAZ] Name=network-interface.vpc-id,Values=[$provers_vpc_id] --query "Reservations[*].Instances[*][InstanceId]" --output text | xargs)
else
    provers=$provers_running
    single_prover_running=true
fi

for prover in $provers; do
    [[ ! -z $single_prover_running ]] || aws ec2 start-instances --profile $profile --instance-ids $prover
    if [ $? -eq 0 ]; then
        ipaddr=$(aws ec2 describe-instances --profile $profile --instance-ids $prover --query "Reservations[*].Instances[*].NetworkInterfaces[*].[PrivateIpAddress]" --output text)
        if [ $ipaddr != $dns_ipaddr ]; then
            cp $route53_dir/route53.template{,.json}
            sed -i "s/CHANGEME/$ipaddr/" $route53_dir/route53.template.json
            # TTL=60 so sleep for 60+1
            aws route53 change-resource-record-sets --profile $profile --hosted-zone-id $zone_id --change-batch file://$route53_dir/route53.template.json
            sleep 61
            rm $route53_dir/route53.template.json
	    ssh-keygen -f "/home/CI/.ssh/known_hosts" -R "prover.cirunners.internal"
        fi
        break
    fi
    sleep 2
done

# Wait until prover is accessible
while true; do
    sshprover
    if [ $? -eq 0 ]; then
        break
    else
        sleep 2
    fi
done
