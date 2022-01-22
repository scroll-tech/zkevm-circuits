#!/bin/bash
#set -e 
#set -x

sshprover () {
ssh -o ConnectTimeout=5 prover << EOF
export PATH=$PATH:/usr/local/go/bin
EOF
}

#get prover state and boot if state=stopped
state=$(aws ec2 describe-instance-status --instance-id i-0f92100cb5a0ff7d5 --profile cirunner | jq .'InstanceStatuses | .[0] | .InstanceState | .Name')

if [[ "$state" == '"running"' ]];then
	echo "i am up and running"
else
	echo "Prover is stopped, starting..."
	aws ec2 start-instances --instance-ids i-0f92100cb5a0ff7d5 --profile cirunner
fi

#wait until prover is accessible
while true
  do
    sshprover
    if [ $? -eq 0 ]
      then
        break
    else
      sleep 2
    fi
  done
