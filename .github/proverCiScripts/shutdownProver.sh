#!/bin/bash
#set -e 
#set -xx

aws ec2 stop-instances --instance-ids i-0f92100cb5a0ff7d5 --profile cirunner
sleep 30
