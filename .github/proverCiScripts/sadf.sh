#!/bin/bash

sleep 5
sudo rm -f /var/log/sysstat/sar*
sacount=$(sudo find /var/log/sysstat/ -type f | wc -l)
previousdays=$(expr 1 - $sacount)
while [ $previousdays -lt 0 ] 
  do
    sadf $previousdays -d >> cpu.stats
    sadf $previousdays -d -- -r >> mem.stats
    (( previousdays++ ))
  done
sadf -d >> cpu.stats
sadf -d -- -r >> mem.stats
