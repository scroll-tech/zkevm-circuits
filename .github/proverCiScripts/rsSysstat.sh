#!/bin/bash
set -e
#set -x

sudo systemctl stop sysstat.service
sudo rm -rf /var/log/sysstat/*
sudo rm -f sar.stats
sudo rm -rf cpu.stats
sudo rm -rf mem.stats

sleep 10

sudo systemctl start sysstat.service

