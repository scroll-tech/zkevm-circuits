#!/bin/bash

index=""
if [ -e "export" ]; then
    i=$(expr $(cat export | awk -F '=' '{print $2}') + 0)

    offset=0
    env_offset="TESTOOL_IDS_EXPORT_OFFSET"
    if [ -n "${!env_offset}" ]; then
        offset=$((env_offset))
    fi
    echo $offset

    index="index-"$((offset + i))
fi
echo $index

start=""
env_start="TEST_IDS_START"
if [ -n "${!env_start}" ]; then
    start="start-"$((env_start))
fi
echo $start

mkdir -p /opt/report/$index$start

testool --suite nightly --circuits sc --test-ids test_ids.txt --report > /opt/report/$index$start/run_test_ids.log 2>&1
