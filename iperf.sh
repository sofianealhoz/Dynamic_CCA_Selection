#!/bin/bash

SERVER_IP="188.120.200.2"
DATA_SIZE="15000000M"

while true; do
    echo "attempting co"
    iperf3 -c "$SERVER_IP" -n "$DATA_SIZE" -R

    exit_code=$?

    if [ "$exit_code" -eq 0 ]; then
        echo "iperf3 ok"
        break
    else
        echo "iperf3 error"
        sleep 0.1
    fi
done