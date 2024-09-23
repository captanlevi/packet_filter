#!/bin/bash

# Path to your IP list file
IP_FILE="filtered_server_ips.txt"

# Read IPs from the file
IFS=',' read -r -a ips < "$IP_FILE"

# Build tcpdump filter
filter=""
for ip in "${ips[@]}"; do
    if [ -n "$filter" ]; then
        filter+=" or "
    fi
    filter+="(src host $ip or dst host $ip)"
done


# Run tcpdump with the dynamically created filter
sudo tcpdump -i wlp0s20f3  "$filter"
