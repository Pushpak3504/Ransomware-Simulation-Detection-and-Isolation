#!/bin/bash

# Simple Network Scanner
# Scans a /24 network and checks for live hosts using ping

read -p "Enter the network address to scan (e.g., 192.168.80): " netid

echo "Scanning network: $netid.0/24"
echo "--------------------------------"

for host in {1..254}
do
    ping -c 1 -W 1 "$netid.$host" &> /dev/null

    if [ $? -eq 0 ]; then
        echo "$netid.$host is LIVE"
    fi
done

echo "--------------------------------"
echo "Scan completed."
