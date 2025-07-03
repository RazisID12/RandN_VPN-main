#!/bin/bash
set -e

SECONDS=0

cd /opt/randn_vpn-main

SUM1="$(sha256sum update.sh)"
cat update.sh | bash -s "$1"
SUM2="$(sha256sum update.sh)"
if [[ "$SUM1" != "$SUM2" ]]; then
	echo 'update.sh has been updated, restarting update.sh'
	cat update.sh | bash -s "$1"
fi
./parse.sh "$1"
if [[ -d /var/randn_vpn-main/openvpn/log ]]; then
    find /var/randn_vpn-main/openvpn/log -type f -size +10M -delete
fi
./custom-doall.sh "$1"

echo "Execution time: $SECONDS seconds"