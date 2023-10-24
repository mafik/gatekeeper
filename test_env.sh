#!/usr/bin/env bash

# Small helper script for starting Gatekeeper in a test environment and leaving it running

set -e

mkdir -p /etc/netns/$NS
touch /etc/netns/$NS/resolv.conf

ip addr flush dev veth0a
ip netns exec ns0 ip addr flush dev veth0b
ip netns exec ns0 ip link set veth0b up
systemctl reset-failed
systemd-run --service-type=notify --same-dir --unit=gatekeeper-e2e --setenv=LAN=veth0a --quiet build/debug_gatekeeper
echo GATEKEEPER_STATUS=$?

INVOCATION_ID=$(systemctl show --value -p InvocationID gatekeeper-e2e)

echo "Use 'journalctl _SYSTEMD_INVOCATION_ID=$INVOCATION_ID' to see Gatekeeper logs"

cp -f test-dhclient-hook /etc/dhcp/dhclient-enter-hooks.d/
ip netns exec ns0 dhclient -1 -cf ./test-dhclient.conf veth0b

dhclient -x 2>/dev/null
rm -f /etc/dhcp/dhclient-enter-hooks.d/test-dhclient-hook

echo "Use 'ip netns exec ns0 curl -v --no-progress-meter --connect-timeout 5 --max-time 10 www.google.com' to test connectivity"

journalctl _SYSTEMD_INVOCATION_ID=$INVOCATION_ID -f
