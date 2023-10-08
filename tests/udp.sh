#!/usr/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

NS=ns0
DEV=veth0

DEV_A=${DEV}a
DEV_B=${DEV}b

# Setup network
if [ ! -e /run/netns/$NS ]; then
  ip netns add $NS
fi
if [ ! -e /sys/class/net/$DEV_A ]; then
  ip link add $DEV_A type veth peer name $DEV_B netns $NS
fi

# Setup fake resolv.conf for our network namespace.
# See man ip-netns for reference.
# TL;DR is that empty file is enough for `ip netns` to bind mount it over /etc/resolv.conf
# This file will be filled by `test-dhclient-hook`
mkdir -p /etc/netns/$NS
touch /etc/netns/$NS/resolv.conf

ip addr flush dev $DEV_A
ip netns exec $NS ip addr flush dev $DEV_B
ip netns exec $NS ip link set $DEV_B up

# Start Gatekeeper
systemctl reset-failed
systemd-run --service-type=notify --same-dir --unit=gatekeeper-udp --setenv=LAN=$DEV_A --quiet build/debug_gatekeeper
GATEKEEPER_STATUS=$?
INVOCATION_ID=$(systemctl show --value -p InvocationID gatekeeper-udp)

if [ $GATEKEEPER_STATUS -ne 0 ]; then
  echo "Gatekeeper failed to start. Status code: $GATEKEEPER_STATUS"
  echo "Gatekeeper log:"
  journalctl _SYSTEMD_INVOCATION_ID=$INVOCATION_ID
  exit 1
fi

echo "Use 'journalctl _SYSTEMD_INVOCATION_ID=$INVOCATION_ID' to see Gatekeeper logs"

# Start dhclient
cp -f test-dhclient-hook /etc/dhcp/dhclient-enter-hooks.d/
ip netns exec $NS dhclient -1 -cf ./test-dhclient.conf $DEV_B

GATEKEEPER_IP=$(ip addr show dev $DEV_A | grep -oP '(?<=inet )([0-9.]*)')

# Start iperf server
iperf -s -u -e -B $GATEKEEPER_IP%$DEV_A &
IPERF_PID=$!

# Start iperf client
ip netns exec $NS iperf -c $GATEKEEPER_IP -u -b 1000M -t 10 -e

# Stop iperf server
kill $IPERF_PID

# Stop dhclient
dhclient -x 2>/dev/null
rm -f /etc/dhcp/dhclient-enter-hooks.d/test-dhclient-hook

# Stop Gatekeeper
systemctl stop gatekeeper-udp
