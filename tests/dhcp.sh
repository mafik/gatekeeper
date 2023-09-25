#!/usr/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

NS=ns0
DEV=veth0

DEV_A=${DEV}a
DEV_B=${DEV}b

LOG_TO_FILE=tests/dhcp.log

# Setup network
if [ ! -e /run/netns/$NS ]; then
  ip netns add $NS
fi
if [ ! -e /sys/class/net/$DEV_A ]; then
  ip link add $DEV_A type veth peer name $DEV_B netns $NS
fi

ip addr flush dev $DEV_A
ip netns exec $NS ip addr flush dev $DEV_B
ip netns exec $NS ip link set $DEV_B up

# Start Gatekeeper
systemctl reset-failed
systemd-run --service-type=notify --same-dir --unit=gatekeeper-e2e --setenv=LAN=$DEV_A --setenv=LOG_TO_FILE=$LOG_TO_FILE --quiet build/debug_gatekeeper

# Start dhammer
# 200 requests / second over 10 seconds
# Linux has limits for its ARP table size.
# See /proc/sys/net/ipv4/neigh/default/gc_thresh{1,2,3}.
ip netns exec $NS ./tests/dhammer.v2.0.0.linux.amd64 dhcpv4 --interface $DEV_B --mac-count 1000 --rps 200 --maxlife 10

# Stop Gatekeeper
systemctl stop gatekeeper-e2e