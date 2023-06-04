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
ip addr flush dev $DEV_A
ip netns exec $NS ip addr flush dev $DEV_B
ip addr add 192.168.0.1/24 dev $DEV_A
ip link set $DEV_A up
ip netns exec $NS ip link set $DEV_B up

# Start Gatekeeper
systemctl reset-failed
systemd-run --service-type=notify --same-dir --unit=gatekeeper-e2e --quiet ./gatekeeper $DEV_A

# Start dhclient
cp -f test-dhclient-hook /etc/dhcp/dhclient-enter-hooks.d/
ip netns exec $NS dhclient -1 -cf ./test-dhclient.conf $DEV_B

# Collect results
CLIENT_IP=$(sudo ip netns exec ns0 hostname -I | xargs)
HOSTNAME=$(hostname)
DIG_HOSTNAME_LOCAL=$(ip netns exec $NS dig +short $HOSTNAME.local @192.168.0.1)
CURL_1337=$(ip netns exec $NS curl -s http://192.168.0.1:1337)

# Stop dhclient
dhclient -x 2>/dev/null
rm -f /etc/dhcp/dhclient-enter-hooks.d/test-dhclient-hook

# Stop Gatekeeper
systemctl stop gatekeeper-e2e

if [ "$CLIENT_IP" != "192.168.0.2" ]; then
  echo "client IP is [$CLIENT_IP] but expected [192.168.0.2]"
  exit 1
fi

if [ "$DIG_HOSTNAME_LOCAL" != "192.168.0.1" ]; then
  echo "dig returned [$DIG_HOSTNAME_LOCAL] but expected [192.168.0.1]"
  exit 1
fi

if [[ $CURL_1337 != *Gatekeeper* ]]; then
  echo "http://192.168.0.1:1337 should contain [Gatekeeper]. Got [$CURL_1337]"
  exit 1
fi
