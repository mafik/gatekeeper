#!/usr/bin/bash -x

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

# Setup resolv.conf
mkdir -p /etc/netns/$NS
touch /etc/netns/$NS/resolv.conf # empty file is enough for `ip netns` to bind mount it over /etc/resolv.conf
# this file will be filled by `test-dhclient-hook`

ip addr flush dev $DEV_A
ip netns exec $NS ip addr flush dev $DEV_B
ip netns exec $NS ip link set $DEV_B up

# Start Gatekeeper
systemctl reset-failed
systemd-run --service-type=notify --same-dir --unit=gatekeeper-e2e --setenv=LAN=$DEV_A --quiet valgrind --leak-check=yes --track-origins=yes --log-file=valgrind.log build/debug_gatekeeper

# Start dhclient
cp -f test-dhclient-hook /etc/dhcp/dhclient-enter-hooks.d/
ip netns exec $NS dhclient -1 -cf ./test-dhclient.conf $DEV_B

# Collect results
GATEKEEPER_IP=$(ip addr show dev $DEV_A | grep -oP '(?<=inet )([0-9.]*)')
CLIENT_IP=$(ip netns exec $NS hostname -I | xargs)
HOSTNAME=$(hostname)
TEST_DOMAIN="www.google.com"
DIG_RESULT=$(ip netns exec $NS dig +short $TEST_DOMAIN @$GATEKEEPER_IP | head -n 1)
CURL_1337=$(ip netns exec $NS curl -s http://$GATEKEEPER_IP:1337)
CURL_EXAMPLE=$(ip netns exec $NS curl -s --connect-timeout 5 --max-time 10 $TEST_DOMAIN)
CURL_EXAMPLE_STATUS=$?

# Stop dhclient
dhclient -x 2>/dev/null
rm -f /etc/dhcp/dhclient-enter-hooks.d/test-dhclient-hook

# Stop Gatekeeper
systemctl stop gatekeeper-e2e

# replace the last segment of $GATEKEEPER_IP with "2"
EXPECTED_CLIENT_IP=$(echo $GATEKEEPER_IP | sed 's/\.[0-9]*$/.2/')

if [ "$CLIENT_IP" != "$EXPECTED_CLIENT_IP" ]; then
  echo "client IP is [$CLIENT_IP] but expected [$EXPECTED_CLIENT_IP]"
  exit 1
fi

if [ "$DIG_RESULT" == "" ]; then
  echo "dig '$TEST_DOMAIN' returned empty result"
  exit 1
fi

if [[ $CURL_1337 != *Gatekeeper* ]]; then
  echo "http://$GATEKEEPER_IP:1337 should contain [Gatekeeper]. Got [$CURL_1337]"
  exit 1
fi

if [[ $CURL_EXAMPLE_STATUS -ne 0 ]]; then
  echo "curl $TEST_DOMAIN should return 0. Got [$CURL_EXAMPLE_STATUS]"
  exit 1
fi
