'''Commands used for development.'''

import fcntl
import make
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
from functools import wraps
from pathlib import Path
from contextlib import contextmanager


@wraps(subprocess.run)
def sh(*args, **kwargs):
    return subprocess.run(*args, shell=True, **kwargs)


def run(args: str):
    return make.Popen(args.split(),
                      env={
                          'PORTABLE': '1',
                          'LAN': 'enxe8802ee74415'
                      })


def debug():
    return run('build/debug_gatekeeper')


def gdb():
    return run('gdb build/debug_gatekeeper -q -ex run')


def net_reset():
    sh('sudo nft delete table gatekeeper')
    sh('sudo ip addr flush dev veth0a')
    sh('sudo ip netns exec ns0 ip addr flush dev veth0b')
    sh('sudo dhclient -x')
    sh('sudo rm -f /etc/dhcp/dhclient-enter-hooks.d/test-dhclient-hook')


def dogfood():
    '''Copy the binary to maf's router and run it.'''
    sh('scp build/debug_gatekeeper root@protectli:/opt/gatekeeper/gatekeeper.new',
       check=True)
    try:
        sh('ssh root@protectli "mv /opt/gatekeeper/gatekeeper{,.old} && mv /opt/gatekeeper/gatekeeper{.new,} && systemctl restart gatekeeper"',
        check=True)
    except subprocess.CalledProcessError:
        print('Failed to restart gatekeeper. Reverting changes.')
        sh('ssh root@protectli "mv /opt/gatekeeper/gatekeeper{.old,} && systemctl restart gatekeeper"',
        check=True)


@contextmanager
def dns_blocker():
    '''
    Start a "blocker" of port 53.
    Gatekeeper should kill it during startup.
    '''
    blocker = subprocess.Popen(['nc', '-lup', '53'])
    try:
        yield blocker
    finally:
        blocker.send_signal(signal.SIGTERM)


@contextmanager
def run_systemd(env):
    '''
    Run Gatekeeper as a systemd service.
    '''
    # This seems to mess with the DHCP server used by Ubuntu's NetworkManager
    # TODO: figure out why this happens (Wireshark) & fix it
    subprocess.check_call(['systemctl', 'reset-failed'])
    args = ['systemd-run', '--service-type=notify', '--same-dir', '--unit=gatekeeper-e2e', '--quiet']
    for k, v in env.items():
        args.append(f'--setenv={k}={v}')
    args += ['build/debug_gatekeeper']
    p = subprocess.run(args)
    p.invocation_id = subprocess.check_output(['systemctl', 'show', '--value', '-p', 'InvocationID', 'gatekeeper-e2e']).decode().strip()
    if p.returncode != 0:
        print('Gatekeeper failed to start. Status code: ', p.returncode)
        print('Gatekeeper log:')
        subprocess.run(['journalctl', '_SYSTEMD_INVOCATION_ID=' + p.invocation_id])
        sys.exit(1)
    try:
        print('Use "journalctl _SYSTEMD_INVOCATION_ID=' + p.invocation_id + '" to see Gatekeeper logs')
        yield p
    finally:
        subprocess.run(['systemctl', 'stop', 'gatekeeper-e2e'])
        # If Gatekeeper crashes it may leave its nft table active.
        # This breaks the internet on the test machine.
        # So we delete it here.
        subprocess.run(['nft',  'delete', 'table', 'gatekeeper'], stderr=subprocess.DEVNULL)
        subprocess.run(['ip', 'link', 'set', 'lan', 'down'], stderr=subprocess.DEVNULL)
        subprocess.run(['brctl', 'delbr', 'lan'], stderr=subprocess.DEVNULL)


@contextmanager
def run_dhclient(namespace, interface):
    if not os.path.exists('./tests/dhclient'):
        shutil.copyfile('/sbin/dhclient', './tests/dhclient')
        shutil.copymode('/sbin/dhclient', './tests/dhclient')
    subprocess.check_call(['sudo', 'ip', 'netns', 'exec', namespace, './tests/dhclient', '-1', '-cf', './tests/dhclient.conf', '-sf', './tests/dhclient-script', '-pf', './tests/dhclient.pid', interface])
    try:
        yield
    finally:
        subprocess.call(['sudo', 'ip', 'netns', 'exec', namespace, './tests/dhclient', '-cf', './tests/dhclient.conf', '-sf', './tests/dhclient-script', '-pf', './tests/dhclient.pid', '-x', interface], stderr=subprocess.DEVNULL)


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname.encode()[:15])
        )[20:24])
    except OSError:
        return None
    

def setup_veth_namespace(i):
    NS = f'ns{i}'
    A = f'veth{i}a'
    B = f'veth{i}b'
    if not os.path.exists(f'/run/netns/{NS}'):
        subprocess.check_call(['sudo', 'ip', 'netns', 'add', NS])
    if not os.path.exists(f'/sys/class/net/{A}'):
        subprocess.check_call(['sudo', 'ip', 'link', 'add', A, 'type', 'veth', 'peer', 'name', B, 'netns', NS])

    subprocess.check_call(['sudo', 'ip', 'addr', 'flush', 'dev', A])
    subprocess.check_call(['sudo', 'ip', 'link', 'set', A, 'down'])
    subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, 'ip', 'addr', 'flush', 'dev', B])
    subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, 'ip', 'link', 'set', B, 'down'])

    # Setup fake resolv.conf for our network namespaces.
    # See man ip-netns for reference.
    # TL;DR is that empty file is enough for `ip netns` to bind mount it over /etc/resolv.conf
    # This file will be filled by `test-dhclient-hook`
    subprocess.check_call(['sudo', 'mkdir', '-p', f'/etc/netns/{NS}'])
    subprocess.check_call(['sudo', 'touch', f'/etc/netns/{NS}/resolv.conf'])
    return NS, A, B


def test_env():
    if os.geteuid() != 0:
        raise Exception('This script must be run as root')
    
    for i in range(4):
        setup_veth_namespace(i)

    # Start Gatekeeper
    env = {'LAN': ' '.join([f'veth{i}a' for i in range(4)])}
    with run_systemd(env), run_dhclient('ns0', 'veth0b'):
        input('Press Enter to continue...')


def test_e2e():
    if os.geteuid() != 0:
        raise Exception('This script must be run as root')
    
    for i in range(4):
        setup_veth_namespace(i)

    # Start Gatekeeper
    env = {'LAN': ' '.join([f'veth{i}a' for i in range(4)])}
    with dns_blocker() as blocker, run_systemd(env), run_dhclient('ns0', 'veth0b'):
       
        # Collect test results
        GATEKEEPER_IP = get_ip_address('lan')
        if GATEKEEPER_IP is None:
            print('DHCP issue. Gatekeeper IP is None')
            sys.exit(1)
        CLIENT_IP = subprocess.check_output("ip netns exec ns0 ip route get 1 | awk '{print $(NF-2);exit}'", shell=True).decode().strip()
        TEST_DOMAIN = 'www.google.com'
        CURL_EXAMPLE_STATUS = subprocess.call(['ip', 'netns', 'exec', 'ns0', 'curl', '-v', '--no-progress-meter', '--connect-timeout', '5', '--max-time', '10', TEST_DOMAIN], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        CURL_1337 = subprocess.check_output(['ip', 'netns', 'exec', 'ns0', 'curl', '-s', 'http://' + GATEKEEPER_IP + ':1337']).decode().strip()
        NFT_RULES = subprocess.check_output(['nft', 'list', 'ruleset']).decode().strip()

        if blocker.poll() == None: # DNS blocker is still running
            print('Startup issue. Gatekeeper failed to kill another process listening on DNS port')
            sys.exit(1)

    # replace the last segment of $GATEKEEPER_IP with '2'
    EXPECTED_CLIENT_IP = '.'.join(GATEKEEPER_IP.split('.')[:-1]) + '.2'
    
    if CLIENT_IP != EXPECTED_CLIENT_IP:
        print('DHCP issue. Client IP is [{}] but expected [{}].'.format(CLIENT_IP, EXPECTED_CLIENT_IP))
        sys.exit(1)
    if 'Gatekeeper' not in CURL_1337:
        print('Web UI issue. http://{}:1337 should contain [Gatekeeper]. Got [{}].'.format(GATEKEEPER_IP, CURL_1337))
        sys.exit(1)
    if CURL_EXAMPLE_STATUS != 0:
        print('DNS / NAT issue. Curl {} should return status code 0 but returned {}.'.format(TEST_DOMAIN, CURL_EXAMPLE_STATUS))
        print('Netfilter rules (`nft list ruleset`):')
        print(NFT_RULES)
        sys.exit(1)


def test_dhcp():
    NS, A, B = setup_veth_namespace(0)
    subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, 'ip', 'link', 'set', B, 'up'])
    with run_systemd({'LAN': A}):
        # Start dhammer
        # 200 requests / second over 10 seconds
        # Linux has limits for its ARP table size.
        # See /proc/sys/net/ipv4/neigh/default/gc_thresh{1,2,3}.
        subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, './tests/dhammer.v2.0.0.linux.amd64', 'dhcpv4', '--interface', B, '--mac-count', '1000', '--rps', '200', '--maxlife', '10'])


def test_dns():
    NS, A, B = setup_veth_namespace(0)
    with run_systemd({'LAN': A}), run_dhclient(NS, B):
        ip = get_ip_address(A)
        # Start dnsblast
        # 1000 queries at a rate of 100 QPS.
        subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, './tests/dnsblast.linux.amd64', ip, '1000', '100'])


def test_tcp():
    NS, A, B = setup_veth_namespace(0)
    with run_systemd({'LAN': A}), run_dhclient(NS, B):
        ip = get_ip_address(A)
        # Start iperf server
        iperf = subprocess.Popen(['iperf3', '-s', '-B', f'{ip}%{A}'])
        # Start iperf client
        subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, 'iperf3', '-c', ip, '-t', '10'])
        # Stop iperf server
        iperf.kill()
        

def test_udp():
    NS, A, B = setup_veth_namespace(0)
    with run_systemd({'LAN': A}), run_dhclient(NS, B):
        ip = get_ip_address(A)
        # Start iperf server
        iperf = subprocess.Popen(['iperf3', '-s', '-B', f'{ip}%{A}'])
        # Start iperf client
        subprocess.check_call(['sudo', 'ip', 'netns', 'exec', NS, 'iperf3', '-c', ip, '-u', '-b', '1000M', '-t', '10'])
        # Stop iperf server
        iperf.kill()


def hook_final(srcs, objs, bins, recipe: make.Recipe):
    deps = ['build/debug_gatekeeper']
    recipe.add_step(debug, [], deps)
    recipe.add_step(gdb, [], deps)
    recipe.add_step(net_reset, [], deps)
    recipe.add_step(test_env, [], deps)
    recipe.add_step(test_e2e, [], deps)
    recipe.add_step(test_dhcp, [], deps)
    recipe.add_step(test_dns, [], deps)
    recipe.add_step(test_tcp, [], deps)
    recipe.add_step(test_udp, [], deps)
    recipe.add_step(dogfood, [], deps)
