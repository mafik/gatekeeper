# [![Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/static/gatekeeper.gif?raw=true)](https://github.com/mafik/gatekeeper) Gatekeeper
DHCP &amp; DNS server for your home gateway. Gives you visibility into what's happening inside your network.

[![End-to-end test](https://github.com/mafik/gatekeeper/actions/workflows/test.yml/badge.svg)](https://github.com/mafik/gatekeeper/actions/workflows/test.yml)

## What is Gatekeeper?

Gatekeeper aims to replace traditional DHCP and DNS servers, such as dnsmasq, for home network management. Gatekeeper is resource efficient thanks to implementation in modern C++. It offers visibility into its configuration & network state with a web interface served on port 1337.

![Screenshot](https://github.com/mafik/gatekeeper/blob/main/screenshot-2023-06-11.png?raw=true)

Current feature set covers most of the basic DHCP & DNS functionality and should be usable for most home networks. In the future it may be extended with more "Home Gateway"-oriented features, such as interface configuration, port forwarding, bandwidth accounting, NAT connection tracking, etc.

If there are features you'd like to see, don't hesitate to modify its source code. Gatekeeper is written in a readable manner, making it easy for anyone with basic C++ knowledge to extend its functionality.

## Rationale

Over last years I've grown annoyed with lack of well-designed open-source software for managing home gateways. I imagine I can't be the only person that would like to have a performant & intuitive admin panel for my home network. Probably everybody is busy writing configs for dnsmasq (or netplan, or networkd, or whatever). By sharing a simple implementation of a gateway management server I hope to redirect the ad-hoc efforts of various home-network-admins into a single project. Instead of writing configs we could be adding cool features that would be used by everyone.

The key idea that distinguishes Gatekeeper from most other network management software is the focus on "Home Gateway" use-case. While other tools offer great flexibility, this flexibility comes at a cost of complexity. As a result they lack sensible defaults and their config options are a mess. What it means for Gatekeeper is that its only configuration option is "which interface to run on". Everything else is handled automatically. Because really - why wouldn't it be?

## ![Running Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/gatekeeper-running.gif?raw=true) Running Gatekeeper

### Interface configuration

Before running Gatekeeper you should configure the home network interface. This means:

1. The gateway machine should be able to access internet. This usually means plugging the internet cable & running DHCP client on the external interface: `dhclient <external interface name>`.
2. Assign IP & netmask to the interface. You can see current interface configuration with `ip addr show`. Adding IP addresses can be done with `ip addr add 192.168.1.1/24 dev <local interface name>`.
3. The interface should be in "up" state. You can bring it up with `ip link set <local interface name> up`.
4. The interface should have "forwarding" enabled. You can enable it with `sysctl -w net.ipv4.ip_forward=1`.
5. Enable NAT Masquerading. You can do it with `iptables -t nat -A POSTROUTING -o <external interface name> -j MASQUERADE`.

This config will be lost after reboot - so add those commands to `/etc/rc.local` & `sudo chmod a+x /etc/rc.local` to make it executable.

Interface configuration can also be done with other tools, such as `systemd-networkd` (Debian), `netplan` (Ubuntu) or other, distro-specific mechanisms.

Eventually, Gatekeeper should take care of this but I'm adding new features as I need them.

### Installation

1. Create `/opt/gatekeeper/` directory.
2. Download .tar.gz file from the [Releases page](https://github.com/mafik/gatekeeper/releases).
3. Extract it with `cd /opt/gatekeeper && tar -xzf <path to downloaded gatekeeper.tar.gz>`.
4. (Optionally) Do a test run with `sudo ./gatekeeper <interface name>`. Ctrl+C to stop.
5. Edit `/opt/gatekeeper/gatekeeper.service` file and change the interface name from `br0` to the name of your local interface.
6. Install systemd service with `sudo systemctl enable --now /opt/gatekeeper/gatekeeper.service`.
7.  Open web interface by navigating to `http://<IP of the local interface>:1337/` in your browser.

## Building from source

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17
sudo apt install -y libncurses5 llvm-dev libsystemd-dev valgrind
make gatekeeper
```

## Credits

- Logo from [aamatniekss.itch.io](https://aamatniekss.itch.io/fantasy-knight-free-pixelart-animated-character) ([Twitter](https://twitter.com/Namatnieks))
- Daytime clouds from [https://anokolisa.itch.io/](https://anokolisa.itch.io/sidescroller-pixelart-sprites-asset-pack-forest-16x16/devlog/398014/high-forest-new-update) ([Patreon](https://img.itch.zone/aW1nLzkzMTE1NzAucG5n/original/lXKJcR.png), [Twitter](https://img.itch.zone/aW1nLzkzMTE1NzEucG5n/original/ph%2BgkH.png), [Instagram](https://img.itch.zone/aW1nLzEwNDYzNDQ5LnBuZw==/original/Di01oS.png))
- Daytime mountains from [vnitti.itch.io](https://vnitti.itch.io/grassy-mountains-parallax-background) ([DeviantArt](http://www.deviantart.com/vnitti), [Twitter](https://twitter.com/vnitti_art))
- Night theme from [brullov.itch.io](https://brullov.itch.io/2d-platformer-asset-pack-castle-of-despair) ([Twitter](https://twitter.com/brullov_art))
- Header icons from [cainos.itch.io](https://cainos.itch.io/pixel-art-platformer-village-props) ([Twitter](https://twitter.com/cainos_chen))
