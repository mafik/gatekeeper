# [![Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/static/gatekeeper.gif?raw=true)](https://github.com/mafik/gatekeeper) Gatekeeper
DHCP &amp; DNS server for your home gateway. Gives you visibility into what's happening inside your network.

[![End-to-end test](https://github.com/mafik/gatekeeper/actions/workflows/test.yml/badge.svg)](https://github.com/mafik/gatekeeper/actions/workflows/test.yml)

## What is Gatekeeper?

Gatekeeper aims to replace traditional DHCP and DNS servers, such as dnsmasq, for home network management. Gatekeeper is resource efficient thanks to implementation in modern C++. It offers visibility into its configuration & network state with a web interface served on port 1337.

[2023-06-12 Gatekeeper Screencast.webm](https://github.com/mafik/gatekeeper/assets/309914/76b61336-205b-4342-8715-d62d37a582c3)

| Light mode                                                                                                                            | Dark mode                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| ![Light mode](https://raw.githubusercontent.com/mafik/gatekeeper/f6204d11fd968177254feaa4e16e45360c07f4b5/screenshots/2023-06-24.png) | ![Dark mode](https://raw.githubusercontent.com/mafik/gatekeeper/f6204d11fd968177254feaa4e16e45360c07f4b5/screenshots/2023-06-24-dark.png) |

Current feature set covers LAN interface configuration (including NAT) and most of the basic DHCP & DNS functionality. It should be usable for most home networks. In the future it may be extended with more "Home Gateway"-oriented features, such as WAN interface configuration, port forwarding, bandwidth accounting, etc.

If there are features you'd like to see, don't hesitate to modify its source code. Gatekeeper is written in a readable manner, making it easy for anyone with basic C++ knowledge to extend its functionality.

## Rationale

Over last years I've grown annoyed with lack of well-designed open-source software for managing home gateways. I imagine I can't be the only person that would like to have a performant & intuitive admin panel for my home network. Probably everybody is busy writing configs for dnsmasq (or netplan, or networkd, or whatever). By sharing a simple implementation of a gateway management server I hope to redirect the ad-hoc efforts of various home-network-admins into a single project. Instead of writing configs we could be adding cool features that would be used by everyone.

The key idea that distinguishes Gatekeeper from most other network management software is the focus on "Home Gateway" use-case. While other tools offer great flexibility, this flexibility comes at a cost of complexity. As a result they lack sensible defaults and their config options are a mess. What it means for Gatekeeper is that its only configuration option is "which interface to run on". Everything else is handled automatically. Because really - why wouldn't it be?

## ![Running Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/gatekeeper-running.gif?raw=true) Running Gatekeeper

```bash
curl https://github.com/mafik/gatekeeper/releases/latest/download/gatekeeper -o gatekeeper \
  && chmod +x gatekeeper \
  && sudo ./gatekeeper
```

That's it. Gatekeeper will copy itself to `/opt/gatekeeper`, register as a systemd service and start. You can remove the downloaded binary with `rm gatekeeper` now. After installation it's no longer needed.

To remove Gatekeeper, run `sudo systemctl disable --now gatekeeper` (this stops Gatekeeper and prevents it from starting again on next reboot) and `rm -rf /opt/gatekeeper`.

### Portable mode

You can also start Gatekeeper without installing it by running `sudo PORTABLE=1 ./gatekeeper`.

### LAN interface selection

Gatekeeper will manage the first interface without IP address that it finds. It your LAN interface is already configured you can either flush it with `sudo ip addr flush dev <interface>` or tell Gatekeeper to use it by running it with `LAN=<interface>` environment variable. This can be easiest done by running `sudo systemctl edit gatekeeper` and adding the following lines:

```
[Service]
Environment="LAN=<interface>"
```

### Limitations

Gatekeeper doesn't configure the WAN interface. It has to be done using stardard OS-supplied tools (most likely just DHCP). In the future Gatekeeper will take care of this.

Gatekeeper only runs on x86_64 Linux. In the future I'd like to also port it to ARM (32 & 64-bit) & MIPS (for those dirt-cheap OpenWRT routers).

## Building from source

```
sudo bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
sudo apt install -y valgrind inotify-tools
sudo ./run gatekeeper
```

## Credits

- Logo from [aamatniekss.itch.io](https://aamatniekss.itch.io/fantasy-knight-free-pixelart-animated-character) ([Twitter](https://twitter.com/Namatnieks))
- Daytime clouds from [anokolisa.itch.io](https://anokolisa.itch.io/sidescroller-pixelart-sprites-asset-pack-forest-16x16/devlog/398014/high-forest-new-update) ([Patreon](https://img.itch.zone/aW1nLzkzMTE1NzAucG5n/original/lXKJcR.png), [Twitter](https://img.itch.zone/aW1nLzkzMTE1NzEucG5n/original/ph%2BgkH.png), [Instagram](https://img.itch.zone/aW1nLzEwNDYzNDQ5LnBuZw==/original/Di01oS.png))
- Daytime mountains from [vnitti.itch.io](https://vnitti.itch.io/grassy-mountains-parallax-background) ([DeviantArt](http://www.deviantart.com/vnitti), [Twitter](https://twitter.com/vnitti_art))
- Night theme from [brullov.itch.io](https://brullov.itch.io/2d-platformer-asset-pack-castle-of-despair) ([Twitter](https://twitter.com/brullov_art))
- Header icons from [cainos.itch.io](https://cainos.itch.io/pixel-art-platformer-village-props) ([Twitter](https://twitter.com/cainos_chen))
- Font from [github.com/Omnibus-Type/Texturina](https://github.com/Omnibus-Type/Texturina)
