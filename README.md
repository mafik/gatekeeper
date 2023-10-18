# [![Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/static/gatekeeper.webp?raw=true)](https://github.com/mafik/gatekeeper) Gatekeeper
DHCP &amp; DNS server optimized for use in home networks.

[![End-to-end test](https://github.com/mafik/gatekeeper/actions/workflows/test.yml/badge.svg)](https://github.com/mafik/gatekeeper/actions/workflows/test.yml)

## What is Gatekeeper?

Between you and the Internet there is a router. It's a small computer that connects your home network to the Internet. It's responsible for assigning IP addresses to your devices, translating between your private network and the Internet, and more. It's a very important piece of your home network. Quite often they're provided by your Internet Service Provider (ISP) and you don't have much control over them.

**Gatekeeper is a piece of software that allows you to replace (or isolate) the router provided by your ISP. With Gatekeeper you can get more visibility & control over your home network.**

There are other software projects that can manage a router but they're usually optimized for professional use & maximum flexibility. This makes them fairly complex. Gatekeeper, unlike others, is designed specifically for home networks. It is a single executable file that configures itself automatically, updates itself every week & automatically restarts itself in case of a hangup or a crash. Once installed it should never require any interaction.

Since it's meant for home use, it can offer features &amp; information that general-purpose routers can't. For example, by accessing its web interface it can tell you what devices are connected to your network or what domains are accessed by your IoT devices.

### Screenshots

[2023-06-12 Gatekeeper Screencast.webm](https://github.com/mafik/gatekeeper/assets/309914/76b61336-205b-4342-8715-d62d37a582c3)

| Light mode                                                                                                                            | Dark mode                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| ![Light mode](https://raw.githubusercontent.com/mafik/gatekeeper/f6204d11fd968177254feaa4e16e45360c07f4b5/screenshots/2023-06-24.png) | ![Dark mode](https://raw.githubusercontent.com/mafik/gatekeeper/f6204d11fd968177254feaa4e16e45360c07f4b5/screenshots/2023-06-24-dark.png) |

### Privacy

Gatekeeper deliberately exposes the unencrypted traffic that goes through the router to all LAN members.

<hr>

<img title="Alice, Eve & Even before Alice installed Gatekeeper" src=https://github.com/mafik/gatekeeper/assets/309914/49fe04dc-4650-4e35-837c-8462dc87cf79 width=25% align=left>

<img title="Alice, Eve & Even after Alice installed Gatekeeper" src=https://github.com/mafik/gatekeeper/assets/309914/8800314c-aa72-4187-a4be-dd2b67555c53 width=25% align=right>

**Alice**, a journalist, used to be oblivious to the amount of private information that that she leaks to her ISP whenever she browses internet. **Eve**, who works for the ISP, had great fun snooping on what Alice has been up to. **Evan** who works as an analyst in the police cybercrime department, got a bonus for tracking down Alice's whistleblowers.

After installing Gatekeeper, Alice learned that other LAN members, her ISP and IXPs (internet exchange points) can monitor her traffic. She started using secure protocols & encryption for her online activity. As a result Eve no longer could snoop on Alice. Evan also couldn't track Alice's communication any more.

<hr>

By exposing the LAN traffic Gatekeeper informs LAN clients about the data they may be leaking to [other LAN members](https://cylab.be/blog/73/man-in-the-middle-mitm-with-arpspoof), ISP & IXPs. It also helps in understanding the behavior of IoT devices that are present in the LAN.

## ![Running Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/gatekeeper-running.gif?raw=true) Running Gatekeeper

```bash
curl -L https://github.com/mafik/gatekeeper/releases/latest/download/gatekeeper.x86_64 -o gatekeeper \
  && chmod +x gatekeeper \
  && sudo ./gatekeeper
```

That's it. Gatekeeper will pick the first unconfigured interface and manage it.

This can be handy when you want to quickly set up a small network for example to host a LAN party.

You can open the URL printed on the command line (usually  http://10.0.0.1:1337/) to see the web interface.

### Installation

To permanently install Gatekeeper, press the `Install` button in the web interface. Gatekeeper will copy itself to `/opt/gatekeeper`, register as a systemd service and start.

After installation you can remove the downloaded binary with `rm gatekeeper`. It's no longer needed.

To remove Gatekeeper, run `sudo systemctl disable --now gatekeeper` (this stops Gatekeeper and prevents it from starting again on next reboot). Also run `rm -rf /opt/gatekeeper` to remove any installed files.

### LAN interface selection

Did you got an error like this?

```
Couldn't find any candidate interface (src/gatekeeper.cc:###).
``````

Gatekeeper will manage the first interface without IP address that it finds. It your LAN interface is already configured you can either clear its IP it with `sudo ip addr flush dev <interface>` or tell Gatekeeper to use it as is by running Gatekeeper with `LAN=<interface>` environment variable.

If Gatekeeper was already installed, this can be easiest done by running `sudo systemctl edit gatekeeper` and adding the following lines:

```
[Service]
Environment="LAN=<interface>"
```

### Limitations

Current feature set covers LAN interface configuration (including NAT) and most of the basic DHCP & DNS functionality. It should be usable for most home networks. In the future it may be extended with more "Home Gateway"-oriented features, such as WAN interface configuration, port forwarding, bandwidth accounting, etc.

Gatekeeper doesn't configure the WAN interface. It has to be done using stardard OS-supplied tools (most likely just DHCP). In the future Gatekeeper will take care of this.

Gatekeeper only runs on x86_64 Linux. In the future I'd like to also port it to ARM (32 & 64-bit) & MIPS (for those dirt-cheap OpenWRT routers).

If there are features you'd like to see, don't hesitate to modify its source code. Gatekeeper is written in a readable manner, making it easy for anyone with basic C++ knowledge to extend its functionality.

## Building from source

```
sudo bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
sudo apt install -y valgrind inotify-tools
sudo ./run gatekeeper
```

## Reporting vulverabilities

See [SECURITY.md](SECURITY.md).

## Credits

- Logo from [aamatniekss.itch.io](https://aamatniekss.itch.io/fantasy-knight-free-pixelart-animated-character) ([Twitter](https://twitter.com/Namatnieks))
- Daytime clouds from [anokolisa.itch.io](https://anokolisa.itch.io/sidescroller-pixelart-sprites-asset-pack-forest-16x16/devlog/398014/high-forest-new-update) ([Patreon](https://img.itch.zone/aW1nLzkzMTE1NzAucG5n/original/lXKJcR.png), [Twitter](https://img.itch.zone/aW1nLzkzMTE1NzEucG5n/original/ph%2BgkH.png), [Instagram](https://img.itch.zone/aW1nLzEwNDYzNDQ5LnBuZw==/original/Di01oS.png))
- Daytime mountains from [vnitti.itch.io](https://vnitti.itch.io/grassy-mountains-parallax-background) ([DeviantArt](http://www.deviantart.com/vnitti), [Twitter](https://twitter.com/vnitti_art))
- Night theme from [brullov.itch.io](https://brullov.itch.io/2d-platformer-asset-pack-castle-of-despair) ([Twitter](https://twitter.com/brullov_art))
- Header icons from [cainos.itch.io](https://cainos.itch.io/pixel-art-platformer-village-props) ([Twitter](https://twitter.com/cainos_chen))
- Font from [github.com/Omnibus-Type/Texturina](https://github.com/Omnibus-Type/Texturina)
- Cliparts
  - Globe & people by callmetak on <a href="https://www.freepik.com/free-vector/global-network-system-vector-concept-illustration-with-satellites-around-globe_40343325.htm#query=internet&position=18&from_view=search&track=sph">Freepik</a>
  - Laptop by macrovector on <a href="https://www.freepik.com/free-vector/retro-gadgets-2x2-isometric-design-concept-with-computer-evolution-3d-isolated_6845899.htm#query=old%20laptop&position=1&from_view=search&track=ais">Freepik</a>
