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

**Alice**, a journalist, assumed that her VPN will keep her whistleblowers safe. **Eve**, who runs the VPN company has great fun snooping on what Alice has been up to. **Evan** who works as an analyst in the police cybercrime department, recently got a bonus for tracking down Alice's whistleblowers from the IXP (internet exchange point) traffic.

After installing Gatekeeper, Alice learned what information she leaks online. Instead of dodgy VPNs she started using secure protocols & encryption for her online activity. As a result Eve no longer could snoop on Alice. Evan also couldn't track Alice's communication any more.

<hr>

By exposing the LAN traffic Gatekeeper informs LAN clients about the data they may be leaking to [other LAN members](https://cylab.be/blog/73/man-in-the-middle-mitm-with-arpspoof), ISPs & IXPs. It also helps in understanding the behavior of IoT devices that are present in the LAN.

## ![Running Gatekeeper](https://github.com/mafik/gatekeeper/blob/main/gatekeeper-running.gif?raw=true) Running Gatekeeper

Running Gatekeeper is fairly easy. It may take longer if you're new to Linux but don't worry - this section will guide you through the process step by step. Once you're familiar with the process you'll be able to set up Gatekeeper in less than a minute!

The setup process can be separated into roughly four steps:

1. Obtain the hardware
2. Prepare OS
3. Run Gatekeeper
4. Install Gatekeeper

Let's get started by getting the hardware!

### Hardware

Generally speaking Gatekeeper needs to sit between your LAN network and the internet. It can either completely replace the router provided by ISP, or sit between the ISP router and your LAN network. Although replacing the ISP router allows you to reduce the number of computers and total power usage, it may be more complicated. Some ISPs perform MAC filtering to limit access to their network. Quite often it's possible to bypass it by cloning the MAC address of the ISP router but that would go a little beyond the scope of this guide. Feel free to try this out as an exercise though! Here we'll cover the case where Gatekeeper is used to "isolate" the ISP router from your LAN network.

<img title="Ethernet cable & port" src=https://github.com/mafik/gatekeeper/assets/309914/49542abb-f572-4711-9ac4-036b3af26595 align=right width=15%>

The machine that will run Gatekeeper will need at least two Ethernet ports. One for the Wide Area Network (WAN) side and one for Local Area Network (LAN) side. Probably more - depending on how many LAN clients you'd like to connect directly. If your machine has only one ethernet port you can always just buy an USB ethernet adapter to add the second one. It may be a good idea to also buy an Ethernet Switch (new ones can be bought from Amazon for less than $20) since they're more cost-efficient than a bunch of USB ethernet adapters.

There is also the question of Wireless connectivity. As of now Gatekeeper doesn't configure the Wireless LAN, but if you're more experienced with Linux you may use wpa_supplicant to set up a network. Once the wireless settings are in place, Gatekeeper will gladly manage it. You can also spend some cash on Wireless Access Point (make sure it's a "dumb" access point - not a "router") and turn any regular ethernet port into wireless one.

*Ok, so with all the requirements in place, what are our options for hardware?*

The first and most obvious one is **any spare laptop** (or PC) that you have laying around. With a simple Ethernet USB adapter you can plug it between your ISP router & your LAN network. You can also **look online for used laptops**. Computer hardware drops in value very fast so you may find pretty good deals online. Be careful about power usage though - a cheap PC may actually cost you more in power bills than the hardware itself. Generally speaking laptops are not a problem - they rarely draw more than 20 W - but it's good to do your math and account for power bills when buying new stuff.

The second option is to get a **single board x86 computer**. Single board computers, often called SBCs, are the most compact form of a general purpose computer. They look similar to appliances and don't have as much upgrade potential as regular PCs or laptops but otherwise they're not much different. Being compact and power efficient is good for a machine that will run all the time. The "x86" part indicates the type of computer that Gatekeeper can run on. Some SBCs are marked as "ARM". Gatekeeper is in the process of adding ARM support though - so for the time being better avoid them and find an x86 SBC. To find them you can google "x86 sbc". My personal choice was https://eu.protectli.com/. They're on the expensive side and technically speaking they're not SBCs but they can also handle much more than Gatekeeper. I've been pretty happy with my 4-port VP2420, which I also use to host my website.

Overall if you're a beginner I'd recommend trying out the laptop approach. SBCs doesn't have a screen or a keyboard which makes them a little more troublesome during setup. If anything goes wrong, investigation is much easier when you can just pop open a laptop vs carrying a monitor + laptop to see why SBC can't be reached over the network.

Ok, so with the hardware in place, we can start setting up the OS!

### OS setup

Gatekeeper will happily run on any 64-bit Linux. Feel free to skip this section if your machine already has one installed.

There are many flavors of Linux, depending on what you want to use your computer for. Most people go for Ubuntu because of it's polished experience and popularity. For a server machine I'd actually recommend Debian. Under the hood it's very similar to Ubuntu so most of the guides for Ubuntu will work on Debian. Debian is also known for being boring but boring is a good thing when it comes to servers. Security issues are very rare and things generally don't change much between versions.

So without further ado let me redirect you to another guide, which will explain how to install Debian: https://www.debian.org/releases/bookworm/amd64/.

This step may take quite a bit of time if you're new to Linux. Once you know the drill, it's ~5 minutes of manual work and 15 minutes of waiting for the installation to finish.

Once you're done with the installation, we can finish the process by testing & installing Gatekeeper!

### Run Gatekeeper

Ok, we've wasted enough time already for all this setup so let's get this one out of the way quickly.

Copy this command and run it in terminal:

```bash
curl -L https://github.com/mafik/gatekeeper/releases/latest/download/gatekeeper.x86_64 -o gatekeeper \
  && chmod +x gatekeeper \
  && sudo ./gatekeeper
```

That's it. The first part of the command will grab the latest Gatekeeper release from GitHub, the second one will make it executable and the final one will run it with administrator's privileges.

During startup Gatekeeper will pick the first unconfigured network interface and manage it. It can be stopped at any time by pressing Ctrl+C in the terminal window.

You can open the URL printed on the command line (usually  http://10.0.0.1:1337/) to see the web interface. It's also accessible from any computer in your LAN network.

#### LAN interface selection

Did you got an error like this?

```
Couldn't find any candidate interface (src/gatekeeper.cc:###).
``````

Gatekeeper will manage the first interface without IP address that it finds. It your LAN interface is already configured you can either clear its IP it with `sudo ip addr flush dev <interface>` or tell Gatekeeper to use it as is by running Gatekeeper with `LAN=<interface>` environment variable.

If Gatekeeper was already installed (you completed the next step), this can be easiest done by running `sudo systemctl edit gatekeeper` and adding the following lines:

```
[Service]
Environment="LAN=<interface>"
```

### Installation

To permanently install Gatekeeper, press the `Install` button in the web interface. Gatekeeper will copy itself to `/opt/gatekeeper`, register as a systemd service and start (systemd is a program that manages background tasks on Linux).

After installation you can remove the downloaded binary with `rm gatekeeper`. It's no longer needed.

If you've seen a page with an installation log then it means that the process completed successfully. 🎉🎉 Congrats!

#### Uninstallation

To remove Gatekeeper, run `sudo systemctl disable --now gatekeeper` (this stops Gatekeeper and prevents it from starting again on next reboot). Also run `sudo rm -rf /opt/gatekeeper` to remove any installed files.

## Limitations

Current feature set covers LAN interface configuration (including NAT) and most of the basic DHCP & DNS functionality. It should be usable for most home networks. In the future it may be extended with more "Home Gateway"-oriented features, such as WAN interface configuration, port forwarding, etc.

Gatekeeper doesn't configure the WAN interface. Most Linux distributions will do this automatically through DHCP during startup, but it's not always the case. In the future Gatekeeper will take care of this.

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
