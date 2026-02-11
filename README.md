# Portspoof

![License](https://img.shields.io/badge/license-GPLv2-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20POSIX-lightgrey.svg)
![Build Status](https://github.com/drk1wi/portspoof/actions/workflows/cmake.yml/badge.svg)

**Portspoof** emulates open ports and service signatures across all 65535 TCP ports, turning the reconnaissance phase from a quick scan into a long, resource-intensive process. Scanners see thousands of convincing but fake services, making it impractical to identify the real attack surface.

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [How It Works](#how-it-works)
- [Design Approach](#design-approach)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Hardening with iptables](#hardening-with-iptables)
- [Portspoof Pro](#portspoof-pro)
- [Authors & License](#authors--license)

## Overview

The primary goal of Portspoof is to make reconnaissance slow, costly, and unreliable for attackers. Instead of a standard 5-second Nmap scan that maps every real service on a system, an attacker facing Portspoof sees 65535 open ports, each running what looks like a different legitimate service. There is no quick way to tell which ones are real.

### Key Features

*   **All 65535 TCP Ports Are Always Open:** Instead of informing an attacker that a port is CLOSED or FILTERED, Portspoof returns `SYN+ACK` for every connection attempt.
*   **Service Emulation:** Over 9000 dynamic service signatures generated from regular expressions. Every port responds to probes with a different, convincing service identity.
*   **Mixed Delivery Modes:** Each port gets a different behavioral profile at startup (immediate banner, delayed response, or silent hold) with hold times spread across a wide range. Full-range version detection (`nmap -sV -p-`) goes well beyond practical limits.
*   **Offensive Defense:** Can be used as an 'Exploitation Framework Frontend' to exploit vulnerabilities in the attacker's own scanning tools.
*   **Lightweight & Secure:** Runs in userland (no root privileges required), binds to just **ONE** TCP port per running instance, and has marginal CPU/memory usage.

---

## How It Works

### 1. Defeating Port Scanners

**Example Nmap Scan:**
```bash
$ nmap -p 1-20 target
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for target
Host is up (0.00016s latency).
PORT   STATE SERVICE
1/tcp  open  tcpmux
2/tcp  open  compressnet
3/tcp  open  compressnet
4/tcp  open  unknown
5/tcp  open  rje
6/tcp  open  unknown
7/tcp  open  echo
8/tcp  open  unknown
9/tcp  open  discard
10/tcp open  unknown
11/tcp open  systat
12/tcp open  unknown
13/tcp open  daytime
14/tcp open  unknown
15/tcp open  netstat
16/tcp open  unknown
17/tcp open  qotd
18/tcp open  unknown
19/tcp open  chargen
20/tcp open  ftp-data
```

### 2. Confusing Version Detection
Portspoof responds to service probes with valid, dynamically generated signatures based on a massive regular expression database. As a result, an attacker will not be able to determine which port numbers your system is truly using.

**Example Version Scan (ports 1–100):**
```bash
$ nmap -sV -p 1-100 target
Nmap scan report for target
Host is up (0.00016s latency).
PORT    STATE SERVICE            VERSION
1/tcp   open  tcpmux?
2/tcp   open  irc                ircu ircd
3/tcp   open  tcpwrapped
5/tcp   open  http               Polycom CMA Global Address Book (GAB) httpd
10/tcp  open  http               PGP Universal httpd
11/tcp  open  http               SnapStream Media Beyond TV PVR http config
12/tcp  open  pop3               Novell GroupWise pop3d
13/tcp  open  http               micro_httpd
15/tcp  open  ssh                OpenSSH r (protocol 8; NCSA GSSAPI authentication patch)
16/tcp  open  ftp                QMS/Minolta Magicolor 2200 DeskLaser printer ftpd
17/tcp  open  smtp               Network Box smtpd
21/tcp  open  ftp?
22/tcp  open  ssh                OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
23/tcp  open  tcpwrapped
25/tcp  open  smtp?
27/tcp  open  http               BMC/Marimba Management http config
37/tcp  open  http               Indy httpd qlRKjiF
39/tcp  open  pop3
41/tcp  open  ftp                VSE ftpd WhH
43/tcp  open  imap               Scalix imapd 6
46/tcp  open  telnet             AXIS webcam telnetd 96747 (Linux)
49/tcp  open  smtp               Openwave Email Mx smtpd
50/tcp  open  http               3Ware web interface 3v (RAID storage)
51/tcp  open  ftp                WebStar 4dftp ...
53/tcp  open  tcpwrapped
55/tcp  open  webdav             Tonido WebDAV
56/tcp  open  tor-control        Tor control port (Authentication required)
59/tcp  open  irc                ircu ircd
60/tcp  open  rtsp               GStreamer rtspd
64/tcp  open  http               BaseHTTPServer CAxoE (Mercurial hg serve; Python LDkW)
66/tcp  open  telnet             Slirp PPP/SLIP-on-terminal emulator telnetd
70/tcp  open  smtp               qpsmtpd
71/tcp  open  smtp               Microsoft Exchange smtpd
73/tcp  open  http               Avaya IP Office VoIP PBX httpd
77/tcp  open  smtp               Zeus SMTPS smtpd
79/tcp  open  ftp                Sambar ftpd
80/tcp  open  tcpwrapped
81/tcp  open  imap-proxy         nginx imap proxy
82/tcp  open  ssh                (protocol 811)
83/tcp  open  http               peercast.org
88/tcp  open  csta               Alcatel OmniPCX Enterprise
90/tcp  open  http               WASD httpd
91/tcp  open  http               Fortinet FortiGate 50B firewall http config
93/tcp  open  imap               ModusMail imapd 4
98/tcp  open  ssh                Sysax Multi Server sshd 7 (protocol 940)
99/tcp  open  http               2Wire HomePortal http config 5473
100/tcp open  newacct?
```

### The Result
Combined, these techniques mean:
*   There is no fast way to distinguish real services from fake ones. Timing, behavior, and banner content all vary across the port range.
*   A full version scan (`nmap -sV -p-`) with default tarpit settings takes 10+ hours and generates hundreds of megabytes of bogus data.
*   The attacker's scanner burns time and threads on connections that lead nowhere.

---

### Design Approach

Real services (SSH, SMTP, FTP, HTTP) send a banner and keep the connection open, waiting for client input. Convincing emulation means doing the same: accept, send, hold. But a thread-per-client model burns memory and CPU on context switching, and at scale the defender runs out of resources before the attacker runs out of patience. The deception tool becomes a self-DOS vector.

**The approach:** a single-threaded `epoll` event loop. Each port is assigned a delivery mode at startup: some push a banner immediately, some wait for the client to send data before responding, and some stay silent. Hold times are spread across orders of magnitude (tens of milliseconds to minutes) with per-connection jitter, so repeated probes to the same port don't return identical timing.

This matters because without it, an attacker can send garbage to every port and measure response timing: real services close fast (wrong protocol), while a naive tarpit holds for seconds. With mixed modes and a wide timing spread, thousands of fake ports also close in the same range as real services. There's no clean threshold to filter on.

The economics work because of asymmetry:

- **Defender cost:** ~1–2 KB kernel memory per idle connection. The epoll loop is single-threaded, no context switching overhead. A modest box holds 10k+ concurrent connections without breaking a sweat.
- **Attacker cost:** time and effort. A port scan tells them nothing — every port is open. To find real services they need version detection across all 65535 ports, then protocol-level probing on anything that looks plausible. A 5-second scan becomes 10+ hours of active work, the result is still a haystack, and most attackers move on to an easier target.

Per-port delivery modes are fixed for the lifetime of the process but unpredictable across restarts. Hold times have a per-connection random component so repeated probes show natural variance, similar to real services under load.

**v2.0** replaces the original banner-and-close behavior that was vulnerable to a connection-closure bypass (see Vicarius/Hored1971 blog post). The tarpit engine holds all connections open with mixed timing, defeating connection-closure filtering, timing fingerprinting, banner analysis, and statistical pattern modeling.

---

## Installation

### Prerequisites
Ensure you have a C++ compiler and CMake (3.10+) installed.

### Build from Source
```bash
mkdir build && cd build
cmake -DCMAKE_INSTALL_SYSCONFDIR=/etc .. 
make
sudo make install
```

---

## Configuration

Portspoof runs in userland but relies on system firewall rules to intercept traffic destined for other ports.

### 1. Configure Firewall (iptables)
Redirect all incoming TCP traffic (ports 1-65535) to the Portspoof port (default 4444).

**Linux (iptables):**
```bash
# Exclude real services first, then redirect the rest to Portspoof
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j RETURN
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp -j REDIRECT --to-ports 4444
```
*Note: Replace `eth0` with your network interface. Add a RETURN rule for each port running a real service.*

To make this persistent, you can save your iptables rules or use the `iptables-config` provided in the `system_files` directory.

### 2. System Startup
You can add Portspoof to your startup scripts using the examples in `system_files/init.d/`.

---

## Usage

### Service Emulation Mode (Recommended)
This mode generates and feeds port scanners with bogus service signatures.
```bash
portspoof -c /etc/portspoof.conf -s /etc/portspoof_signatures -D
```

With custom tarpit timings (hold each connection between 10 and 60 seconds):
```bash
portspoof -s /etc/portspoof_signatures -t 10 -T 60 -D
```

### Open Port Mode
This mode simply returns an `OPEN` state for every connection attempt without sending service banners. Connections are still tarpitted.
```bash
portspoof -D
```

### Fuzzing Mode
Portspoof can be used to fuzz scanning tools by sending random or wordlist-based payloads.

**Fuzz with internal generator:**
```bash
# Generates random payloads of random size
portspoof -1 -v
```

**Fuzz with a wordlist:**
```bash
portspoof -f payloads.txt -v
```

---

## Hardening with iptables

The basic REDIRECT rule above works, but an aggressive scanner can still try to overwhelm Portspoof with connections. The following ruleset adds rate limiting and automatic banning for hosts that exceed the connection threshold. Ports hosting real services (SSH in this example) are excluded from the redirect but still protected by the global ban rule.

```bash
# --- NAT: redirect everything except real services ---
# add a RETURN rule for each port you actually use (SSH, HTTP, etc.)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j RETURN
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 4444

# --- FILTER: defense in depth ---

# allow loopback (critical: prevents breaking local services)
iptables -A INPUT -i lo -j ACCEPT

# if this IP was flagged as abusive, drop everything (silent, no RST)
iptables -A INPUT -m recent --name PORTSCAN --rcheck --seconds 60 -j DROP

# rate-limit new SYNs per source IP
iptables -A INPUT -p tcp --syn -m hashlimit \
  --hashlimit-above 10/sec --hashlimit-burst 30 \
  --hashlimit-mode srcip --hashlimit-name syn_throttle -j DROP

# if a single IP holds 100+ connections to portspoof, flag and drop
iptables -A INPUT -p tcp --syn --dport 4444 -m connlimit \
  --connlimit-above 100 --connlimit-mask 32 \
  -m recent --name PORTSCAN --set -j DROP

# allow established traffic and new connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --syn -j ACCEPT
iptables -A INPUT -j DROP
```

For high-traffic deployments, increase the `xt_recent` list size:

```bash
echo "options xt_recent ip_list_tot=10000" > /etc/modprobe.d/xt_recent.conf
```

And tune kernel connection tracking:
```bash
sysctl -w net.netfilter.nf_conntrack_max=131072
sysctl -w net.core.somaxconn=4096
```

---

## Portspoof Pro

[**Portspoof Pro**](https://portspoof.io) scales deception from a single host to an entire network. A single sensor emulates full /16 networks: thousands of IPs, each with unique services across all ports, holding stateful multi-step conversations.

*   **Network-wide deception.** Turn dark IP space and unused subnets into an active deception grid. Every emulated host presents unique services with a different personality per source IP. Active tarpitting exhausts attacker socket pools and throttles automated tools.
*   **Scan detection and tool fingerprinting.** Detects SYN, FIN, NULL, XMAS, ACK scan techniques. Fingerprints Nmap, Masscan, ZMap, and custom scanners. Structured JSON telemetry with MITRE ATT&CK mapping, streamed to your SIEM.
*   **Production-safe deployment.** Runs in a sandboxed environment alongside production traffic. Routing policies steer deception traffic to the sensor. No inline taps, no risk to real workloads.
*   **Compliance out of the box.** Supports NIS2, DORA, ISO 27001, NIST CSF, and CIS Controls.

[portspoof.io](https://portspoof.io)

---

## Authors & License

**Author:** Piotr Duszyński ([@drk1wi](https://twitter.com/drk1wi))

**License:** GNU General Public License v2.0 (GPLv2). See the `LICENSE` file for details.

For commercial, legitimate applications, please contact the author for the appropriate licensing arrangements.

---

## Reporting Issues

If you encounter any bugs or have feature requests, please report them on the [GitHub Issue Tracker](https://github.com/drk1wi/portspoof/issues) or contact the author via email at `piotr [at] duszynski.eu`.
