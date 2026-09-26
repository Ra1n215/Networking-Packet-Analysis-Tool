# netmon — Live Network Monitor & Packet Analyzer

A lightweight, dependency-minimal network monitoring tool built with
[Scapy](https://scapy.net/). It sniffs live traffic on a network interface,
displays a rolling traffic dashboard, and raises real-time alerts for
suspicious activity such as port scans, SYN floods, and ARP spoofing.

## Features

- **Live packet capture** on any network interface
- **Traffic dashboard** refreshed on a configurable interval:
  - Total packets / bytes captured
  - Average packets per second
  - Protocol breakdown (TCP / UDP / ICMP / ARP / other)
  - Top talkers by bytes sent
  - Top destination ports
- **Security alerts**:
  - **Port scan detection** — flags a source IP hitting many distinct ports within a short time window
  - **SYN flood detection** — flags a burst of SYN packets from one source
  - **ARP spoofing detection** — flags an IP address whose MAC address suddenly changes
- **Session export**:
  - Save captured traffic to a `.pcap` file for later analysis in Wireshark
  - Save a JSON summary of the session's stats and alerts
- **Alert logging** to a plain-text file

## Requirements

- Python 3.8+
- [Scapy](https://scapy.net/)
- Root/administrator privileges (raw packet capture requires elevated permissions)

Install dependencies:

```bash
pip install scapy
```

## Usage

Basic live capture:

```bash
sudo python3 netmon.py -i eth0
```

Custom dashboard refresh rate:

```bash
sudo python3 netmon.py -i wlan0 --dashboard-interval 5
```

Log alerts to a file:

```bash
sudo python3 netmon.py -i eth0 --log alerts.log
```

Save the raw capture and a JSON summary when you stop the session (Ctrl+C):

```bash
sudo python3 netmon.py -i eth0 --pcap-out capture.pcap --json-out summary.json
```

Tune detection sensitivity:

```bash
sudo python3 netmon.py -i eth0 \
  --portscan-threshold 20 --portscan-window 15 \
  --synflood-threshold 200 --synflood-window 5
```

### Finding your interface name

- Linux/macOS: `ip a` or `ifconfig`
- Windows: `ipconfig` (Scapy usually expects something like `Ethernet` or an interface index — see [Scapy's Windows notes](https://scapy.readthedocs.io/en/latest/installation.html#windows))

## CLI Options

| Flag | Default | Description |
|---|---|---|
| `-i`, `--iface` | *required* | Network interface to sniff on |
| `--dashboard-interval` | `10` | Seconds between dashboard refreshes |
| `--log` | none | File to append alerts to |
| `--portscan-threshold` | `15` | Distinct ports from one IP to trigger a scan alert |
| `--portscan-window` | `10` | Time window (seconds) for port scan detection |
| `--synflood-threshold` | `100` | SYN packets from one IP to trigger a flood alert |
| `--synflood-window` | `5` | Time window (seconds) for SYN flood detection |
| `--pcap-out` | none | Save captured packets to this `.pcap` file on exit |
| `--json-out` | none | Save a JSON session summary to this file on exit |

## How the detection works

- **Port scans**: for each source IP, the tool keeps a rolling window of
  `(timestamp, destination_port)` pairs. If the number of *distinct* ports
  contacted within `--portscan-window` seconds reaches `--portscan-threshold`,
  it raises an alert.
- **SYN floods**: similarly tracks TCP packets with the SYN flag set (and ACK
  unset) per source IP. A burst above `--synflood-threshold` within
  `--synflood-window` seconds triggers an alert.
- **ARP spoofing**: maintains an IP → MAC address table built from ARP
  replies. If an IP suddenly maps to a different MAC address, it raises an
  alert — a classic sign of ARP cache poisoning.

These are heuristic, threshold-based checks intended for learning and
lightweight monitoring — not a replacement for a production IDS/IPS like
Snort, Suricata, or Zeek.

## Example output

```
============================================================
 NETWORK MONITOR - eth0  (uptime: 30s)
============================================================
 Total packets : 1423
 Total bytes   : 812,204
 Avg pkt/sec   : 47.43
------------------------------------------------------------
 Protocol breakdown:
   TCP        980
   UDP        401
   ARP        30
   ICMP       12
------------------------------------------------------------
 Top talkers (by bytes):
   192.168.1.14       412,003 bytes
   192.168.1.1        190,221 bytes
------------------------------------------------------------
 Top destination ports:
   port 443        612 hits
   port 80         210 hits
------------------------------------------------------------
 Alerts raised : 0
============================================================
```

## ⚠️ Legal & Ethical Use

This tool captures and analyzes live network traffic. Only run it on
networks and interfaces you **own** or are **explicitly authorized** to
monitor (e.g., your own home network, a personal lab, or an environment
where you have written permission). Capturing traffic on networks you don't
own or control may violate wiretapping, computer misuse, or privacy laws
depending on your jurisdiction.

This project is intended for:
- Personal network visibility and learning
- Home lab / CTF environments
- Authorized security assessments

It is **not** intended for unauthorized surveillance of others' traffic.

## Roadmap / Ideas for contributions

- [ ] Web-based dashboard (Flask/FastAPI + WebSocket)
- [ ] Configurable alert destinations (Slack/Discord webhook, email)
- [ ] Basic signature matching for known malicious payloads
- [ ] IPv6 support
- [ ] Unit tests with pre-recorded pcap fixtures

## License

MIT — feel free to fork, modify, and use for learning or your own projects.
