#!/usr/bin/env python3
"""
netmon.py - Live Network Monitor & Packet Analyzer

A defensive security tool that sniffs live traffic on a network interface,
maintains a rolling traffic dashboard, and raises alerts for suspicious
patterns such as port scans, ARP spoofing, and SYN floods.

Intended use: monitoring networks/interfaces you own or are authorized to
observe (home lab, personal servers, CTF ranges, employer-approved audits).

Requirements:
    pip install scapy

Usage:
    sudo python3 netmon.py -i eth0
    sudo python3 netmon.py -i wlan0 --dashboard-interval 5
    sudo python3 netmon.py -i eth0 --log alerts.log

Run with sudo/administrator privileges since raw packet capture requires it.
"""

import argparse
import sys
import time
import threading
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether
except ImportError:
    print("[!] scapy is required. Install it with: pip install scapy")
    sys.exit(1)


class NetworkMonitor:
    def __init__(self, iface, dashboard_interval=10, log_file=None,
                 portscan_threshold=15, portscan_window=10,
                 synflood_threshold=100, synflood_window=5):
        self.iface = iface
        self.dashboard_interval = dashboard_interval
        self.log_file = log_file

        # --- Traffic stats ---
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = defaultdict(int)
        self.top_talkers = defaultdict(int)   # src_ip -> byte count
        self.top_ports = defaultdict(int)     # dst_port -> hit count
        self.start_time = time.time()

        # --- Port scan detection ---
        # src_ip -> deque of (timestamp, dst_port)
        self.port_activity = defaultdict(lambda: deque())
        self.portscan_threshold = portscan_threshold
        self.portscan_window = portscan_window

        # --- SYN flood detection ---
        self.syn_activity = defaultdict(lambda: deque())
        self.synflood_threshold = synflood_threshold
        self.synflood_window = synflood_window

        # --- ARP spoofing detection ---
        self.arp_table = {}  # ip -> mac

        self.lock = threading.Lock()
        self.alerts = []

    # ---------- Alerting ----------

    def raise_alert(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[ALERT {timestamp}] {message}"
        print(f"\033[91m{line}\033[0m")  # red text
        self.alerts.append(line)
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(line + "\n")

    # ---------- Detection logic ----------

    def check_port_scan(self, src_ip, dst_port, now):
        dq = self.port_activity[src_ip]
        dq.append((now, dst_port))
        # drop entries outside the time window
        while dq and now - dq[0][0] > self.portscan_window:
            dq.popleft()
        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= self.portscan_threshold:
            self.raise_alert(
                f"Possible port scan from {src_ip}: "
                f"{len(distinct_ports)} distinct ports in {self.portscan_window}s"
            )
            dq.clear()  # avoid repeat-spamming the same alert

    def check_syn_flood(self, src_ip, now):
        dq = self.syn_activity[src_ip]
        dq.append(now)
        while dq and now - dq[0] > self.synflood_window:
            dq.popleft()
        if len(dq) >= self.synflood_threshold:
            self.raise_alert(
                f"Possible SYN flood from {src_ip}: "
                f"{len(dq)} SYN packets in {self.synflood_window}s"
            )
            dq.clear()

    def check_arp_spoof(self, ip, mac):
        known_mac = self.arp_table.get(ip)
        if known_mac and known_mac != mac:
            self.raise_alert(
                f"Possible ARP spoofing: {ip} changed MAC from "
                f"{known_mac} to {mac}"
            )
        self.arp_table[ip] = mac

    # ---------- Packet handling ----------

    def handle_packet(self, pkt):
        now = time.time()
        with self.lock:
            self.total_packets += 1
            pkt_len = len(pkt)
            self.total_bytes += pkt_len

            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                # op 2 = "is-at" (ARP reply) -- most relevant for spoofing
                if arp.op == 2:
                    self.check_arp_spoof(arp.psrc, arp.hwsrc)
                self.protocol_counts["ARP"] += 1
                return

            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                self.top_talkers[src_ip] += pkt_len

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    self.protocol_counts["TCP"] += 1
                    self.top_ports[tcp.dport] += 1
                    self.check_port_scan(src_ip, tcp.dport, now)
                    # SYN flag set, ACK not set => SYN packet
                    if tcp.flags & 0x02 and not tcp.flags & 0x10:
                        self.check_syn_flood(src_ip, now)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    self.protocol_counts["UDP"] += 1
                    self.top_ports[udp.dport] += 1
                    self.check_port_scan(src_ip, udp.dport, now)
                elif pkt.haslayer(ICMP):
                    self.protocol_counts["ICMP"] += 1
                else:
                    self.protocol_counts["OTHER_IP"] += 1
            elif pkt.haslayer(Ether):
                self.protocol_counts["NON_IP"] += 1

    # ---------- Dashboard ----------

    def print_dashboard(self):
        with self.lock:
            elapsed = max(time.time() - self.start_time, 1)
            print("\n" + "=" * 60)
            print(f" NETWORK MONITOR - {self.iface}  "
                  f"(uptime: {int(elapsed)}s)")
            print("=" * 60)
            print(f" Total packets : {self.total_packets}")
            print(f" Total bytes   : {self.total_bytes:,}")
            print(f" Avg pkt/sec   : {self.total_packets/elapsed:.2f}")
            print("-" * 60)
            print(" Protocol breakdown:")
            for proto, count in sorted(self.protocol_counts.items(),
                                        key=lambda x: -x[1]):
                print(f"   {proto:<10} {count}")
            print("-" * 60)
            print(" Top talkers (by bytes):")
            for ip, b in sorted(self.top_talkers.items(),
                                 key=lambda x: -x[1])[:5]:
                print(f"   {ip:<18} {b:,} bytes")
            print("-" * 60)
            print(" Top destination ports:")
            for port, hits in sorted(self.top_ports.items(),
                                      key=lambda x: -x[1])[:5]:
                print(f"   port {port:<8} {hits} hits")
            print("-" * 60)
            print(f" Alerts raised : {len(self.alerts)}")
            print("=" * 60)

    def dashboard_loop(self, stop_event):
        while not stop_event.is_set():
            stop_event.wait(self.dashboard_interval)
            if not stop_event.is_set():
                self.print_dashboard()

    # ---------- Run ----------

    def run(self):
        stop_event = threading.Event()
        dash_thread = threading.Thread(
            target=self.dashboard_loop, args=(stop_event,), daemon=True
        )
        dash_thread.start()

        print(f"[*] Starting capture on interface: {self.iface}")
        print("[*] Press Ctrl+C to stop.\n")
        try:
            sniff(iface=self.iface, prn=self.handle_packet, store=False)
        except KeyboardInterrupt:
            pass
        except OSError as e:
            print(f"[!] Failed to open interface '{self.iface}': {e}")
            print("[!] Check the interface name and that you have permission "
                  "(try running with sudo).")
        finally:
            stop_event.set()
            self.print_dashboard()
            print("\n[*] Capture stopped.")
            if self.alerts:
                print(f"[*] {len(self.alerts)} alert(s) raised this session.")
                if self.log_file:
                    print(f"[*] Alerts written to: {self.log_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Live network monitor & packet analyzer with security alerts."
    )
    parser.add_argument("-i", "--iface", required=True,
                         help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("--dashboard-interval", type=int, default=10,
                         help="Seconds between dashboard refreshes (default: 10)")
    parser.add_argument("--log", type=str, default=None,
                         help="File to append alerts to (default: none)")
    parser.add_argument("--portscan-threshold", type=int, default=15,
                         help="Distinct ports from one IP to trigger a scan alert")
    parser.add_argument("--portscan-window", type=int, default=10,
                         help="Time window (s) for port scan detection")
    parser.add_argument("--synflood-threshold", type=int, default=100,
                         help="SYN packets from one IP to trigger a flood alert")
    parser.add_argument("--synflood-window", type=int, default=5,
                         help="Time window (s) for SYN flood detection")
    args = parser.parse_args()

    monitor = NetworkMonitor(
        iface=args.iface,
        dashboard_interval=args.dashboard_interval,
        log_file=args.log,
        portscan_threshold=args.portscan_threshold,
        portscan_window=args.portscan_window,
        synflood_threshold=args.synflood_threshold,
        synflood_window=args.synflood_window,
    )
    monitor.run()


if __name__ == "__main__":
    main()
