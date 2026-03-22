#!/usr/bin/env python3
"""
FortiGate Demo Syslog Injector
================================
Sends realistic FortiGate-formatted syslog messages to your SOC parser
for demo purposes. Simulates:
  - Port scan / intrusion attempts
  - Firewall ALLOW / DENY traffic events

Usage:
    python fortigate_demo_injector.py
    python fortigate_demo_injector.py --host 127.0.0.1 --port 514 --scenario all
    python fortigate_demo_injector.py --scenario portscan --count 20 --delay 0.3
"""

import socket
import time
import random
import argparse
import datetime
from typing import List

# ─────────────────────────────────────────────
#  CONFIG  (edit these if needed)
# ─────────────────────────────────────────────
DEFAULT_HOST  = "127.0.0.1"   # your SOC parser listener IP
DEFAULT_PORT  = 514            # syslog UDP port
DEVICE_NAME   = "FortiGate-VM64"
DEVICE_ID     = "FGVMSLTM26010201"
VDOM          = "root"

# ─────────────────────────────────────────────
#  REALISTIC DATA POOLS
# ─────────────────────────────────────────────
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.50", "192.168.1.100", "192.168.1.105",
    "192.168.1.200", "10.0.0.5", "10.0.0.12",
]

ATTACKER_IPS = [
    "45.33.32.156",   # Scanme.nmap.org range
    "185.220.101.47", # Known Tor exit node
    "194.165.16.73",  # Known scanner
    "77.91.124.55",
    "103.149.87.100",
    "91.92.251.103",
    "179.43.176.2",
    "198.235.24.101",
]

LEGIT_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "142.250.185.78",  # Google
    "52.86.45.60", "34.120.195.249",           # AWS/GCP
    "104.21.44.155",                           # Cloudflare hosted
]

COUNTRIES = {
    "45.33.32.156":     "United States",
    "185.220.101.47":   "Germany",
    "194.165.16.73":    "Netherlands",
    "77.91.124.55":     "Russia",
    "103.149.87.100":   "China",
    "91.92.251.103":    "Bulgaria",
    "179.43.176.2":     "Switzerland",
    "198.235.24.101":   "United States",
    "8.8.8.8":          "United States",
    "1.1.1.1":          "Australia",
}

SERVICES_TCP = {
    22:   "SSH",    23:  "Telnet",  25:   "SMTP",
    53:   "DNS",    80:  "HTTP",    443:  "HTTPS",
    445:  "SMB",    3389:"RDP",     8080: "HTTP.BROWSER",
    8443: "HTTPS",  21:  "FTP",     110:  "POP3",
    3306: "MYSQL",  5432:"PGSQL",   6379: "tcp/6379",
    27017:"MONGODB",1433:"MSSQL",   5900: "VNC",
}

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def now_fields():
    now = datetime.datetime.now()
    ts  = int(now.timestamp() * 1e9)
    return now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S"), ts

def send_syslog(host: str, port: int, message: str):
    """Send a single UDP syslog message."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(message.encode("utf-8"), (host, port))

def build_header(priority=189) -> str:
    return f"<{priority}>"

def country_for(ip: str) -> str:
    return COUNTRIES.get(ip, "Reserved")

def rand_session() -> int:
    return random.randint(1000, 65000)

def rand_policy() -> int:
    return random.randint(1, 10)

# ─────────────────────────────────────────────
#  SCENARIO 1 — PORT SCAN / INTRUSION
# ─────────────────────────────────────────────
def make_portscan_log(attacker_ip: str, victim_ip: str, dst_port: int, action: str = "deny") -> str:
    date, ttime, ts = now_fields()
    service = SERVICES_TCP.get(dst_port, f"tcp/{dst_port}")
    src_port = random.randint(40000, 65000)
    src_country = country_for(attacker_ip)
    pkt_sent = random.randint(1, 3)

    # IPS inline block log (logid 0419016384)
    msg = (
        f'{build_header(170)}date={date} time={ttime} devname="{DEVICE_NAME}" '
        f'devid="{DEVICE_ID}" eventtime={ts} tz="+0200" logid="0419016384" '
        f'type="utm" subtype="ips" level="alert" vd="{VDOM}" '
        f'severity="high" srcip={attacker_ip} srcport={src_port} '
        f'srcintf="port1" srcintfrole="wan" '
        f'dstip={victim_ip} dstport={dst_port} dstintf="port2" dstintfrole="lan" '
        f'srccountry="{src_country}" dstcountry="Reserved" '
        f'sessionid={rand_session()} action="{action}" proto=6 '
        f'policyid={rand_policy()} service="{service}" '
        f'attack="Network.Scan.Generic" attackid=53793 '
        f'profile="default" ref="http://www.fortiguard.com/encyclopedia/ips/53793" '
        f'incidentserialno={random.randint(100000000,999999999)} '
        f'msg="Network.Scan.Generic: {attacker_ip}:{src_port} -> {victim_ip}:{dst_port}"'
    )
    return msg


def make_portscan_traffic_log(attacker_ip: str, victim_ip: str, dst_port: int) -> str:
    """Accompanying traffic log for the scan."""
    date, ttime, ts = now_fields()
    service = SERVICES_TCP.get(dst_port, f"tcp/{dst_port}")
    src_port = random.randint(40000, 65000)
    src_country = country_for(attacker_ip)

    msg = (
        f'{build_header(189)}date={date} time={ttime} devname="{DEVICE_NAME}" '
        f'devid="{DEVICE_ID}" eventtime={ts} tz="+0200" logid="0001000014" '
        f'type="traffic" subtype="forward" level="notice" vd="{VDOM}" '
        f'srcip={attacker_ip} srcport={src_port} srcintf="port1" srcintfrole="wan" '
        f'dstip={victim_ip} dstport={dst_port} dstintf="port2" dstintfrole="lan" '
        f'srccountry="{src_country}" dstcountry="Reserved" '
        f'sessionid={rand_session()} proto=6 action="deny" '
        f'policyid=0 service="{service}" trandisp="noop" app="{service}" '
        f'duration=0 sentbyte=60 rcvdbyte=0 sentpkt=1 rcvdpkt=0 '
        f'policytype="policy" poluuid="auto"'
    )
    return msg


# ─────────────────────────────────────────────
#  SCENARIO 2 — FIREWALL ALLOW / DENY
# ─────────────────────────────────────────────
def make_fw_allow_log(src_ip: str, dst_ip: str, dst_port: int) -> str:
    date, ttime, ts = now_fields()
    service = SERVICES_TCP.get(dst_port, f"tcp/{dst_port}")
    src_port = random.randint(1024, 60000)
    duration = random.randint(5, 3600)
    sent = random.randint(500, 500000)
    rcvd = random.randint(500, 2000000)
    src_country = country_for(src_ip) if src_ip in COUNTRIES else "Reserved"
    dst_country = country_for(dst_ip) if dst_ip in COUNTRIES else "United States"

    msg = (
        f'{build_header(189)}date={date} time={ttime} devname="{DEVICE_NAME}" '
        f'devid="{DEVICE_ID}" eventtime={ts} tz="+0200" logid="0000000013" '
        f'type="traffic" subtype="forward" level="notice" vd="{VDOM}" '
        f'srcip={src_ip} srcport={src_port} srcintf="port2" srcintfrole="lan" '
        f'dstip={dst_ip} dstport={dst_port} dstintf="port1" dstintfrole="wan" '
        f'srccountry="{src_country}" dstcountry="{dst_country}" '
        f'sessionid={rand_session()} proto=6 action="accept" '
        f'policyid={rand_policy()} policytype="policy" service="{service}" '
        f'trandisp="snat" transip={random.choice(INTERNAL_IPS)} transport={src_port} '
        f'app="{service}" duration={duration} '
        f'sentbyte={sent} rcvdbyte={rcvd} '
        f'sentpkt={sent//60} rcvdpkt={rcvd//60} '
        f'appcat="Network.Service" applist="default"'
    )
    return msg


def make_fw_deny_log(src_ip: str, dst_ip: str, dst_port: int, reason: str = "policy-violation") -> str:
    date, ttime, ts = now_fields()
    service = SERVICES_TCP.get(dst_port, f"tcp/{dst_port}")
    src_port = random.randint(1024, 60000)
    src_country = country_for(src_ip) if src_ip in COUNTRIES else "Reserved"
    dst_country = country_for(dst_ip) if dst_ip in COUNTRIES else "United States"

    msg = (
        f'{build_header(189)}date={date} time={ttime} devname="{DEVICE_NAME}" '
        f'devid="{DEVICE_ID}" eventtime={ts} tz="+0200" logid="0001000014" '
        f'type="traffic" subtype="forward" level="warning" vd="{VDOM}" '
        f'srcip={src_ip} srcport={src_port} srcintf="port2" srcintfrole="lan" '
        f'dstip={dst_ip} dstport={dst_port} dstintf="port1" dstintfrole="wan" '
        f'srccountry="{src_country}" dstcountry="{dst_country}" '
        f'sessionid={rand_session()} proto=6 action="deny" '
        f'policyid=0 service="{service}" trandisp="noop" '
        f'duration=0 sentbyte=60 rcvdbyte=0 sentpkt=1 rcvdpkt=0 '
        f'policytype="policy" poluuid="auto" '
        f'msg="Traffic denied: {reason}"'
    )
    return msg


# ─────────────────────────────────────────────
#  SCENARIO RUNNERS
# ─────────────────────────────────────────────
def run_portscan(host, port, count, delay):
    print(f"\n🔍 [PORT SCAN] Simulating scan from {count} probe(s)...")
    attacker = random.choice(ATTACKER_IPS)
    victim   = random.choice(INTERNAL_IPS)
    ports    = random.sample(list(SERVICES_TCP.keys()), min(count, len(SERVICES_TCP)))
    if len(ports) < count:
        ports += [random.randint(1, 65535) for _ in range(count - len(ports))]

    print(f"   Attacker: {attacker}  →  Victim: {victim}")
    for p in ports[:count]:
        svc = SERVICES_TCP.get(p, f"tcp/{p}")
        # Send IPS alert + traffic log pair
        ips_log     = make_portscan_log(attacker, victim, p)
        traffic_log = make_portscan_traffic_log(attacker, victim, p)
        send_syslog(host, port, ips_log)
        time.sleep(0.05)
        send_syslog(host, port, traffic_log)
        print(f"   → Probed port {p:5d} ({svc})")
        time.sleep(delay)
    print(f"   ✅ Sent {count} port scan event pairs.\n")


def run_firewall(host, port, count, delay):
    print(f"\n🛡️  [FIREWALL] Simulating {count} allow/deny events...")
    allow_count = 0
    deny_count  = 0

    for i in range(count):
        action = random.choices(["allow", "deny"], weights=[0.6, 0.4])[0]
        dst_port = random.choice(list(SERVICES_TCP.keys()))

        if action == "allow":
            src = random.choice(INTERNAL_IPS)
            dst = random.choice(LEGIT_EXTERNAL_IPS)
            log = make_fw_allow_log(src, dst, dst_port)
            allow_count += 1
            label = "ALLOW"
        else:
            # Mix: external attacker trying to reach internal OR internal hitting blocked port
            if random.random() > 0.5:
                src = random.choice(ATTACKER_IPS)
                dst = random.choice(INTERNAL_IPS)
                reason = "implicit-deny"
            else:
                src = random.choice(INTERNAL_IPS)
                dst = random.choice(LEGIT_EXTERNAL_IPS)
                reason = "policy-violation"
            log = make_fw_deny_log(src, dst, dst_port, reason)
            deny_count += 1
            label = "DENY "

        svc = SERVICES_TCP.get(dst_port, f"tcp/{dst_port}")
        send_syslog(host, port, log)
        print(f"   [{label}] {src:18s} → {dst:18s}  port {dst_port} ({svc})")
        time.sleep(delay)

    print(f"\n   ✅ Sent {allow_count} ALLOW + {deny_count} DENY events.\n")


def run_mixed_stream(host, port, count, delay):
    """Interleaved realistic traffic stream."""
    print(f"\n🌊 [MIXED STREAM] Running combined scenario ({count} total events)...")
    attacker = random.choice(ATTACKER_IPS)
    victim   = random.choice(INTERNAL_IPS)
    scan_ports = [22, 23, 80, 443, 3389, 8080, 445, 21]

    events = []
    # Seed with a port scan burst
    for p in scan_ports:
        events.append(("scan", attacker, victim, p))
    # Fill rest with firewall events
    for _ in range(count - len(scan_ports)):
        action = random.choices(["allow", "deny"], weights=[0.6, 0.4])[0]
        p = random.choice(list(SERVICES_TCP.keys()))
        if action == "allow":
            events.append(("allow", random.choice(INTERNAL_IPS), random.choice(LEGIT_EXTERNAL_IPS), p))
        else:
            events.append(("deny", random.choice(ATTACKER_IPS), random.choice(INTERNAL_IPS), p))
    random.shuffle(events)

    for ev in events[:count]:
        kind = ev[0]
        src, dst, p = ev[1], ev[2], ev[3]
        svc = SERVICES_TCP.get(p, f"tcp/{p}")

        if kind == "scan":
            send_syslog(host, port, make_portscan_log(src, dst, p))
            time.sleep(0.02)
            send_syslog(host, port, make_portscan_traffic_log(src, dst, p))
            print(f"   [SCAN ] {src:18s} → {dst:18s}  port {p} ({svc})")
        elif kind == "allow":
            send_syslog(host, port, make_fw_allow_log(src, dst, p))
            print(f"   [ALLOW] {src:18s} → {dst:18s}  port {p} ({svc})")
        else:
            send_syslog(host, port, make_fw_deny_log(src, dst, p))
            print(f"   [DENY ] {src:18s} → {dst:18s}  port {p} ({svc})")

        time.sleep(delay)

    print(f"\n   ✅ Mixed stream complete.\n")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="FortiGate Demo Syslog Injector")
    parser.add_argument("--host",     default=DEFAULT_HOST,  help="Syslog listener IP (default: 127.0.0.1)")
    parser.add_argument("--port",     default=DEFAULT_PORT,  type=int, help="Syslog UDP port (default: 514)")
    parser.add_argument("--scenario", default="all",
                        choices=["portscan", "firewall", "mixed", "all"],
                        help="Which scenario to run (default: all)")
    parser.add_argument("--count",    default=15, type=int,  help="Number of events per scenario (default: 15)")
    parser.add_argument("--delay",    default=0.5, type=float, help="Delay between events in seconds (default: 0.5)")
    args = parser.parse_args()

    print("=" * 60)
    print("  FortiGate Demo Syslog Injector")
    print(f"  Target  : {args.host}:{args.port} (UDP)")
    print(f"  Scenario: {args.scenario}")
    print(f"  Count   : {args.count} events")
    print(f"  Delay   : {args.delay}s between events")
    print("=" * 60)

    if args.scenario in ("portscan", "all"):
        run_portscan(args.host, args.port, args.count, args.delay)

    if args.scenario in ("firewall", "all"):
        run_firewall(args.host, args.port, args.count, args.delay)

    if args.scenario in ("mixed", "all"):
        run_mixed_stream(args.host, args.port, args.count, args.delay)

    print("🎯 All done! Check your SOC parser for the incoming events.")


if __name__ == "__main__":
    main()
