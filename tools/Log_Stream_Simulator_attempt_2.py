"""
Log Stream Simulator v2 — FortiGate / PaloAlto Native Format
=============================================================
Reads CIC-IDS-2017 / CIC-IDS-Collection parquet datasets and produces a
simulated real-time stream of **vendor-native** firewall logs that are
indistinguishable from real FortiGate or PaloAlto REST API output.

Designed for the SOCrates hackathon — logs are fed to an OpenAI-powered
SOC assistant that reasons over them exactly as it would over production
firewall telemetry.

Modes
-----
* **CLI streaming** (stdout / file / HTTP POST)
* **REST API server** (``--serve``) — the SOCrates backend polls this
  endpoint as if it were a real FortiGate / PaloAlto appliance.

Usage
-----
  # Stream FortiGate-format logs at 10× speed, 200 flows
  python Log_Stream_Simulator_attempt_2.py \\
      --parquet ../data/cic-collection.parquet \\
      --max-flows 200 --speed 10 --format fortigate

  # Start a REST API on port 5050 that the backend can poll
  python Log_Stream_Simulator_attempt_2.py \\
      --parquet ../data/DoS-Wednesday-no-metadata.parquet \\
      --serve --port 5050 --format fortigate --speed 0

  # PaloAlto CSV-style logs to a file
  python Log_Stream_Simulator_attempt_2.py \\
      --parquet ../data/Botnet-Friday-no-metadata.parquet \\
      --format paloalto --output /tmp/pa_logs.csv --speed 0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import textwrap
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import numpy as np
import pandas as pd

# ═══════════════════════════════════════════════════════════════════════════
# LABEL NORMALISATION (shared logic with v1)
# ═══════════════════════════════════════════════════════════════════════════

LABEL_NORMALISATION: dict[str, str] = {
    "BENIGN":                        "Benign",
    "Bot":                           "Botnet",
    "DoS GoldenEye":                 "DoS-Goldeneye",
    "DoS Hulk":                      "DoS-Hulk",
    "DoS Slowhttptest":              "DoS-Slowhttptest",
    "DoS slowloris":                 "DoS-Slowloris",
    "Heartbleed":                    "DoS-Heartbleed",
    "FTP-Patator":                   "Bruteforce-FTP",
    "SSH-Patator":                   "Bruteforce-SSH",
    "PortScan":                      "Portscan",
    "Web Attack \u2013 Brute Force": "Webattack-bruteforce",
    "Web Attack \u2013 Sql Injection": "Webattack-SQLi",
    "Web Attack \u2013 XSS":        "Webattack-XSS",
    "Web Attack \ufffd Brute Force": "Webattack-bruteforce",
    "Web Attack \ufffd Sql Injection": "Webattack-SQLi",
    "Web Attack \ufffd XSS":        "Webattack-XSS",
}

LABEL_TO_CLASS: dict[str, str] = {
    "Benign": "Benign", "Botnet": "Botnet",
    "Infiltration": "Infiltration", "Portscan": "Portscan",
}
_CLASS_PREFIXES = [
    ("DDoS", "DDoS"), ("DoS", "DoS"),
    ("Webattack", "Webattack"), ("Bruteforce", "Bruteforce"),
]


def _derive_class_label(label: str) -> str:
    if label in LABEL_TO_CLASS:
        return LABEL_TO_CLASS[label]
    for prefix, cls in _CLASS_PREFIXES:
        if label.startswith(prefix):
            return cls
    return label


def normalise_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["Label"] = df["Label"].map(lambda lbl: LABEL_NORMALISATION.get(lbl, lbl))
    if "ClassLabel" not in df.columns:
        df["ClassLabel"] = df["Label"].map(_derive_class_label)
    return df


# ═══════════════════════════════════════════════════════════════════════════
# SYNTHETIC NETWORK IDENTITY GENERATION
# ═══════════════════════════════════════════════════════════════════════════

_INTERNAL_SUBNETS = ["10.0.{}.{}", "192.168.{}.{}", "172.16.{}.{}"]
_EXTERNAL_SUBNETS = ["203.0.{}.{}", "198.51.{}.{}", "185.220.{}.{}"]


def _synth_ip(flow_id: int, salt: str, internal: bool) -> str:
    h = hashlib.md5(f"{flow_id}-{salt}".encode(), usedforsecurity=False).digest()
    if internal:
        tpl = _INTERNAL_SUBNETS[h[0] % len(_INTERNAL_SUBNETS)]
    else:
        tpl = _EXTERNAL_SUBNETS[h[0] % len(_EXTERNAL_SUBNETS)]
    return tpl.format(h[1] % 254 + 1, h[2] % 254 + 1)


def _synth_mac(flow_id: int, salt: str) -> str:
    h = hashlib.md5(f"{flow_id}-mac-{salt}".encode(), usedforsecurity=False).digest()
    # Use realistic OUI prefixes (VMware, Dell, HP, Cisco)
    ouis = ["00:50:56", "00:0C:29", "D4:BE:D9", "00:25:B5", "3C:22:FB"]
    oui = ouis[h[0] % len(ouis)]
    return f"{oui}:{h[1]:02X}:{h[2]:02X}:{h[3]:02X}"


def _synth_country(flow_id: int) -> tuple[str, str]:
    """Deterministic country assignment for external IPs."""
    h = hashlib.md5(f"{flow_id}-geo".encode(), usedforsecurity=False).digest()
    countries = [
        ("United States", "US"), ("Germany", "DE"), ("China", "CN"),
        ("Russia", "RU"), ("Netherlands", "NL"), ("United Kingdom", "GB"),
        ("France", "FR"), ("Japan", "JP"), ("Brazil", "BR"),
        ("South Korea", "KR"), ("India", "IN"), ("Romania", "RO"),
    ]
    return countries[h[0] % len(countries)]


# ═══════════════════════════════════════════════════════════════════════════
# FortiGate FIELD MAPPING
# ═══════════════════════════════════════════════════════════════════════════

# Attack label → FortiGate action
_FG_ACTION: dict[str, str] = {
    "Benign":             "close",
    "Botnet":             "deny",
    "Infiltration":       "deny",
    "Portscan":           "deny",
    "DoS-Hulk":           "server-rst",
    "DoS-Goldeneye":      "server-rst",
    "DoS-Slowloris":      "timeout",
    "DoS-Slowhttptest":   "timeout",
    "DoS-Heartbleed":     "deny",
    "DDoS":               "deny",
    "Webattack-bruteforce": "deny",
    "Webattack-XSS":      "deny",
    "Webattack-SQLi":     "deny",
    "Bruteforce-SSH":     "deny",
    "Bruteforce-FTP":     "deny",
}

# Destination port → FortiGate service name
_FG_SERVICE: dict[int, str] = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 3389: "RDP", 8080: "HTTP",
    21: "FTP", 25: "SMTP", 110: "POP3", 123: "NTP",
    3306: "MySQL", 5432: "PostgreSQL", 8443: "HTTPS",
}

# Label → FortiGate app/appcat/apprisk enrichment
_FG_APP_MAP: dict[str, tuple[str, str, str]] = {
    # (app, appcat, apprisk)
    "Benign":                ("SSL_TLS", "Network.Service", "low"),
    "Botnet":                ("IRC", "Collaboration", "critical"),
    "Infiltration":          ("SMB", "File.Sharing", "elevated"),
    "Portscan":              ("NMAP", "Network.Service", "elevated"),
    "DoS-Hulk":              ("HTTP.BROWSER", "Web.Client", "medium"),
    "DoS-Goldeneye":         ("HTTP.BROWSER", "Web.Client", "medium"),
    "DoS-Slowloris":         ("HTTP.BROWSER", "Web.Client", "medium"),
    "DoS-Slowhttptest":      ("HTTP.BROWSER", "Web.Client", "medium"),
    "DoS-Heartbleed":        ("OpenSSL", "Network.Service", "critical"),
    "DDoS":                  ("QUIC", "Network.Service", "elevated"),
    "Webattack-bruteforce":  ("HTTP.BROWSER", "Web.Client", "elevated"),
    "Webattack-XSS":         ("HTTP.BROWSER", "Web.Client", "critical"),
    "Webattack-SQLi":        ("HTTP.BROWSER", "Web.Client", "critical"),
    "Bruteforce-SSH":        ("SSH", "Remote.Access", "elevated"),
    "Bruteforce-FTP":        ("FTP", "File.Sharing", "elevated"),
}

# Label → FortiGate policy name
_FG_POLICY: dict[str, str] = {
    "Benign":                "Allow-Outbound-Web",
    "Botnet":                "Block-Known-C2",
    "Infiltration":          "Monitor-Internal-Lateral",
    "Portscan":              "Block-Scan-Activity",
    "DoS-Hulk":              "Rate-Limit-HTTP",
    "DoS-Goldeneye":         "Rate-Limit-HTTP",
    "DoS-Slowloris":         "Rate-Limit-Slow-HTTP",
    "DoS-Slowhttptest":      "Rate-Limit-Slow-HTTP",
    "DoS-Heartbleed":        "Block-TLS-Exploits",
    "DDoS":                  "DDoS-Mitigation",
    "Webattack-bruteforce":  "WAF-Brute-Force",
    "Webattack-XSS":         "WAF-XSS-Protection",
    "Webattack-SQLi":        "WAF-SQLi-Protection",
    "Bruteforce-SSH":        "Limit-SSH-Attempts",
    "Bruteforce-FTP":        "Limit-FTP-Attempts",
}

# Label → FortiGate threat level
_FG_LEVEL: dict[str, str] = {
    "Benign": "notice",
}

# Label → FortiGate UTM subtype/logid for attacks
_FG_UTM: dict[str, tuple[str, str]] = {
    # (subtype, logid)
    "Botnet":                ("botnet", "0211054601"),
    "Webattack-XSS":         ("webfilter", "0316013056"),
    "Webattack-SQLi":        ("webfilter", "0316013057"),
    "Webattack-bruteforce":  ("ips", "0419016384"),
    "DoS-Heartbleed":        ("ips", "0419016385"),
}

# Hardware vendor fingerprints (deterministic per src)
_HW_VENDORS = [
    ("VMware", "Server"),
    ("Dell", "Server"),
    ("Hewlett-Packard", "Computer"),
    ("Apple", "iPhone"),
    ("Microsoft", "Windows Phone"),
    ("Cisco", "Router/Switch"),
    ("Intel Corporate", "Computer"),
]

_FG_INTERFACES = [
    ("port1", "port2"),   # LAN → WAN
    ("port3", "port2"),   # DMZ → WAN
    ("port1", "port3"),   # LAN → DMZ
    ("ssl.root", "port2"),  # VPN → WAN
]


def _fg_logid(label: str) -> str:
    """Generate a FortiGate logid based on the label."""
    if label in _FG_UTM:
        return _FG_UTM[label][1]
    if label == "Benign":
        return "0000000013"  # traffic/forward
    return "0000000020"      # traffic/forward deny


def _fg_well_known_port(h_byte: int) -> int:
    ports = [22, 53, 80, 443, 445, 993, 3389, 8080, 21, 25, 8443, 123]
    return ports[h_byte % len(ports)]


def _fg_ephemeral_port(h_byte: int) -> int:
    return 49152 + h_byte * 127 % 16383


# ═══════════════════════════════════════════════════════════════════════════
# FortiGate LOG FORMATTER
# ═══════════════════════════════════════════════════════════════════════════

def format_fortigate(row: pd.Series, ts: datetime, flow_id: int) -> str:
    """
    Produce a single FortiGate traffic log line in native key=value format.
    Matches the exact format from real FortiGate REST API / syslog output.
    """
    label = row["Label"]
    h = hashlib.md5(f"{flow_id}".encode(), usedforsecurity=False).digest()

    # Network identity
    is_benign = label == "Benign"
    src_ip = _synth_ip(flow_id, "src", internal=True)
    dst_ip = _synth_ip(flow_id, "dst", internal=(not is_benign and h[3] % 3 == 0))
    src_port = _fg_ephemeral_port(h[4])
    dst_port = _fg_well_known_port(h[5])
    src_mac = _synth_mac(flow_id, "src")

    # FortiGate enrichment
    action = _FG_ACTION.get(label, "deny")
    service = _FG_SERVICE.get(dst_port, "tcp/{}".format(dst_port))
    app_info = _FG_APP_MAP.get(label, ("UNKNOWN", "Unknown", "medium"))
    policy = _FG_POLICY.get(label, "default-deny")
    level = _FG_LEVEL.get(label, "warning")
    logid = _fg_logid(label)

    # Protocol from dataset (6=TCP, 17=UDP) or inferred
    proto_num = int(row.get("Protocol", 6)) if "Protocol" in row.index else 6
    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, "TCP")

    # Interface pair (deterministic per flow)
    intf_src, intf_dst = _FG_INTERFACES[h[6] % len(_FG_INTERFACES)]

    # Hardware vendor
    hw = _HW_VENDORS[h[7] % len(_HW_VENDORS)]

    # Duration from flow features (µs → seconds)
    duration_sec = max(int(float(row["Flow Duration"]) / 1e6), 1)

    # Bytes and packets from CIC-IDS features
    sent_byte = max(int(float(row["Fwd Packets Length Total"])), 0)
    rcvd_byte = max(int(float(row["Bwd Packets Length Total"])), 0)
    sent_pkt = max(int(row["Total Fwd Packets"]), 0)
    rcvd_pkt = max(int(row["Total Backward Packets"]), 0)

    # Country for external destination
    country_name, country_code = _synth_country(flow_id)

    # Unique session ID
    session_id = (flow_id * 7919 + h[0]) % 10_000_000

    # Build the FortiGate key=value log line
    # Field order matches real FortiGate output
    fields = [
        f'date={ts.strftime("%Y-%m-%d")}',
        f'time={ts.strftime("%H:%M:%S")}',
        f'eventtime={int(ts.timestamp())}',
        f'tz="+0000"',
        f'logid="{logid}"',
        f'type="traffic"',
        f'subtype="forward"',
        f'level="{level}"',
        f'vd="root"',
        f'srcip={src_ip}',
        f'srcport={src_port}',
        f'srcintf="{intf_src}"',
        f'srcintfrole="lan"',
        f'dstip={dst_ip}',
        f'dstport={dst_port}',
        f'dstintf="{intf_dst}"',
        f'dstintfrole="wan"',
        f'srccountry="Reserved"',
        f'dstcountry="{country_name}"',
        f'sessionid={session_id}',
        f'proto={proto_num}',
        f'action="{action}"',
        f'policyid={h[8] % 20 + 1}',
        f'policyname="{policy}"',
        f'policytype="policy"',
        f'service="{service}"',
        f'trandisp="snat"',
        f'transip={_synth_ip(flow_id, "nat", internal=False)}',
        f'transport={_fg_ephemeral_port(h[9])}',
        f'duration={duration_sec}',
        f'sentbyte={sent_byte}',
        f'rcvdbyte={rcvd_byte}',
        f'sentpkt={sent_pkt}',
        f'rcvdpkt={rcvd_pkt}',
        f'app="{app_info[0]}"',
        f'appcat="{app_info[1]}"',
        f'apprisk="{app_info[2]}"',
        f'srchwvendor="{hw[0]}"',
        f'devtype="{hw[1]}"',
        f'mastersrcmac="{src_mac}"',
        f'srcmac="{src_mac}"',
        f'srcserver=0',
    ]

    # Add UTM fields for attack traffic
    if label != "Benign":
        utm_info = _FG_UTM.get(label)
        if utm_info:
            fields.append(f'utmaction="blocked"')
            fields.append(f'utmevent="{utm_info[0]}"')
        fields.append(f'threatweight={_threat_weight(label)}')
        fields.append(f'crscore={_threat_weight(label) * 5}')
        fields.append(f'craction={8323072 + h[10] % 1000}')
    else:
        fields.append(f'utmaction="allow"')

    return " ".join(fields)


def _threat_weight(label: str) -> int:
    low = label.lower()
    if "xss" in low or "sqli" in low or "heartbleed" in low:
        return 50
    if "dos" in low or "ddos" in low:
        return 40
    if "botnet" in low:
        return 40
    if "webattack" in low or "bruteforce" in low:
        return 30
    if "portscan" in low:
        return 20
    return 10


# ═══════════════════════════════════════════════════════════════════════════
# PaloAlto LOG FORMATTER
# ═══════════════════════════════════════════════════════════════════════════

# PaloAlto action mapping
_PA_ACTION: dict[str, str] = {
    "Benign": "allow",
    "Botnet": "deny",
    "Infiltration": "drop",
    "Portscan": "deny",
}

_PA_APP_MAP: dict[str, str] = {
    "Benign": "ssl", "Botnet": "irc", "Infiltration": "smb",
    "Portscan": "nmap", "DoS-Hulk": "web-browsing",
    "DoS-Goldeneye": "web-browsing", "DoS-Slowloris": "web-browsing",
    "DoS-Slowhttptest": "web-browsing", "DoS-Heartbleed": "ssl",
    "DDoS": "quic", "Webattack-bruteforce": "web-browsing",
    "Webattack-XSS": "web-browsing", "Webattack-SQLi": "web-browsing",
    "Bruteforce-SSH": "ssh", "Bruteforce-FTP": "ftp",
}

_PA_RULE: dict[str, str] = {
    "Benign": "Allow-Outbound",
    "Botnet": "Block-C2-Traffic",
    "Infiltration": "Block-Lateral-Movement",
    "Portscan": "Block-Reconnaissance",
}

_PA_ZONES = [
    ("trust", "untrust"),
    ("dmz", "untrust"),
    ("trust", "dmz"),
    ("vpn", "untrust"),
]

_PA_END_REASON: dict[str, str] = {
    "Benign": "tcp-fin",
    "Botnet": "policy-deny",
    "Infiltration": "policy-deny",
    "Portscan": "policy-deny",
}


def format_paloalto_csv(row: pd.Series, ts: datetime, flow_id: int) -> str:
    """
    Produce a PaloAlto Traffic log in CSV format (matches PA syslog output).
    """
    label = row["Label"]
    h = hashlib.md5(f"{flow_id}".encode(), usedforsecurity=False).digest()

    src_ip = _synth_ip(flow_id, "src", internal=True)
    dst_ip = _synth_ip(flow_id, "dst", internal=(label != "Benign" and h[3] % 3 == 0))
    src_port = _fg_ephemeral_port(h[4])
    dst_port = _fg_well_known_port(h[5])

    action = _PA_ACTION.get(label, "deny")
    app = _PA_APP_MAP.get(label, "unknown-tcp")
    rule = _PA_RULE.get(label, "Block-Threats")
    from_zone, to_zone = _PA_ZONES[h[6] % len(_PA_ZONES)]
    end_reason = _PA_END_REASON.get(label, "policy-deny")
    rule_uuid = str(uuid.UUID(bytes=hashlib.md5(
        f"{flow_id}-rule".encode(), usedforsecurity=False
    ).digest()))

    proto_num = int(row.get("Protocol", 6)) if "Protocol" in row.index else 6
    proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto_num, "tcp")

    duration_sec = max(int(float(row["Flow Duration"]) / 1e6), 1)
    sent_byte = max(int(float(row["Fwd Packets Length Total"])), 0)
    rcvd_byte = max(int(float(row["Bwd Packets Length Total"])), 0)
    sent_pkt = max(int(row["Total Fwd Packets"]), 0)
    rcvd_pkt = max(int(row["Total Backward Packets"]), 0)

    country_name, country_code = _synth_country(flow_id)
    session_id = (flow_id * 7919 + h[0]) % 10_000_000

    # PaloAlto CSV syslog format — field order matches real PA output
    fields = [
        ts.strftime("%Y/%m/%d %H:%M:%S"),   # receive_time
        "PA-5220",                            # serial
        "TRAFFIC",                            # type
        "end",                                # subtype
        "2025.0.1",                           # config_version
        ts.strftime("%Y/%m/%d %H:%M:%S"),    # generated_time
        src_ip,                               # src
        dst_ip,                               # dst
        "",                                   # natsrc
        "",                                   # natdst
        rule,                                 # rule
        "",                                   # srcuser
        "",                                   # dstuser
        app,                                  # app
        "vsys1",                              # vsys
        from_zone,                            # from
        to_zone,                              # to
        "ethernet1/1",                        # inbound_if
        "ethernet1/2",                        # outbound_if
        "Syslog-Traffic",                     # logset
        "",                                   # future_use_1
        str(session_id),                      # sessionid
        "0",                                  # repeatcnt
        str(src_port),                        # sport
        str(dst_port),                        # dport
        "",                                   # natsport
        "",                                   # natdport
        "0x400000",                           # flags
        proto_name,                           # proto
        action,                               # action
        str(sent_byte + rcvd_byte),           # bytes
        str(sent_byte),                       # bytes_sent
        str(rcvd_byte),                       # bytes_received
        str(sent_pkt + rcvd_pkt),             # packets
        ts.strftime("%Y/%m/%d %H:%M:%S"),    # start_time
        str(duration_sec),                    # elapsed
        "networking",                         # category
        "",                                   # future_use_2
        "0",                                  # seqno
        "0x8000000000000000",                 # actionflags
        "Reserved",                           # srcloc
        country_name,                         # dstloc
        "",                                   # future_use_3
        str(sent_pkt),                        # pkts_sent
        str(rcvd_pkt),                        # pkts_received
        end_reason,                           # session_end_reason
        "0",                                  # dg_hier_level_1
        rule_uuid,                            # rule_uuid
    ]

    return ",".join(fields)


PA_CSV_HEADER = (
    "receive_time,serial,type,subtype,config_version,generated_time,"
    "src,dst,natsrc,natdst,rule,srcuser,dstuser,app,vsys,from,to,"
    "inbound_if,outbound_if,logset,future_use_1,sessionid,repeatcnt,"
    "sport,dport,natsport,natdport,flags,proto,action,bytes,"
    "bytes_sent,bytes_received,packets,start_time,elapsed,category,"
    "future_use_2,seqno,actionflags,srcloc,dstloc,future_use_3,"
    "pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,"
    "rule_uuid"
)


# ═══════════════════════════════════════════════════════════════════════════
# TIMESTAMP SYNTHESIS
# ═══════════════════════════════════════════════════════════════════════════

def generate_flow_timestamp(
    base: datetime,
    flow_id: int,
    total_flows: int,
    speed: float,
) -> datetime:
    """
    Generate a timestamp for a flow.  Flows are spread over a time window
    proportional to the total number of flows (approx 1-3 flows/second).
    """
    avg_gap_sec = random.uniform(0.3, 1.5)
    offset = timedelta(seconds=flow_id * avg_gap_sec)
    return base + offset


# ═══════════════════════════════════════════════════════════════════════════
# CORE STREAMING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def stream_logs(
    df: pd.DataFrame,
    *,
    max_flows: int | None = None,
    speed: float = 1.0,
    start_time: datetime | None = None,
    sample_frac: float | None = None,
    shuffle: bool = True,
    fmt: str = "fortigate",
    seed: int | None = None,
) -> Generator[str, None, None]:
    """
    Yield log events (one per flow) in vendor-native format.

    Unlike v1 (which emitted per-packet events), v2 emits one log line
    per flow — matching real firewall session logs.
    """
    if seed is not None:
        random.seed(seed)
        np.random.seed(seed)

    if sample_frac is not None:
        df = df.sample(frac=sample_frac, random_state=seed or 42)

    if shuffle:
        df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    if max_flows is not None:
        df = df.head(max_flows)

    if start_time is None:
        start_time = datetime.now(tz=timezone.utc)

    formatter = format_fortigate if fmt == "fortigate" else format_paloalto_csv
    total = len(df)

    wall_anchor = time.monotonic()

    for flow_id, (_, row) in enumerate(df.iterrows()):
        ts = generate_flow_timestamp(start_time, flow_id, total, speed)
        line = formatter(row, ts, flow_id)

        # Real-time pacing
        if speed > 0:
            sim_elapsed = (ts - start_time).total_seconds()
            target_wall = wall_anchor + sim_elapsed / speed
            sleep_dur = target_wall - time.monotonic()
            if sleep_dur > 0:
                time.sleep(sleep_dur)

        yield line


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT SINKS
# ═══════════════════════════════════════════════════════════════════════════

def sink_stdout(line: str) -> None:
    print(line)


def sink_file(path: Path, fmt: str):
    fh = open(path, "a", encoding="utf-8")
    header_written = path.exists() and path.stat().st_size > 0
    if fmt == "paloalto" and not header_written:
        fh.write(PA_CSV_HEADER + "\n")

    def _write(line: str) -> None:
        fh.write(line + "\n")
        fh.flush()
    return _write


def sink_http(endpoint: str):
    import urllib.request
    import urllib.error

    def _post(line: str) -> None:
        data = json.dumps({"log": line}).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError as exc:
            print(f"[WARN] POST failed: {exc}", file=sys.stderr)
    return _post


# ═══════════════════════════════════════════════════════════════════════════
# REST API SERVER MODE
# ═══════════════════════════════════════════════════════════════════════════

def run_server(df: pd.DataFrame, host: str, port: int, fmt: str,
               speed: float, max_flows: int | None, seed: int | None) -> None:
    """
    Start a simple HTTP server that mimics a FortiGate / PaloAlto log
    retrieval API.  The SOCrates backend can poll GET /api/v2/log/traffic
    to receive batches of logs, just like a real FortiGate REST API.
    """
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import threading

    # Pre-generate a pool of logs that rotates
    log_buffer: list[str] = []
    buffer_lock = threading.Lock()
    gen_done = threading.Event()

    def _generate():
        for line in stream_logs(df, max_flows=max_flows, speed=speed,
                                fmt=fmt, seed=seed, shuffle=True):
            with buffer_lock:
                log_buffer.append(line)
        gen_done.set()

    gen_thread = threading.Thread(target=_generate, daemon=True)
    gen_thread.start()

    read_cursor = 0

    class LogHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal read_cursor
            if self.path.startswith("/api/v2/log"):
                # Mimic FortiGate REST API response
                batch_size = 50
                with buffer_lock:
                    batch = log_buffer[read_cursor:read_cursor + batch_size]
                    read_cursor = min(read_cursor + batch_size, len(log_buffer))
                    total = len(log_buffer)

                if fmt == "fortigate":
                    # FortiGate API returns JSON with results array
                    response = {
                        "http_method": "GET",
                        "results": batch,
                        "vdom": "root",
                        "total": total,
                        "returned": len(batch),
                        "last_cursor": read_cursor,
                    }
                    body = json.dumps(response).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                else:
                    # PaloAlto — return CSV lines
                    body = (PA_CSV_HEADER + "\n" + "\n".join(batch)).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv")

                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            elif self.path == "/health":
                body = json.dumps({
                    "status": "running",
                    "logs_generated": len(log_buffer),
                    "generation_complete": gen_done.is_set(),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # Suppress default access logging to stderr
            pass

    server = HTTPServer((host, port), LogHandler)
    print(f"[*] REST API server listening on http://{host}:{port}", file=sys.stderr)
    print(f"[*] Fetch logs:  GET http://{host}:{port}/api/v2/log/traffic", file=sys.stderr)
    print(f"[*] Health:      GET http://{host}:{port}/health", file=sys.stderr)
    print(f"[*] Format: {fmt}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] Server stopped. Generated {len(log_buffer):,} logs total.",
              file=sys.stderr)
        server.server_close()


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SOCrates Log Stream Simulator v2 — "
                    "FortiGate / PaloAlto native format logs from CIC-IDS data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # FortiGate logs to stdout, 100 flows, no delay
          %(prog)s --parquet ../data/cic-collection.parquet --max-flows 100 --speed 0

          # PaloAlto CSV logs to file
          %(prog)s --parquet ../data/DoS-Wednesday-no-metadata.parquet \\
                   --format paloalto --output /tmp/pa.csv --speed 0

          # REST API server mode (backend polls this)
          %(prog)s --parquet ../data/cic-collection.parquet \\
                   --serve --port 5050 --speed 0
        """),
    )
    p.add_argument("--parquet", required=True, type=Path,
                   help="Path to a CIC-IDS parquet file.")
    p.add_argument("--max-flows", type=int, default=None,
                   help="Limit number of flows (default: all).")
    p.add_argument("--speed", type=float, default=1.0,
                   help="Playback speed. 0=no delay, 1=real-time, 10=10× (default: 1.0).")
    p.add_argument("--sample-frac", type=float, default=None,
                   help="Randomly sample this fraction of rows first.")
    p.add_argument("--output", type=Path, default=None,
                   help="Write output to this file instead of stdout.")
    p.add_argument("--endpoint", type=str, default=None,
                   help="POST each log to this HTTP endpoint.")
    p.add_argument("--format", choices=["fortigate", "paloalto"],
                   default="fortigate", dest="log_format",
                   help="Output format (default: fortigate).")
    p.add_argument("--serve", action="store_true",
                   help="Start REST API server mode.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Server bind address (default: 127.0.0.1).")
    p.add_argument("--port", type=int, default=5050,
                   help="Server port (default: 5050).")
    p.add_argument("--no-shuffle", action="store_true",
                   help="Keep dataset order (no shuffle).")
    p.add_argument("--seed", type=int, default=None,
                   help="Random seed for reproducibility.")
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        np.random.seed(args.seed)

    print(f"[*] Loading dataset from {args.parquet} ...", file=sys.stderr)
    df = pd.read_parquet(args.parquet)
    df = normalise_dataframe(df)
    print(f"[*] Loaded {len(df):,} flows  ({df['Label'].nunique()} labels)",
          file=sys.stderr)
    print(f"[*] Labels: {sorted(df['Label'].unique())}", file=sys.stderr)
    print(f"[*] Format: {args.log_format}", file=sys.stderr)

    # --- Server mode ---
    if args.serve:
        run_server(df, args.host, args.port, args.log_format,
                   args.speed, args.max_flows, args.seed)
        return

    # --- Streaming mode ---
    sinks = []
    if args.output:
        sinks.append(sink_file(args.output, args.log_format))
        print(f"[*] Writing to {args.output}", file=sys.stderr)
        if args.log_format == "paloalto":
            # Write CSV header
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(PA_CSV_HEADER + "\n")
    if args.endpoint:
        sinks.append(sink_http(args.endpoint))
        print(f"[*] Posting to {args.endpoint}", file=sys.stderr)
    if not sinks:
        sinks.append(sink_stdout)

    speed_label = "no delay" if args.speed == 0 else f"{args.speed}\u00d7"
    print(f"[*] Streaming at {speed_label} speed ...\n", file=sys.stderr)

    count = 0
    try:
        for line in stream_logs(
            df,
            max_flows=args.max_flows,
            speed=args.speed,
            sample_frac=args.sample_frac,
            shuffle=not args.no_shuffle,
            fmt=args.log_format,
            seed=args.seed,
        ):
            for s in sinks:
                s(line)
            count += 1
    except KeyboardInterrupt:
        print(f"\n[*] Interrupted after {count:,} events.", file=sys.stderr)
    else:
        print(f"\n[*] Done — emitted {count:,} log lines.", file=sys.stderr)


if __name__ == "__main__":
    main()
