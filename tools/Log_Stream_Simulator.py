"""
Log Stream Simulator for SOCrates
==================================
Reads CIC-IDS-2017 / CIC-IDS-Collection parquet datasets and produces a
simulated real-time stream of security logs, each tagged with a source
device (Firewall, IDS/IPS, EDR, NMAP-Scanner).

Usage examples at ./README.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Simulated device registry
# ---------------------------------------------------------------------------

DEVICES = {
    "firewall": {
        "device_name": "PaloAlto-FW-01",
        "device_ip": "10.0.1.1",
        "log_format": "firewall_connection_log",
        "vendor": "Palo Alto Networks",
    },
    "ids": {
        "device_name": "Suricata-IDS-01",
        "device_ip": "10.0.2.1",
        "log_format": "ids_alert",
        "vendor": "Suricata",
    },
    "edr": {
        "device_name": "CrowdStrike-EDR-01",
        "device_ip": "10.0.3.1",
        "log_format": "edr_telemetry",
        "vendor": "CrowdStrike",
    },
    "nmap": {
        "device_name": "Nmap-Scanner-01",
        "device_ip": "10.0.4.1",
        "log_format": "nmap_scan_result",
        "vendor": "Nmap",
    },
}

# ---------------------------------------------------------------------------
# CIC-IDS-2017 → normalised label mapping
# The original 2017 dataset uses different label strings than the
# CIC-IDS-Collection.  We normalise everything to a canonical form so
# the device-assignment heuristics work with either dataset.
# ---------------------------------------------------------------------------

LABEL_NORMALISATION: dict[str, str] = {
    # CIC-IDS-2017 originals → canonical
    "BENIGN":                       "Benign",
    "Bot":                          "Botnet",
    "DoS GoldenEye":                "DoS-Goldeneye",
    "DoS Hulk":                     "DoS-Hulk",
    "DoS Slowhttptest":             "DoS-Slowhttptest",
    "DoS slowloris":                "DoS-Slowloris",
    "Heartbleed":                   "DoS-Heartbleed",
    "FTP-Patator":                  "Bruteforce-FTP",
    "SSH-Patator":                  "Bruteforce-SSH",
    "PortScan":                     "Portscan",
    "Web Attack \u2013 Brute Force": "Webattack-bruteforce",
    "Web Attack \u2013 Sql Injection": "Webattack-SQLi",
    "Web Attack \u2013 XSS":        "Webattack-XSS",
    # Handle the mojibake variant (CP-1252 rendered as UTF-8)
    "Web Attack \ufffd Brute Force": "Webattack-bruteforce",
    "Web Attack \ufffd Sql Injection": "Webattack-SQLi",
    "Web Attack \ufffd XSS":        "Webattack-XSS",
}

# Canonical label → class label (used when ClassLabel column is absent)
LABEL_TO_CLASS: dict[str, str] = {
    "Benign": "Benign",
    "Botnet": "Botnet",
    "Infiltration": "Infiltration",
    "Portscan": "Portscan",
}
# Everything starting with these prefixes maps to the prefix class
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
    """Normalise labels and ensure ClassLabel column exists."""
    df = df.copy()
    df["Label"] = df["Label"].map(lambda lbl: LABEL_NORMALISATION.get(lbl, lbl))
    if "ClassLabel" not in df.columns:
        df["ClassLabel"] = df["Label"].map(_derive_class_label)
    return df


# ---------------------------------------------------------------------------
# Synthetic IP generation
# ---------------------------------------------------------------------------
# CIC-IDS datasets strip src/dst IPs.  We synthesise deterministic IPs
# per-flow so the AI SOC agent can practise correlation.

_INTERNAL_SUBNETS = ["10.0.{}.{}", "192.168.{}.{}", "172.16.{}.{}"]
_EXTERNAL_SUBNETS = ["203.0.{}.{}", "198.51.{}.{}", "185.{}.{}.{}"]


def _synth_ip(flow_id: int, salt: str, internal: bool) -> str:
    """Deterministic but varied IP from flow_id."""
    h = hashlib.md5(f"{flow_id}-{salt}".encode(), usedforsecurity=False).digest()
    if internal:
        tpl = _INTERNAL_SUBNETS[h[0] % len(_INTERNAL_SUBNETS)]
        return tpl.format(h[1] % 16 + 1, h[2] % 254 + 1)
    tpl = _EXTERNAL_SUBNETS[h[0] % len(_EXTERNAL_SUBNETS)]
    return tpl.format(h[1] % 254 + 1, h[2] % 254 + 1)


def _synth_port(h_byte: int, well_known: bool) -> int:
    if well_known:
        return [22, 53, 80, 443, 445, 993, 3389, 8080][h_byte % 8]
    return 1024 + h_byte * 251 % 64511


# ---------------------------------------------------------------------------
# Heuristic device assignment
# ---------------------------------------------------------------------------

# Labels routed to IDS/IPS (attack signatures)
IDS_LABELS: set[str] = {
    "DoS-Hulk", "DoS-Goldeneye", "DoS-Slowloris", "DoS-Slowhttptest",
    "DoS-Slowread", "DoS-Slowheaders", "DoS-Slowbody", "DoS-Rudy",
    "DoS-Heartbleed",
    "DDoS", "DDoS-LOIC-HTTP", "DDoS-HOIC", "DDoS-NTP", "DDoS-TFTP",
    "DDoS-Syn", "DDoS-UDP", "DDoS-MSSQL", "DDoS-UDPLag", "DDoS-Ddossim",
    "DDoS-DNS", "DDoS-LDAP", "DDoS-SNMP", "DDoS-Slowloris", "DDoS-NetBIOS",
    "Webattack-bruteforce", "Webattack-XSS", "Webattack-SQLi",
    "Bruteforce-SSH", "Bruteforce-FTP",
}

# Labels routed to EDR (endpoint-focused)
EDR_LABELS: set[str] = {"Botnet", "Infiltration"}


def assign_device(row: pd.Series) -> str:
    """Return device key based on flow features and label."""
    label: str = row["Label"]

    # 1. Portscan → Nmap scanner
    if label == "Portscan":
        return "nmap"

    # 2. IDS/IPS attack signatures
    if label in IDS_LABELS:
        return "ids"

    # 3. EDR labels
    if label in EDR_LABELS:
        return "edr"

    # 4. Benign traffic — split across firewall & EDR
    #    Heuristic: SYN-heavy or very short flows → firewall,
    #    some sampled → EDR (endpoint telemetry)
    syn_count = int(row.get("SYN Flag Count", 0))
    flow_duration = float(row.get("Flow Duration", 0))

    if syn_count > 0 or flow_duration < 100:
        return "firewall"

    # 20% of remaining benign goes to EDR as endpoint baseline
    if random.random() < 0.20:
        return "edr"

    return "firewall"


# ---------------------------------------------------------------------------
# Timestamp generation
# ---------------------------------------------------------------------------

def generate_packet_timestamps(
    flow_start: datetime,
    flow_duration_us: float,
    total_fwd: int,
    total_bwd: int,
    iat_mean: float,
    iat_std: float,
    is_attack: bool,
) -> list[datetime]:
    """
    Synthesize per-packet timestamps for a single flow.

    Strategy:
    - total packets = total_fwd + total_bwd  (at least 1)
    - draw inter-arrival times from a lognormal (benign) or gamma (attack,
      burstier) distribution parameterised by IAT Mean / Std
    - scale the cumulative IATs so the last packet lands at
      flow_start + flow_duration
    """
    n_packets = max(int(total_fwd) + int(total_bwd), 1)

    if n_packets == 1:
        return [flow_start]

    n_gaps = n_packets - 1
    flow_dur_sec = max(flow_duration_us, 1.0) / 1e6  # µs → s

    mean_sec = max(float(iat_mean), 1.0) / 1e6
    std_sec = max(float(iat_std), 0.0) / 1e6

    if std_sec == 0:
        # Constant spacing
        gap = flow_dur_sec / n_gaps
        iats = np.full(n_gaps, gap)
    elif is_attack:
        # Gamma distribution — burstier (lower shape → more bursty)
        shape = max((mean_sec / std_sec) ** 2, 0.3)
        scale = max(std_sec ** 2 / mean_sec, 1e-9)
        iats = np.random.gamma(shape * 0.5, scale, size=n_gaps)  # halved shape for extra burstiness
    else:
        # Lognormal for benign
        if mean_sec > 0:
            sigma2 = np.log1p((std_sec / mean_sec) ** 2)
            sigma = np.sqrt(max(sigma2, 1e-12))
            mu = np.log(max(mean_sec, 1e-12)) - sigma2 / 2
        else:
            mu, sigma = -14.0, 1.0
        iats = np.random.lognormal(mu, sigma, size=n_gaps)

    # Scale so cumulative sum equals flow_duration
    cumsum = iats.cumsum()
    if cumsum[-1] > 0:
        iats = iats * (flow_dur_sec / cumsum[-1])

    timestamps = [flow_start]
    for gap in iats:
        timestamps.append(timestamps[-1] + timedelta(seconds=float(gap)))

    return timestamps


# ---------------------------------------------------------------------------
# Log event formatting
# ---------------------------------------------------------------------------

def _flow_ips(flow_id: int, label: str) -> dict:
    """Generate synthetic src/dst IPs and ports for a flow."""
    h = hashlib.md5(f"{flow_id}".encode(), usedforsecurity=False).digest()
    is_benign = label == "Benign"
    return {
        "src_ip": _synth_ip(flow_id, "src", internal=(not is_benign or h[3] % 2 == 0)),
        "dst_ip": _synth_ip(flow_id, "dst", internal=True),
        "src_port": _synth_port(h[4], well_known=False),
        "dst_port": _synth_port(h[5], well_known=True),
        "protocol": ["TCP", "UDP", "TCP"][h[6] % 3],
    }


def format_log_event(
    row: pd.Series,
    device_key: str,
    pkt_timestamp: datetime,
    pkt_index: int,
    flow_id: int,
    *,
    fmt: str = "json",
) -> dict | str:
    """Build a log event.  *fmt* = 'json' | 'syslog' | 'cef'."""
    device = DEVICES[device_key]
    ips = _flow_ips(flow_id, row["Label"])

    event: dict = {
        "timestamp": pkt_timestamp.isoformat(),
        "flow_id": flow_id,
        "packet_index": pkt_index,
        # Device metadata
        "source_device": device["device_name"],
        "device_ip": device["device_ip"],
        "log_format": device["log_format"],
        "vendor": device["vendor"],
        # Network 5-tuple
        **ips,
        # Label / classification
        "label": row["Label"],
        "class_label": row["ClassLabel"],
        # Core flow features (subset for the log)
        "flow_duration_us": int(row["Flow Duration"]),
        "total_fwd_packets": int(row["Total Fwd Packets"]),
        "total_bwd_packets": int(row["Total Backward Packets"]),
        "fwd_packets_length_total": float(row["Fwd Packets Length Total"]),
        "bwd_packets_length_total": float(row["Bwd Packets Length Total"]),
        "flow_bytes_per_sec": float(row["Flow Bytes/s"]),
        "flow_packets_per_sec": float(row["Flow Packets/s"]),
        # Flags
        "syn_flag_count": int(row["SYN Flag Count"]),
        "urg_flag_count": int(row["URG Flag Count"]),
        "fwd_psh_flags": int(row["Fwd PSH Flags"]),
        # Packet size features
        "packet_length_max": float(row["Packet Length Max"]),
        "packet_length_mean": float(row["Packet Length Mean"]),
        "avg_packet_size": float(row["Avg Packet Size"]),
        # Window
        "init_fwd_win_bytes": int(row["Init Fwd Win Bytes"]),
        "init_bwd_win_bytes": int(row["Init Bwd Win Bytes"]),
        # IAT stats
        "flow_iat_mean": float(row["Flow IAT Mean"]),
        "flow_iat_std": float(row["Flow IAT Std"]),
    }

    # Device-specific enrichment
    if device_key == "firewall":
        event["action"] = "block" if row["Label"] != "Benign" else "allow"
        event["rule_id"] = f"FW-{random.randint(1000, 9999)}"
    elif device_key == "ids":
        event["severity"] = _ids_severity(row["Label"])
        event["signature_id"] = f"SID-{hash(row['Label']) % 100000:05d}"
        event["alert_msg"] = f"Detected {row['Label']} activity"
    elif device_key == "edr":
        event["process_name"] = "svchost.exe" if row["Label"] == "Benign" else "unknown.exe"
        event["threat_score"] = 0 if row["Label"] == "Benign" else random.randint(60, 100)
    elif device_key == "nmap":
        event["scan_type"] = "SYN scan"
        event["ports_scanned"] = random.randint(100, 65535)

    if fmt == "json":
        return event
    if fmt == "cef":
        return _to_cef(event, device_key)
    return _to_syslog(event, device_key)


def _ids_severity(label: str) -> str:
    if label.startswith("DDoS") or label.startswith("DoS"):
        return "high"
    if label.startswith("Webattack"):
        return "critical"
    if label.startswith("Bruteforce"):
        return "medium"
    return "medium"


# ---------------------------------------------------------------------------
# Natural-language / industry log formats
# These produce the kind of text an AI SOC agent would see from real devices.
# ---------------------------------------------------------------------------

def _to_syslog(ev: dict, device_key: str) -> str:
    """Render as a realistic syslog line matching the vendor."""
    ts = ev["timestamp"]
    src = ev["src_ip"]
    dst = ev["dst_ip"]
    sp = ev["src_port"]
    dp = ev["dst_port"]
    proto = ev["protocol"]

    if device_key == "firewall":
        action = ev.get("action", "allow").upper()
        return (
            f'{ts} {ev["source_device"]} : %ASA-4-106023: '
            f'{action} {proto} src outside:{src}/{sp} dst inside:{dst}/{dp} '
            f'by access-group "global" [0x0, 0x0] '
            f'rule_id={ev.get("rule_id","")} '
            f'flow_bytes={ev["flow_bytes_per_sec"]:.0f}B/s '
            f'label={ev["label"]}'
        )
    if device_key == "ids":
        sev = ev.get("severity", "medium")
        sid = ev.get("signature_id", "SID-00000")
        msg = ev.get("alert_msg", "")
        return (
            f'{ts} {ev["source_device"]} suricata[1]: '
            f'[{sid}] [{sev.upper()}] {msg} '
            f'{{Proto: {proto}}} {{Src: {src}:{sp}}} -> {{Dst: {dst}:{dp}}} '
            f'pkts_toserver={ev["total_fwd_packets"]} '
            f'pkts_toclient={ev["total_bwd_packets"]}'
        )
    if device_key == "edr":
        proc = ev.get("process_name", "unknown.exe")
        score = ev.get("threat_score", 0)
        return (
            f'{ts} {ev["source_device"]} CrowdStrike '
            f'DetectionSummaryEvent: '
            f'ComputerName={dst} '
            f'ProcessName={proc} '
            f'RemoteAddress={src}:{sp} '
            f'ThreatScore={score} '
            f'Protocol={proto} '
            f'label={ev["label"]}'
        )
    # nmap
    return (
        f'{ts} {ev["source_device"]} nmap: '
        f'Scan from {src} -> {dst}:{dp} '
        f'{ev.get("scan_type","SYN scan")} '
        f'ports_checked={ev.get("ports_scanned",0)} '
        f'SYN_flags={ev["syn_flag_count"]} '
        f'label={ev["label"]}'
    )


def _to_cef(ev: dict, device_key: str) -> str:
    """Render as a CEF (Common Event Format) line."""
    sev_map = {"critical": 10, "high": 8, "medium": 5, "low": 2}
    sev_str = ev.get("severity", "medium")
    sev_num = sev_map.get(sev_str, 3)
    name = ev.get("alert_msg", ev["label"])
    return (
        f'CEF:0|{ev["vendor"]}|{ev["source_device"]}|1.0|'
        f'{ev.get("signature_id", ev["label"])}|{name}|{sev_num}|'
        f'src={ev["src_ip"]} spt={ev["src_port"]} '
        f'dst={ev["dst_ip"]} dpt={ev["dst_port"]} '
        f'proto={ev["protocol"]} '
        f'act={ev.get("action", "")} '
        f'cs1={ev["label"]} cs1Label=attack_label '
        f'cn1={ev["flow_duration_us"]} cn1Label=flow_duration_us '
        f'cn2={ev["total_fwd_packets"]} cn2Label=fwd_packets '
        f'cn3={ev["total_bwd_packets"]} cn3Label=bwd_packets'
    )


# ---------------------------------------------------------------------------
# Core streaming generator
# ---------------------------------------------------------------------------

def stream_logs(
    df: pd.DataFrame,
    *,
    max_flows: int | None = None,
    speed: float = 1.0,
    start_time: datetime | None = None,
    sample_frac: float | None = None,
    shuffle: bool = True,
    fmt: str = "json",
) -> Generator[dict | str, None, None]:
    """
    Yield log events one packet at a time in simulated real-time order.

    Parameters
    ----------
    df          : The loaded CIC-IDS dataframe.
    max_flows   : Cap the number of flows to process (None = all).
    speed       : Playback speed multiplier (0 = no delay, 1 = real-time).
    start_time  : Anchor timestamp for the first flow.
    sample_frac : If set, randomly sample this fraction of rows first.
    shuffle     : Shuffle flow order for realistic interleaving.
    fmt         : 'json' | 'syslog' | 'cef'.
    """
    if sample_frac is not None:
        df = df.sample(frac=sample_frac, random_state=42)

    if shuffle:
        df = df.sample(frac=1.0).reset_index(drop=True)

    if max_flows is not None:
        df = df.head(max_flows)

    if start_time is None:
        start_time = datetime.now(tz=timezone.utc)

    # --- Pre-compute device assignments & per-flow timestamps ---
    all_events: list[tuple[datetime, dict]] = []
    current_flow_start = start_time

    for flow_id, (_, row) in enumerate(df.iterrows()):
        device_key = assign_device(row)
        is_attack = row["Label"] != "Benign"

        # Jitter the gap between flow starts (50–500 ms in sim-time)
        inter_flow_gap = timedelta(
            milliseconds=random.uniform(50, 500)
        )
        current_flow_start += inter_flow_gap

        pkt_timestamps = generate_packet_timestamps(
            flow_start=current_flow_start,
            flow_duration_us=float(row["Flow Duration"]),
            total_fwd=int(row["Total Fwd Packets"]),
            total_bwd=int(row["Total Backward Packets"]),
            iat_mean=float(row["Flow IAT Mean"]),
            iat_std=float(row["Flow IAT Std"]),
            is_attack=is_attack,
        )

        for pkt_idx, pkt_ts in enumerate(pkt_timestamps):
            event = format_log_event(row, device_key, pkt_ts, pkt_idx, flow_id, fmt=fmt)
            all_events.append((pkt_ts, event))

        # Advance start for next flow to end of this one
        if pkt_timestamps:
            current_flow_start = pkt_timestamps[-1]

    # Sort all packets globally by timestamp
    all_events.sort(key=lambda x: x[0])

    # --- Emit with optional real-time pacing ---
    wall_anchor = time.monotonic()
    sim_anchor = all_events[0][0] if all_events else start_time

    for sim_ts, event in all_events:
        if speed > 0:
            sim_elapsed = (sim_ts - sim_anchor).total_seconds()
            target_wall = wall_anchor + sim_elapsed / speed
            sleep_dur = target_wall - time.monotonic()
            if sleep_dur > 0:
                time.sleep(sleep_dur)
        yield event


# ---------------------------------------------------------------------------
# Output sinks
# ---------------------------------------------------------------------------

def sink_stdout(event: dict | str) -> None:
    print(json.dumps(event) if isinstance(event, dict) else event)


def sink_file(path: Path):
    fh = open(path, "a", encoding="utf-8")

    def _write(event: dict | str) -> None:
        line = json.dumps(event) if isinstance(event, dict) else event
        fh.write(line + "\n")
        fh.flush()

    return _write


def sink_http(endpoint: str):
    import urllib.request
    import urllib.error

    def _post(event: dict | str) -> None:
        payload = json.dumps(event) if isinstance(event, dict) else event
        data = payload.encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError as exc:
            print(f"[WARN] POST failed: {exc}", file=sys.stderr)

    return _post


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SOCrates Log Stream Simulator — replay CIC-IDS flows "
                    "as a simulated real-time event stream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--parquet", required=True, type=Path,
        help="Path to the CIC-IDS parquet file.",
    )
    p.add_argument(
        "--max-flows", type=int, default=None,
        help="Limit the number of flows to replay (default: all).",
    )
    p.add_argument(
        "--speed", type=float, default=1.0,
        help="Playback speed multiplier.  0 = no delay (fastest), "
             "1 = real-time, 10 = 10× faster (default: 1.0).",
    )
    p.add_argument(
        "--sample-frac", type=float, default=None,
        help="Randomly sample this fraction of rows before streaming.",
    )
    p.add_argument(
        "--output", type=Path, default=None,
        help="Write JSONL output to this file instead of stdout.",
    )
    p.add_argument(
        "--endpoint", type=str, default=None,
        help="POST each log event to this HTTP endpoint.",
    )
    p.add_argument(
        "--no-shuffle", action="store_true",
        help="Do NOT shuffle flow order (keep dataset order).",
    )
    p.add_argument(
        "--format", choices=["json", "syslog", "cef"], default="json",
        dest="log_format",
        help="Output format: json (structured), syslog (Cisco/Suricata "
             "natural-language), cef (ArcSight CEF). (default: json)",
    )
    p.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducibility.",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        np.random.seed(args.seed)

    print(f"[*] Loading dataset from {args.parquet} ...", file=sys.stderr)
    df = pd.read_parquet(args.parquet)
    df = normalise_dataframe(df)
    print(f"[*] Loaded {len(df):,} flows  ({df['Label'].nunique()} labels)", file=sys.stderr)
    print(f"[*] Output format: {args.log_format}", file=sys.stderr)

    # Pick sink(s)
    sinks = []
    if args.output:
        sinks.append(sink_file(args.output))
        print(f"[*] Writing to {args.output}", file=sys.stderr)
    if args.endpoint:
        sinks.append(sink_http(args.endpoint))
        print(f"[*] Posting to {args.endpoint}", file=sys.stderr)
    if not sinks:
        sinks.append(sink_stdout)

    speed_label = "no delay" if args.speed == 0 else f"{args.speed}×"
    print(f"[*] Streaming at {speed_label} speed ...", file=sys.stderr)

    count = 0
    try:
        for event in stream_logs(
            df,
            max_flows=args.max_flows,
            speed=args.speed,
            sample_frac=args.sample_frac,
            shuffle=not args.no_shuffle,
            fmt=args.log_format,
        ):
            for sink in sinks:
                sink(event)
            count += 1
    except KeyboardInterrupt:
        print(f"\n[*] Interrupted after {count:,} events.", file=sys.stderr)
    else:
        print(f"[*] Done — emitted {count:,} events.", file=sys.stderr)


if __name__ == "__main__":
    main()
