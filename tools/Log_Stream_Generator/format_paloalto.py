"""PaloAlto CSV syslog log formatter."""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

import pandas as pd

from .identity import _synth_ip, _synth_country
from .format_fortigate import _fg_ephemeral_port, _fg_well_known_port

# ── PaloAlto field mappings ───────────────────────────────────────────────

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

# ── Formatter ─────────────────────────────────────────────────────────────

def format_paloalto_csv(row: pd.Series, ts: datetime, flow_id: int) -> str:
    """
    Produce a PaloAlto Traffic log in CSV format (matches PA syslog output).
    """
    label = row["Label"]
    h = hashlib.md5(f"{flow_id}".encode(), usedforsecurity=False).digest()

    src_ip = _synth_ip(flow_id, "src-palo", internal=True)
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

    country_name, _ = _synth_country(flow_id)
    session_id = (flow_id * 7919 + h[0]) % 10_000_000

    # PaloAlto CSV syslog format — field order matches real PA output
    fields = [
        ts.strftime("%Y/%m/%d %H:%M:%S"),     # receive_time
        "PA-5220",                            # serial
        "TRAFFIC",                            # type
        "end",                                # subtype
        "2025.0.1",                           # config_version
        ts.strftime("%Y/%m/%d %H:%M:%S"),     # generated_time
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
        ts.strftime("%Y/%m/%d %H:%M:%S"),     # start_time
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
