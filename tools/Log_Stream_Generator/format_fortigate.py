from __future__ import annotations
import hashlib
from datetime import datetime
import pandas as pd

from .identity import _synth_ip, _synth_mac, _synth_country

# FortiGate field mappings
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

_FG_SERVICE: dict[int, str] = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 3389: "RDP", 8080: "HTTP",
    21: "FTP", 25: "SMTP", 110: "POP3", 123: "NTP",
    3306: "MySQL", 5432: "PostgreSQL", 8443: "HTTPS",
}

_FG_APP_MAP: dict[str, tuple[str, str, str]] = {
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

_FG_LEVEL: dict[str, str] = {
    "Benign": "notice",
}

_FG_UTM: dict[str, tuple[str, str]] = {
    "Botnet":                ("botnet", "0211054601"),
    "Webattack-XSS":         ("webfilter", "0316013056"),
    "Webattack-SQLi":        ("webfilter", "0316013057"),
    "Webattack-bruteforce":  ("ips", "0419016384"),
    "DoS-Heartbleed":        ("ips", "0419016385"),
}

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
    ("port1", "port2"),     # LAN → WAN
    ("port3", "port2"),     # DMZ → WAN
    ("port1", "port3"),     # LAN → DMZ
    ("ssl.root", "port2"),  # VPN → WAN
]

def _fg_logid(label: str) -> str:
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

# Formatter
def format_fortigate(row: pd.Series, ts: datetime, flow_id: int) -> str:
    label = row["Label"]
    h = hashlib.md5(f"{flow_id}".encode(), usedforsecurity=False).digest()

    is_benign = label == "Benign"
    src_ip = _synth_ip(flow_id, "src-forti", internal=True)
    dst_ip = _synth_ip(flow_id, "dst", internal=(not is_benign and h[3] % 3 == 0))
    src_port = _fg_ephemeral_port(h[4])
    dst_port = _fg_well_known_port(h[5])
    src_mac = _synth_mac(flow_id, "src")

    action = _FG_ACTION.get(label, "deny")
    service = _FG_SERVICE.get(dst_port, "tcp/{}".format(dst_port))
    app_info = _FG_APP_MAP.get(label, ("UNKNOWN", "Unknown", "medium"))
    policy = _FG_POLICY.get(label, "default-deny")
    level = _FG_LEVEL.get(label, "warning")
    logid = _fg_logid(label)

    proto_num = int(row.get("Protocol", 6)) if "Protocol" in row.index else 6
    intf_src, intf_dst = _FG_INTERFACES[h[6] % len(_FG_INTERFACES)]
    hw = _HW_VENDORS[h[7] % len(_HW_VENDORS)]

    duration_sec = max(int(float(row["Flow Duration"]) / 1e6), 1)
    sent_byte = max(int(float(row["Fwd Packets Length Total"])), 0)
    rcvd_byte = max(int(float(row["Bwd Packets Length Total"])), 0)
    sent_pkt = max(int(row["Total Fwd Packets"]), 0)
    rcvd_pkt = max(int(row["Total Backward Packets"]), 0)
    country_name, _ = _synth_country(flow_id)
    session_id = (flow_id * 7919 + h[0]) % 10_000_000

    fields = [
        f'date={ts.strftime("%Y-%m-%d")}',
        f'time={ts.strftime("%H:%M:%S")}',
        f'eventtime={int(ts.timestamp())}',
        f'tz="+0000"',
        f'devname="FGT-SOCrates"',
        f'devid="FGT60FSOCRATES00"',
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
