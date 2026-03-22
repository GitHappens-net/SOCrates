from __future__ import annotations
import hashlib

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
    # Realistic OUI prefixes (VMware, Dell, HP, Cisco)
    ouis = ["00:50:56", "00:0C:29", "D4:BE:D9", "00:25:B5", "3C:22:FB"]
    oui = ouis[h[0] % len(ouis)]
    return f"{oui}:{h[1]:02X}:{h[2]:02X}:{h[3]:02X}"

def _synth_country(flow_id: int) -> tuple[str, str]:
    h = hashlib.md5(f"{flow_id}-geo".encode(), usedforsecurity=False).digest()
    countries = [
        ("United States", "US"), ("Germany", "DE"), ("China", "CN"),
        ("Russia", "RU"), ("Netherlands", "NL"), ("United Kingdom", "GB"),
        ("France", "FR"), ("Japan", "JP"), ("Brazil", "BR"),
        ("South Korea", "KR"), ("India", "IN"), ("Romania", "RO"),
    ]
    return countries[h[0] % len(countries)]
