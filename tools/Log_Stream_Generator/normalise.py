from __future__ import annotations
import pandas as pd

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
