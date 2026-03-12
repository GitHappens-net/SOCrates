"""CLI parser and main entry point."""
from __future__ import annotations

import argparse
import random
import sys
import textwrap
from pathlib import Path

import numpy as np
import pandas as pd

from .engine import stream_logs
from .normalise import normalise_dataframe
from .server import run_server
from .sinks import sink_file, sink_http, sink_stdout, sink_syslog


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="SOCrates Log Stream Generator — "
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

          # Send FortiGate logs via syslog UDP
          %(prog)s --parquet ../data/cic-collection.parquet \\
                   --syslog --syslog-port 514 --speed 5
        """),
    )
    p.add_argument("--parquet", required=True, type=Path,
                   help="Path to a CIC-IDS parquet file.")
    p.add_argument("--max-flows", type=int, default=None,
                   help="Limit number of flows (default: all).")
    p.add_argument("--speed", type=float, default=1.0,
                   help="Playback speed. 0=no delay, 1=real-time, 10=10\u00d7 (default: 1.0).")
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
    p.add_argument("--syslog", action="store_true",
                   help="Send logs as syslog UDP to --syslog-host:--syslog-port.")
    p.add_argument("--syslog-host", type=str, default="127.0.0.1",
                   help="Syslog server host (default: 127.0.0.1).")
    p.add_argument("--syslog-port", type=int, default=514,
                   help="Syslog server UDP port (default: 514).")
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

    if args.serve:
        run_server(df, args.host, args.port, args.log_format,
                   args.speed, args.max_flows, args.seed)
        return

    sinks = []
    if args.output:
        sinks.append(sink_file(args.output, args.log_format))
        print(f"[*] Writing to {args.output}", file=sys.stderr)
    if args.endpoint:
        sinks.append(sink_http(args.endpoint))
        print(f"[*] Posting to {args.endpoint}", file=sys.stderr)
    if args.syslog:
        sinks.append(sink_syslog(args.syslog_host, args.syslog_port))
        print(f"[*] Sending syslog to {args.syslog_host}:{args.syslog_port}", file=sys.stderr)
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
        print(f"\n[*] Done \u2014 emitted {count:,} log lines.", file=sys.stderr)
