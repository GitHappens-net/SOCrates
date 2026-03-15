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
    p.add_argument("--from", choices=["fortigate", "paloalto"],
                   default="fortigate", dest="from_device",
                   help="Pretend to send logs from this device (sets format and source IP).")
    p.add_argument("--demo", action="store_true",
                   help="Run both fortigate and paloalto streams concurrently (ignores --from).")
    p.add_argument("--serve", action="store_true",
                   help="Start REST API server mode.")
    p.add_argument("--host", default="127.0.0.1",
                   help="Server bind address (default: 127.0.0.1).")
    p.add_argument("--port", type=int, default=5050,
                   help="Server port (default: 5050).")
    p.add_argument("--syslog", action=argparse.BooleanOptionalAction, default=True,
                   help="Send logs as syslog UDP to --syslog-host:--syslog-port (now ON by default). Use --no-syslog to disable.")
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

    if args.demo:
        formats = ["fortigate", "paloalto"]
        print(f"[*] Format: DEMO MODE (fortigate AND paloalto)", file=sys.stderr)
    else:
        formats = [args.from_device]
        print(f"[*] Format: {formats[0]}", file=sys.stderr)

    if args.serve:
        if args.demo:
            print("[-] Cannot use --serve with --demo. Demo mode is for dual-streaming syslog logs.", file=sys.stderr)
            sys.exit(1)

        run_server(df, args.host, args.port, formats[0],
                   args.speed, args.max_flows, args.seed)
        return

    import threading

    def run_stream(log_format: str, start_index: int = 0):
        sinks = []
        if args.output:
            out_file = args.output
            if args.demo:
                out_path = Path(args.output)
                out_file = out_path.with_name(f"{out_path.stem}_{log_format}{out_path.suffix}")
            sinks.append(sink_file(out_file, log_format))
            print(f"[*] Writing {log_format} to {out_file}", file=sys.stderr)
        if args.endpoint:
            sinks.append(sink_http(args.endpoint))
            print(f"[*] Posting {log_format} to {args.endpoint}", file=sys.stderr)
        if args.syslog:
            source_ip = "127.0.0.1" if log_format == "fortigate" else "127.0.0.2"
            sinks.append(sink_syslog(args.syslog_host, args.syslog_port, source_ip))
            print(f"[*] Sending {log_format} syslog to {args.syslog_host}:{args.syslog_port} (spoof {source_ip})", file=sys.stderr)
        if not sinks:
            sinks.append(sink_stdout)

        speed_label = "no delay" if args.speed == 0 else f"{args.speed}\u00d7"
        print(f"[*] Streaming {log_format} at {speed_label} speed ...\n", file=sys.stderr)

        # Slice the dataframe starting from `start_index`
        stream_df = df.iloc[start_index:] if start_index > 0 else df

        count = 0
        try:
            for line in stream_logs(
                stream_df,
                max_flows=args.max_flows,
                speed=args.speed,
                sample_frac=args.sample_frac,
                shuffle=not args.no_shuffle,
                fmt=log_format,
                seed=args.seed,
            ):
                for s in sinks:
                    s(line)
                count += 1
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\n[*] Done \u2014 emitted {count:,} {log_format} log lines.", file=sys.stderr)

    threads = []
    for i, fmt in enumerate(formats):
        # 0 for the first format, 5000 for the second format in demo mode
        start_index = 5000 if args.demo and i == 1 else 0
        t = threading.Thread(target=run_stream, args=(fmt, start_index), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            while t.is_alive():
                t.join(0.1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.", file=sys.stderr)

