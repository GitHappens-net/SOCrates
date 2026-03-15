# SOCrates Log Stream Generator

A high-fidelity firewall log simulator that transforms **CIC-IDS-2017 / CIC-IDS-Collection** network flow datasets into vendor-native firewall log streams. Designed to feed the SOCrates AI-powered SOC assistant with realistic telemetry for development, testing, and demos.

## Why This Exists

Real FortiGate / PaloAlto appliances produce logs only when real traffic is present. This generator solves that by:

- Converting **academic IDS datasets** (CIC-IDS) into **production-grade firewall logs**
- Producing output **indistinguishable** from real FortiGate/PaloAlto logs
- Supporting multiple delivery modes — stdout, file, syslog UDP, HTTP POST, or a full REST API server
- Including **33 attack categories** (DDoS, Botnet, Portscan, Web Attacks, Brute Force, etc.) alongside benign traffic

## Architecture

```
Log_Stream_Generator/
├── __init__.py            Package exports
├── __main__.py            Entry point (python -m)
├── normalise.py           Label normalisation (CIC-IDS-2017 ↔ CIC-IDS-Collection)
├── identity.py            Deterministic synthetic IP / MAC / country generation
├── format_fortigate.py    FortiGate key=value formatter (~40 fields)
├── format_paloalto.py     PaloAlto CSV syslog formatter (~45 fields)
├── engine.py              Timestamp synthesis + core streaming generator
├── sinks.py               Output sinks (stdout, file, syslog UDP, HTTP POST)
├── server.py              REST API server (mimics FortiGate REST API)
├── cli.py                 CLI parser + main()
└── README.md              This file
```

## Data Flow

```
┌──────────────┐     ┌────────────┐     ┌──────────────┐     ┌─────────────┐
│  CIC-IDS     │────>│ normalise  │────>│   engine     │────>│   sinks     │
│  .parquet    │     │ labels     │     │ stream_logs  │     │ stdout/file │
│  dataset     │     │ ClassLabel │     │ timestamps   │     │ syslog/http │
└──────────────┘     └────────────┘     │ pacing       │     │ REST server │
                                        └──────┬───────┘     └─────────────┘
                                               │
                                    ┌──────────┴──────────┐
                                    │                     │
                             ┌──────▼──────┐       ┌──────▼──────┐
                             │ FortiGate   │       │ PaloAlto    │
                             │ key=value   │       │ CSV syslog  │
                             │ ~40 fields  │       │ ~45 fields  │
                             └─────────────┘       └─────────────┘
```

## Quick Start

```bash
# From the SOCrates project root:

# FortiGate logs to stdout, 100 flows, no delay
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --max-flows 100 --speed 0

# Run BOTH PaloAlto and FortiGate concurrently
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --max-flows 500 --speed 5 --demo

# FortiGate logs to stdout, 1 flows, real speed
python -m tools.Log_Stream_Generator --parquet data/DDoS-Friday-no-metadata.parquet --max-flows 1 --speed 1

# PaloAlto CSV logs to file
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --from paloalto --output /tmp/pa.csv --speed 0

# REST API server
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --serve --port 5050 --speed 0

# Syslog UDP to a SIEM / log collector (we use this to stream to SOCrates)
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --syslog --syslog-host 10.0.0.50 --syslog-port 514 --speed 5
```

## Output Modes

### 1. Stdout (default)

Prints one log line per flow to stdout. Ideal for piping into other tools.

```bash
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet --max-flows 5 --speed 0
```

### 2. File Output (`--output`)

Writes logs to a file. PaloAlto format automatically prepends the CSV header row.

```bash
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet \
    --format paloalto --output logs.csv --speed 0
```

### 3. Syslog UDP (`--syslog`)

Sends each log as a UDP syslog message in standard `<PRI>HOSTNAME: message` format. Compatible with any syslog receiver (rsyslog, syslog-ng, Splunk, ELK, etc.).

```bash
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet \
    --syslog --syslog-host 127.0.0.1 --syslog-port 514 --speed 1
```

### 4. HTTP POST (`--endpoint`)

POSTs each log as JSON `{"log": "<line>"}` to any HTTP endpoint.

```bash
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet \
    --endpoint http://localhost:8000/ingest --speed 5
```

### 5. REST API Server (`--serve`)

Starts an HTTP server that mimics a FortiGate REST API. The SOCrates backend can poll it as if it were a real appliance.

```bash
python -m tools.Log_Stream_Generator --parquet data/cic-collection.parquet \
    --serve --port 5050 --speed 0
```

**Endpoints:**

| Method |         Path          |                       Description                     |
|--------|-----------------------|-------------------------------------------------------|
| `GET`  | `/api/v2/log/traffic` | Fetch next batch of 50 logs (cursor-based pagination) |
| `GET`  | `/health`             | Server status, log count, generation progress         |
<br>
> Multiple sinks can be combined: `--output logs.txt --syslog --endpoint http://...`

## Output Formats

### FortiGate (`--from fortigate`)

Native key=value format matching real FortiGate 7.x REST API / syslog output:

```
date=2025-01-15 time=10:30:22 eventtime=1736934622 tz="+0000" logid="0000000013"
type="traffic" subtype="forward" level="notice" vd="root" srcip=10.0.45.12
srcport=51692 srcintf="port1" srcintfrole="lan" dstip=203.0.113.50 dstport=443
dstintf="port2" dstintfrole="wan" action="close" policyname="Allow-Outbound-Web"
service="HTTPS" duration=45 sentbyte=12480 rcvdbyte=89320 sentpkt=42 rcvdpkt=65
app="SSL_TLS" appcat="Network.Service" apprisk="low" utmaction="allow"
```

**Includes 40+ fields:** timestamps, source/destination IPs & ports, interfaces, policies, NAT translation, byte/packet counts, application identification, UTM verdicts, hardware vendor fingerprints, geographic enrichment, session IDs, and threat scoring for attacks.

### PaloAlto (`--from paloalto`)

CSV syslog format matching real PaloAlto TRAFFIC logs:

```
2025/01/15 10:30:22,PA-5220,TRAFFIC,end,2025.0.1,2025/01/15 10:30:22,
10.0.45.12,203.0.113.50,,,Allow-Outbound,,,ssl,vsys1,trust,untrust,
ethernet1/1,ethernet1/2,Syslog-Traffic,,4521307,0,51692,443,,,0x400000,
tcp,allow,101800,12480,89320,107,2025/01/15 10:30:22,45,networking,,0,
0x8000000000000000,Reserved,United States,,42,65,tcp-fin,0,<uuid>
```

**45 fields** in correct PaloAlto field order with inline comments in source code for each field position.

## CLI Reference

```
usage: Log_Stream_Generator [-h] --parquet PARQUET [--max-flows N]
                             [--speed SPEED] [--sample-frac FRAC]
                             [--output FILE] [--endpoint URL]
                             [--from {fortigate,paloalto}] [--demo]
                             [--serve] [--host HOST] [--port PORT]
                             [--syslog] [--syslog-host HOST] [--syslog-port PORT]
                             [--no-shuffle] [--seed SEED]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `--parquet` | *(required)* | Path to a CIC-IDS `.parquet` file |
| `--max-flows` | all | Limit number of flows to emit |
| `--speed` | `1.0` | Playback speed: `0` = no delay, `1` = real-time, `10` = 10x |
| `--sample-frac` | — | Randomly sample this fraction of the dataset first |
| `--from` | `fortigate` | Output format: `fortigate` or `paloalto` |
| `--demo` | off | Run both fortigate and paloalto streams concurrently (ignores `--from`) |
| `--output` | — | Write logs to this file |
| `--endpoint` | — | POST each log to this HTTP URL |
| `--syslog` | off | Send logs as syslog UDP datagrams |
| `--syslog-host` | `127.0.0.1` | Syslog destination host |
| `--syslog-port` | `514` | Syslog destination UDP port |
| `--serve` | off | Start REST API server instead of streaming |
| `--host` | `127.0.0.1` | REST server bind address |
| `--port` | `5050` | REST server port |
| `--no-shuffle` | off | Keep dataset row order (skip shuffle) |
| `--seed` | — | Random seed for reproducible output |

## Dataset Compatibility

Tested with the following CIC-IDS datasets:

| Dataset | Rows | Labels | Notes |
|---------|------|--------|-------|
| CIC-IDS-Collection | 9,167,581 | 33 | Merged superset |
| Benign-Monday | ~529K | 1 | Clean traffic only |
| DoS-Wednesday | ~691K | 5 | DoS variants |
| WebAttacks-Thursday | ~168K | 4 | XSS, SQLi, Brute Force |
| Portscan-Friday | ~286K | 2 | Port scanning |
| DDoS-Friday | ~225K | 2 | DDoS traffic |
| Botnet-Friday | ~286K | 2 | Botnet C2 traffic |

Both **CIC-IDS-2017** (78 columns) and **CIC-IDS-Collection** (59 columns) schemas are supported via automatic label normalisation and column mapping.

## Dependencies

- Python 3.10+
- `pandas` — DataFrame operations
- `numpy` — Random number generation
- `pyarrow` — Parquet file reading

All listed in the project-level `requirements.txt`.
