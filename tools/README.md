# What changed vs v1

| Feature | v1 (`Log_Stream_Simulator.py`) | v2 (`attempt_2`) |
| :--- | :--- | :--- |
| **Format** | Generic syslog/CEF/JSON | Native FortiGate key=value + PaloAlto CSV |
| **Fields** | ~20 synthetic fields | ~40+ fields matching real FortiGate output |
| **Granularity**| Per-packet | Per-flow |
| **REST API** | HTTP POST sink only | Built-in server mode |
| **Readability**| AI sees fabricated syslog | AI sees logs identical to real production |

---

# How to use attempt 2

## Option 1: Stream to stdout (pipe to backend)
```bash
python tools/Log_Stream_Simulator_attempt_2.py \
    --parquet data/cic-collection.parquet \
    --max-flows 500 --speed 10 --format fortigate
```

## Option 2: REST API mode (backend polls this like a real FortiGate)
```bash
python tools/Log_Stream_Simulator_attempt_2.py \
    --parquet data/cic-collection.parquet \
    --serve --port 5050 --speed 0 --max-flows 1000
```

## Then from your backend:
```bash
GET http://localhost:5050/api/v2/log/traffic  → returns 50 logs per batch
GET http://localhost:5050/health              → server status
```

---

# Usage examples for attempt 1

## Fast dump of 500 flows (no delay)
```bash
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --max-flows 500 --speed 0
```

## Simulated real-time at 10× speed
```bash
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --speed 10 --max-flows 1000
```

## POST to backend API
```bash
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --endpoint http://localhost:546/api/logs --speed 5
```

## Write to JSONL file
```bash
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --output logs.jsonl --speed 0
```

---

# Recommended usage pattern for OpenAI API testing for attempt 1

## Generate a compact syslog batch for an AI to triage

```bash
python tools/Log_Stream_Simulator.py \
    --parquet data/cic-collection.parquet \
    --max-flows 200 --speed 0 --seed 42 \
    --format syslog --output test_batch.log
```

## Then feed `test_batch.log` (or chunks of it) as context to your OpenAI agent with a prompt like:

> "You are a SOC analyst. Review these security logs and identify any incidents, correlate events by source IP, and recommend response actions."

The syslog format is ideal for this because it resembles what the AI would see from real Cisco ASA / Suricata / CrowdStrike integrations, and it's 3-4x more token-efficient than JSON.