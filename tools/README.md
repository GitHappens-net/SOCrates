# Usage examples

## Fast dump of 500 flows (no delay)
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --max-flows 500 --speed 0

## Simulated real-time at 10× speed
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --speed 10 --max-flows 1000

## POST to backend API
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --endpoint http://localhost:546/api/logs --speed 5

## Write to JSONL file
python tools/Log_Stream_Simulator.py --parquet data/cic-collection.parquet --output logs.jsonl --speed 0


# Recommended usage pattern for OpenAI API testing

## Generate a compact syslog batch for an AI to triage

python tools/Log_Stream_Simulator.py \
    --parquet data/cic-collection.parquet \
    --max-flows 200 --speed 0 --seed 42 \
    --format syslog --output test_batch.log

## Then feed test_batch.log (or chunks of it) as context to your OpenAI agent with a prompt like:

"You are a SOC analyst. Review these security logs and identify any incidents, correlate events by source IP, and recommend response actions."

The syslog format is ideal for this because it resembles what the AI would see from real Cisco ASA / Suricata / CrowdStrike integrations, and it's 3-4x more token-efficient than JSON.