# SOCrates
Your SOC AI assistant!

---

## Setup

**Requirements**
```
pip install -r backend/requirements.txt
```

**Dataset**

Download at least the [CIC-IDS Collection](https://www.kaggle.com/datasets/dhoogla/cicidscollection?resource=download) parquet from Kaggle and place it in the `data/` folder:

```
data/
  cic-collection.parquet
```

**`backend/.env`**
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL_PARSER=gpt-4.1
OPENAI_MODEL_AGENT=gpt-4.1
SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=514
```

---

## Running

**Start the parser** (from project root):
```powershell
python -m backend.services.parser
```

Listens on UDP 514. On first run, creates `backend/database/socrates.db` automatically.

**Simulate logs** (separate terminal, from project root):
```powershell
python -m tools.Log_Stream_Generator `
  --parquet data\cic-collection.parquet `
  --syslog --max-flows 10000 --speed 1
```

`--format` defaults to `fortigate`. Use `--format paloalto` for PaloAlto logs.

Other output modes: `--output file.log` (file), `--endpoint http://...` (HTTP POST), `--serve` (REST API server). See [tools/Log_Stream_Generator/README.md](tools/Log_Stream_Generator/README.md) for full details.

---

## Example Datasets

- [Real CyberSecurity Datasets (GitHub)](https://github.com/gfek/Real-CyberSecurity-Datasets)
- [Network Intrusion dataset (CIC-IDS-2017) (Kaggle)](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset)
- [CIC-IDS Collection (Kaggle)](https://www.kaggle.com/datasets/dhoogla/cicidscollection)
- [TON IoT and UNSW-NB15 (UNSW)](https://research.unsw.edu.au/projects/unsw-nb15-dataset)