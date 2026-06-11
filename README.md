# humanized-cti-llm

**Repository description:** Incident-level network telemetry abstraction, MITRE ATT&CK alignment, explainable evidence tracing, and LLM-ready humanized Cyber Threat Intelligence report generation.

Prototype ini mengikuti arah metodologi pada `Pebri___CTI.pdf`: raw network telemetry tidak dikirim langsung ke LLM. Data terlebih dahulu diubah menjadi abstraksi insiden, diperkaya dengan konteks MITRE ATT&CK, lalu dijadikan laporan CTI bergaya analis.

## Suggested GitHub Metadata

- Repository name: `humanized-cti-llm`
- Short description: `Explainable LLM-ready CTI report generation from network telemetry using incident abstraction and MITRE ATT&CK alignment.`
- Topics: `cyber-threat-intelligence`, `cti`, `llm`, `mitre-attack`, `xai`, `network-telemetry`, `ddos`, `incident-response`

## Dataset yang Disarankan

- `datasets/UWF-ZeekData24-csv/`: dataset utama untuk prototipe karena sudah memiliki fitur flow dan label MITRE (`label_tactic`, `label_technique`, `label_cve`).
- `datasets/Syn.csv`, `datasets/SDN-TCP-SYN ATTACK-DDOS-CLEAN.csv`, dan `datasets/BCCC-Cpacket-Cloud-DDoS-2024.csv`: dataset DDoS sederhana untuk studi kasus volumetrik. Skemanya hanya IP, timestamp, dan label, sehingga abstraksinya lebih terbatas.

## Jalankan Pipeline

Generate laporan CTI dari UWF-ZeekData24:

```bash
python3 scripts/generate_cti_reports.py --dataset uwf24 --limit-files 4 --max-incidents 8
```

Secara default pipeline memfilter traffic benign/normal/`none`, sehingga laporan berfokus pada insiden yang relevan untuk CTI. Tambahkan `--include-benign` jika ingin membuat pembanding benign.

Generate laporan dari dataset SYN/DDoS sederhana:

```bash
python3 scripts/generate_cti_reports.py --dataset syn --max-incidents 5
python3 scripts/generate_cti_reports.py --dataset sdn-syn --max-incidents 5
python3 scripts/generate_cti_reports.py --dataset bccc --max-incidents 5
```

Hasil akan dibuat di:

```text
outputs/incidents.jsonl
outputs/reports.md
outputs/evaluation_rubric.csv
```

## Integrasi LLM Opsional

Secara default, script menggunakan renderer template lokal agar pipeline bisa diuji tanpa API key. Untuk memakai OpenAI API:

```bash
export OPENAI_API_KEY="..."
python3 scripts/generate_cti_reports.py --dataset uwf24 --use-llm --model gpt-4.1-mini
```

Input ke LLM hanya berupa JSON abstraksi insiden, bukan raw telemetry.
