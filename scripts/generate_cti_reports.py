#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cti_pipeline.abstraction import build_incidents
from cti_pipeline.evaluation import write_evaluation_rubric
from cti_pipeline.loaders import iter_supported_datasets, load_dataset
from cti_pipeline.reporting import render_openai_report, render_reports
from cti_pipeline.threat_mapping import enrich_incidents


def parse_args():
    parser = argparse.ArgumentParser(description="Generate humanized CTI reports from network telemetry abstraction.")
    parser.add_argument("--dataset", choices=list(iter_supported_datasets()), default="uwf24")
    parser.add_argument("--limit-files", type=int, default=None, help="Limit UWF24 CSV files for fast experiments.")
    parser.add_argument("--nrows", type=int, default=None, help="Limit rows per loaded CSV.")
    parser.add_argument("--window-minutes", type=int, default=15)
    parser.add_argument("--max-incidents", type=int, default=10)
    parser.add_argument("--output-dir", default="outputs")
    parser.add_argument("--include-benign", action="store_true", help="Include benign/normal/none labels in incident construction.")
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--model", default="gpt-4.1-mini")
    return parser.parse_args()


def main():
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    df = load_dataset(
        args.dataset,
        limit_files=args.limit_files,
        nrows=args.nrows,
        include_benign=args.include_benign,
    )
    incidents = build_incidents(
        df,
        dataset=args.dataset,
        window_minutes=args.window_minutes,
        max_incidents=args.max_incidents,
    )
    incidents = enrich_incidents(incidents)

    incidents_path = output_dir / "incidents.jsonl"
    with incidents_path.open("w", encoding="utf-8") as handle:
        for incident in incidents:
            handle.write(json.dumps(incident.to_dict(), sort_keys=True) + "\n")

    if args.use_llm:
        reports = []
        for incident in incidents:
            reports.append(f"## Incident {incident.incident_id}\n\n{render_openai_report(incident, args.model)}")
        report_text = "\n\n".join(reports)
    else:
        report_text = render_reports(incidents)

    reports_path = output_dir / "reports.md"
    reports_path.write_text(report_text, encoding="utf-8")
    write_evaluation_rubric(output_dir / "evaluation_rubric.csv", incidents)

    print(f"Loaded rows: {len(df)}")
    print(f"Generated incidents: {len(incidents)}")
    print(f"Wrote: {incidents_path}")
    print(f"Wrote: {reports_path}")
    print(f"Wrote: {output_dir / 'evaluation_rubric.csv'}")


if __name__ == "__main__":
    main()
