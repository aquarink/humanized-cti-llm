#!/usr/bin/env python3
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cti_pipeline.abstraction import build_incidents
from cti_pipeline.loaders import load_dataset
from cti_pipeline.metrics import binary_metrics_for_dataset, uwf24_attack_mapping_metrics
from cti_pipeline.threat_mapping import enrich_incidents
from cti_pipeline.visualization import write_bar_chart_svg, write_confusion_matrix_svg
from cti_pipeline.xai import add_explanations


def value_counts(df, column, limit=12):
    if column not in df.columns:
        return {}
    return df[column].astype(str).value_counts().head(limit).astype(int).to_dict()


def dataset_stats(dataset, df, incidents):
    labels = {}
    if dataset == "uwf24":
        labels = value_counts(df, "tactic")
    else:
        labels = value_counts(df, "label")
    mapped = sum(1 for incident in incidents if incident.threat_context.get("technique_id") != "none")
    return {
        "dataset": dataset,
        "raw_rows_loaded": int(len(df)),
        "incident_count": int(len(incidents)),
        "mapping_coverage": round(mapped / max(len(incidents), 1), 4),
        "top_labels": labels,
    }


def write_dataset_summary(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["dataset", "raw_rows_loaded", "incident_count", "mapping_coverage", "top_labels_json"])
        for row in rows:
            writer.writerow(
                [
                    row["dataset"],
                    row["raw_rows_loaded"],
                    row["incident_count"],
                    row["mapping_coverage"],
                    json.dumps(row["top_labels"], sort_keys=True),
                ]
            )


def write_metrics_summary(path, metrics_rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["dataset", "task", "accuracy", "label", "precision", "recall", "f1", "support", "note"])
        for result in metrics_rows:
            for row in result["per_label"]:
                writer.writerow(
                    [
                        result["dataset"],
                        result["task"],
                        result["accuracy"],
                        row["label"],
                        row["precision"],
                        row["recall"],
                        row["f1"],
                        row["support"],
                        result.get("note", ""),
                    ]
                )


def write_xai_summary(path, incidents):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "incident_id",
                "dataset",
                "technique_id",
                "traceability_score",
                "top_feature_1",
                "top_feature_1_value",
                "rule_count",
            ]
        )
        for incident in incidents:
            feature = incident.explanations["feature_evidence"][0]
            writer.writerow(
                [
                    incident.incident_id,
                    incident.dataset,
                    incident.threat_context.get("technique_id", "none"),
                    incident.explanations.get("traceability_score", 0),
                    feature["feature"],
                    feature["value"],
                    len(incident.explanations.get("rules", [])),
                ]
            )


def main():
    parser = argparse.ArgumentParser(description="Generate journal experiment tables and SVG figures.")
    parser.add_argument("--output-dir", default="paper_assets")
    parser.add_argument("--uwf24-limit-files", type=int, default=4)
    parser.add_argument("--max-incidents", type=int, default=12)
    parser.add_argument("--bccc-nrows", type=int, default=None)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    figure_dir = output_dir / "figures"
    output_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)

    configs = [
        ("uwf24", {"limit_files": args.uwf24_limit_files}),
        ("sdn-syn", {}),
        ("bccc", {"nrows": args.bccc_nrows}),
    ]

    summary_rows = []
    metrics_rows = []
    all_incidents = []

    for dataset, kwargs in configs:
        df_all = load_dataset(dataset, include_benign=True, **kwargs)
        df_relevant = load_dataset(dataset, include_benign=False, **kwargs)
        incidents = build_incidents(df_relevant, dataset=dataset, max_incidents=args.max_incidents)
        incidents = add_explanations(enrich_incidents(incidents))
        all_incidents.extend(incidents)

        summary_rows.append(dataset_stats(dataset, df_all, incidents))
        metrics = binary_metrics_for_dataset(df_all, dataset)
        metrics_rows.append(metrics)

        label_column = "tactic" if dataset == "uwf24" else "label"
        write_bar_chart_svg(
            figure_dir / f"{dataset}_label_distribution.svg",
            f"{dataset} Label Distribution",
            value_counts(df_all, label_column),
        )
        write_confusion_matrix_svg(
            figure_dir / f"{dataset}_confusion_matrix.svg",
            f"{dataset} Security Relevance Confusion Matrix",
            metrics["labels"],
            metrics["confusion_matrix"],
        )

        if dataset == "uwf24":
            mapping_metrics = uwf24_attack_mapping_metrics(df_all)
            metrics_rows.append(mapping_metrics)
            write_bar_chart_svg(
                figure_dir / "uwf24_mitre_technique_distribution.svg",
                "UWF24 MITRE Technique Distribution",
                value_counts(df_all, "technique"),
            )
            write_confusion_matrix_svg(
                figure_dir / "uwf24_mitre_technique_confusion_matrix.svg",
                "UWF24 MITRE Technique Mapping Confusion Matrix",
                mapping_metrics["labels"],
                mapping_metrics["confusion_matrix"],
                width=860,
                height=760,
            )

    write_dataset_summary(output_dir / "dataset_summary.csv", summary_rows)
    write_metrics_summary(output_dir / "metrics_summary.csv", metrics_rows)
    write_xai_summary(output_dir / "xai_summary.csv", all_incidents)
    (output_dir / "metrics.json").write_text(json.dumps(metrics_rows, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote journal assets to {output_dir}")


if __name__ == "__main__":
    main()
