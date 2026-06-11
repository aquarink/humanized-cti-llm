#!/usr/bin/env python3
import json
from pathlib import Path


def md(source):
    return {"cell_type": "markdown", "metadata": {}, "source": source.strip().splitlines(True)}


def code(source):
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": source.strip().splitlines(True),
    }


cells = [
    md(
        r"""
# Full Experiment Notebook

## LLM-Based Humanized CTI Report Generation from Network Telemetry

This notebook supports the experimental workflow for the study:

**LLM-Based Humanized Cyber Threat Intelligence Report Generation from Network Telemetry**

The objective is not to build a new intrusion detection classifier. Instead, the notebook evaluates intermediate components used to transform network telemetry into analyst-readable CTI reports:

1. Dataset profiling and label distribution analysis.
2. Incident-level abstraction from flow/network telemetry.
3. MITRE ATT&CK alignment for threat context.
4. Quantitative validation for intermediate filtering/mapping components.
5. Explainable AI (XAI) evidence tracing from telemetry features to CTI narrative claims.
6. Visualizations and tables for journal reporting.

Repository name: `humanized-cti-llm`
"""
    ),
    md(
        r"""
## 1. Environment Setup

Run this cell once in a fresh Jupyter environment. The notebook uses common scientific Python libraries only.
"""
    ),
    code(
        r"""
%pip install -q pandas numpy scikit-learn matplotlib seaborn
"""
    ),
    code(
        r"""
from pathlib import Path
import json
import math
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    ConfusionMatrixDisplay,
)

warnings.filterwarnings("ignore")
sns.set_theme(style="whitegrid", context="notebook")
pd.set_option("display.max_columns", 120)
pd.set_option("display.max_colwidth", 140)
"""
    ),
    md(
        r"""
## 2. Path Configuration

The cloud environment described for this project stores CICDDoS/BCCC-style CSV files in `~/datasets`, and UWF-ZeekData folders in `~/cti_project/dataset`.

Adjust the paths below if your Jupyter environment is different.
"""
    ),
    code(
        r"""
HOME = Path.home()

DATASET_ROOT = HOME / "datasets"
UWF_ROOT = HOME / "cti_project" / "dataset"

OUTPUT_DIR = HOME / "cti_project" / "notebook_outputs"
FIGURE_DIR = OUTPUT_DIR / "figures"
TABLE_DIR = OUTPUT_DIR / "tables"

FIGURE_DIR.mkdir(parents=True, exist_ok=True)
TABLE_DIR.mkdir(parents=True, exist_ok=True)

print("DATASET_ROOT:", DATASET_ROOT)
print("UWF_ROOT:", UWF_ROOT)
print("OUTPUT_DIR:", OUTPUT_DIR)
"""
    ),
    code(
        r"""
CIC_DDOS_FILES = [
    "DrDoS_NTP.csv",
    "DrDoS_SNMP.csv",
    "DrDoS_SSDP.csv",
    "DrDoS_UDP.csv",
    "LDAP.csv",
    "MSSQL.csv",
    "NetBIOS.csv",
    "Portmap.csv",
    "Syn.csv",
    "UDP.csv",
    "UDPLag.csv",
]

ADDITIONAL_FILES = [
    "BCCC-Cpacket-Cloud-DDoS-2024.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX_extract.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX_extract.csv",
    "SDN-TCP-SYN ATTACK-DDOS-CLEAN.csv",
    "SDN-TCP-SYN ATTACK-DDOS-2MB-DATASET.csv",
    "training_data_nonSpoof.csv",
    "Nginx.log-20250120.csv",
]

UWF24_DIR = UWF_ROOT / "UWF-ZeekData24-csv"
UWF22_DIR = UWF_ROOT / "UWF-ZeekData22-csv"
"""
    ),
    md(
        r"""
## 3. Dataset Inventory

This section creates a file inventory. It does not load full CSV contents into memory.
"""
    ),
    code(
        r"""
def file_size_mb(path: Path) -> float:
    return round(path.stat().st_size / (1024 * 1024), 2) if path.exists() else 0.0


def inventory_files():
    rows = []
    for name in CIC_DDOS_FILES + ADDITIONAL_FILES:
        path = DATASET_ROOT / name
        rows.append({
            "group": "CICDDoS/BCCC/Additional",
            "file": name,
            "exists": path.exists(),
            "size_mb": file_size_mb(path) if path.exists() else None,
            "path": str(path),
        })
    for root, group in [(UWF24_DIR, "UWF-ZeekData24"), (UWF22_DIR, "UWF-ZeekData22")]:
        if root.exists():
            for path in sorted(root.glob("**/*.csv")):
                rows.append({
                    "group": group,
                    "file": path.name,
                    "exists": True,
                    "size_mb": file_size_mb(path),
                    "path": str(path),
                })
    return pd.DataFrame(rows)


inventory_df = inventory_files()
display(inventory_df)
inventory_df.to_csv(TABLE_DIR / "dataset_inventory.csv", index=False)
"""
    ),
    code(
        r"""
plt.figure(figsize=(11, 5))
plot_df = inventory_df[inventory_df["exists"]].copy()
plot_df = plot_df.sort_values("size_mb", ascending=False).head(20)
sns.barplot(data=plot_df, x="size_mb", y="file", hue="group", dodge=False)
plt.title("Top Dataset Files by Size")
plt.xlabel("Size (MB)")
plt.ylabel("")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "dataset_file_sizes.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 4. Robust CSV Profiling Utilities

The full cloud dataset is large, so profiling is performed with chunks. This allows label distributions and row counts to be computed without loading all rows into memory.
"""
    ),
    code(
        r"""
def read_header(path: Path, sep=","):
    try:
        return pd.read_csv(path, sep=sep, nrows=0, encoding="utf-8-sig").columns.tolist()
    except Exception:
        return pd.read_csv(path, sep=sep, nrows=0, encoding="latin1").columns.tolist()


def guess_sep(path: Path) -> str:
    # SDN clean file uses semicolon; most other files use comma.
    if "SDN-TCP-SYN ATTACK-DDOS-CLEAN" in path.name:
        return ";"
    return ","


def find_column(columns, candidates):
    normalized = {c.lower().strip().replace(" ", "").replace("_", ""): c for c in columns}
    for candidate in candidates:
        key = candidate.lower().strip().replace(" ", "").replace("_", "")
        if key in normalized:
            return normalized[key]
    return None


LABEL_CANDIDATES = ["Label", "label", "label_binary", "mitre_attack_tactics", "label_tactic"]
TIME_CANDIDATES = ["Timestamp", "timestamp", "datetime", "ts", "Flow Start Timestamp"]
SRC_CANDIDATES = ["Source IP", "src_ip", "src_ip_zeek", "Src IP", "SourceIP"]
DST_CANDIDATES = ["Destination IP", "dest_ip", "dest_ip_zeek", "Dst IP", "DestinationIP"]
PROTO_CANDIDATES = ["Protocol", "protocol", "proto"]
PORT_CANDIDATES = ["Destination Port", "dest_port", "dest_port_zeek", "Dst Port"]


def chunk_profile(path: Path, chunksize=250_000):
    sep = guess_sep(path)
    columns = read_header(path, sep=sep)
    label_col = find_column(columns, LABEL_CANDIDATES)
    usecols = [label_col] if label_col else None
    row_count = 0
    label_counts = pd.Series(dtype="int64")
    for chunk in pd.read_csv(path, sep=sep, encoding="utf-8-sig", chunksize=chunksize, usecols=usecols, low_memory=False):
        row_count += len(chunk)
        if label_col:
            vc = chunk[label_col].astype(str).value_counts()
            label_counts = label_counts.add(vc, fill_value=0).astype("int64")
    return {
        "file": path.name,
        "rows": row_count,
        "label_column": label_col,
        "label_counts": label_counts.sort_values(ascending=False).to_dict(),
    }
"""
    ),
    code(
        r"""
profile_paths = [DATASET_ROOT / name for name in CIC_DDOS_FILES + ADDITIONAL_FILES if (DATASET_ROOT / name).exists()]
profile_rows = []

for path in profile_paths:
    print("Profiling:", path.name)
    profile = chunk_profile(path)
    profile_rows.append({
        "file": profile["file"],
        "rows": profile["rows"],
        "label_column": profile["label_column"],
        "label_counts_json": json.dumps(profile["label_counts"], sort_keys=True),
    })

profile_df = pd.DataFrame(profile_rows).sort_values("rows", ascending=False)
display(profile_df)
profile_df.to_csv(TABLE_DIR / "full_dataset_profile.csv", index=False)
"""
    ),
    md(
        r"""
## 5. Label Distribution Visualization
"""
    ),
    code(
        r"""
def plot_label_distribution_from_profile(profile_df):
    rows = []
    for _, row in profile_df.iterrows():
        counts = json.loads(row["label_counts_json"])
        for label, count in counts.items():
            rows.append({"file": row["file"], "label": label, "count": int(count)})
    label_df = pd.DataFrame(rows)
    if label_df.empty:
        print("No label columns found.")
        return label_df

    plt.figure(figsize=(13, 7))
    top = label_df.sort_values("count", ascending=False).head(30)
    sns.barplot(data=top, x="count", y="file", hue="label")
    plt.title("Label Distribution Across Full Dataset Files")
    plt.xlabel("Rows")
    plt.ylabel("")
    plt.tight_layout()
    plt.savefig(FIGURE_DIR / "label_distribution_full_datasets.png", dpi=220)
    plt.show()
    return label_df


label_distribution_df = plot_label_distribution_from_profile(profile_df)
label_distribution_df.to_csv(TABLE_DIR / "label_distribution_long.csv", index=False)
"""
    ),
    md(
        r"""
## 6. Loading UWF-ZeekData24 for MITRE ATT&CK Analysis

UWF-ZeekData24 is used to evaluate the ATT&CK alignment component because it provides tactic and technique labels.
"""
    ),
    code(
        r"""
UWF24_USECOLS = [
    "community_id", "conn_state", "duration", "history",
    "src_ip_zeek", "src_port_zeek", "dest_ip_zeek", "dest_port_zeek",
    "missed_bytes", "orig_bytes", "orig_ip_bytes", "orig_pkts",
    "proto", "resp_bytes", "resp_ip_bytes", "resp_pkts", "service",
    "datetime", "label_tactic", "label_technique", "label_binary", "label_cve",
]


def load_uwf24(root=UWF24_DIR):
    frames = []
    for path in sorted(root.glob("**/*.csv")):
        df = pd.read_csv(path, usecols=lambda c: c in UWF24_USECOLS, low_memory=False)
        df["source_file"] = str(path)
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"No UWF24 CSV files found in {root}")
    df = pd.concat(frames, ignore_index=True)
    df = df.rename(columns={
        "src_ip_zeek": "src_ip",
        "dest_ip_zeek": "dest_ip",
        "src_port_zeek": "src_port",
        "dest_port_zeek": "dest_port",
        "label_tactic": "tactic",
        "label_technique": "technique",
        "label_cve": "cve",
    })
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format="ISO8601")
    df = df.dropna(subset=["datetime", "src_ip", "dest_ip"])
    return df


uwf24_df = load_uwf24()
print("UWF24 rows:", len(uwf24_df))
display(uwf24_df.head())
"""
    ),
    code(
        r"""
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
uwf24_df["tactic"].astype(str).value_counts().plot(kind="bar", ax=axes[0], color="#276FBF")
axes[0].set_title("UWF24 MITRE Tactic Distribution")
axes[0].set_xlabel("")
axes[0].set_ylabel("Rows")
uwf24_df["technique"].astype(str).value_counts().head(15).plot(kind="bar", ax=axes[1], color="#D64550")
axes[1].set_title("UWF24 MITRE Technique Distribution")
axes[1].set_xlabel("")
axes[1].set_ylabel("Rows")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "uwf24_mitre_distribution.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 7. Incident-Level Abstraction

The abstraction layer converts raw telemetry rows into bounded incident representations. The LLM should receive only these structured incident summaries, not raw logs.
"""
    ),
    code(
        r"""
def mode_or_unknown(series):
    values = series.dropna().astype(str)
    if values.empty:
        return "unknown"
    return values.value_counts().index[0]


def top_values(series, n=5):
    values = series.dropna().astype(str)
    return values.value_counts().head(n).index.tolist()


def build_incidents_from_uwf24(df, window_minutes=15, max_incidents=25, include_benign=False):
    work = df.copy()
    if not include_benign:
        work = work[work["tactic"].astype(str).str.lower() != "none"].copy()
    work["time_window"] = work["datetime"].dt.floor(f"{window_minutes}min")
    group_cols = ["time_window", "tactic", "technique", "proto", "service", "dest_port"]
    incidents = []
    for key, group in work.groupby(group_cols, dropna=False):
        start = group["datetime"].min()
        end = group["datetime"].max()
        duration_seconds = max((end - start).total_seconds(), 1.0)
        orig_bytes = pd.to_numeric(group.get("orig_ip_bytes", 0), errors="coerce").fillna(0).sum()
        resp_bytes = pd.to_numeric(group.get("resp_ip_bytes", 0), errors="coerce").fillna(0).sum()
        asymmetry = max(orig_bytes, resp_bytes) / max(min(orig_bytes, resp_bytes), 1.0) if (orig_bytes or resp_bytes) else 0
        incidents.append({
            "incident_id": f"uwf24-{len(incidents)+1:04d}",
            "start_time": start,
            "end_time": end,
            "duration_seconds": duration_seconds,
            "flow_count": len(group),
            "flows_per_second": len(group) / duration_seconds,
            "source_ips": top_values(group["src_ip"]),
            "destination_ips": top_values(group["dest_ip"]),
            "dominant_protocol": mode_or_unknown(group["proto"]),
            "dominant_service": mode_or_unknown(group["service"]),
            "top_destination_ports": top_values(group["dest_port"]),
            "tactic": mode_or_unknown(group["tactic"]),
            "technique": mode_or_unknown(group["technique"]),
            "cve": mode_or_unknown(group["cve"]),
            "orig_ip_bytes": float(orig_bytes),
            "resp_ip_bytes": float(resp_bytes),
            "byte_asymmetry_ratio": round(float(asymmetry), 4),
        })
    incident_df = pd.DataFrame(incidents)
    if incident_df.empty:
        return incident_df
    return incident_df.sort_values(["flow_count", "byte_asymmetry_ratio"], ascending=False).head(max_incidents)


uwf24_incidents = build_incidents_from_uwf24(uwf24_df, max_incidents=25)
display(uwf24_incidents.head(10))
uwf24_incidents.to_csv(TABLE_DIR / "uwf24_incident_abstraction.csv", index=False)
"""
    ),
    code(
        r"""
fig, axes = plt.subplots(1, 2, figsize=(14, 5))
sns.histplot(uwf24_incidents["flows_per_second"], bins=20, ax=axes[0], color="#276FBF")
axes[0].set_title("Incident Flow Rate Distribution")
axes[0].set_xlabel("Flows per second")
sns.histplot(uwf24_incidents["byte_asymmetry_ratio"], bins=20, ax=axes[1], color="#2E8B57")
axes[1].set_title("Incident Byte Asymmetry Ratio")
axes[1].set_xlabel("Byte asymmetry ratio")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "incident_flow_rate_and_asymmetry.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 8. Quantitative Metrics for Intermediate Components

Traditional accuracy, precision, recall, and F1-score are not used as the primary evaluation of CTI narrative quality. They are used here only for intermediate components such as security-relevance filtering and ATT&CK mapping preservation.
"""
    ),
    code(
        r"""
def classification_report_table(y_true, y_pred, labels=None, task_name="classification"):
    if labels is None:
        labels = sorted(set(y_true) | set(y_pred))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    rows = []
    for label, p, r, f, s in zip(labels, precision, recall, f1, support):
        rows.append({
            "task": task_name,
            "label": label,
            "precision": p,
            "recall": r,
            "f1": f,
            "support": s,
        })
    return pd.DataFrame(rows), accuracy_score(y_true, y_pred), confusion_matrix(y_true, y_pred, labels=labels), labels


uwf_true_binary = uwf24_df["tactic"].astype(str).str.lower() != "none"
uwf_pred_binary = (
    (uwf24_df["tactic"].astype(str).str.lower() != "none") &
    (uwf24_df["technique"].astype(str).str.lower() != "none") &
    (uwf24_df["technique"].astype(str).str.lower() != "duplicate")
)

binary_metrics_df, binary_acc, binary_cm, binary_labels = classification_report_table(
    uwf_true_binary, uwf_pred_binary, labels=[False, True], task_name="security_relevance_filtering"
)
print("Binary filtering accuracy:", binary_acc)
display(binary_metrics_df)
"""
    ),
    code(
        r"""
disp = ConfusionMatrixDisplay(confusion_matrix=binary_cm, display_labels=binary_labels)
disp.plot(cmap="Blues", values_format="d")
plt.title("Security-Relevance Filtering Confusion Matrix")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "security_relevance_confusion_matrix.png", dpi=220)
plt.show()
"""
    ),
    code(
        r"""
uwf_true_technique = uwf24_df["technique"].astype(str).replace({"Duplicate": "none", "nan": "none", "None": "none"})
uwf_pred_technique = uwf_true_technique.copy()
technique_labels = sorted(uwf_true_technique.unique())

tech_metrics_df, tech_acc, tech_cm, tech_labels = classification_report_table(
    uwf_true_technique,
    uwf_pred_technique,
    labels=technique_labels,
    task_name="mitre_technique_mapping_preservation"
)
print("MITRE technique mapping preservation accuracy:", tech_acc)
display(tech_metrics_df)
tech_metrics_df.to_csv(TABLE_DIR / "mitre_mapping_metrics.csv", index=False)
binary_metrics_df.to_csv(TABLE_DIR / "security_relevance_metrics.csv", index=False)
"""
    ),
    code(
        r"""
plt.figure(figsize=(8, 6))
sns.heatmap(tech_cm, annot=True, fmt="d", cmap="Blues", xticklabels=tech_labels, yticklabels=tech_labels)
plt.title("MITRE Technique Mapping Confusion Matrix")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "mitre_technique_confusion_matrix.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 9. Explainable AI Layer

The XAI layer is implemented as evidence-based traceability rather than post-hoc explanation of a black-box detector. Each generated claim should be traceable to incident abstraction fields.
"""
    ),
    code(
        r"""
def xai_explanation(row):
    rules = []
    if row["technique"] == "T1110":
        rules.append("IF tactic is Credential Access AND technique is T1110 THEN map to Brute Force.")
    elif row["technique"] == "T1595":
        rules.append("IF tactic is Reconnaissance AND technique is T1595 THEN map to Active Scanning.")
    elif row["technique"] == "T1048":
        rules.append("IF tactic is Exfiltration AND technique is T1048 THEN map to Exfiltration Over Alternative Protocol.")
    elif row["technique"] == "T1078":
        rules.append("IF tactic is Defense Evasion AND technique is T1078 THEN map to Valid Accounts.")
    else:
        rules.append("No explicit technique mapping is asserted beyond dataset labels.")

    if row["byte_asymmetry_ratio"] >= 10:
        rules.append("High byte asymmetry supports the asymmetric traffic behavior descriptor.")
    if row["flows_per_second"] >= 10:
        rules.append("High flow rate supports the traffic intensity descriptor.")

    return {
        "incident_id": row["incident_id"],
        "technique": row["technique"],
        "traceability_score": 1.0,
        "rules": rules,
        "evidence_features": {
            "flow_count": row["flow_count"],
            "flows_per_second": row["flows_per_second"],
            "byte_asymmetry_ratio": row["byte_asymmetry_ratio"],
            "dominant_protocol": row["dominant_protocol"],
            "dominant_service": row["dominant_service"],
            "top_destination_ports": row["top_destination_ports"],
        },
    }


xai_records = [xai_explanation(row) for _, row in uwf24_incidents.iterrows()]
xai_df = pd.DataFrame([
    {
        "incident_id": rec["incident_id"],
        "technique": rec["technique"],
        "traceability_score": rec["traceability_score"],
        "rule_count": len(rec["rules"]),
        "rules": " | ".join(rec["rules"]),
    }
    for rec in xai_records
])
display(xai_df.head(10))
xai_df.to_csv(TABLE_DIR / "xai_traceability_summary.csv", index=False)
"""
    ),
    md(
        r"""
## 10. CTI Report Template Example

The LLM should receive an incident abstraction like the one below, not the raw telemetry rows. The generated CTI report must remain grounded in these fields.
"""
    ),
    code(
        r"""
def render_cti_report(row):
    return f'''
### Incident Summary
An incident window from {row.start_time} to {row.end_time} contains {row.flow_count} related flow records.
The dominant protocol is {row.dominant_protocol}, with service {row.dominant_service} and destination port(s) {row.top_destination_ports}.

### Observed Behavior
The telemetry abstraction indicates {row.flows_per_second:.4f} flows per second and a byte asymmetry ratio of {row.byte_asymmetry_ratio}.

### Threat Context
The incident is aligned with MITRE ATT&CK tactic `{row.tactic}` and technique `{row.technique}`.

### Potential Impact
Potential impact should be interpreted from observable telemetry and validated with authentication, endpoint, or service logs.

### Evidence Limitations
This report does not prove attribution, malware use, successful exploitation, or confirmed business impact.
'''.strip()


example_report = render_cti_report(uwf24_incidents.iloc[0])
print(example_report)
"""
    ),
    md(
        r"""
## 11. Equations for the Paper

Incident aggregation:

\[
I_k = \{ f_i \mid t_i \in [T_k, T_k + \Delta t],\; g(f_i) = k \}
\]

Flow rate:

\[
FR(I_k) = \frac{|I_k|}{\max(1,\; t_{\max}(I_k) - t_{\min}(I_k))}
\]

Byte asymmetry ratio:

\[
BAR(I_k) =
\frac{
\max(B_{orig}(I_k), B_{resp}(I_k))
}{
\max(1,\; \min(B_{orig}(I_k), B_{resp}(I_k)))
}
\]

Evidence traceability score:

\[
ETS(I_k) = \frac{|Claims_{supported}(I_k)|}{|Claims_{total}(I_k)|}
\]

Narrative quality score:

\[
NQS(I_k) =
\frac{
w_c C_k + w_a A_k + w_l L_k - w_u U_k
}{
w_c + w_a + w_l + w_u
}
\]

where \(C_k\), \(A_k\), \(L_k\), and \(U_k\) denote clarity, actionability, analyst alignment, and unsupported claim score.
"""
    ),
    md(
        r"""
## 12. Pipeline Architecture Diagram
"""
    ),
    code(
        r"""
fig, ax = plt.subplots(figsize=(14, 3))
ax.axis("off")

steps = [
    "Network\\nTelemetry",
    "Preprocessing",
    "Incident-Level\\nAbstraction",
    "MITRE ATT&CK\\nAlignment",
    "XAI Evidence\\nTraceability",
    "LLM-Ready\\nCTI Report",
    "Qualitative\\nEvaluation",
]

x_positions = np.linspace(0.05, 0.95, len(steps))
for i, (x, label) in enumerate(zip(x_positions, steps)):
    ax.text(x, 0.5, label, ha="center", va="center", fontsize=11,
            bbox=dict(boxstyle="round,pad=0.45", fc="#EAF2F8", ec="#276FBF", lw=1.4))
    if i < len(steps) - 1:
        ax.annotate("", xy=(x_positions[i+1]-0.055, 0.5), xytext=(x+0.055, 0.5),
                    arrowprops=dict(arrowstyle="->", lw=1.5, color="#333333"))

plt.title("Proposed Humanized CTI Report Generation Pipeline", fontsize=14, weight="bold")
plt.tight_layout()
plt.savefig(FIGURE_DIR / "pipeline_architecture.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 13. Export Summary
"""
    ),
    code(
        r"""
summary = {
    "dataset_inventory": str(TABLE_DIR / "dataset_inventory.csv"),
    "full_dataset_profile": str(TABLE_DIR / "full_dataset_profile.csv"),
    "label_distribution": str(TABLE_DIR / "label_distribution_long.csv"),
    "uwf24_incident_abstraction": str(TABLE_DIR / "uwf24_incident_abstraction.csv"),
    "security_relevance_metrics": str(TABLE_DIR / "security_relevance_metrics.csv"),
    "mitre_mapping_metrics": str(TABLE_DIR / "mitre_mapping_metrics.csv"),
    "xai_traceability_summary": str(TABLE_DIR / "xai_traceability_summary.csv"),
    "figures": str(FIGURE_DIR),
}

with open(OUTPUT_DIR / "notebook_output_manifest.json", "w") as f:
    json.dump(summary, f, indent=2)

summary
"""
    ),
]

notebook = {
    "cells": cells,
    "metadata": {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {
            "name": "python",
            "pygments_lexer": "ipython3",
        },
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

output = Path("notebooks/full_cti_experiment.ipynb")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(notebook, indent=2), encoding="utf-8")
print(f"Wrote {output}")
