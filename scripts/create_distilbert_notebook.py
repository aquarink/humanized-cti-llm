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
# DistilBERT Baseline Notebook

## Transformer-Based Baseline for Intermediate CTI Classification

This notebook applies **DistilBERT** as a lightweight transformer baseline for the intermediate classification stage of the CTI pipeline.

Important scope statement:

- DistilBERT is **not** used to generate CTI narratives.
- DistilBERT is used to evaluate whether incident-level abstractions can support quantitative classification tasks.
- The final CTI reports should still be generated from structured incident abstractions using controlled LLM prompting.

Recommended paper framing:

> DistilBERT is used as a lightweight transformer-based baseline for intermediate incident classification. It provides quantitative metrics such as accuracy, precision, recall, F1-score, and confusion matrix, while LLM-generated CTI narratives are evaluated using analyst-oriented qualitative criteria.
"""
    ),
    md(
        r"""
## 1. Install and Import Dependencies
"""
    ),
    code(
        r"""
%pip install -q pandas numpy scikit-learn matplotlib seaborn torch transformers
"""
    ),
    code(
        r"""
from pathlib import Path
import json
import random
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

import torch
from torch.utils.data import DataLoader, TensorDataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)

warnings.filterwarnings("ignore")
sns.set_theme(style="whitegrid")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

device = torch.device("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu")
print("Device:", device)
"""
    ),
    md(
        r"""
## 2. Path and Experiment Configuration

The paths below match the cloud notebook layout you described:

- CICDDoS/BCCC datasets: `~/datasets`
- UWF-ZeekData datasets: `~/cti_project/dataset`

The default task is `uwf24_tactic`, because UWF-ZeekData24 has MITRE tactic labels suitable for CTI alignment evaluation.
"""
    ),
    code(
        r"""
HOME = Path.home()
DATASET_ROOT = HOME / "datasets"
UWF_ROOT = HOME / "cti_project" / "dataset"
UWF24_DIR = UWF_ROOT / "UWF-ZeekData24-csv"

OUTPUT_DIR = HOME / "cti_project" / "notebook_outputs_distilbert"
FIGURE_DIR = OUTPUT_DIR / "figures"
TABLE_DIR = OUTPUT_DIR / "tables"
MODEL_DIR = OUTPUT_DIR / "models" / "distilbert_incident_classifier"

FIGURE_DIR.mkdir(parents=True, exist_ok=True)
TABLE_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

TASK = "uwf24_tactic"  # options: uwf24_tactic, uwf24_binary, bccc_binary, sdn_syn_binary
MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 256
MAX_INCIDENTS_PER_CLASS = 3000  # set to None for larger/full experiments
MIN_SAMPLES_PER_CLASS = 2
BATCH_SIZE = 16
EPOCHS = 2
LEARNING_RATE = 2e-5
INCLUDE_LABEL_HINTS = False  # keep False for defensible classification without label leakage
DROP_AMBIGUOUS_TEXTS = True  # remove identical abstractions that map to multiple labels
USE_CLASS_WEIGHTS = True

print("DATASET_ROOT:", DATASET_ROOT)
print("UWF24_DIR:", UWF24_DIR)
print("OUTPUT_DIR:", OUTPUT_DIR)
"""
    ),
    md(
        r"""
## 3. Data Loading Utilities
"""
    ),
    code(
        r"""
UWF24_USECOLS = [
    "conn_state", "duration", "history",
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
        raise FileNotFoundError(f"No UWF-ZeekData24 files found in {root}")
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


def load_simple_ddos(path, sep=",", timestamp_format=None):
    df = pd.read_csv(path, sep=sep, encoding="utf-8-sig", low_memory=False)
    df = df.rename(columns={
        "Source IP": "src_ip",
        "Destination IP": "dest_ip",
        "Timestamp": "datetime",
        "Label": "label",
    })
    df = df[df["label"].astype(str).str.lower() != "label"].copy()
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format=timestamp_format)
    df = df.dropna(subset=["datetime", "src_ip", "dest_ip"])
    df["proto"] = "unknown"
    df["service"] = "unknown"
    df["dest_port"] = "unknown"
    return df
"""
    ),
    md(
        r"""
## 4. Incident Abstraction to Text

DistilBERT expects text input. Therefore, each incident-level abstraction is converted into a compact textual representation. This preserves the research principle that models should consume structured abstractions, not raw telemetry rows.
"""
    ),
    code(
        r"""
def mode_or_unknown(series):
    values = series.dropna().astype(str)
    if values.empty:
        return "unknown"
    return values.value_counts().index[0]


def top_values(series, n=3):
    values = series.dropna().astype(str)
    return values.value_counts().head(n).index.tolist()


def safe_sum(group, column):
    if column not in group.columns:
        return 0.0
    return float(pd.to_numeric(group[column], errors="coerce").fillna(0).sum())


def build_uwf24_incident_texts(df, task="uwf24_tactic", window_minutes=15):
    work = df.copy()
    work["time_window"] = work["datetime"].dt.floor(f"{window_minutes}min")
    group_cols = ["time_window", "tactic", "technique", "proto", "service", "dest_port"]
    rows = []
    for _, group in work.groupby(group_cols, dropna=False):
        start = group["datetime"].min()
        end = group["datetime"].max()
        duration_seconds = max((end - start).total_seconds(), 1.0)
        flow_count = len(group)
        flows_per_second = flow_count / duration_seconds
        orig_bytes = safe_sum(group, "orig_ip_bytes") + safe_sum(group, "orig_bytes")
        resp_bytes = safe_sum(group, "resp_ip_bytes") + safe_sum(group, "resp_bytes")
        byte_asymmetry_ratio = max(orig_bytes, resp_bytes) / max(min(orig_bytes, resp_bytes), 1.0) if (orig_bytes or resp_bytes) else 0.0
        tactic = mode_or_unknown(group["tactic"])
        technique = mode_or_unknown(group["technique"])
        binary = "malicious" if str(tactic).lower() != "none" else "benign"
        label = tactic if task == "uwf24_tactic" else binary
        text = (
            f"Incident telemetry abstraction. "
            f"Flow count: {flow_count}. Duration seconds: {duration_seconds:.2f}. "
            f"Flows per second: {flows_per_second:.4f}. "
            f"Dominant protocol: {mode_or_unknown(group['proto'])}. "
            f"Dominant service: {mode_or_unknown(group['service'])}. "
            f"Destination ports: {', '.join(top_values(group['dest_port']))}. "
            f"Unique sources: {group['src_ip'].nunique()}. Unique destinations: {group['dest_ip'].nunique()}. "
            f"Originator bytes: {orig_bytes:.0f}. Responder bytes: {resp_bytes:.0f}. "
            f"Byte asymmetry ratio: {byte_asymmetry_ratio:.4f}."
        )
        if INCLUDE_LABEL_HINTS:
            text += f" MITRE technique label in abstraction: {technique}."
        rows.append({
            "text": text,
            "label": label,
            "tactic": tactic,
            "technique": technique,
            "flow_count": flow_count,
            "flows_per_second": flows_per_second,
            "byte_asymmetry_ratio": byte_asymmetry_ratio,
        })
    return pd.DataFrame(rows)


def build_simple_ddos_incident_texts(df, task_name, window_minutes=15):
    work = df.copy()
    work["time_window"] = work["datetime"].dt.floor(f"{window_minutes}min")
    rows = []
    for _, group in work.groupby(["time_window", "label", "src_ip", "dest_ip"], dropna=False):
        start = group["datetime"].min()
        end = group["datetime"].max()
        duration_seconds = max((end - start).total_seconds(), 1.0)
        flow_count = len(group)
        label_raw = mode_or_unknown(group["label"])
        label = "benign" if str(label_raw).lower() in {"benign", "normal"} else "malicious"
        text = (
            f"Incident telemetry abstraction. Dataset task: {task_name}. "
            f"Flow count: {flow_count}. Duration seconds: {duration_seconds:.2f}. "
            f"Flows per second: {flow_count / duration_seconds:.4f}. "
            f"Source IP count: {group['src_ip'].nunique()}. Destination IP count: {group['dest_ip'].nunique()}. "
            f"Dominant label in abstraction: {label_raw}. "
            f"Dominant protocol: unknown. Dominant service: unknown."
        )
        rows.append({"text": text, "label": label, "raw_label": label_raw, "flow_count": flow_count})
    return pd.DataFrame(rows)
"""
    ),
    md(
        r"""
## 5. Build the Selected Dataset
"""
    ),
    code(
        r"""
if TASK in {"uwf24_tactic", "uwf24_binary"}:
    raw_df = load_uwf24()
    dataset_df = build_uwf24_incident_texts(raw_df, task=TASK)
elif TASK == "bccc_binary":
    raw_df = load_simple_ddos(DATASET_ROOT / "BCCC-Cpacket-Cloud-DDoS-2024.csv")
    dataset_df = build_simple_ddos_incident_texts(raw_df, TASK)
elif TASK == "sdn_syn_binary":
    raw_df = load_simple_ddos(
        DATASET_ROOT / "SDN-TCP-SYN ATTACK-DDOS-CLEAN.csv",
        sep=";",
        timestamp_format="%d/%m/%y %H.%M",
    )
    dataset_df = build_simple_ddos_incident_texts(raw_df, TASK)
else:
    raise ValueError(f"Unsupported TASK: {TASK}")

print("Raw rows:", len(raw_df))
print("Incident text rows:", len(dataset_df))
display(dataset_df.head())
display(dataset_df["label"].value_counts())
"""
    ),
    md(
        r"""
## 5.1. Ambiguous Abstraction Check

Some UWF-ZeekData24 rows may be duplicated across tactics or may contain the same observable abstraction with different labels. If the same text maps to multiple labels, a text classifier cannot reliably learn a unique class from telemetry evidence alone.

For the main DistilBERT baseline, `DROP_AMBIGUOUS_TEXTS=True` removes identical text abstractions that have conflicting labels.
"""
    ),
    code(
        r"""
ambiguous_texts = (
    dataset_df.groupby("text")["label"]
    .nunique()
    .reset_index(name="label_count")
    .query("label_count > 1")
)

print("Ambiguous text abstractions:", len(ambiguous_texts))
if len(ambiguous_texts):
    ambiguous_examples = dataset_df[dataset_df["text"].isin(ambiguous_texts["text"])].sort_values("text")
    display(ambiguous_examples[["label", "tactic", "technique", "flow_count", "text"]].head(20))
    ambiguous_examples.to_csv(TABLE_DIR / f"{TASK}_ambiguous_abstractions.csv", index=False)
"""
    ),
    code(
        r"""
plt.figure(figsize=(10, 5))
sns.countplot(data=dataset_df, y="label", order=dataset_df["label"].value_counts().index, color="#276FBF")
plt.title(f"DistilBERT Classification Labels: {TASK}")
plt.xlabel("Incident count")
plt.ylabel("")
plt.tight_layout()
plt.savefig(FIGURE_DIR / f"{TASK}_label_distribution.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 6. Balance and Split the Dataset

To keep the baseline practical on cloud notebooks, the dataset can be capped per class. Increase `MAX_INCIDENTS_PER_CLASS` or set it to `None` for larger experiments.
"""
    ),
    code(
        r"""
def cap_per_class(df, label_col="label", max_per_class=None):
    if max_per_class is None:
        return df.sample(frac=1, random_state=SEED).reset_index(drop=True)
    parts = []
    for label, group in df.groupby(label_col):
        parts.append(group.sample(n=min(len(group), max_per_class), random_state=SEED))
    return pd.concat(parts, ignore_index=True).sample(frac=1, random_state=SEED).reset_index(drop=True)


counts = dataset_df["label"].value_counts()
valid_labels = counts[counts >= MIN_SAMPLES_PER_CLASS].index
filtered_df = dataset_df[dataset_df["label"].isin(valid_labels)].copy()
if DROP_AMBIGUOUS_TEXTS:
    label_counts_by_text = filtered_df.groupby("text")["label"].transform("nunique")
    before = len(filtered_df)
    filtered_df = filtered_df[label_counts_by_text == 1].copy()
    print(f"Dropped ambiguous text abstractions: {before - len(filtered_df)}")

balanced_df = cap_per_class(filtered_df, max_per_class=MAX_INCIDENTS_PER_CLASS)

label_names = sorted(balanced_df["label"].unique())
label2id = {label: i for i, label in enumerate(label_names)}
id2label = {i: label for label, i in label2id.items()}
balanced_df["label_id"] = balanced_df["label"].map(label2id)

print("Labels:", label_names)
display(balanced_df["label"].value_counts())
balanced_df.to_csv(TABLE_DIR / f"{TASK}_distilbert_training_abstractions.csv", index=False)

stratify = balanced_df["label_id"] if balanced_df["label_id"].value_counts().min() >= 2 else None
train_df, test_df = train_test_split(
    balanced_df,
    test_size=0.2,
    random_state=SEED,
    stratify=stratify,
)

print("Train:", len(train_df), "Test:", len(test_df))
"""
    ),
    md(
        r"""
## 7. Tokenization
"""
    ),
    code(
        r"""
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


def encode_texts(texts):
    return tokenizer(
        list(texts),
        padding=True,
        truncation=True,
        max_length=MAX_LENGTH,
        return_tensors="pt",
    )


train_enc = encode_texts(train_df["text"])
test_enc = encode_texts(test_df["text"])

train_dataset = TensorDataset(
    train_enc["input_ids"],
    train_enc["attention_mask"],
    torch.tensor(train_df["label_id"].values, dtype=torch.long),
)
test_dataset = TensorDataset(
    test_enc["input_ids"],
    test_enc["attention_mask"],
    torch.tensor(test_df["label_id"].values, dtype=torch.long),
)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE)
"""
    ),
    md(
        r"""
## 8. Fine-Tune DistilBERT

For a quick baseline, start with 1-2 epochs. For a final experiment, report the exact epoch count, model checkpoint, sample size, and random seed.
"""
    ),
    code(
        r"""
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=len(label_names),
    id2label=id2label,
    label2id=label2id,
)
model.to(device)

if USE_CLASS_WEIGHTS:
    class_counts = train_df["label_id"].value_counts().sort_index()
    weights = len(train_df) / (len(label_names) * class_counts)
    class_weights = torch.tensor(weights.values, dtype=torch.float).to(device)
    print("Class weights:", {label_names[i]: round(float(w), 4) for i, w in enumerate(class_weights.detach().cpu())})
else:
    class_weights = None

optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)

for epoch in range(EPOCHS):
    model.train()
    total_loss = 0.0
    for input_ids, attention_mask, labels in train_loader:
        input_ids = input_ids.to(device)
        attention_mask = attention_mask.to(device)
        labels = labels.to(device)

        optimizer.zero_grad()
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
        if class_weights is None:
            loss = torch.nn.functional.cross_entropy(outputs.logits, labels)
        else:
            loss = torch.nn.functional.cross_entropy(outputs.logits, labels, weight=class_weights)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    avg_loss = total_loss / max(len(train_loader), 1)
    print(f"Epoch {epoch + 1}/{EPOCHS} - train loss: {avg_loss:.4f}")
"""
    ),
    md(
        r"""
## 9. Evaluate the DistilBERT Baseline
"""
    ),
    code(
        r"""
def predict(model, loader):
    model.eval()
    preds = []
    truths = []
    probs = []
    with torch.no_grad():
        for input_ids, attention_mask, labels in loader:
            input_ids = input_ids.to(device)
            attention_mask = attention_mask.to(device)
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits.detach().cpu()
            pred = torch.argmax(logits, dim=1).numpy()
            prob = torch.softmax(logits, dim=1).numpy()
            preds.extend(pred.tolist())
            probs.extend(prob.tolist())
            truths.extend(labels.numpy().tolist())
    return np.array(truths), np.array(preds), np.array(probs)


y_true, y_pred, y_prob = predict(model, test_loader)
accuracy = accuracy_score(y_true, y_pred)
print("Accuracy:", round(accuracy, 4))
print(classification_report(y_true, y_pred, target_names=label_names, zero_division=0))
print("Macro-F1 should be prioritized over accuracy for imbalanced classes.")

precision, recall, f1, support = precision_recall_fscore_support(
    y_true, y_pred, labels=list(range(len(label_names))), zero_division=0
)
metrics_df = pd.DataFrame({
    "label": label_names,
    "precision": precision,
    "recall": recall,
    "f1": f1,
    "support": support,
})
metrics_df.insert(0, "task", TASK)
metrics_df.insert(1, "accuracy", accuracy)
display(metrics_df)
metrics_df.to_csv(TABLE_DIR / f"{TASK}_distilbert_metrics.csv", index=False)
"""
    ),
    code(
        r"""
cm = confusion_matrix(y_true, y_pred, labels=list(range(len(label_names))))
plt.figure(figsize=(max(7, len(label_names) * 1.1), max(5, len(label_names) * 0.8)))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=label_names, yticklabels=label_names)
plt.title(f"DistilBERT Confusion Matrix: {TASK}")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig(FIGURE_DIR / f"{TASK}_distilbert_confusion_matrix.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 10. Error Analysis
"""
    ),
    code(
        r"""
analysis_df = test_df.copy().reset_index(drop=True)
analysis_df["true_label"] = [id2label[i] for i in y_true]
analysis_df["pred_label"] = [id2label[i] for i in y_pred]
analysis_df["correct"] = analysis_df["true_label"] == analysis_df["pred_label"]
analysis_df["confidence"] = y_prob.max(axis=1)

display(analysis_df[["true_label", "pred_label", "confidence", "correct", "text"]].head(20))
display(analysis_df[~analysis_df["correct"]][["true_label", "pred_label", "confidence", "text"]].head(20))
analysis_df.to_csv(TABLE_DIR / f"{TASK}_distilbert_predictions.csv", index=False)
"""
    ),
    md(
        r"""
## 11. Lightweight Token-Level Explanation

This cell provides a simple occlusion-based token importance view for a single prediction. It is not a replacement for a full SHAP/LIME study, but it provides an explainability signal that can be discussed as a supplementary XAI analysis.
"""
    ),
    code(
        r"""
def token_occlusion_importance(text, target_label_id=None, max_tokens=80):
    model.eval()
    encoded = tokenizer(text, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")
    input_ids = encoded["input_ids"].to(device)
    attention_mask = encoded["attention_mask"].to(device)
    with torch.no_grad():
        base_logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
        base_probs = torch.softmax(base_logits, dim=1)[0]
    if target_label_id is None:
        target_label_id = int(torch.argmax(base_probs).item())
    base_score = float(base_probs[target_label_id].item())
    tokens = tokenizer.convert_ids_to_tokens(input_ids[0].detach().cpu().tolist())

    rows = []
    candidate_positions = [
        i for i, tok in enumerate(tokens)
        if tok not in [tokenizer.cls_token, tokenizer.sep_token, tokenizer.pad_token]
    ][:max_tokens]
    for pos in candidate_positions:
        masked_ids = input_ids.clone()
        masked_ids[0, pos] = tokenizer.mask_token_id if tokenizer.mask_token_id is not None else tokenizer.unk_token_id
        with torch.no_grad():
            logits = model(input_ids=masked_ids, attention_mask=attention_mask).logits
            probs = torch.softmax(logits, dim=1)[0]
        score = float(probs[target_label_id].item())
        rows.append({
            "token": tokens[pos],
            "base_score": base_score,
            "masked_score": score,
            "importance": base_score - score,
        })
    return pd.DataFrame(rows).sort_values("importance", ascending=False)


sample_idx = int(np.argmax(analysis_df["confidence"].values))
sample_text = analysis_df.iloc[sample_idx]["text"]
sample_target = label2id[analysis_df.iloc[sample_idx]["pred_label"]]

importance_df = token_occlusion_importance(sample_text, target_label_id=sample_target)
display(importance_df.head(20))
importance_df.to_csv(TABLE_DIR / f"{TASK}_token_importance_example.csv", index=False)
"""
    ),
    code(
        r"""
plt.figure(figsize=(10, 6))
top_imp = importance_df.head(15).sort_values("importance")
sns.barplot(data=top_imp, x="importance", y="token", color="#D64550")
plt.title("Token Occlusion Importance Example")
plt.xlabel("Probability drop after token masking")
plt.ylabel("")
plt.tight_layout()
plt.savefig(FIGURE_DIR / f"{TASK}_token_importance_example.png", dpi=220)
plt.show()
"""
    ),
    md(
        r"""
## 12. Save Model and Experiment Manifest
"""
    ),
    code(
        r"""
model.save_pretrained(MODEL_DIR)
tokenizer.save_pretrained(MODEL_DIR)

manifest = {
    "task": TASK,
    "model_name": MODEL_NAME,
    "max_length": MAX_LENGTH,
    "epochs": EPOCHS,
    "batch_size": BATCH_SIZE,
    "learning_rate": LEARNING_RATE,
    "include_label_hints": INCLUDE_LABEL_HINTS,
    "drop_ambiguous_texts": DROP_AMBIGUOUS_TEXTS,
    "use_class_weights": USE_CLASS_WEIGHTS,
    "labels": label_names,
    "train_size": int(len(train_df)),
    "test_size": int(len(test_df)),
    "accuracy": float(accuracy),
    "metrics_csv": str(TABLE_DIR / f"{TASK}_distilbert_metrics.csv"),
    "predictions_csv": str(TABLE_DIR / f"{TASK}_distilbert_predictions.csv"),
    "confusion_matrix_png": str(FIGURE_DIR / f"{TASK}_distilbert_confusion_matrix.png"),
    "model_dir": str(MODEL_DIR),
}

with open(OUTPUT_DIR / f"{TASK}_distilbert_manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

manifest
"""
    ),
    md(
        r"""
## 13. Paper Interpretation Template

Suggested wording:

> DistilBERT was fine-tuned as a lightweight transformer baseline for intermediate incident classification. Each input sample was constructed from incident-level telemetry abstraction rather than raw flow rows. The model was evaluated using accuracy, precision, recall, F1-score, and confusion matrix. These metrics validate the classification/mapping component of the pipeline, while the final CTI narrative quality is evaluated separately using clarity, actionability, analyst alignment, and unsupported-claim analysis.

Important limitation:

> DistilBERT does not generate CTI reports and does not perform analyst reasoning. Its role is restricted to quantitative validation of intermediate classification tasks.
"""
    ),
]

notebook = {
    "cells": cells,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "pygments_lexer": "ipython3"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

output = Path("notebooks/full_cti_experiment_DistilBERT.ipynb")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(notebook, indent=2), encoding="utf-8")
print(f"Wrote {output}")
