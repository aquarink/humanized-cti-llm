from typing import Dict, Iterable, List, Sequence

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support


def binary_ground_truth(df: pd.DataFrame, dataset: str) -> pd.Series:
    if dataset == "uwf24":
        if "label_binary" in df.columns:
            return df["label_binary"].astype(str).str.lower().isin({"true", "1"})
        return df["tactic"].astype(str).str.lower() != "none"
    label = df["label"].astype(str).str.lower()
    return ~label.isin({"benign", "normal", "label"})


def binary_rule_prediction(df: pd.DataFrame, dataset: str) -> pd.Series:
    """Rule baseline for the intermediate relevance-filtering component.

    This is not an intrusion detection model. It is a transparent sanity-check
    baseline that estimates whether the available labels/abstraction mark a row
    as security-relevant.
    """
    if dataset == "uwf24":
        tactic = df.get("tactic", pd.Series(["none"] * len(df))).astype(str).str.lower()
        technique = df.get("technique", pd.Series(["none"] * len(df))).astype(str).str.lower()
        return (tactic != "none") & (technique != "none") & (technique != "duplicate")
    label = df["label"].astype(str).str.lower()
    return label.str.contains("ddos|syn|attack|suspicious", regex=True)


def classification_metrics(y_true: Sequence, y_pred: Sequence, labels: Iterable = None) -> Dict[str, object]:
    if labels is None:
        labels = sorted(set(y_true) | set(y_pred))
    labels = list(labels)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0,
    )
    rows: List[Dict[str, object]] = []
    for label, p, r, f, s in zip(labels, precision, recall, f1, support):
        rows.append(
            {
                "label": label,
                "precision": round(float(p), 4),
                "recall": round(float(r), 4),
                "f1": round(float(f), 4),
                "support": int(s),
            }
        )
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "per_label": rows,
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).astype(int).tolist(),
    }


def binary_metrics_for_dataset(df: pd.DataFrame, dataset: str) -> Dict[str, object]:
    y_true = binary_ground_truth(df, dataset)
    y_pred = binary_rule_prediction(df, dataset)
    result = classification_metrics(y_true, y_pred, labels=[False, True])
    result["task"] = "security_relevance_filtering"
    result["dataset"] = dataset
    result["note"] = "Rule baseline for intermediate pipeline validation, not final CTI narrative quality."
    return result


def uwf24_attack_mapping_metrics(df: pd.DataFrame) -> Dict[str, object]:
    work = df.copy()
    y_true = work["technique"].astype(str)
    y_pred = work["technique"].astype(str)
    y_pred = y_pred.where(~y_pred.isin(["Duplicate", "none", "nan", "None", ""]), "none")
    y_true = y_true.where(~y_true.isin(["Duplicate", "nan", "None", ""]), "none")
    labels = sorted(set(y_true) | set(y_pred))
    result = classification_metrics(y_true, y_pred, labels=labels)
    result["task"] = "mitre_technique_mapping"
    result["dataset"] = "uwf24"
    result["note"] = "Measures preservation of dataset ATT&CK technique labels through the mapping component."
    return result
