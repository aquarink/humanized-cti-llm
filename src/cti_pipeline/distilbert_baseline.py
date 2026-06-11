from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


UWF24_USECOLS = [
    "conn_state",
    "duration",
    "history",
    "src_ip_zeek",
    "src_port_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "missed_bytes",
    "orig_bytes",
    "orig_ip_bytes",
    "orig_pkts",
    "proto",
    "resp_bytes",
    "resp_ip_bytes",
    "resp_pkts",
    "service",
    "datetime",
    "label_tactic",
    "label_technique",
    "label_binary",
    "label_cve",
]


@dataclass
class DistilBertBaselineConfig:
    task: str = "uwf24_tactic"
    model_name: str = "distilbert-base-uncased"
    max_length: int = 256
    max_incidents_per_class: Optional[int] = 3000
    min_samples_per_class: int = 2
    batch_size: int = 16
    epochs: int = 2
    learning_rate: float = 2e-5
    seed: int = 42
    include_label_hints: bool = False
    drop_ambiguous_texts: bool = True
    use_class_weights: bool = True
    test_size: float = 0.2

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def set_reproducibility(seed: int) -> None:
    import random

    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def get_device():
    import torch

    if torch.cuda.is_available():
        return torch.device("cuda")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


def mode_or_unknown(series: pd.Series) -> str:
    values = series.dropna().astype(str)
    if values.empty:
        return "unknown"
    return values.value_counts().index[0]


def top_values(series: pd.Series, n: int = 3) -> List[str]:
    values = series.dropna().astype(str)
    return values.value_counts().head(n).index.tolist()


def safe_sum(group: pd.DataFrame, column: str) -> float:
    if column not in group.columns:
        return 0.0
    return float(pd.to_numeric(group[column], errors="coerce").fillna(0).sum())


def load_uwf24(root: Path, limit_files: Optional[int] = None, nrows_per_file: Optional[int] = None) -> pd.DataFrame:
    files = sorted(root.glob("**/*.csv"))
    if limit_files:
        files = files[:limit_files]
    frames = []
    for path in files:
        df = pd.read_csv(
            path,
            usecols=lambda column: column in UWF24_USECOLS,
            nrows=nrows_per_file,
            low_memory=False,
        )
        df["source_file"] = str(path)
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"No UWF-ZeekData24 CSV files found in {root}")
    df = pd.concat(frames, ignore_index=True)
    df = df.rename(
        columns={
            "src_ip_zeek": "src_ip",
            "dest_ip_zeek": "dest_ip",
            "src_port_zeek": "src_port",
            "dest_port_zeek": "dest_port",
            "label_tactic": "tactic",
            "label_technique": "technique",
            "label_cve": "cve",
        }
    )
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format="ISO8601")
    return df.dropna(subset=["datetime", "src_ip", "dest_ip"])


def load_simple_ddos(path: Path, sep: str = ",", timestamp_format: Optional[str] = None) -> pd.DataFrame:
    df = pd.read_csv(path, sep=sep, encoding="utf-8-sig", low_memory=False)
    df = df.rename(
        columns={
            "Source IP": "src_ip",
            "Destination IP": "dest_ip",
            "Timestamp": "datetime",
            "Label": "label",
        }
    )
    df = df[df["label"].astype(str).str.lower() != "label"].copy()
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format=timestamp_format)
    df = df.dropna(subset=["datetime", "src_ip", "dest_ip"])
    df["proto"] = "unknown"
    df["service"] = "unknown"
    df["dest_port"] = "unknown"
    return df


def build_uwf24_incident_texts(
    df: pd.DataFrame,
    task: str = "uwf24_tactic",
    window_minutes: int = 15,
    include_label_hints: bool = False,
) -> pd.DataFrame:
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
        if orig_bytes or resp_bytes:
            byte_asymmetry_ratio = max(orig_bytes, resp_bytes) / max(min(orig_bytes, resp_bytes), 1.0)
        else:
            byte_asymmetry_ratio = 0.0
        tactic = mode_or_unknown(group["tactic"])
        technique = mode_or_unknown(group["technique"])
        binary = "malicious" if str(tactic).lower() != "none" else "benign"
        label = tactic if task == "uwf24_tactic" else binary
        text = (
            "Incident telemetry abstraction. "
            f"Flow count: {flow_count}. Duration seconds: {duration_seconds:.2f}. "
            f"Flows per second: {flows_per_second:.4f}. "
            f"Dominant protocol: {mode_or_unknown(group['proto'])}. "
            f"Dominant service: {mode_or_unknown(group['service'])}. "
            f"Destination ports: {', '.join(top_values(group['dest_port']))}. "
            f"Unique sources: {group['src_ip'].nunique()}. Unique destinations: {group['dest_ip'].nunique()}. "
            f"Originator bytes: {orig_bytes:.0f}. Responder bytes: {resp_bytes:.0f}. "
            f"Byte asymmetry ratio: {byte_asymmetry_ratio:.4f}."
        )
        if include_label_hints:
            text += f" MITRE technique label in abstraction: {technique}."
        rows.append(
            {
                "text": text,
                "label": label,
                "tactic": tactic,
                "technique": technique,
                "flow_count": flow_count,
                "flows_per_second": flows_per_second,
                "byte_asymmetry_ratio": byte_asymmetry_ratio,
            }
        )
    return pd.DataFrame(rows)


def build_simple_ddos_incident_texts(df: pd.DataFrame, task_name: str, window_minutes: int = 15) -> pd.DataFrame:
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
            "Dominant protocol: unknown. Dominant service: unknown."
        )
        rows.append({"text": text, "label": label, "raw_label": label_raw, "flow_count": flow_count})
    return pd.DataFrame(rows)


def find_ambiguous_texts(dataset_df: pd.DataFrame) -> pd.DataFrame:
    ambiguous = (
        dataset_df.groupby("text")["label"]
        .nunique()
        .reset_index(name="label_count")
        .query("label_count > 1")
    )
    if ambiguous.empty:
        return dataset_df.iloc[0:0].copy()
    return dataset_df[dataset_df["text"].isin(ambiguous["text"])].sort_values("text")


def prepare_training_frame(dataset_df: pd.DataFrame, config: DistilBertBaselineConfig) -> Tuple[pd.DataFrame, Dict[int, str], Dict[str, int]]:
    counts = dataset_df["label"].value_counts()
    valid_labels = counts[counts >= config.min_samples_per_class].index
    filtered = dataset_df[dataset_df["label"].isin(valid_labels)].copy()
    if config.drop_ambiguous_texts:
        label_counts_by_text = filtered.groupby("text")["label"].transform("nunique")
        filtered = filtered[label_counts_by_text == 1].copy()

    if config.max_incidents_per_class is not None:
        parts = []
        for _, group in filtered.groupby("label"):
            n = min(len(group), config.max_incidents_per_class)
            parts.append(group.sample(n=n, random_state=config.seed))
        filtered = pd.concat(parts, ignore_index=True)

    balanced = filtered.sample(frac=1, random_state=config.seed).reset_index(drop=True)
    label_names = sorted(balanced["label"].unique())
    label2id = {label: i for i, label in enumerate(label_names)}
    id2label = {i: label for label, i in label2id.items()}
    balanced["label_id"] = balanced["label"].map(label2id)
    return balanced, id2label, label2id


def split_training_frame(
    df: pd.DataFrame,
    config: DistilBertBaselineConfig,
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    stratify = df["label_id"] if df["label_id"].value_counts().min() >= 2 else None
    return train_test_split(
        df,
        test_size=config.test_size,
        random_state=config.seed,
        stratify=stratify,
    )


def encode_texts(tokenizer, texts: pd.Series, max_length: int):
    return tokenizer(
        list(texts),
        padding=True,
        truncation=True,
        max_length=max_length,
        return_tensors="pt",
    )


def make_dataloaders(train_df: pd.DataFrame, test_df: pd.DataFrame, tokenizer, config: DistilBertBaselineConfig):
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    train_enc = encode_texts(tokenizer, train_df["text"], config.max_length)
    test_enc = encode_texts(tokenizer, test_df["text"], config.max_length)
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
    return (
        DataLoader(train_dataset, batch_size=config.batch_size, shuffle=True),
        DataLoader(test_dataset, batch_size=config.batch_size),
    )


def train_model(model, train_loader, train_df: pd.DataFrame, label_names: List[str], config: DistilBertBaselineConfig, device) -> List[float]:
    import torch

    if config.use_class_weights:
        class_counts = train_df["label_id"].value_counts().sort_index()
        weights = len(train_df) / (len(label_names) * class_counts)
        class_weights = torch.tensor(weights.values, dtype=torch.float).to(device)
    else:
        class_weights = None

    optimizer = torch.optim.AdamW(model.parameters(), lr=config.learning_rate)
    losses = []
    for _ in range(config.epochs):
        model.train()
        total_loss = 0.0
        for input_ids, attention_mask, labels in train_loader:
            input_ids = input_ids.to(device)
            attention_mask = attention_mask.to(device)
            labels = labels.to(device)
            optimizer.zero_grad()
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            loss = torch.nn.functional.cross_entropy(outputs.logits, labels, weight=class_weights)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        losses.append(total_loss / max(len(train_loader), 1))
    return losses


def predict_model(model, loader, device):
    import torch

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


def evaluate_predictions(y_true, y_pred, label_names: List[str]) -> Tuple[Dict[str, object], pd.DataFrame]:
    labels = list(range(len(label_names)))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        zero_division=0,
    )
    metrics_df = pd.DataFrame(
        {
            "label": label_names,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
    )
    result = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(metrics_df["f1"].mean()),
        "weighted_f1": float(np.average(metrics_df["f1"], weights=metrics_df["support"])),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).astype(int).tolist(),
        "classification_report": classification_report(y_true, y_pred, target_names=label_names, zero_division=0),
    }
    return result, metrics_df


def token_occlusion_importance(model, tokenizer, text: str, device, target_label_id: Optional[int] = None, max_tokens: int = 80) -> pd.DataFrame:
    import torch

    model.eval()
    encoded = tokenizer(text, truncation=True, max_length=tokenizer.model_max_length, return_tensors="pt")
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
        i
        for i, token in enumerate(tokens)
        if token not in [tokenizer.cls_token, tokenizer.sep_token, tokenizer.pad_token]
    ][:max_tokens]
    for pos in candidate_positions:
        masked_ids = input_ids.clone()
        masked_ids[0, pos] = tokenizer.mask_token_id if tokenizer.mask_token_id is not None else tokenizer.unk_token_id
        with torch.no_grad():
            logits = model(input_ids=masked_ids, attention_mask=attention_mask).logits
            probs = torch.softmax(logits, dim=1)[0]
        score = float(probs[target_label_id].item())
        rows.append(
            {
                "token": tokens[pos],
                "base_score": base_score,
                "masked_score": score,
                "importance": base_score - score,
            }
        )
    return pd.DataFrame(rows).sort_values("importance", ascending=False)
