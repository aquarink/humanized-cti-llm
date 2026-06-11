from pathlib import Path
from typing import Iterable, List, Optional

import pandas as pd


DATASET_ROOT = Path("datasets")


def _read_csv(path: Path, sep: str = ",", nrows: Optional[int] = None, usecols=None) -> pd.DataFrame:
    return pd.read_csv(path, sep=sep, encoding="utf-8-sig", nrows=nrows, low_memory=False, usecols=usecols)


def load_simple_ddos(name: str, nrows: Optional[int] = None) -> pd.DataFrame:
    if name == "syn":
        path = DATASET_ROOT / "Syn.csv"
        sep = ","
    elif name == "sdn-syn":
        path = DATASET_ROOT / "SDN-TCP-SYN ATTACK-DDOS-CLEAN.csv"
        sep = ";"
    elif name == "bccc":
        path = DATASET_ROOT / "BCCC-Cpacket-Cloud-DDoS-2024.csv"
        sep = ","
    else:
        raise ValueError(f"Unsupported simple DDoS dataset: {name}")

    df = _read_csv(path, sep=sep, nrows=nrows)
    df = df.rename(
        columns={
            "Source IP": "src_ip",
            "Destination IP": "dest_ip",
            "Timestamp": "datetime",
            "Label": "label",
        }
    )
    df = df[df["label"].astype(str).str.lower() != "label"].copy()
    df["dataset"] = name
    if name == "sdn-syn":
        df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format="%d/%m/%y %H.%M")
    else:
        df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce")
    df = df.dropna(subset=["datetime", "src_ip", "dest_ip"])
    df["proto"] = "unknown"
    df["service"] = "unknown"
    df["dest_port"] = "unknown"
    return df


def uwf24_files(limit_files: Optional[int] = None) -> List[Path]:
    files = sorted((DATASET_ROOT / "UWF-ZeekData24-csv").glob("*/*.csv"))
    if limit_files:
        return files[:limit_files]
    return files


def load_uwf24(limit_files: Optional[int] = None, nrows_per_file: Optional[int] = None) -> pd.DataFrame:
    frames = []
    usecols = [
        "community_id",
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
    for path in uwf24_files(limit_files):
        df = _read_csv(path, nrows=nrows_per_file, usecols=usecols)
        df["source_file"] = str(path)
        frames.append(df)
    if not frames:
        raise FileNotFoundError("No UWF-ZeekData24 CSV files found.")

    df = pd.concat(frames, ignore_index=True)
    df = df.rename(
        columns={
            "src_ip_zeek": "src_ip",
            "dest_ip_zeek": "dest_ip",
            "dest_port_zeek": "dest_port",
            "src_port_zeek": "src_port",
            "label_tactic": "tactic",
            "label_technique": "technique",
            "label_cve": "cve",
        }
    )
    df["dataset"] = "uwf24"
    df["datetime"] = pd.to_datetime(df["datetime"], errors="coerce", format="ISO8601")
    df = df.dropna(subset=["datetime", "src_ip", "dest_ip"])
    return df


def filter_security_relevant(df: pd.DataFrame, dataset: str, include_benign: bool = False) -> pd.DataFrame:
    if include_benign:
        return df
    if dataset == "uwf24":
        if "tactic" not in df.columns:
            return df
        return df[df["tactic"].astype(str).str.lower() != "none"].copy()
    if "label" not in df.columns:
        return df
    benign_labels = {"benign", "normal"}
    return df[~df["label"].astype(str).str.lower().isin(benign_labels)].copy()


def load_dataset(
    dataset: str,
    limit_files: Optional[int] = None,
    nrows: Optional[int] = None,
    include_benign: bool = False,
) -> pd.DataFrame:
    if dataset == "uwf24":
        df = load_uwf24(limit_files=limit_files, nrows_per_file=nrows)
    else:
        df = load_simple_ddos(dataset, nrows=nrows)
    return filter_security_relevant(df, dataset=dataset, include_benign=include_benign)


def iter_supported_datasets() -> Iterable[str]:
    return ("uwf24", "syn", "sdn-syn", "bccc")
