from hashlib import sha1
from typing import Dict, List
import pandas as pd

from .schemas import Incident


def _mode(series: pd.Series, default: str = "unknown") -> str:
    values = series.dropna().astype(str)
    if values.empty:
        return default
    return values.value_counts().index[0]


def _top_values(series: pd.Series, limit: int = 5) -> List[str]:
    values = series.dropna().astype(str)
    if values.empty:
        return []
    return values.value_counts().head(limit).index.tolist()


def _value_counts(series: pd.Series, limit: int = 8) -> Dict[str, int]:
    if series is None:
        return {}
    values = series.dropna().astype(str)
    return values.value_counts().head(limit).astype(int).to_dict()


def _numeric_sum(df: pd.DataFrame, columns: List[str]) -> Dict[str, float]:
    metrics = {}
    for col in columns:
        if col in df.columns:
            metrics[col] = float(pd.to_numeric(df[col], errors="coerce").fillna(0).sum())
    return metrics


def _descriptors(metrics: Dict[str, float], flow_count: int, duration_seconds: float, protocol: str) -> List[str]:
    desc = []
    flows_per_second = flow_count / max(duration_seconds, 1.0)
    if flows_per_second >= 100:
        desc.append("very high flow rate")
    elif flows_per_second >= 10:
        desc.append("high flow rate")
    elif flows_per_second >= 1:
        desc.append("moderate flow rate")
    else:
        desc.append("low flow rate")

    if duration_seconds >= 900:
        desc.append("sustained activity")
    elif duration_seconds <= 60:
        desc.append("short burst activity")

    orig_bytes = metrics.get("orig_ip_bytes", 0.0) + metrics.get("orig_bytes", 0.0)
    resp_bytes = metrics.get("resp_ip_bytes", 0.0) + metrics.get("resp_bytes", 0.0)
    if orig_bytes or resp_bytes:
        ratio = max(orig_bytes, resp_bytes) / max(min(orig_bytes, resp_bytes), 1.0)
        if ratio >= 10:
            desc.append("asymmetric request-response volume")

    if protocol in {"udp", "tcp"}:
        desc.append(f"{protocol.upper()}-dominant traffic")
    return desc


def _incident_id(dataset: str, group_key: str, start_time: pd.Timestamp) -> str:
    raw = f"{dataset}|{group_key}|{start_time.isoformat()}"
    return sha1(raw.encode("utf-8")).hexdigest()[:12]


def build_incidents(df: pd.DataFrame, dataset: str, window_minutes: int = 15, max_incidents: int = 20) -> List[Incident]:
    if df.empty:
        return []

    work = df.copy()
    work["time_window"] = work["datetime"].dt.floor(f"{window_minutes}min")

    if dataset == "uwf24":
        group_cols = ["time_window", "tactic", "technique", "proto", "service", "dest_port"]
    else:
        group_cols = ["time_window", "label", "src_ip", "dest_ip"]

    incidents: List[Incident] = []
    for key, group in work.groupby(group_cols, dropna=False):
        if len(group) < 2 and dataset != "uwf24":
            continue

        start = group["datetime"].min()
        end = group["datetime"].max()
        duration = max(float((end - start).total_seconds()), 1.0)
        protocol = _mode(group.get("proto", pd.Series(dtype=str)))
        service = _mode(group.get("service", pd.Series(dtype=str)))
        metrics = _numeric_sum(
            group,
            [
                "duration",
                "orig_pkts",
                "resp_pkts",
                "orig_bytes",
                "resp_bytes",
                "orig_ip_bytes",
                "resp_ip_bytes",
                "missed_bytes",
            ],
        )
        metrics["flows_per_second"] = round(len(group) / duration, 4)
        metrics["unique_source_count"] = int(group["src_ip"].nunique())
        metrics["unique_destination_count"] = int(group["dest_ip"].nunique())
        if "technique" in group.columns:
            metrics["dominant_technique"] = _mode(group["technique"], default="none")
        if "cve" in group.columns:
            metrics["dominant_cve"] = _mode(group["cve"], default="none")

        label_col = "tactic" if dataset == "uwf24" else "label"
        labels = _value_counts(group[label_col]) if label_col in group.columns else {}
        group_key = "|".join([str(x) for x in key])
        incident = Incident(
            incident_id=_incident_id(dataset, group_key, start),
            dataset=dataset,
            start_time=start.isoformat(),
            end_time=end.isoformat(),
            duration_seconds=round(duration, 3),
            flow_count=int(len(group)),
            source_ips=_top_values(group["src_ip"], limit=5),
            destination_ips=_top_values(group["dest_ip"], limit=5),
            dominant_protocol=protocol,
            dominant_service=service,
            top_destination_ports=_top_values(group.get("dest_port", pd.Series(dtype=str)), limit=5),
            labels=labels,
            metrics=metrics,
            descriptors=_descriptors(metrics, len(group), duration, protocol),
        )
        incidents.append(incident)

    incidents.sort(
        key=lambda item: (
            item.flow_count,
            item.metrics.get("orig_ip_bytes", 0) + item.metrics.get("resp_ip_bytes", 0),
        ),
        reverse=True,
    )
    return incidents[:max_incidents]
