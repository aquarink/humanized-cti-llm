from typing import Any, Dict, List

from .schemas import Incident


def byte_asymmetry_ratio(incident: Incident) -> float:
    metrics = incident.metrics
    orig = float(metrics.get("orig_ip_bytes", 0.0) or 0.0) + float(metrics.get("orig_bytes", 0.0) or 0.0)
    resp = float(metrics.get("resp_ip_bytes", 0.0) or 0.0) + float(metrics.get("resp_bytes", 0.0) or 0.0)
    if orig == 0 and resp == 0:
        return 0.0
    return round(max(orig, resp) / max(min(orig, resp), 1.0), 4)


def feature_evidence(incident: Incident) -> List[Dict[str, Any]]:
    evidence = [
        {
            "feature": "flow_count",
            "value": incident.flow_count,
            "interpretation": "Number of related flows in the incident time window.",
        },
        {
            "feature": "flows_per_second",
            "value": incident.metrics.get("flows_per_second", 0),
            "interpretation": "Traffic intensity normalized by incident duration.",
        },
        {
            "feature": "duration_seconds",
            "value": incident.duration_seconds,
            "interpretation": "Temporal span used to distinguish burst and sustained activity.",
        },
        {
            "feature": "dominant_protocol",
            "value": incident.dominant_protocol,
            "interpretation": "Protocol context used for analyst-readable behavior description.",
        },
        {
            "feature": "dominant_service",
            "value": incident.dominant_service,
            "interpretation": "Service context used to support triage and response actions.",
        },
        {
            "feature": "byte_asymmetry_ratio",
            "value": byte_asymmetry_ratio(incident),
            "interpretation": "Higher ratios indicate imbalanced request-response volume.",
        },
    ]
    return evidence


def rule_explanations(incident: Incident) -> List[str]:
    ctx = incident.threat_context
    technique_id = ctx.get("technique_id", "none")
    rules: List[str] = []
    if technique_id == "T1498":
        rules.append("IF label indicates DDoS/attack/suspicious AND repeated flows occur in a bounded window THEN map to Impact/T1498.")
        if incident.metrics.get("flows_per_second", 0) >= 100:
            rules.append("Very high flows_per_second strengthens the availability-risk explanation.")
    elif technique_id == "T1110":
        rules.append("IF UWF24 label_tactic is Credential Access AND label_technique is T1110 THEN map to Brute Force.")
        if byte_asymmetry_ratio(incident) >= 10:
            rules.append("High byte_asymmetry_ratio supports the observed asymmetric traffic description.")
    elif technique_id == "T1595":
        rules.append("IF UWF24 label_tactic is Reconnaissance AND label_technique is T1595 THEN map to Active Scanning.")
    elif technique_id != "none":
        rules.append("Mapping is derived from the dataset ATT&CK label and preserved through incident abstraction.")
    else:
        rules.append("No ATT&CK technique is asserted when labels and abstraction do not provide security-relevant evidence.")
    return rules


def traceability_claims(incident: Incident) -> List[Dict[str, str]]:
    ctx = incident.threat_context
    return [
        {
            "claim": "Incident time window",
            "evidence": "start_time, end_time, duration_seconds",
        },
        {
            "claim": "Observed traffic behavior",
            "evidence": "flow_count, flows_per_second, descriptors, dominant_protocol, dominant_service",
        },
        {
            "claim": "MITRE ATT&CK mapping",
            "evidence": "labels, dominant_technique, threat_context.rationale",
        },
        {
            "claim": "Potential impact",
            "evidence": f"technique_id={ctx.get('technique_id', 'none')} and observable telemetry metrics",
        },
    ]


def explanation_payload(incident: Incident) -> Dict[str, Any]:
    rules = rule_explanations(incident)
    evidence = feature_evidence(incident)
    return {
        "method": "rule-based evidence traceability",
        "feature_evidence": evidence,
        "rules": rules,
        "traceability_claims": traceability_claims(incident),
        "traceability_score": round(len(traceability_claims(incident)) / 4.0, 3),
    }


def add_explanations(incidents):
    for incident in incidents:
        incident.explanations = explanation_payload(incident)
    return incidents
