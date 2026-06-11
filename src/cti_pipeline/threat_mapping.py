from typing import Dict

from .schemas import Incident


TECHNIQUE_NAMES = {
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1498": "Network Denial of Service",
    "T1595": "Active Scanning",
}


def _ddos_context(incident: Incident) -> Dict[str, object]:
    labels = {label.lower() for label in incident.labels}
    label_text = " ".join(labels)
    if any(token in label_text for token in ["syn", "ddos", "attack", "suspicious"]):
        return {
            "tactic": "Impact",
            "technique_id": "T1498",
            "technique_name": TECHNIQUE_NAMES["T1498"],
            "confidence": "medium",
            "rationale": "High-volume traffic labels and repeated flows are consistent with denial-of-service behavior.",
            "cve": "none",
            "cve_note": "No CVE is asserted from flow-only evidence.",
        }
    return {
        "tactic": "none",
        "technique_id": "none",
        "technique_name": "none",
        "confidence": "low",
        "rationale": "No malicious behavior label is present in the incident abstraction.",
        "cve": "none",
        "cve_note": "No CVE context available.",
    }


def enrich_threat_context(incident: Incident) -> Incident:
    if incident.dataset != "uwf24":
        incident.threat_context = _ddos_context(incident)
        return incident

    tactic = next(iter(incident.labels.keys()), "none")
    technique_id = str(incident.metrics.get("dominant_technique", "none"))
    cve = str(incident.metrics.get("dominant_cve", "none"))

    if technique_id in {"Duplicate", "nan", "None", ""}:
        technique_id = "none"

    # Fall back to common mappings when the dataset marks duplicated rows
    # instead of repeating a technique label.
    if technique_id == "none" and tactic == "Credential Access":
        technique_id = "T1110"
    elif technique_id == "none" and tactic == "Reconnaissance":
        technique_id = "T1595"
    elif technique_id == "none" and tactic == "Exfiltration":
        technique_id = "T1048"
    elif technique_id == "none" and tactic == "Defense Evasion":
        technique_id = "T1078"
    elif technique_id == "none" and tactic == "Initial Access":
        technique_id = "T1190"

    incident.threat_context = {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": TECHNIQUE_NAMES.get(technique_id, "not mapped"),
        "confidence": "high" if technique_id != "none" else "low",
        "rationale": "Mapping is derived from UWF-ZeekData24 ATT&CK labels and incident-level aggregation.",
        "cve": cve,
        "cve_note": "CVE enrichment is contextual only; this pipeline does not assert confirmed exploitation.",
    }
    return incident


def enrich_incidents(incidents):
    return [enrich_threat_context(incident) for incident in incidents]
