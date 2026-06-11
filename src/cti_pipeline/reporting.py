import json
import os
from typing import Iterable

from .schemas import Incident


SYSTEM_PROMPT = """You are a cyber threat intelligence analyst.
Generate a concise analyst-style CTI report only from the provided incident abstraction.
Do not mention raw log rows. Do not infer attribution, exploitation, malware family, or attacker identity.
If evidence is insufficient, state the limitation clearly."""


def build_prompt(incident: Incident) -> str:
    payload = json.dumps(incident.to_dict(), indent=2, sort_keys=True)
    return f"""{SYSTEM_PROMPT}

Required sections:
1. Incident Summary
2. Observed Behavior
3. Threat Context
4. Potential Impact
5. Recommended Analyst Actions
6. Evidence Limitations

Incident abstraction JSON:
{payload}
"""


def _potential_impact(ctx) -> str:
    technique_id = ctx.get("technique_id", "none")
    tactic = ctx.get("tactic", "none")
    if technique_id == "T1498":
        return (
            "The observed traffic pattern may affect service availability by saturating the targeted host, "
            "network path, or upstream filtering capacity. The telemetry supports availability-risk assessment, "
            "but it does not by itself confirm outage duration or business impact."
        )
    if technique_id == "T1110":
        return (
            "The mapped behavior may indicate repeated authentication attempts or credential pressure against "
            "the exposed service. Potential impact includes account lockout, unauthorized access attempts, and "
            "increased authentication infrastructure load, pending corroboration from authentication logs."
        )
    if technique_id == "T1595":
        return (
            "The mapped behavior may indicate external or internal service discovery. Potential impact is mainly "
            "reconnaissance exposure: attackers may use discovered services to plan later access attempts."
        )
    if tactic not in {"none", ""}:
        return (
            f"The incident is aligned with the `{tactic}` tactic. Operational impact should be assessed by "
            "correlating the affected service with asset criticality and supporting host or application logs."
        )
    return (
        "No ATT&CK technique is asserted for this incident. Impact should be limited to observable network "
        "conditions and validated against surrounding alerts before escalation."
    )


def _recommended_actions(ctx) -> str:
    technique_id = ctx.get("technique_id", "none")
    if technique_id == "T1498":
        actions = [
            "Confirm whether the target experienced packet loss, saturation, latency, or service degradation during the incident window.",
            "Review upstream firewall, rate-limit, CDN, or DDoS protection telemetry for matching spikes.",
            "Check whether the source and target relationship is expected; escalate repeated high-rate sources for blocking or scrubbing policy review.",
        ]
    elif technique_id == "T1110":
        actions = [
            "Correlate the window with authentication logs for failed logins, account lockouts, or repeated attempts against the same accounts.",
            "Validate whether the exposed service and port are expected for the destination assets.",
            "Review MFA, password policy, and source reputation before deciding containment.",
        ]
    elif technique_id == "T1595":
        actions = [
            "Check whether the scanned services are intentionally exposed and covered by monitoring.",
            "Review firewall logs for repeated probing from the same sources across adjacent ports or hosts.",
            "Prioritize remediation for exposed services with known vulnerabilities or weak access controls.",
        ]
    else:
        actions = [
            "Validate whether the source and destination hosts are expected to communicate during this time window.",
            "Check service exposure and firewall policy for the listed destination ports.",
            "Correlate this incident with IDS alerts, authentication logs, endpoint telemetry, and asset criticality.",
        ]
    actions.append("Treat CVE context as enrichment only unless confirmed by vulnerability scanning or exploit evidence.")
    return "\n".join(f"- {action}" for action in actions)


def render_template_report(incident: Incident) -> str:
    ctx = incident.threat_context
    ports = ", ".join(incident.top_destination_ports) or "unknown"
    sources = ", ".join(incident.source_ips[:3]) or "unknown"
    destinations = ", ".join(incident.destination_ips[:3]) or "unknown"
    descriptors = ", ".join(incident.descriptors) or "no qualitative descriptor"

    return f"""## Incident {incident.incident_id}

### Incident Summary
An incident window from {incident.start_time} to {incident.end_time} contains {incident.flow_count} related flow records between source(s) {sources} and destination(s) {destinations}. The dominant protocol is {incident.dominant_protocol}, with dominant service {incident.dominant_service} and destination port(s) {ports}.

### Observed Behavior
The abstraction characterizes the activity as {descriptors}. The summarized telemetry shows {incident.metrics.get('flows_per_second', 0)} flows per second across the incident window.

### Threat Context
The behavior is mapped to MITRE ATT&CK tactic `{ctx.get('tactic', 'none')}` and technique `{ctx.get('technique_id', 'none')}` ({ctx.get('technique_name', 'not mapped')}). Mapping confidence is {ctx.get('confidence', 'unknown')}. Rationale: {ctx.get('rationale', 'No rationale available')}

### Potential Impact
{_potential_impact(ctx)}

### Recommended Analyst Actions
{_recommended_actions(ctx)}

### Evidence Limitations
This report is generated from incident-level network telemetry abstraction. It does not prove attacker identity, malware use, successful exploitation, or confirmed business impact.
"""


def render_reports(incidents: Iterable[Incident]) -> str:
    return "\n\n".join(render_template_report(incident) for incident in incidents)


def render_openai_report(incident: Incident, model: str) -> str:
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise RuntimeError("Install openai or run without --use-llm.") from exc

    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is not set.")

    client = OpenAI()
    response = client.responses.create(
        model=model,
        input=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(incident)},
        ],
    )
    return response.output_text
