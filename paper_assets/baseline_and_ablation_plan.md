# Baseline and Ablation Plan

## Baselines

| Baseline | Description | Purpose |
|---|---|---|
| Template-only CTI | Deterministic report generated from incident abstraction | Measures structured reporting quality without LLM fluency |
| LLM without MITRE | LLM receives incident abstraction but no ATT&CK context | Measures contribution of threat knowledge alignment |
| LLM with MITRE | LLM receives incident abstraction plus ATT&CK mapping | Main proposed setting |
| Raw-summary baseline | Summary generated from simple label/time/IP statistics | Tests whether incident abstraction improves clarity |
| Analyst-authored report | Human analyst writes report for same incident | Qualitative gold/reference baseline |

## Ablation Variables

| Ablation | Removed Component | Expected Effect |
|---|---|---|
| No incident abstraction | Raw telemetry summary only | Lower clarity and higher cognitive load |
| No MITRE mapping | Remove tactic/technique context | Lower analyst alignment and consistency |
| No XAI evidence | Remove rules and traceability notes | Lower explainability and auditability |
| No CVE/CVSS enrichment | Remove vulnerability context | Lower actionability for service exposure cases |

## Recommended Evaluation Table

| Setting | Clarity | Actionability | Analyst Alignment | Unsupported Claims | Traceability Score |
|---|---:|---:|---:|---:|---:|
| Template-only CTI | TBD | TBD | TBD | TBD | TBD |
| LLM without MITRE | TBD | TBD | TBD | TBD | TBD |
| LLM with MITRE | TBD | TBD | TBD | TBD | TBD |
| Analyst-authored report | Reference | Reference | Reference | Reference | Reference |

## Notes

Accuracy, precision, recall, and F1-score should be reported only for intermediate components such as security-relevance filtering or ATT&CK mapping. Final CTI report quality should be evaluated with analyst-oriented qualitative dimensions.

