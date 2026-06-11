import csv
from pathlib import Path
from typing import Iterable

from .schemas import Incident


RUBRIC_ROWS = [
    ("clarity", "1-5", "Does the report clearly explain what happened, where, and during which time window?"),
    ("actionability", "1-5", "Does the report give useful response or triage actions without overclaiming?"),
    ("analyst_alignment", "1-5", "How closely does the generated report align with an analyst-authored report for the same incident?"),
    ("unsupported_claims", "0-5", "Count or score claims not supported by the incident abstraction. Lower is better."),
    ("notes", "free text", "Reviewer notes, disagreements, or evidence gaps."),
]


def write_evaluation_rubric(path: Path, incidents: Iterable[Incident]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["incident_id", "dimension", "score", "question"])
        for incident in incidents:
            for dimension, score, question in RUBRIC_ROWS:
                writer.writerow([incident.incident_id, dimension, score, question])

