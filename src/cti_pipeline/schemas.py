from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class Incident:
    incident_id: str
    dataset: str
    start_time: str
    end_time: str
    duration_seconds: float
    flow_count: int
    source_ips: List[str]
    destination_ips: List[str]
    dominant_protocol: str
    dominant_service: str
    top_destination_ports: List[str]
    labels: Dict[str, int]
    metrics: Dict[str, Any]
    descriptors: List[str]
    threat_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

