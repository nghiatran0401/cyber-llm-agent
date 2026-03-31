from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class UserQuery:
    raw: str
    input_type: str  # technique | ip | hash | log | unknown


@dataclass
class RetrievedContext:
    document: str
    metadata: Dict[str, Any]
    score: float


@dataclass
class MITRETechniqueResponse:
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    detection: str
    mitigations: str
    error: Optional[str] = None


@dataclass
class OTXThreatIntelResponse:
    indicator: str
    type: str
    reputation: str
    pulse_count: int
    malware_families_sample: List[str] = field(default_factory=list)
    total_malware_families: int = 0
    tags_sample: List[str] = field(default_factory=list)
    total_tags: int = 0
    error: Optional[str] = None


@dataclass
class UnifiedResponse:
    mitre: Optional[MITRETechniqueResponse] = None
    otx: Optional[OTXThreatIntelResponse] = None
    raw: Dict[str, Any] = field(default_factory=dict)

