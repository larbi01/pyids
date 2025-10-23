# pyids/detectors/base.py
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List

@dataclass
class Alert:
    kind: str
    severity: str       # "low" "medium" "high"
    message: str
    ts: float           # epoch in seconds
    src: str | None = None
    dst: str | None = None
    meta: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class Detector:
    """Interface: each detector consumes a packet and may yield 0..N alerts."""
    def process(self, pkt, now: float) -> List[Alert]:
        raise NotImplementedError
