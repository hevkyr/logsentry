"""
logsentry.analyzers.engine — core engine, registry, data model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    CLEAN = "CLEAN"


SEVERITY_ORDER: Dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.CLEAN: 5,
}


@dataclass
class DetectorResult:
    check_id: str
    category: str
    title: str
    severity: Severity
    status: str  # FAIL | WARN | PASS | INFO
    detail: str = ""
    recommendation: str = ""
    reference: str = ""
    iocs: List[str] = field(default_factory=list)

    @property
    def is_issue(self) -> bool:
        return self.status in ("FAIL", "WARN")


@dataclass
class AnalysisReport:
    hostname: str
    os_info: str
    kernel: str
    timestamp: str  # dd/mm/yyyy HH:MM:SS
    results: List[DetectorResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def clean(self) -> int:
        return sum(1 for r in self.results if not r.is_issue)

    @property
    def triggered(self) -> int:
        return sum(1 for r in self.results if r.is_issue)

    @property
    def score(self) -> int:
        if not self.results:
            return 0
        return round(100 * self.clean / self.total)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90: return "A"
        if s >= 80: return "B"
        if s >= 70: return "C"
        if s >= 60: return "D"
        return "F"

    def by_severity(self, sev: Severity) -> List[DetectorResult]:
        return [r for r in self.results if r.severity == sev and r.is_issue]

    def by_category(self) -> Dict[str, List[DetectorResult]]:
        out: Dict[str, List[DetectorResult]] = {}
        for r in self.results:
            out.setdefault(r.category, []).append(r)
        return out

    def all_iocs(self) -> List[str]:
        seen, out = set(), []
        for r in self.results:
            for i in r.iocs:
                if i not in seen:
                    seen.add(i); out.append(i)
        return out

    def summary(self) -> dict:
        return {
            "hostname": self.hostname,
            "os": self.os_info,
            "kernel": self.kernel,
            "timestamp": self.timestamp,
            "score": self.score,
            "grade": self.grade,
            "total_detectors": self.total,
            "clean": self.clean,
            "triggered": self.triggered,
            "critical": len(self.by_severity(Severity.CRITICAL)),
            "high": len(self.by_severity(Severity.HIGH)),
            "medium": len(self.by_severity(Severity.MEDIUM)),
            "low": len(self.by_severity(Severity.LOW)),
        }


# ----------------------- registry ------------------------------ #

DetectorFn = Callable[[dict], DetectorResult]
_REGISTRY: List[DetectorFn] = []


def detector(fn: DetectorFn) -> DetectorFn:
    """Decorator to register a detector function."""
    _REGISTRY.append(fn)
    return fn


def registry() -> List[DetectorFn]:
    return list(_REGISTRY)


class AnalysisEngine:
    """Runs all registered detectors against an evidence bundle."""

    def __init__(self, evidence: dict) -> None:
        self.evidence = evidence

    def run(self) -> AnalysisReport:
        meta = self.evidence.get("meta", {})
        from datetime import datetime
        report = AnalysisReport(
            hostname=meta.get("hostname", "unknown"),
            os_info=meta.get("os", "unknown"),
            kernel=meta.get("kernel", "unknown"),
            timestamp=meta.get("collected_at",
                               datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
        )
        for fn in registry():
            try:
                report.results.append(fn(self.evidence))
            except Exception as e:  # detectors must never crash the run
                report.results.append(DetectorResult(
                    check_id=getattr(fn, "__name__", "DETECTOR"),
                    category="Engine", title=fn.__name__,
                    severity=Severity.INFO, status="WARN",
                    detail=f"detector raised: {e!r}",
                ))
        return report
