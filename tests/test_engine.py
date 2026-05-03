"""tests/test_engine.py — unit tests for engine, model and a few detectors."""
import pytest

from src.analyzers.engine import (
    AnalysisReport, AnalysisEngine, DetectorResult, Severity,
    SEVERITY_ORDER, registry,
)
import src.analyzers.detectors  # noqa: F401  (registers detectors)


# ----------------------- helpers ----------------------- #

def make_result(status="PASS", severity=Severity.HIGH, category="Test"):
    return DetectorResult(
        check_id="T-001", category=category, title="t",
        severity=severity, status=status, detail="d",
    )


def make_report(results=None):
    return AnalysisReport(
        hostname="h", os_info="Fedora 40", kernel="6.8",
        timestamp="03/05/2026 00:00:00", results=results or [],
    )


# ----------------------- DetectorResult ----------------------- #

class TestDetectorResult:
    def test_fail_is_issue(self):
        assert make_result("FAIL").is_issue is True

    def test_warn_is_issue(self):
        assert make_result("WARN").is_issue is True

    def test_pass_is_not_issue(self):
        assert make_result("PASS").is_issue is False

    def test_info_is_not_issue(self):
        assert make_result("INFO").is_issue is False


# ----------------------- AnalysisReport ----------------------- #

class TestAnalysisReport:
    def test_score_all_clean(self):
        r = make_report([make_result("PASS") for _ in range(10)])
        assert r.score == 100

    def test_score_all_failing(self):
        r = make_report([make_result("FAIL") for _ in range(10)])
        assert r.score == 0

    def test_score_half(self):
        r = make_report([make_result("PASS")] * 5 + [make_result("FAIL")] * 5)
        assert r.score == 50

    def test_grade_a(self):
        assert make_report([make_result("PASS")] * 10).grade == "A"

    def test_grade_f(self):
        assert make_report([make_result("FAIL")] * 10).grade == "F"

    def test_by_severity_only_issues(self):
        r = make_report([
            make_result("FAIL", Severity.CRITICAL),
            make_result("PASS", Severity.CRITICAL),
        ])
        assert len(r.by_severity(Severity.CRITICAL)) == 1

    def test_by_category(self):
        r = make_report([
            make_result(category="Auth"),
            make_result(category="Auth"),
            make_result(category="Sudo"),
        ])
        cats = r.by_category()
        assert len(cats["Auth"]) == 2
        assert len(cats["Sudo"]) == 1

    def test_summary_contains_keys(self):
        r = make_report([make_result("PASS"), make_result("FAIL")])
        s = r.summary()
        for k in ("hostname", "score", "grade", "total_detectors",
                  "clean", "triggered", "critical", "high"):
            assert k in s

    def test_empty_report_score(self):
        assert make_report([]).score == 0


# ----------------------- Severity order ----------------------- #

def test_critical_before_high():
    assert SEVERITY_ORDER[Severity.CRITICAL] < SEVERITY_ORDER[Severity.HIGH]


def test_clean_after_low():
    assert SEVERITY_ORDER[Severity.CLEAN] > SEVERITY_ORDER[Severity.LOW]


# ----------------------- Registry & engine ----------------------- #

def test_registry_has_detectors():
    assert len(registry()) >= 15


def test_engine_runs_on_empty_evidence():
    ev = {"meta": {"hostname": "h", "os": "x", "kernel": "y",
                   "collected_at": "03/05/2026 00:00:00"},
          "sources": {}}
    report = AnalysisEngine(ev).run()
    assert report.total == len(registry())
    # with empty sources, every detector should be CLEAN
    assert report.triggered == 0
    assert report.score == 100


def test_engine_detects_brute_force():
    failed = [f"May 03 12:00:0{i} host sshd[1]: Failed password for root from "
              f"45.155.205.233 port 22 ssh2" for i in range(60)]
    ev = {"meta": {"hostname": "h", "os": "x", "kernel": "y"},
          "sources": {"auth_sshd": failed}}
    report = AnalysisEngine(ev).run()
    titles = [r.title for r in report.results if r.is_issue]
    assert "SSH Brute-force burst" in titles
    crit = report.by_severity(Severity.CRITICAL)
    assert any("45.155.205.233" in r.iocs for r in crit)


def test_engine_detects_firewall_drops():
    ev = {"meta": {}, "sources": {
        "ufw": [f"UFW BLOCK IN=eth0 SRC=10.0.0.{i%10} DST=1.1.1.1" for i in range(120)]
    }}
    report = AnalysisEngine(ev).run()
    fw = [r for r in report.results if r.category == "Firewall" and r.is_issue]
    assert fw, "expected firewall drop finding"
