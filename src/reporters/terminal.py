"""
logsentry.reporters.terminal — color terminal output (no deps).
"""
from __future__ import annotations

from ..analyzers.engine import AnalysisReport, Severity, SEVERITY_ORDER

RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {
    Severity.CRITICAL: "\033[91m",  # red
    Severity.HIGH:     "\033[33m",  # orange/yellow
    Severity.MEDIUM:   "\033[93m",  # bright yellow
    Severity.LOW:      "\033[96m",  # cyan
    Severity.INFO:     "\033[94m",  # blue
    Severity.CLEAN:    "\033[92m",  # green
}
ICONS = {"FAIL": "❌", "WARN": "⚠ ", "PASS": "✅", "INFO": "ℹ "}


def _bar(passed: int, total: int, width: int = 40) -> str:
    if total == 0:
        return "[" + " " * width + "]"
    filled = round(width * passed / total)
    return "[" + "█" * filled + "░" * (width - filled) + "]"


def print_report(report: AnalysisReport, verbose: bool = False) -> None:
    print()
    print("══════════════════════════════════════════════════════════════")
    print(f"  {BOLD}🛰️  LOGSENTRY — Linux Log Forensics{RESET}")
    print("══════════════════════════════════════════════════════════════")
    print(f"  Host    : {report.hostname}")
    print(f"  OS      : {report.os_info}")
    print(f"  Kernel  : {report.kernel}")
    print(f"  Time    : {report.timestamp}")
    print()
    grade_color = (COLORS[Severity.CLEAN] if report.grade in ("A", "B")
                   else COLORS[Severity.MEDIUM] if report.grade == "C"
                   else COLORS[Severity.CRITICAL])
    print(f"  {BOLD}Threat Score: {report.score}/100  Grade: "
          f"{grade_color}{report.grade}{RESET}")
    print()
    print(f"  {_bar(report.clean, report.total)} "
          f"{report.clean}/{report.total} clean")
    print()

    counts = {sev: len(report.by_severity(sev)) for sev in
              (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)}
    print(f"  CRITICAL  : {COLORS[Severity.CRITICAL]}{counts[Severity.CRITICAL]}{RESET}")
    print(f"  HIGH      : {COLORS[Severity.HIGH]}{counts[Severity.HIGH]}{RESET}")
    print(f"  MEDIUM    : {COLORS[Severity.MEDIUM]}{counts[Severity.MEDIUM]}{RESET}")
    print(f"  LOW       : {COLORS[Severity.LOW]}{counts[Severity.LOW]}{RESET}")
    print(f"  Triggered : {report.triggered}")
    print()

    issues = sorted(
        [r for r in report.results if r.is_issue],
        key=lambda r: SEVERITY_ORDER.get(r.severity, 99),
    )
    if not issues:
        print(f"  {COLORS[Severity.CLEAN]}✓ No issues detected.{RESET}\n")
        return

    print(f"  {BOLD}Findings:{RESET}")
    for r in issues:
        c = COLORS.get(r.severity, "")
        icon = ICONS.get(r.status, "•")
        print(f"  {icon} {c}[{r.severity.value:<8}]{RESET} "
              f"{BOLD}{r.title}{RESET} ({r.category})")
        print(f"         {r.detail}")
        if verbose:
            if r.recommendation:
                print(f"         Fix: {r.recommendation}")
            if r.reference:
                print(f"         Ref: {r.reference}")
            if r.iocs:
                print(f"         IOCs: {', '.join(r.iocs[:8])}"
                      f"{' …' if len(r.iocs) > 8 else ''}")
    print()
