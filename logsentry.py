#!/usr/bin/env python3
"""
logsentry — Linux log forensics CLI.

Usage:
    python logsentry.py evidence.json [options]
    sudo python logsentry.py --collect [--since "24 hours ago"]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Register detectors via decorator
import src.analyzers.detectors  # noqa: F401

from src.analyzers.engine import (
    AnalysisEngine, AnalysisReport, Severity, SEVERITY_ORDER,
)
from src.reporters.terminal import print_report


def run_collector(since: str) -> dict:
    script = Path(__file__).resolve().parent / "scripts" / "collect.sh"
    if not script.exists():
        print(f"❌ collector not found at {script}", file=sys.stderr)
        sys.exit(2)
    fd, tmp = tempfile.mkstemp(prefix="logsentry-", suffix=".json")
    os.close(fd)
    try:
        subprocess.check_call(
            ["bash", str(script), "--since", since, "--out", tmp]
        )
        with open(tmp, "r", encoding="utf-8") as f:
            return json.load(f)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def filter_report(report: AnalysisReport, category: str | None,
                  severity: str | None) -> AnalysisReport:
    items = list(report.results)
    if category:
        items = [r for r in items if r.category.lower() == category.lower()]
    if severity:
        min_o = SEVERITY_ORDER[Severity(severity)]
        items = [r for r in items if SEVERITY_ORDER.get(r.severity, 99) <= min_o]
    return AnalysisReport(
        hostname=report.hostname, os_info=report.os_info,
        kernel=report.kernel, timestamp=report.timestamp, results=items,
    )


def main() -> None:
    p = argparse.ArgumentParser(
        prog="logsentry",
        description="🛰️  Linux log forensics — collects, scores and surfaces suspicious activity",
    )
    p.add_argument("evidence", nargs="?", help="evidence.json from scripts/collect.sh")
    p.add_argument("--collect", action="store_true",
                   help="Run scripts/collect.sh now and analyze its output")
    p.add_argument("--since", default="24 hours ago",
                   help='Time window for collector (default: "24 hours ago")')
    p.add_argument("--output", "-o", default=None,
                   help="Export report to Excel (.xlsx)")
    p.add_argument("--json", "-j", default=None,
                   help="Export findings to JSON")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show fix recommendations and IOCs in terminal output")
    p.add_argument("--category", "-c", default=None,
                   help="Filter to a category (Auth, Sudo, Users, Firewall, Kernel, Packages)")
    p.add_argument("--severity", "-s", default=None,
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                   help="Filter to a minimum severity")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="Exit with code 1 if any CRITICAL findings exist (CI-friendly)")

    args = p.parse_args()

    if args.collect:
        evidence = run_collector(args.since)
    else:
        if not args.evidence:
            p.error("provide evidence.json or use --collect")
        with open(args.evidence, "r", encoding="utf-8") as f:
            evidence = json.load(f)

    print(f"🔍 Analyzing log evidence (host: {evidence.get('meta',{}).get('hostname','?')})...")
    report = AnalysisEngine(evidence).run()

    filtered = filter_report(report, args.category, args.severity)
    print_report(filtered, verbose=args.verbose)

    if args.output:
        try:
            from src.reporters.excel_reporter import ExcelReporter
            path = ExcelReporter(report).generate(args.output)
            print(f"📊 Excel report saved: {path}")
        except ImportError:
            print("❌ openpyxl not installed. Run: pip install openpyxl")

    if args.json:
        out = {
            "meta": report.summary(),
            "results": [
                {
                    "id": r.check_id, "category": r.category, "title": r.title,
                    "severity": r.severity.value, "status": r.status,
                    "detail": r.detail, "recommendation": r.recommendation,
                    "reference": r.reference, "iocs": r.iocs,
                }
                for r in report.results
            ],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"📄 JSON report saved: {args.json}")

    if args.fail_on_critical:
        crits = report.by_severity(Severity.CRITICAL)
        if crits:
            print(f"💥 {len(crits)} CRITICAL finding(s) — exiting with code 1")
            sys.exit(1)


if __name__ == "__main__":
    main()
