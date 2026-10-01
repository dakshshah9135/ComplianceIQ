#!/usr/bin/env python3
"""
ComplianceIQ v1.0 — GRC Risk & Compliance Analyzer
Author: Daksh Shah | github.com/dakshshah9135/complianceiq
Maps organization security controls to NIST CSF, generates risk register & compliance gap report.

Usage:
  python complianceiq.py sample_assessments/sample_org.json
  python complianceiq.py assessment.json --output report.html
  python complianceiq.py assessment.json --no-report
"""
import argparse, sys, os, datetime
from core.analyzer import analyze
from core.reporter import generate_report

RISK_C = {"CRITICAL":"\033[95m","HIGH":"\033[91m","MEDIUM":"\033[33m","LOW":"\033[92m"}
R = "\033[0m"; B = "\033[1m"; CY = "\033[96m"; GY = "\033[90m"; GR = "\033[92m"

def main():
    p = argparse.ArgumentParser(description="ComplianceIQ — GRC Risk & Compliance Analyzer")
    p.add_argument("assessment", help="Path to JSON assessment file")
    p.add_argument("--output", default=None)
    p.add_argument("--no-report", action="store_true")
    args = p.parse_args()

    if not os.path.exists(args.assessment):
        print(f"Error: '{args.assessment}' not found."); sys.exit(1)

    print(f"\n{B}🛡️  ComplianceIQ v1.0 — GRC Risk & Compliance Analyzer{R}")
    print(f"{GY}   Framework: NIST Cybersecurity Framework v1.1{R}\n{'─'*60}")

    report = analyze(args.assessment)

    print(f"\n  {B}Organization :{R} {report.org_name}")
    print(f"  {B}Industry     :{R} {report.industry}")
    print(f"  {B}Assessor     :{R} {report.assessor}")
    print(f"  {B}Controls     :{R} {report.assessed}/{report.total_controls} assessed")

    print(f"\n  {B}NIST CSF Function Maturity Scores:{R}")
    for fn, sc in report.function_scores.items():
        bar_len = int(sc/5)
        color = "\033[91m" if sc<30 else "\033[33m" if sc<50 else "\033[93m" if sc<70 else "\033[92m"
        print(f"  {color}{fn:<12}{R} {'█'*bar_len}{'░'*(20-bar_len)} {color}{B}{sc:.0f}/100{R}")

    print(f"\n  {B}Overall Maturity: {report.overall_maturity:.0f}/100{R}")

    print(f"\n  {B}Risk Register ({len(report.risk_register)} items):{R}")
    for r in report.risk_register:
        c = RISK_C.get(r.risk_level,R)
        print(f"  {c}{r.risk_level:8}{R}  Score={r.risk_score:2}  {r.id}  {r.title}")

    print(f"\n  {B}Top Compliance Gaps:{R}")
    for g in report.top_gaps:
        c = {"CRITICAL":"\033[95m","HIGH":"\033[91m","MEDIUM":"\033[33m","LOW":"\033[92m"}.get(g.priority,R)
        print(f"  {c}{g.priority:8}{R}  {CY}{g.control_id}{R}  {g.maturity_label}  {g.control_desc[:55]}...")

    print(f"\n  {B}Recommendations:{R}")
    for i,rec in enumerate(report.recommendations,1):
        print(f"  {GR}{i}.{R} {rec}")

    if not args.no_report:
        os.makedirs("reports", exist_ok=True)
        ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = args.output or f"reports/complianceiq_{report.org_name.replace(' ','_')}_{ts}.html"
        generate_report(report, out)
        print(f"\n  {GR}✓ HTML report:{R} {B}{out}{R}")

    print(f"\n{GY}  ComplianceIQ complete. For authorized GRC assessment use only.{R}\n")

if __name__ == "__main__":
    main()
