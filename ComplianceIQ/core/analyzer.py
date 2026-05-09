"""ComplianceIQ | core/analyzer.py — NIST CSF compliance gap & risk analysis engine."""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from collections import defaultdict

_CSF = json.loads((Path(__file__).parent.parent / "config" / "nist_csf.json").read_text())

@dataclass
class ControlGap:
    control_id:    str
    control_desc:  str
    function:      str
    category:      str
    category_name: str
    current_maturity:  int
    maturity_label:    str
    maturity_color:    str
    notes:         str
    gap_score:     int      # 100 - current score
    priority:      str      # CRITICAL / HIGH / MEDIUM / LOW

@dataclass
class RiskItem:
    id:          str
    title:       str
    category:    str
    likelihood:  int
    impact:      int
    risk_score:  int
    risk_level:  str
    description: str
    owner:       str
    treatment:   str
    controls_affected: list[str]

@dataclass
class ComplianceReport:
    org_name:         str
    industry:         str
    size:             str
    assessor:         str
    assessment_date:  str
    scope:            str
    framework:        str
    total_controls:   int
    assessed:         int
    overall_maturity: float
    function_scores:  dict
    control_gaps:     list[ControlGap]
    risk_register:    list[RiskItem]
    top_gaps:         list[ControlGap]
    compliance_pct:   float
    recommendations:  list[str]

RISK_THRESHOLDS = _CSF["risk_matrix"]["thresholds"]
MATURITY        = _CSF["maturity_levels"]

def _risk_level(score: int) -> str:
    for level, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi: return level
    return "CRITICAL"

def _gap_priority(gap_score: int) -> str:
    if gap_score >= 75: return "CRITICAL"
    if gap_score >= 50: return "HIGH"
    if gap_score >= 25: return "MEDIUM"
    return "LOW"

def analyze(assessment_path: str) -> ComplianceReport:
    data      = json.loads(Path(assessment_path).read_text())
    org       = data["organization"]
    assessed  = data["control_assessments"]
    risks_raw = data.get("risk_register", [])

    gaps           = []
    function_totals = defaultdict(list)

    for func_name, func_data in _CSF["functions"].items():
        for cat_id, cat_data in func_data["categories"].items():
            for ctrl in cat_data["controls"]:
                cid = ctrl["id"]
                a   = assessed.get(cid, {})
                mat = a.get("maturity", 0)
                notes = a.get("notes", "Not assessed.")
                m_info = MATURITY[str(mat)]
                score  = m_info["score"]
                gap    = 100 - score
                function_totals[func_name].append(score)
                if mat < 3:  # gap = anything below Repeatable
                    gaps.append(ControlGap(
                        control_id=cid, control_desc=ctrl["desc"],
                        function=func_name, category=cat_id,
                        category_name=cat_data["name"],
                        current_maturity=mat, maturity_label=m_info["label"],
                        maturity_color=m_info["color"],
                        notes=notes, gap_score=gap,
                        priority=_gap_priority(gap)))

    # Function-level scores
    func_scores = {f: round(sum(v)/len(v), 1) for f, v in function_totals.items()}
    overall     = round(sum(func_scores.values()) / len(func_scores), 1)
    total_ctrl  = sum(len(cat["controls"]) for fd in _CSF["functions"].values() for cat in fd["categories"].values())
    compliance_pct = round(sum(1 for g in gaps if g.gap_score == 0) / total_ctrl * 100 if total_ctrl else 0, 1)

    # Risk register
    risk_items = []
    for r in risks_raw:
        score = r["likelihood"] * r["impact"]
        risk_items.append(RiskItem(
            id=r["id"], title=r["title"], category=r["category"],
            likelihood=r["likelihood"], impact=r["impact"],
            risk_score=score, risk_level=_risk_level(score),
            description=r["description"], owner=r["owner"],
            treatment=r["treatment"], controls_affected=r["controls_affected"]))
    risk_items.sort(key=lambda x: x.risk_score, reverse=True)

    # Top 5 gaps by gap_score
    top_gaps = sorted(gaps, key=lambda g: g.gap_score, reverse=True)[:6]

    # Recommendations
    recs = []
    crit_gaps = [g for g in gaps if g.priority == "CRITICAL"]
    if crit_gaps:
        recs.append(f"Address {len(crit_gaps)} CRITICAL control gap(s) immediately — focus on {', '.join(g.control_id for g in crit_gaps[:3])}.")
    crit_risks = [r for r in risk_items if r.risk_level == "CRITICAL"]
    if crit_risks:
        recs.append(f"Prioritize mitigation for {len(crit_risks)} CRITICAL risk(s): {', '.join(r.title for r in crit_risks[:2])}.")
    low_func   = min(func_scores, key=func_scores.get)
    recs.append(f"Lowest function maturity: '{low_func}' ({func_scores[low_func]:.0f}/100) — allocate resources here first.")
    recs.append("Conduct a formal Tabletop Exercise (TTX) to test Incident Response and Business Continuity plans.")
    recs.append("Implement a formal Vulnerability Management program with defined SLAs for critical/high CVE patching.")
    recs.append("Define and document organizational Risk Tolerance — align with board/senior management.")
    recs.append("Deploy SIEM for log correlation and real-time threat detection across all critical systems.")
    recs.append("Establish Third-Party Risk Management (TPRM) program with vendor security assessments.")

    return ComplianceReport(
        org_name=org["name"], industry=org["industry"], size=org["size"],
        assessor=org["assessor"], assessment_date=org["assessment_date"],
        scope=org["scope"], framework=_CSF["framework"],
        total_controls=total_ctrl, assessed=len(assessed),
        overall_maturity=overall, function_scores=func_scores,
        control_gaps=gaps, risk_register=risk_items,
        top_gaps=top_gaps, compliance_pct=compliance_pct,
        recommendations=recs)
