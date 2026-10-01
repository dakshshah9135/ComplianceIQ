# 🛡️ ComplianceIQ — GRC Risk & Compliance Analyzer

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Framework](https://img.shields.io/badge/Framework-NIST%20CSF%20v1.1-navy)
![License](https://img.shields.io/badge/License-MIT-green)
![Domain](https://img.shields.io/badge/Domain-GRC%20%7C%20Cybersecurity-purple)

A GRC (Governance, Risk & Compliance) assessment tool that maps an organization's security controls against the **NIST Cybersecurity Framework (CSF) v1.1**, generates a **risk register** with likelihood × impact scoring, identifies **compliance gaps**, and produces a professional **audit-ready HTML report**.

## Features
- 📋 **NIST CSF Assessment** — 57 controls across 5 functions (Identify, Protect, Detect, Respond, Recover)
- 📊 **Maturity Scoring** — 5-level scale (Not Implemented → Adaptive) per control with gap analysis  
- ⚠️ **Risk Register** — Likelihood × Impact matrix, risk heatmap, risk treatment tracking
- 🎯 **Gap Analysis** — Identifies and prioritizes controls below Repeatable maturity
- 📈 **Radar Chart** — SVG radar chart of function-level maturity scores
- 🏢 **India-aware** — Risk scenarios include RBI/SEBI regulatory compliance context
- 💡 **Recommendations** — Prioritized, actionable remediation guidance
- 📄 **HTML Report** — Professional, audit-ready report with full evidence trail

## Usage
```bash
# Assess an organization
python complianceiq.py sample_assessments/sample_org.json

# Custom output
python complianceiq.py assessment.json --output my_report.html

# Terminal only (no report)
python complianceiq.py assessment.json --no-report
```

## Assessment File Format
Create a JSON file with your organization details and control maturity ratings (0–4):
```json
{
  "organization": { "name": "Acme Corp", "industry": "FinTech", ... },
  "control_assessments": {
    "ID.AM-1": { "maturity": 2, "notes": "Asset inventory partially complete." },
    "PR.AC-1": { "maturity": 3, "notes": "IAM fully implemented." }
  },
  "risk_register": [
    { "id": "RSK-001", "title": "Data Breach", "likelihood": 4, "impact": 5, ... }
  ]
}
```

## Maturity Levels
| Level | Label | Score |
|-------|-------|-------|
| 0 | Not Implemented | 0% |
| 1 | Partial | 25% |
| 2 | Risk Informed | 50% |
| 3 | Repeatable ✅ | 75% |
| 4 | Adaptive (Optimal) | 100% |

## Project Structure
```
ComplianceIQ/
├── complianceiq.py              # CLI entry point
├── core/
│   ├── analyzer.py              # NIST CSF mapping, gap & risk scoring engine
│   └── reporter.py              # HTML report + radar chart + risk heatmap
├── config/
│   └── nist_csf.json            # Full NIST CSF v1.1 control database (57 controls)
└── sample_assessments/
    └── sample_org.json          # Sample FinTech org assessment (57 controls, 8 risks)
```

## Author
**Daksh Shah** — B.Tech Cybersecurity, SAKEC Mumbai  
Interested in GRC Analysis, Risk Management, and Information Security compliance.  
[![LinkedIn](https://img.shields.io/badge/LinkedIn-daksh--shah9135-blue)](https://linkedin.com/in/daksh-shah9135)

MIT License — For authorized GRC assessment use only.
