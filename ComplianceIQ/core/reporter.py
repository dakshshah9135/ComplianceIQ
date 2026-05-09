"""ComplianceIQ | core/reporter.py — Professional GRC audit HTML report generator."""
import datetime
from pathlib import Path

FUNC_COLORS = {"IDENTIFY":"#3b82f6","PROTECT":"#16a34a","DETECT":"#f59e0b","RESPOND":"#ef4444","RECOVER":"#8b5cf6"}
RISK_C      = {"CRITICAL":"#7c3aed","HIGH":"#dc2626","MEDIUM":"#ea580c","LOW":"#16a34a"}
MAT_C       = {"0":"#dc2626","1":"#ea580c","2":"#d97706","3":"#16a34a","4":"#2563eb"}
PRI_C       = {"CRITICAL":"#7c3aed","HIGH":"#dc2626","MEDIUM":"#ea580c","LOW":"#16a34a"}

def _badge(text, color):
    return f'<span style="background:{color};color:#fff;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700">{text}</span>'

def _maturity_bar(score):
    color = "#dc2626" if score<30 else "#ea580c" if score<50 else "#d97706" if score<70 else "#16a34a"
    return f'<div style="background:#e5e7eb;border-radius:4px;height:8px;width:120px;display:inline-block;vertical-align:middle"><div style="background:{color};height:8px;border-radius:4px;width:{score}%"></div></div> <span style="font-size:11px;color:{color};font-weight:700">{score:.0f}%</span>'

def _radar_svg(func_scores):
    import math
    labels = list(func_scores.keys())
    values = [func_scores[l] for l in labels]
    n = len(labels); cx,cy,r = 160,160,120; W=320
    pts_outer=[]; pts_data=[]
    for i in range(n):
        angle = math.pi/2 - 2*math.pi*i/n
        pts_outer.append((cx+r*math.cos(angle), cy-r*math.sin(angle)))
        v = values[i]/100
        pts_data.append((cx+r*v*math.cos(angle), cy-r*v*math.sin(angle)))
    grid=""; spokes=""; lbl_html=""
    for lvl in [0.25,0.5,0.75,1.0]:
        gps=[(cx+r*lvl*math.cos(math.pi/2-2*math.pi*i/n), cy-r*lvl*math.sin(math.pi/2-2*math.pi*i/n)) for i in range(n)]
        grid+=f'<polygon points="{" ".join(f"{x:.1f},{y:.1f}" for x,y in gps)}" fill="none" stroke="#e5e7eb" stroke-width="1"/>'
    for x,y in pts_outer:
        spokes+=f'<line x1="{cx}" y1="{cy}" x2="{x:.1f}" y2="{y:.1f}" stroke="#e5e7eb" stroke-width="1"/>'
    poly_outer=f'<polygon points="{" ".join(f"{x:.1f},{y:.1f}" for x,y in pts_outer)}" fill="none" stroke="#cbd5e1" stroke-width="1.5"/>'
    poly_data =f'<polygon points="{" ".join(f"{x:.1f},{y:.1f}" for x,y in pts_data)}" fill="#3b82f620" stroke="#3b82f6" stroke-width="2"/>'
    for i,(lbl,(x,y)) in enumerate(zip(labels,pts_outer)):
        dx = 0 if abs(x-cx)<5 else (14 if x>cx else -14)
        dy = -10 if y<cy else 14
        color = FUNC_COLORS.get(lbl,"#374151")
        lbl_html+=f'<text x="{x+dx:.1f}" y="{y+dy:.1f}" text-anchor="middle" font-size="9" font-weight="700" fill="{color}">{lbl[:3]}</text>'
        lbl_html+=f'<text x="{x+dx:.1f}" y="{y+dy+11:.1f}" text-anchor="middle" font-size="8" fill="#6b7280">{func_scores[lbl]:.0f}%</text>'
    return f'<svg width="{W}" height="{W}" viewBox="0 0 {W} {W}" style="max-width:100%">{grid}{spokes}{poly_outer}{poly_data}{lbl_html}</svg>'

def generate_report(report, output_path: str) -> str:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Function score cards
    func_cards = ""
    for fn, sc in report.function_scores.items():
        color = FUNC_COLORS.get(fn,"#374151")
        bar_w = int(sc)
        func_cards += f"""
        <div style="border:1px solid #e5e7eb;border-left:4px solid {color};border-radius:8px;padding:.85rem 1rem;flex:1;min-width:140px">
          <div style="font-size:10px;font-weight:700;color:{color};text-transform:uppercase;letter-spacing:.5px">{fn}</div>
          <div style="font-size:1.6rem;font-weight:800;color:#111;margin:4px 0">{sc:.0f}<span style="font-size:12px;color:#6b7280">/100</span></div>
          <div style="background:#e5e7eb;border-radius:4px;height:6px"><div style="background:{color};height:6px;border-radius:4px;width:{bar_w}%"></div></div>
        </div>"""

    # Risk register table
    risk_rows = ""
    for r in report.risk_register:
        rc = RISK_C.get(r.risk_level,"#6b7280")
        heat_bg = {"CRITICAL":"#f5f3ff","HIGH":"#fef2f2","MEDIUM":"#fff7ed","LOW":"#f0fdf4"}.get(r.risk_level,"#fff")
        risk_rows += f"""
        <tr style="background:{heat_bg}">
          <td style="padding:8px 10px;font-weight:600;font-size:12px;color:#374151">{r.id}</td>
          <td style="padding:8px 10px;font-size:12px">{r.title}</td>
          <td style="padding:8px 10px;text-align:center;font-size:12px">{r.category}</td>
          <td style="padding:8px 10px;text-align:center;font-size:12px">{r.likelihood}</td>
          <td style="padding:8px 10px;text-align:center;font-size:12px">{r.impact}</td>
          <td style="padding:8px 10px;text-align:center;font-weight:800;color:{rc}">{r.risk_score}</td>
          <td style="padding:8px 10px;text-align:center">{_badge(r.risk_level,rc)}</td>
          <td style="padding:8px 10px;font-size:11px;color:#6b7280">{r.owner}</td>
          <td style="padding:8px 10px;text-align:center;font-size:11px">{r.treatment}</td>
        </tr>"""

    # Top gaps
    gap_rows = ""
    for g in sorted(report.control_gaps, key=lambda x: x.gap_score, reverse=True)[:12]:
        pc = PRI_C.get(g.priority,"#6b7280")
        mc = g.maturity_color
        gap_rows += f"""
        <tr>
          <td style="padding:8px 10px;font-family:monospace;font-size:12px;font-weight:700;color:#1e40af">{g.control_id}</td>
          <td style="padding:8px 10px;font-size:11px;color:#374151">{g.control_desc[:70]}{'...' if len(g.control_desc)>70 else ''}</td>
          <td style="padding:8px 10px;text-align:center;font-size:10px;font-weight:700;color:{FUNC_COLORS.get(g.function,'#374151')}">{g.function}</td>
          <td style="padding:8px 10px;text-align:center">{_badge(g.maturity_label, mc)}</td>
          <td style="padding:8px 10px;text-align:center">{_badge(g.priority, pc)}</td>
          <td style="padding:8px 10px;font-size:11px;color:#4b5563;font-style:italic">{g.notes}</td>
        </tr>"""

    # Recommendations
    rec_html = "".join(f'<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9"><div style="color:#2563eb;font-weight:700;flex-shrink:0">{i+1}.</div><div style="font-size:13px;color:#374151">{r}</div></div>' for i,r in enumerate(report.recommendations))

    # Risk heatmap 5x5
    heatmap = ""
    risk_map = {(r.likelihood, r.impact): r for r in report.risk_register}
    heatmap += '<div style="display:inline-block"><table style="border-collapse:collapse">'
    heatmap += '<tr><td style="width:60px"></td>' + "".join(f'<td style="text-align:center;font-size:10px;color:#6b7280;padding:3px 2px;width:60px">Impact {i}</td>' for i in range(1,6)) + '</tr>'
    for lik in range(5,0,-1):
        heatmap += f'<tr><td style="font-size:10px;color:#6b7280;text-align:right;padding-right:4px">L{lik}</td>'
        for imp in range(1,6):
            score = lik*imp
            bg = "#fef2f2" if score>=20 else "#fff7ed" if score>=13 else "#fefce8" if score>=7 else "#f0fdf4"
            border = "#dc2626" if score>=20 else "#ea580c" if score>=13 else "#d97706" if score>=7 else "#16a34a"
            r_here = risk_map.get((lik,imp))
            cell_content = f'<div style="font-size:9px;font-weight:700;color:{border}">{score}</div>'
            if r_here:
                cell_content += f'<div style="font-size:8px;color:#374151;line-height:1.1">{r_here.id}</div>'
            heatmap += f'<td style="width:60px;height:50px;border:1px solid {border}22;background:{bg};text-align:center;vertical-align:middle;border-radius:4px;padding:2px">{cell_content}</td>'
        heatmap += '</tr>'
    heatmap += '</table></div>'

    # Overall maturity color
    ov = report.overall_maturity
    ov_color = "#dc2626" if ov<30 else "#ea580c" if ov<50 else "#d97706" if ov<70 else "#16a34a"

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/>
<title>ComplianceIQ — {report.org_name}</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f1f5f9;margin:0;padding:2rem;color:#111827}}
  .wrap{{max-width:1100px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}}
  .hd{{background:linear-gradient(135deg,#0f172a,#1a2b4a);color:#fff;padding:2rem 2.5rem}}
  .meta{{background:#f8fafc;padding:1.25rem 2.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:1rem;border-bottom:1px solid #e5e7eb}}
  .mc{{text-align:center}}.ml{{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}}.mv{{font-size:1.05rem;font-weight:700}}
  .sec{{padding:1.5rem 2.5rem}}.sec+.sec{{border-top:1px solid #f1f5f9}}
  h2{{font-size:14px;font-weight:700;color:#1e293b;text-transform:uppercase;letter-spacing:.5px;padding-bottom:6px;border-bottom:2px solid #e5e7eb;margin-bottom:1rem}}
  table{{width:100%;border-collapse:collapse;font-size:12px}}
  th{{background:#f1f5f9;padding:8px 10px;text-align:left;font-size:10px;text-transform:uppercase;color:#475569;font-weight:600}}
  tr:hover td{{background:#f8fafc55}}
  footer{{text-align:center;padding:1rem;font-size:12px;color:#9ca3af;border-top:1px solid #f1f5f9}}
</style></head><body>
<div class="wrap">
  <div class="hd">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:1rem">
      <div style="width:44px;height:44px;background:#3b82f6;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px">🛡️</div>
      <div><div style="font-size:1.5rem;font-weight:800">ComplianceIQ</div>
           <div style="font-size:11px;color:#94a3b8;letter-spacing:2px;text-transform:uppercase">GRC Risk & Compliance Analyzer</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;background:rgba(255,255,255,.07);border-radius:10px;padding:1.25rem">
      <div>
        <div style="font-size:11px;color:#94a3b8;margin-bottom:2px">ORGANIZATION</div>
        <div style="font-size:1.1rem;font-weight:700">{report.org_name}</div>
        <div style="font-size:12px;color:#94a3b8;margin-top:4px">{report.industry} &nbsp;|&nbsp; {report.size}</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">Scope: {report.scope}</div>
      </div>
      <div style="text-align:right">
        <div style="font-size:11px;color:#94a3b8">OVERALL MATURITY SCORE</div>
        <div style="font-size:3rem;font-weight:900;color:{ov_color};line-height:1">{ov:.0f}<span style="font-size:14px">/100</span></div>
        <div style="font-size:11px;color:#94a3b8">{report.framework}</div>
        <div style="font-size:11px;color:#64748b;margin-top:4px">Assessed by {report.assessor} on {report.assessment_date}</div>
      </div>
    </div>
  </div>

  <div class="meta">
    <div class="mc"><div class="ml">Controls Assessed</div><div class="mv">{report.assessed}/{report.total_controls}</div></div>
    <div class="mc"><div class="ml">Compliance Gaps</div><div class="mv" style="color:#dc2626">{len(report.control_gaps)}</div></div>
    <div class="mc"><div class="ml">Critical Risks</div><div class="mv" style="color:#7c3aed">{sum(1 for r in report.risk_register if r.risk_level=='CRITICAL')}</div></div>
    <div class="mc"><div class="ml">High Risks</div><div class="mv" style="color:#dc2626">{sum(1 for r in report.risk_register if r.risk_level=='HIGH')}</div></div>
    <div class="mc"><div class="ml">Risk Register</div><div class="mv">{len(report.risk_register)} items</div></div>
    <div class="mc"><div class="ml">Report Date</div><div class="mv" style="font-size:.8rem">{ts}</div></div>
  </div>

  <div class="sec">
    <h2>Maturity by NIST CSF Function</h2>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:1.5rem">{func_cards}</div>
    <div style="display:flex;gap:2rem;align-items:flex-start;flex-wrap:wrap">
      <div>{_radar_svg(report.function_scores)}</div>
      <div style="flex:1;min-width:200px">
        <div style="font-size:12px;font-weight:600;color:#374151;margin-bottom:8px">Maturity Scale</div>
        {''.join(f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><div style="width:12px;height:12px;border-radius:3px;background:{v["color"]}"></div><div style="font-size:12px;color:#374151"><strong>{k}</strong> — {v["label"]} ({v["score"]}%)</div></div>' for k,v in {"0":{"color":"#dc2626","label":"Not Implemented","score":0},"1":{"color":"#ea580c","label":"Partial","score":25},"2":{"color":"#d97706","label":"Risk Informed","score":50},"3":{"color":"#16a34a","label":"Repeatable","score":75},"4":{"color":"#2563eb","label":"Adaptive","score":100}}.items())}
      </div>
    </div>
  </div>

  <div class="sec">
    <h2>Risk Register ({len(report.risk_register)} Items) — Likelihood × Impact Matrix</h2>
    <div style="margin-bottom:1.5rem;overflow-x:auto">{heatmap}</div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ID</th><th>Risk Title</th><th>Category</th><th>Likelihood (1–5)</th><th>Impact (1–5)</th><th>Score</th><th>Level</th><th>Owner</th><th>Treatment</th></tr></thead>
      <tbody>{risk_rows}</tbody>
    </table></div>
  </div>

  <div class="sec">
    <h2>Top Compliance Gaps (Controls Below Repeatable Maturity)</h2>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>Control ID</th><th>Description</th><th>Function</th><th>Current Maturity</th><th>Priority</th><th>Assessor Notes</th></tr></thead>
      <tbody>{gap_rows}</tbody>
    </table></div>
  </div>

  <div class="sec">
    <h2>Recommendations</h2>
    {rec_html}
  </div>

  <div class="sec" style="background:#fffbeb;border-top:1px solid #fef3c7">
    <div style="font-size:12px;color:#92400e">
      <strong>⚠️ Disclaimer:</strong> This assessment is based on information provided during the evaluation and reflects the state of controls at the time of assessment.
      Results should be validated by qualified GRC professionals. This report is confidential and intended for internal use only.
    </div>
  </div>

  <footer>ComplianceIQ v1.0 &nbsp;|&nbsp; Built by <strong>Daksh Shah</strong> &nbsp;|&nbsp;
  Framework: NIST CSF v1.1 &nbsp;|&nbsp; github.com/dakshshah9135/complianceiq</footer>
</div></body></html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path
