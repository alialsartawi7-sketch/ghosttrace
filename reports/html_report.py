"""HTML/PDF Report Generator — Professional OSINT Intelligence Reports"""
import os, subprocess
from datetime import datetime
from html import escape
from config import Config
from utils.logger import log


# ═══════════════ All supported result types ═══════════════
RESULT_TYPES = {
    "email":     {"label": "Emails",          "icon": "📧", "color": "#3ecf8e", "tag": "te"},
    "username":  {"label": "Profiles",        "icon": "👤", "color": "#3ecf8e", "tag": "tu"},
    "subdomain": {"label": "Subdomains",      "icon": "🌐", "color": "#38bdf8", "tag": "ts"},
    "metadata":  {"label": "Metadata",        "icon": "📎", "color": "#b79af7", "tag": "tm"},
    "dns":       {"label": "DNS Records",     "icon": "📡", "color": "#4f8ef7", "tag": "td"},
    "ssl":       {"label": "SSL Certificate", "icon": "🔒", "color": "#e8a838", "tag": "tl"},
    "whois":     {"label": "WHOIS",           "icon": "📋", "color": "#e8a838", "tag": "tw"},
    "phone":     {"label": "Phone Intel",     "icon": "📱", "color": "#b79af7", "tag": "tp"},
    "dork":      {"label": "Google Dorks",    "icon": "🔍", "color": "#f16060", "tag": "tg"},
}


class ReportGenerator:
    @staticmethod
    def generate_html(results, target, module, recon_data=None):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target_e = escape(str(target))
        module_e = escape(str(module))

        # Categorize ALL results
        cats = {t: [] for t in RESULT_TYPES}
        high_conf = 0
        med_conf = 0
        for r in results:
            t = r.get("type", "")
            if t in cats:
                cats[t].append(r)
            if r.get("confidence", 0) >= 0.8:
                high_conf += 1
            elif r.get("confidence", 0) >= 0.5:
                med_conf += 1

        # Find which categories have results
        active_cats = {k: v for k, v in cats.items() if v}
        total = len(results)

        # Build stat cards (top 6 with results + total)
        def stat_card(value, label, color):
            return f'<div class="card"><div class="card-v" style="color:{color}">{value}</div><div class="card-l">{label}</div></div>'

        cards_html = stat_card(total, "Total Results", "#4f8ef7")
        for t, items in active_cats.items():
            info = RESULT_TYPES[t]
            cards_html += stat_card(len(items), info["label"], info["color"])
        cards_html += stat_card(high_conf, "High Confidence", "#3ecf8e")

        # Build executive summary
        summary_parts = []
        for t, items in active_cats.items():
            info = RESULT_TYPES[t]
            summary_parts.append(f'{info["icon"]} <span class="highlight">{len(items)} {info["label"].lower()}</span>')
        summary_text = ", ".join(summary_parts) if summary_parts else "No results"

        # Build confidence bar
        conf_high_pct = round(high_conf / max(total, 1) * 100)
        conf_med_pct = round(med_conf / max(total, 1) * 100)
        conf_low_pct = 100 - conf_high_pct - conf_med_pct

        # Table builder
        def tbl(items, tag_cls):
            h = '<table><thead><tr><th class="th-n">#</th><th class="th-v">Value</th><th class="th-s">Source</th><th class="th-c">Confidence</th></tr></thead><tbody>'
            for i, r in enumerate(items, 1):
                conf = r.get('confidence', 0)
                conf_cls = 'conf-high' if conf >= 0.8 else 'conf-med' if conf >= 0.5 else 'conf-low'
                bar_w = max(2, int(conf * 100))
                val = escape(r.get('value', ''))
                src = escape(r.get('source', ''))
                h += f'<tr><td class="td-n">{i}</td><td class="td-v">{val}</td>'
                h += f'<td><span class="tag {tag_cls}">{src}</span></td>'
                h += f'<td class="td-c"><div class="conf-bar"><div class="conf-fill {conf_cls}" style="width:{bar_w}%"></div></div><span class="{conf_cls}">{conf:.0%}</span></td></tr>'
            return h + '</tbody></table>'

        # ═══════════════ HTML ═══════════════
        html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GhostTrace Report — {target_e}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{{--bg:#0a0e14;--surface:#111820;--raised:#182030;--border:#1e2a3a;--accent:#4f8ef7;--green:#3ecf8e;--red:#f16060;--orange:#e8a838;--cyan:#38bdf8;--purple:#b79af7;--text1:#e8edf5;--text2:#8a96aa;--text3:#4a5568;--mono:'JetBrains Mono',monospace;--sans:'Inter',sans-serif}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:var(--sans);background:var(--bg);color:var(--text1);line-height:1.6}}
.rpt{{max-width:960px;margin:0 auto;padding:40px 32px}}

/* Header */
.hdr{{text-align:center;padding:48px 0 40px;border-bottom:2px solid var(--border);margin-bottom:36px;position:relative}}
.hdr::before{{content:'';position:absolute;bottom:-2px;left:50%;transform:translateX(-50%);width:120px;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}}
.hdr .logo{{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:4px;text-transform:uppercase;margin-bottom:8px}}
.hdr h1{{font-size:28px;font-weight:800;letter-spacing:-0.5px;margin-bottom:8px}}
.hdr .sub{{color:var(--text2);font-size:13px}}.hdr .sub b{{color:var(--text1)}}
.hdr .meta{{font-size:11px;color:var(--text3);font-family:var(--mono);margin-top:6px}}

/* Stat Grid */
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:32px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px 16px;text-align:center;transition:border-color .2s}}
.card:hover{{border-color:var(--accent)}}
.card-v{{font-size:28px;font-weight:800;font-family:var(--mono)}}
.card-l{{font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1.5px;margin-top:6px;font-weight:500}}

/* Executive Summary */
.exec{{background:linear-gradient(135deg,var(--surface),var(--raised));border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:32px}}
.exec h3{{font-size:15px;font-weight:700;color:var(--accent);margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.exec h3::before{{content:'📊'}}
.exec p{{font-size:13px;color:var(--text2);line-height:1.8}}
.highlight{{color:var(--green);font-weight:600}}.risk{{color:var(--red);font-weight:600}}

/* Confidence Overview */
.conf-overview{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:32px}}
.conf-overview h4{{font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:12px}}
.conf-bar-big{{height:10px;background:var(--raised);border-radius:5px;overflow:hidden;display:flex}}
.conf-seg{{height:100%;transition:width .3s}}
.conf-legend{{display:flex;gap:20px;margin-top:10px;font-size:11px;font-family:var(--mono)}}
.conf-legend span{{display:flex;align-items:center;gap:6px}}
.conf-dot{{width:8px;height:8px;border-radius:50%;display:inline-block}}

/* Sections */
.sec{{margin-bottom:32px;page-break-inside:avoid}}
.sec-h{{display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:1px solid var(--border);margin-bottom:16px}}
.sec-icon{{font-size:18px}}.sec-title{{font-size:14px;font-weight:700;color:var(--text1);text-transform:uppercase;letter-spacing:1px}}
.sec-count{{font-size:11px;font-family:var(--mono);color:var(--text3);margin-left:auto;background:var(--raised);padding:2px 10px;border-radius:12px}}

/* Tables */
table{{width:100%;border-collapse:collapse;font-size:12px}}
thead th{{text-align:left;font-size:9px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;padding:10px 14px;border-bottom:2px solid var(--border);font-weight:600}}
tbody td{{padding:10px 14px;border-bottom:1px solid var(--border)}}
tbody tr:hover td{{background:rgba(79,142,247,0.03)}}
.th-n,.td-n{{width:36px;color:var(--text3);font-family:var(--mono)}}
.td-v{{font-family:var(--mono);font-size:11px;word-break:break-all;max-width:420px}}
.th-s{{width:120px}}.th-c{{width:140px}}
.td-c{{display:flex;align-items:center;gap:8px}}
.conf-bar{{width:60px;height:4px;background:var(--raised);border-radius:2px;overflow:hidden;flex-shrink:0}}
.conf-fill{{height:100%;border-radius:2px}}
.conf-high,.conf-fill.conf-high{{color:var(--green);background:var(--green)}}
.conf-med,.conf-fill.conf-med{{color:var(--orange);background:var(--orange)}}
.conf-low,.conf-fill.conf-low{{color:var(--red);background:var(--red)}}
.tag{{padding:3px 8px;border-radius:4px;font-size:9px;font-family:var(--mono);font-weight:500}}
.te{{background:#3ecf8e12;color:#3ecf8e}}.tu{{background:#3ecf8e12;color:#3ecf8e}}
.ts{{background:#38bdf812;color:#38bdf8}}.tm{{background:#b79af712;color:#b79af7}}
.td{{background:#4f8ef712;color:#4f8ef7}}.tl{{background:#e8a83812;color:#e8a838}}
.tw{{background:#e8a83812;color:#e8a838}}.tp{{background:#b79af712;color:#b79af7}}
.tg{{background:#f1606012;color:#f16060}}

/* Technical Details */
.details{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:32px}}
.details h4{{font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}}
.detail-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}
.detail-row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)}}
.detail-key{{font-size:11px;color:var(--text3)}}.detail-val{{font-size:11px;font-family:var(--mono);color:var(--text1)}}

/* Footer */
.ftr{{text-align:center;padding:32px 0;border-top:2px solid var(--border);margin-top:40px;position:relative}}
.ftr::before{{content:'';position:absolute;top:-2px;left:50%;transform:translateX(-50%);width:80px;height:2px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}}
.ftr .brand{{font-family:var(--mono);font-size:11px;color:var(--accent);letter-spacing:2px;margin-bottom:4px}}
.ftr .copy{{font-size:10px;color:var(--text3)}}
.ftr .disclaimer{{font-size:9px;color:var(--text3);margin-top:8px;font-style:italic}}

/* Risk Assessment */
.risk-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:12px}}
.risk-header{{display:flex;align-items:center;gap:12px;margin-bottom:10px}}
.risk-host{{font-family:var(--mono);font-size:13px;font-weight:600;color:var(--text1)}}
.risk-score{{font-family:var(--mono);font-size:12px;padding:2px 10px;border-radius:12px;font-weight:600}}
.risk-critical{{background:#f1606025;color:#f16060}}.risk-high{{background:#e8a83825;color:#e8a838}}
.risk-medium{{background:#4f8ef725;color:#4f8ef7}}.risk-low{{background:#3ecf8e25;color:#3ecf8e}}.risk-info{{background:#8a96aa25;color:#8a96aa}}
.risk-reasons{{margin:8px 0;padding-left:16px}}
.risk-reason{{font-size:11px;color:var(--text2);padding:2px 0;list-style:none}}
.risk-reason::before{{content:'→ ';color:var(--orange)}}
.risk-paths{{margin-top:10px;padding-top:10px;border-top:1px solid var(--border)}}
.risk-path{{font-size:11px;margin-bottom:6px}}
.risk-path-name{{font-weight:600;font-family:var(--mono)}}
.risk-path-sev{{font-size:9px;padding:1px 6px;border-radius:4px;margin-left:6px}}
.risk-path-steps{{font-size:10px;color:var(--text3);padding-left:16px;margin-top:2px}}

@media print{{
  body{{background:#fff;color:#1a1a2e;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .card,.exec,.details,.conf-overview{{border-color:#e0e0e0;background:#f8f9fa}}
  .tag{{border:1px solid #ddd}}
  table{{font-size:10px}}
}}
</style></head><body><div class="rpt">

<!-- HEADER -->
<div class="hdr">
<div class="logo">GhostTrace Intelligence Report</div>
<h1>{target_e}</h1>
<div class="sub">Module: <b>{module_e}</b> — Generated by GhostTrace v{Config.VERSION}</div>
<div class="meta">by Alsartawi · {dt}</div>
</div>

<!-- STATS -->
<div class="grid">{cards_html}</div>

<!-- CONFIDENCE OVERVIEW -->
<div class="conf-overview">
<h4>Confidence Distribution</h4>
<div class="conf-bar-big">
<div class="conf-seg" style="width:{conf_high_pct}%;background:var(--green)"></div>
<div class="conf-seg" style="width:{conf_med_pct}%;background:var(--orange)"></div>
<div class="conf-seg" style="width:{conf_low_pct}%;background:var(--red)"></div>
</div>
<div class="conf-legend">
<span><span class="conf-dot" style="background:var(--green)"></span>{high_conf} High (≥80%)</span>
<span><span class="conf-dot" style="background:var(--orange)"></span>{med_conf} Medium (50-79%)</span>
<span><span class="conf-dot" style="background:var(--red)"></span>{total - high_conf - med_conf} Low (&lt;50%)</span>
</div>
</div>

<!-- EXECUTIVE SUMMARY -->
<div class="exec">
<h3>Executive Summary</h3>
<p>Reconnaissance of <span class="highlight">{target_e}</span> using the <b>{module_e}</b> module yielded
<span class="highlight">{total} total findings</span> across {len(active_cats)} categories: {summary_text}.
<br><br>
<span class="highlight">{high_conf} results ({conf_high_pct}%)</span> have high confidence and are considered reliable.
{f'<span class="risk">Significant exposure detected</span> — immediate review recommended.' if total > 20 else ''}
{f'<span class="risk">Sensitive records found</span> — check DNS and SSL sections for misconfigurations.' if cats.get("dns") or cats.get("ssl") else ''}
</p>
</div>'''

        # ═══════════════ KEY FINDINGS (Top 10) ═══════════════
        # Sort all results by confidence, pick top 10 unique high-value findings
        key_findings = sorted(results, key=lambda r: r.get("confidence", 0), reverse=True)
        # Dedup by value
        seen_kf = set()
        unique_kf = []
        for r in key_findings:
            v = r.get("value", "")
            if v not in seen_kf and r.get("confidence", 0) >= 0.5:
                seen_kf.add(v)
                unique_kf.append(r)
                if len(unique_kf) >= 10:
                    break

        if unique_kf:
            html += '''
<div class="sec">
<div class="sec-h"><span class="sec-icon">🎯</span><span class="sec-title">Key Findings</span><span class="sec-count">Top priority items</span></div>
<table><thead><tr><th class="th-n">#</th><th>Type</th><th class="th-v">Finding</th><th class="th-s">Source</th><th class="th-c">Confidence</th></tr></thead><tbody>'''
            for i, r in enumerate(unique_kf, 1):
                conf = r.get('confidence', 0)
                conf_cls = 'conf-high' if conf >= 0.8 else 'conf-med' if conf >= 0.5 else 'conf-low'
                rtype = r.get('type', '')
                info = RESULT_TYPES.get(rtype, {"icon": "?", "tag": "te"})
                bar_w = max(2, int(conf * 100))
                html += f'<tr><td class="td-n">{i}</td><td>{info["icon"]}</td>'
                html += f'<td class="td-v">{escape(r.get("value", ""))}</td>'
                html += f'<td><span class="tag {info["tag"]}">{escape(r.get("source", ""))}</span></td>'
                html += f'<td class="td-c"><div class="conf-bar"><div class="conf-fill {conf_cls}" style="width:{bar_w}%"></div></div><span class="{conf_cls}">{conf:.0%}</span></td></tr>'
            html += '</tbody></table></div>'

        # ═══════════════ RESULT SECTIONS ═══════════════
        for t, items in active_cats.items():
            info = RESULT_TYPES[t]
            html += f'''
<div class="sec">
<div class="sec-h"><span class="sec-icon">{info["icon"]}</span><span class="sec-title">{info["label"]}</span><span class="sec-count">{len(items)} found</span></div>
{tbl(items, info["tag"])}
</div>'''

        # ═══════════════ RISK ASSESSMENT (if recon data provided) ═══════════════
        if recon_data:
            scored = recon_data.get("scored_assets", [])
            summary = recon_data.get("summary", {})
            if scored:
                stats = summary.get("stats", {})
                html += f'''
<div class="sec">
<div class="sec-h"><span class="sec-icon">🛡️</span><span class="sec-title">Risk Assessment</span><span class="sec-count">{len(scored)} hosts analyzed</span></div>'''

                # Summary bar
                if stats:
                    html += f'''<div class="conf-overview" style="margin-bottom:16px">
<h4>Risk Distribution</h4>
<div class="conf-legend">
<span><span class="conf-dot" style="background:#f16060"></span>{stats.get("critical",0)} Critical</span>
<span><span class="conf-dot" style="background:#e8a838"></span>{stats.get("high",0)} High</span>
<span><span class="conf-dot" style="background:#4f8ef7"></span>{stats.get("medium",0)} Medium</span>
<span><span class="conf-dot" style="background:#3ecf8e"></span>{stats.get("low",0)} Low</span>
</div></div>'''

                # Individual host cards
                for a in scored[:15]:  # Top 15
                    level = a.get("level", "info")
                    score = a.get("score", 0)
                    hostname = escape(a.get("hostname", "?"))
                    reasons = a.get("reasons", [])
                    paths = a.get("attack_paths", [])

                    html += f'<div class="risk-card"><div class="risk-header">'
                    html += f'<span class="risk-host">{hostname}</span>'
                    html += f'<span class="risk-score risk-{level}">{score}/100 {level.upper()}</span>'
                    html += '</div>'

                    # Top 3 reasons
                    if reasons:
                        html += '<div class="risk-reasons">'
                        for r in reasons[:3]:
                            html += f'<div class="risk-reason">{escape(r)}</div>'
                        html += '</div>'

                    # Attack paths
                    if paths:
                        html += '<div class="risk-paths">'
                        for p in paths:
                            sev = p.get("severity", "medium")
                            sev_cls = f"risk-{sev}" if sev in ("critical","high") else "risk-medium"
                            html += f'<div class="risk-path"><span class="risk-path-name">{escape(p.get("path",""))}</span>'
                            html += f'<span class="risk-path-sev {sev_cls}">{sev.upper()}</span>'
                            steps = p.get("steps", [])
                            if steps:
                                html += '<div class="risk-path-steps">' + " → ".join(escape(s) for s in steps[:3]) + '</div>'
                            html += '</div>'
                        html += '</div>'

                    html += '</div>'

                # Recommendations
                recs = summary.get("recommendations", [])
                if recs:
                    html += '<div class="exec" style="margin-top:16px"><h3 style="color:var(--orange)">⚠ Recommendations</h3><p>'
                    for rec in recs:
                        html += f'• {escape(rec)}<br>'
                    html += '</p></div>'

                html += '</div>'

        # ═══════════════ TECHNICAL DETAILS ═══════════════
        html += f'''
<div class="details">
<h4>Technical Details</h4>
<div class="detail-grid">
<div><div class="detail-row"><span class="detail-key">Target</span><span class="detail-val">{target_e}</span></div>
<div class="detail-row"><span class="detail-key">Module</span><span class="detail-val">{module_e}</span></div>
<div class="detail-row"><span class="detail-key">Scan Date</span><span class="detail-val">{dt}</span></div></div>
<div><div class="detail-row"><span class="detail-key">Total Results</span><span class="detail-val">{total}</span></div>
<div class="detail-row"><span class="detail-key">High Confidence</span><span class="detail-val">{high_conf} ({conf_high_pct}%)</span></div>
<div class="detail-row"><span class="detail-key">Tool Version</span><span class="detail-val">GhostTrace v{Config.VERSION}</span></div></div>
</div></div>

<!-- FOOTER -->
<div class="ftr">
<div class="brand">GHOSTTRACE v{Config.VERSION}</div>
<div class="copy">by Alsartawi · {dt}</div>
<div class="disclaimer">For authorized security research only. Handle results responsibly. Do not redistribute without permission.</div>
</div>

</div></body></html>'''

        fn = f"ghosttrace_report_{ts}.html"
        fp = os.path.join(Config.EXPORT_DIR, fn)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(html)
        log.info(f"Report generated: {fp}")
        return {"filepath": fp, "filename": fn}

    @staticmethod
    def html_to_pdf(html_filename):
        if ".." in html_filename or "/" in html_filename:
            return {"error": "Invalid filename"}
        html_path = os.path.join(Config.EXPORT_DIR, html_filename)
        if not os.path.exists(html_path):
            return {"error": "HTML report not found"}
        pdf_fn = html_filename.replace(".html", ".pdf")
        pdf_path = os.path.join(Config.EXPORT_DIR, pdf_fn)

        # Try weasyprint first
        try:
            import weasyprint
            weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            if os.path.exists(pdf_path):
                log.info(f"PDF generated via weasyprint: {pdf_path}")
                return {"filename": pdf_fn, "filepath": pdf_path}
        except ImportError:
            pass
        except Exception as e:
            log.warning(f"weasyprint failed: {e}, trying wkhtmltopdf")

        # Fallback to wkhtmltopdf
        try:
            subprocess.run([
                "wkhtmltopdf", "--enable-local-file-access",
                "--page-size", "A4", "--margin-top", "15mm", "--margin-bottom", "15mm",
                "--margin-left", "15mm", "--margin-right", "15mm",
                "--encoding", "UTF-8", "--no-background",
                html_path, pdf_path
            ], capture_output=True, text=True, timeout=30)
            if os.path.exists(pdf_path):
                log.info(f"PDF generated via wkhtmltopdf: {pdf_path}")
                return {"filename": pdf_fn, "filepath": pdf_path}
            return {"error": "PDF generation failed"}
        except FileNotFoundError:
            return {"error": "No PDF engine. Install: pip install weasyprint"}
        except subprocess.TimeoutExpired:
            return {"error": "PDF generation timed out"}
        except Exception as e:
            return {"error": str(e)}
