"""
Recon API — Active reconnaissance pipeline
Runs after passive OSINT scan to validate and enrich results
"""
import json, re
from flask import Blueprint, request, jsonify, Response, stream_with_context
from recon import DNSResolver, HTTPProber, PortScanner, AttackSurfaceDetector, DataQuality
from recon.risk_engine import RiskScorer
from database.manager import Database, ResultDB
from utils.validators import Validators, ValidationError
from utils.logger import log

recon_bp = Blueprint('recon', __name__)


def sse(etype, data):
    return f"event: {etype}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

def _sse_error(msg):
    def gen():
        yield sse("log", {"type": "err", "msg": msg})
        yield sse("recon_done", {"total": 0})
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache"})


@recon_bp.route("/api/recon/validate")
def recon_validate():
    """Full recon pipeline"""
    # BUG 4 FIX: Validate inputs
    scan_id = request.args.get("scan_id", "").strip()
    if scan_id and not re.match(r'^[a-zA-Z0-9\-]{1,40}$', scan_id):
        return _sse_error("Invalid scan_id")

    domain = ""
    domain_raw = request.args.get("domain", "").strip()
    if domain_raw:
        try:
            domain = Validators.domain(domain_raw)
        except ValidationError as e:
            return _sse_error(e.message)

    do_ports = request.args.get("ports", "0") == "1"
    do_attack = request.args.get("attack_surface", "0") == "1"

    def generate():
        yield sse("log", {"type": "info", "msg": "Starting active reconnaissance..."})
        yield sse("progress", {"pct": 5, "label": "Loading targets"})

        # Get targets from DB or domain
        hostnames = set()
        if scan_id:
            results = ResultDB.get_by_scan(scan_id, per_page=500)
            for r in results.get("items", []):
                # BUG 5 FIX: Handle emails and subdomains differently
                if r.get("type") == "subdomain":
                    val = r["value"].split(" ")[0]
                    if "." in val and "@" not in val and not val.startswith("("):
                        hostnames.add(val)
                elif r.get("type") == "email" and "@" in r["value"]:
                    email_domain = r["value"].split("@")[-1].strip()
                    if email_domain and "." in email_domain:
                        hostnames.add(email_domain)
        if domain:
            hostnames.add(domain)
        if not hostnames:
            yield sse("log", {"type": "err", "msg": "No targets found. Run a scan first."})
            yield sse("recon_done", {"total": 0})
            return

        yield sse("log", {"type": "info", "msg": f"Loaded {len(hostnames)} targets"})

        # BUG 3 FIX: Filter private IPs and check wildcard DNS
        import re as _re
        before = len(hostnames)
        hostnames = {h for h in hostnames if not _re.match(r'^\d+\.\d+\.\d+\.\d+$', h) or not DataQuality.is_private_ip(h)}
        if domain:
            if DNSResolver.is_wildcard(domain):
                yield sse("log", {"type": "warn", "msg": f"Wildcard DNS detected for {domain} — results may include noise"})
        if len(hostnames) < before:
            yield sse("log", {"type": "info", "msg": f"Filtered {before - len(hostnames)} private/invalid targets"})

        # ── Step 1: DNS Resolution ──
        yield sse("progress", {"pct": 15, "label": f"DNS resolving {len(hostnames)} hosts"})
        yield sse("log", {"type": "info", "msg": "Phase 1: DNS Resolution"})
        dns_results = DNSResolver.bulk_resolve(hostnames, max_workers=20)
        alive_hosts = [h for h, r in dns_results.items() if r["alive"]]
        dead_hosts = [h for h, r in dns_results.items() if not r["alive"]]

        yield sse("log", {"type": "found", "msg": f"<span class='hl'>{len(alive_hosts)}</span> alive, <span class='muted'>{len(dead_hosts)} dead</span>"})

        for h in dead_hosts[:5]:  # Show first 5 dead
            yield sse("log", {"type": "warn", "msg": f"<span class='muted'>{h}</span> — dead (no DNS)"})

        if not alive_hosts:
            yield sse("log", {"type": "err", "msg": "No alive hosts found"})
            yield sse("recon_done", {"total": 0})
            return

        # ── Step 2: HTTP Probing ──
        yield sse("progress", {"pct": 35, "label": f"HTTP probing {len(alive_hosts)} hosts"})
        yield sse("log", {"type": "info", "msg": "Phase 2: HTTP Probing"})
        http_results = HTTPProber.bulk_probe(alive_hosts, max_workers=10)

        for h, r in http_results.items():
            if r["alive"]:
                tech_str = ", ".join(r["technology"]) if r["technology"] else "unknown"
                title = r.get("title", "")
                status = r.get("https", r.get("http", {}))
                status_code = status.get("status", "?") if status else "?"
                yield sse("log", {"type": "found", "msg": f"<span class='hl'>{h}</span> — {status_code} [{tech_str}] {title}"})
                missing = len(r.get("missing_security_headers", []))
                if missing >= 4:
                    yield sse("log", {"type": "warn", "msg": f"  ↳ {missing} security headers missing"})

        # ── Step 3: Port Scanning (optional) ──
        port_results = {}
        if do_ports:
            yield sse("progress", {"pct": 55, "label": f"Port scanning {len(alive_hosts)} hosts"})
            yield sse("log", {"type": "info", "msg": "Phase 3: Port Scanning (top 25 ports)"})
            port_results = PortScanner.bulk_scan(alive_hosts, max_workers=5)
            for h, r in port_results.items():
                if r["ports"]:
                    ports_str = ", ".join(f"{p['port']}/{p['service']}" for p in r["ports"])
                    yield sse("log", {"type": "found", "msg": f"<span class='hl'>{h}</span> — {ports_str}"})

        # ── Step 4: Attack Surface (optional) ──
        attack_results = {}
        if do_attack:
            # Only scan top 10 alive hosts to avoid abuse
            top_hosts = alive_hosts[:10]
            yield sse("progress", {"pct": 70, "label": f"Attack surface detection ({len(top_hosts)} hosts)"})
            yield sse("log", {"type": "info", "msg": "Phase 4: Attack Surface Detection"})
            for h in top_hosts:
                result = AttackSurfaceDetector.detect(h, timeout=3)
                attack_results[h] = result
                total = len(result["admin_panels"]) + len(result["login_pages"]) + len(result["api_endpoints"])
                if total > 0:
                    parts = []
                    if result["admin_panels"]: parts.append(f"{len(result['admin_panels'])} admin")
                    if result["login_pages"]: parts.append(f"{len(result['login_pages'])} login")
                    if result["api_endpoints"]: parts.append(f"{len(result['api_endpoints'])} API")
                    yield sse("log", {"type": "warn", "msg": f"<span class='hl'>{h}</span> — {', '.join(parts)}"})

        # ── Step 5: Risk Scoring ──
        yield sse("progress", {"pct": 85, "label": "Risk assessment"})
        yield sse("log", {"type": "info", "msg": "Phase 5: Risk Assessment"})

        assets = []
        for h in alive_hosts:
            asset = {
                "hostname": h,
                "alive": True,
                "ports": port_results.get(h, {}).get("ports", []),
                "attack_surface": attack_results.get(h, {}),
                "technology": http_results.get(h, {}).get("technology", []),
                "missing_security_headers": http_results.get(h, {}).get("missing_security_headers", []),
                "http_info": http_results.get(h, {}).get("https") or http_results.get(h, {}).get("http"),
                "title": http_results.get(h, {}).get("title"),
            }
            assets.append(asset)

        scored = RiskScorer.assess_all(assets)
        summary = RiskScorer.executive_summary(scored)

        # Output risk results
        for a in scored:
            if a["score"] > 0:
                level = a["level"].upper()
                color = {"CRITICAL": "err", "HIGH": "warn", "MEDIUM": "info", "LOW": "sys", "INFO": "sys"}
                yield sse("log", {"type": color.get(level, "sys"),
                    "msg": f"[{level}] <span class='hl'>{a['hostname']}</span> — score {a['score']}/100"})
                for reason in a["reasons"][:3]:
                    yield sse("log", {"type": "info", "msg": f"  ↳ {reason}"})
                if a.get("attack_paths"):
                    yield sse("log", {"type": "warn",
                        "msg": f"  ↳ {len(a['attack_paths'])} attack path(s) identified"})
                    for ap in a["attack_paths"]:
                        yield sse("log", {"type": "warn",
                            "msg": f"    [{ap['severity'].upper()}] {ap['path']}"})

        # Summary
        yield sse("progress", {"pct": 100, "label": "Complete"})
        stats = summary["stats"]
        yield sse("log", {"type": "info",
            "msg": f"Assessment complete — <span class='val'>{stats['critical']} critical</span>, "
                   f"<span class='hl'>{stats['high']} high</span>, {stats['medium']} medium, {stats['low']} low"})

        if summary["recommendations"]:
            yield sse("log", {"type": "info", "msg": "Recommendations:"})
            for rec in summary["recommendations"]:
                yield sse("log", {"type": "warn", "msg": f"  → {rec}"})

        yield sse("recon_done", {
            "total": len(scored),
            "summary": summary,
            "scored_assets": scored[:20]  # Top 20
        })

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@recon_bp.route("/api/recon/quick")
def recon_quick():
    """Quick recon on a single host — returns JSON"""
    host_raw = request.args.get("host", "").strip()
    if not host_raw:
        return jsonify({"error": "Host required"}), 400
    try:
        host = Validators.domain(host_raw)
    except ValidationError as e:
        return jsonify({"error": e.message}), 400

    dns = DNSResolver.resolve(host)
    http = HTTPProber.probe(host) if dns and dns["alive"] else None
    ports = PortScanner.scan(host) if dns and dns["alive"] else None

    asset = {
        "hostname": host,
        "alive": dns["alive"] if dns else False,
        "dns": dns,
        "http": http,
        "ports": ports.get("ports", []) if ports else [],
        "technology": http.get("technology", []) if http else [],
        "missing_security_headers": http.get("missing_security_headers", []) if http else [],
        "http_info": (http.get("https") or http.get("http")) if http else None,
    }

    risk = RiskScorer.score_asset(asset)
    asset["risk"] = risk
    return jsonify(asset)
