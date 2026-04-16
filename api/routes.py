"""
API Routes — Flask Blueprints
All endpoints organized by function
"""
import csv, io, os, json
from flask import Blueprint, request, jsonify, Response, stream_with_context, send_file
from config import Config
from core.scanner import run_tool_scan, run_cli_scan, abort_scan, sse
from core.differ import diff_scans
from database.manager import ScanDB, ResultDB, EntityDB
from intelligence.correlator import GraphBuilder
from reports.html_report import ReportGenerator
from tools.registry import ToolRegistry
from utils.validators import Validators, ValidationError
from utils.security import scan_limiter
from utils.logger import log

# ═══════════════ SCAN ENDPOINTS ═══════════════
scans_bp = Blueprint('scans', __name__)

def _sse_error(msg):
    def gen():
        yield sse("log", {"type": "err", "msg": msg})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def _sse_response(generator):
    return Response(stream_with_context(generator), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@scans_bp.route("/api/scan/email")
def scan_email():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
        source = Validators.scan_source(request.args.get("source", "all"))
        limit = Validators.limit(request.args.get("limit", "500"))
    except ValidationError as e:
        return _sse_error(e.message)
    use_tor = request.args.get("tor", "0") == "1"
    return _sse_response(run_tool_scan("theharvester", domain, "email", source=source, limit=limit, tor=use_tor))

@scans_bp.route("/api/scan/username")
def scan_username():
    try:
        username = Validators.username(request.args.get("username", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    tool = request.args.get("tool", "maigret").strip().lower()
    if tool not in ("maigret", "sherlock"):
        tool = "maigret"
    use_tor = request.args.get("tor", "0") == "1"
    sites = request.args.get("sites", "").strip()
    # Validate sites — only allow alphanumeric, dots, commas, spaces
    import re
    if sites and not re.match(r'^[a-zA-Z0-9.,_ \-]+$', sites):
        return _sse_error("Invalid site names")
    return _sse_response(run_tool_scan(tool, username, "username", tor=use_tor, sites=sites or None))

@scans_bp.route("/api/scan/metadata")
def scan_metadata():
    try:
        filepath = Validators.filepath(request.args.get("filepath", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    if not os.path.exists(filepath):
        return _sse_error(f"File not found: {filepath}")
    return _sse_response(run_tool_scan("exiftool", filepath, "metadata"))

@scans_bp.route("/api/scan/phone")
def scan_phone():
    import re as _re
    phone = request.args.get("phone", "").strip()
    if not phone or not _re.match(r'^\+?[0-9\s\-\(\)]{7,20}$', phone):
        return _sse_error("Invalid phone number format")
    return _sse_response(run_tool_scan("phoneinfoga", phone, "phone"))

@scans_bp.route("/api/scan/whois")
def scan_whois():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    return _sse_response(run_tool_scan("whois", domain, "whois"))

@scans_bp.route("/api/scan/dns")
def scan_dns():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    def generate():
        from tools.dns_records import DNSRecordsAdapter
        from database.manager import ScanDB, ResultDB
        from intelligence.correlator import Correlator
        import subprocess
        adapter = DNSRecordsAdapter()
        scan_id = ScanDB.create("dns", domain, "DNSRecords")
        yield sse("scan_start", {"scan_id": scan_id, "tool": "DNSRecords", "target": domain})
        yield sse("log", {"type": "info", "msg": f"Querying DNS records for {domain}..."})
        count = 0
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME"]
        for i, rtype in enumerate(record_types):
            pct = int(10 + (i / len(record_types)) * 80)
            yield sse("progress", {"pct": pct, "label": f"Querying {rtype} records"})
            try:
                cmd = ["dig", domain, rtype, "+noall", "+answer", "+authority", "+time=5"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                for line in proc.stdout.splitlines():
                    ctx = {}
                    results = adapter.parse_line(line.strip(), ctx)
                    for r in results:
                        if ResultDB.add(scan_id, r["value"], r["source"], r["type"], r.get("confidence", 0.8), r.get("extra")):
                            count += 1
                            Correlator.process_result(r["value"], r["type"], r["source"], domain)
                            yield sse("result", r)
                            if ctx.get("_log"):
                                yield sse("log", {"type": ctx["_log"][0], "msg": ctx["_log"][1]})
                            else:
                                yield sse("log", {"type": "found", "msg": f"[{rtype}] {r['value'].split('] ')[-1]}"})
            except Exception as e:
                yield sse("log", {"type": "warn", "msg": f"{rtype} query failed: {str(e)[:60]}"})
        ScanDB.finish(scan_id, "complete", count)
        yield sse("progress", {"pct": 100, "label": "Complete"})
        yield sse("log", {"type": "info", "msg": f"DNS analysis complete — {count} records found"})
        yield sse("scan_done", {"total": count, "scan_id": scan_id})
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@scans_bp.route("/api/scan/ssl")
def scan_ssl():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    def generate():
        from tools.ssl_cert import SSLCertAdapter
        from database.manager import ScanDB, ResultDB
        from intelligence.correlator import Correlator
        adapter = SSLCertAdapter()
        scan_id = ScanDB.create("ssl", domain, "SSLCert")
        yield sse("scan_start", {"scan_id": scan_id, "tool": "SSLCert", "target": domain})
        yield sse("log", {"type": "info", "msg": f"Analyzing SSL certificate for {domain}..."})
        yield sse("progress", {"pct": 20, "label": "Connecting"})
        results = adapter.parse_cert(domain)
        yield sse("progress", {"pct": 70, "label": "Parsing certificate"})
        count = 0
        for r in results:
            if ResultDB.add(scan_id, r["value"], r["source"], r["type"], r.get("confidence", 0.8), r.get("extra")):
                count += 1
                Correlator.process_result(r["value"], r["type"], r["source"], domain)
                yield sse("result", r)
                extra = r.get("extra", "")
                if extra in ("SAN", "CN", "Issuer", "Warning"):
                    yield sse("log", {"type": "found", "msg": f"<span class='hl'>{extra}</span> → {r['value'].split(': ',1)[-1]}"})
                else:
                    yield sse("log", {"type": "info", "msg": r["value"]})
        ScanDB.finish(scan_id, "complete", count)
        yield sse("progress", {"pct": 100, "label": "Complete"})
        yield sse("log", {"type": "info", "msg": f"SSL analysis complete — {count} findings"})
        yield sse("scan_done", {"total": count, "scan_id": scan_id})
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@scans_bp.route("/api/scan/dorks")
def scan_dorks():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    def generate():
        from tools.google_dorks import GoogleDorksAdapter
        from database.manager import ScanDB, ResultDB
        adapter = GoogleDorksAdapter()
        scan_id = ScanDB.create("dorks", domain, "GoogleDorks")
        yield sse("scan_start", {"scan_id": scan_id, "tool": "GoogleDorks", "target": domain})
        yield sse("log", {"type": "info", "msg": f"Generating Google dork queries for {domain}..."})
        yield sse("progress", {"pct": 30, "label": "Building queries"})
        results = adapter.generate(domain)
        count = 0
        current_cat = ""
        for r in results:
            cat = r.get("extra", "").split(":")[0] if r.get("extra") else ""
            if cat != current_cat:
                current_cat = cat
                yield sse("log", {"type": "info", "msg": f"<span class='hl'>{cat}</span>"})
            if ResultDB.add(scan_id, r["value"], r["source"], r["type"], r.get("confidence", 0.5), r.get("extra")):
                count += 1
                yield sse("result", r)
        ScanDB.finish(scan_id, "complete", count)
        yield sse("progress", {"pct": 100, "label": "Complete"})
        yield sse("log", {"type": "info", "msg": f"Generated {count} dork queries — copy them to Google"})
        yield sse("scan_done", {"total": count, "scan_id": scan_id})
    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@scans_bp.route("/api/scan/subdomain")
def scan_subdomain():
    try:
        domain = Validators.domain(request.args.get("domain", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    use_tor = request.args.get("tor", "0") == "1"
    return _sse_response(run_tool_scan("theharvester", domain, "subdomain", source="all", limit="500", tor=use_tor))

@scans_bp.route("/api/auto-detect")
def auto_detect():
    inp = request.args.get("input", "").strip()
    if not inp: return jsonify({"error": "Empty input"}), 400
    dtype, cleaned = Validators.detect_input_type(inp)
    return jsonify({"type": dtype, "cleaned": cleaned, "original": inp})

@scans_bp.route("/api/abort/<scan_id>", methods=["POST"])
def abort(scan_id):
    if abort_scan(scan_id):
        return jsonify({"status": "aborted"})
    return jsonify({"status": "not_found"}), 404

# ═══════════════ FILE UPLOAD ═══════════════
@scans_bp.route("/api/upload", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files['file']
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    # Sanitize filename
    import re as _re
    safe_name = _re.sub(r'[^a-zA-Z0-9._\-]', '_', f.filename)[:100]
    if not safe_name:
        return jsonify({"error": "Invalid filename"}), 400
    upload_dir = os.path.join(Config.BASE_DIR, "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, safe_name)
    f.save(filepath)
    log.info(f"File uploaded: {filepath}")
    return jsonify({"filepath": filepath, "filename": safe_name})

# ═══════════════ CLI MODE ═══════════════
@scans_bp.route("/api/cli")
def cli_execute():
    try:
        parts = Validators.cli_command(request.args.get("cmd", ""))
    except ValidationError as e:
        return _sse_error(e.message)
    return _sse_response(run_cli_scan(parts))


# ═══════════════ HISTORY ═══════════════
history_bp = Blueprint('history', __name__)

@history_bp.route("/api/history")
def get_history():
    page = request.args.get("page", 1, type=int)
    return jsonify(ScanDB.get_history(page))

@history_bp.route("/api/history/<scan_id>/results")
def get_results(scan_id):
    page = request.args.get("page", 1, type=int)
    return jsonify(ResultDB.get_by_scan(scan_id, page))

@history_bp.route("/api/history/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    ScanDB.delete(scan_id)
    return jsonify({"status": "deleted"})

@history_bp.route("/api/history/<scan_id>/notes", methods=["GET", "POST"])
def scan_notes(scan_id):
    if request.method == "GET":
        return jsonify({"notes": ScanDB.get_notes(scan_id)})
    data = request.get_json()
    ScanDB.save_notes(scan_id, data.get("notes", ""))
    return jsonify({"status": "saved"})

@history_bp.route("/api/diff")
def compare_scans():
    old_id = request.args.get("old", "").strip()
    new_id = request.args.get("new", "").strip()
    if not old_id or not new_id:
        return jsonify({"error": "Need old and new scan IDs"}), 400
    import re
    if not re.match(r'^[a-zA-Z0-9\-]{1,40}$', old_id) or not re.match(r'^[a-zA-Z0-9\-]{1,40}$', new_id):
        return jsonify({"error": "Invalid scan ID"}), 400
    result = diff_scans(old_id, new_id)
    return jsonify(result)

@history_bp.route("/api/stats")
def stats():
    return jsonify(EntityDB.get_stats())

@history_bp.route("/api/graph")
def graph():
    return jsonify(GraphBuilder.build())

@history_bp.route("/api/search")
def search():
    q = request.args.get("q", "").strip()
    rtype = request.args.get("type", None)
    if not q: return jsonify([])
    return jsonify(ResultDB.search(q, rtype))


# ═══════════════ EXPORT & REPORTS ═══════════════
exports_bp = Blueprint('exports', __name__)

@exports_bp.route("/api/export", methods=["POST"])
def export():
    data = request.get_json()
    results = data.get("results", [])
    fmt = data.get("format", "json")
    ts = __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        fp = os.path.join(Config.EXPORT_DIR, f"ghosttrace_{ts}.csv")
        with open(fp, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Type", "Value", "Source", "Confidence", "Time"])
            for r in results:
                w.writerow([r.get("type",""), r.get("value",""), r.get("source",""),
                           r.get("confidence",""), r.get("time","")])
    elif fmt == "json":
        fp = os.path.join(Config.EXPORT_DIR, f"ghosttrace_{ts}.json")
        with open(fp, "w") as f: json.dump(results, f, indent=2, ensure_ascii=False)
    else:
        fp = os.path.join(Config.EXPORT_DIR, f"ghosttrace_{ts}.txt")
        with open(fp, "w") as f:
            f.write(f"GhostTrace Export — {ts}\n{'='*60}\n\n")
            for r in results:
                f.write(f"[{r.get('type','?')}] {r.get('value','')} — {r.get('source','?')} ({r.get('confidence','')})\n")
    log.info(f"Exported {len(results)} results as {fmt} → {fp}")
    return jsonify({"status": "ok", "filepath": fp, "format": fmt})

@exports_bp.route("/api/report", methods=["POST"])
def report():
    data = request.get_json()
    result = ReportGenerator.generate_html(
        data.get("results", []), data.get("target", "Unknown"), data.get("module", "Unknown"),
        recon_data=data.get("recon_data"))
    return jsonify({"status": "ok", **result})

@exports_bp.route("/api/report/pdf", methods=["POST"])
def report_pdf():
    data = request.get_json()
    fn = data.get("html_filename", "")
    result = ReportGenerator.html_to_pdf(fn)
    if "error" in result:
        return jsonify(result), 500
    return jsonify({"status": "ok", **result})

@exports_bp.route("/api/report/download/<filename>")
def download_report(filename):
    try: filename = Validators.filename(filename)
    except Exception: return jsonify({"error": "Invalid"}), 400
    fp = os.path.join(Config.EXPORT_DIR, filename)
    if os.path.exists(fp): return send_file(fp, as_attachment=False)
    return jsonify({"error": "Not found"}), 404

@exports_bp.route("/api/report/pdf/download/<filename>")
def download_pdf(filename):
    try: filename = Validators.filename(filename)
    except Exception: return jsonify({"error": "Invalid"}), 400
    if not filename.endswith(".pdf"): return jsonify({"error": "Invalid"}), 400
    fp = os.path.join(Config.EXPORT_DIR, filename)
    if os.path.exists(fp): return send_file(fp, as_attachment=True, download_name=filename)
    return jsonify({"error": "Not found"}), 404


# ═══════════════ SYSTEM ═══════════════
system_bp = Blueprint('system', __name__)

@system_bp.route("/api/check-tools")
def check_tools():
    return jsonify(ToolRegistry.check_all())

@system_bp.route("/api/settings", methods=["GET", "POST"])
def settings():
    if request.method == "GET":
        return jsonify({"api_keys": Config.load_api_keys()})
    data = request.get_json()
    Config.save_api_keys(data.get("api_keys", {}))
    return jsonify({"status": "saved"})
