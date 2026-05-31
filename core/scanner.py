"""
Scan Orchestrator — Manages the full lifecycle of a scan.
Connects: Validator -> DB -> ExecutionEngine.stream -> Tool Adapter
          -> Intelligence -> SSE Output.

All subprocess handling (timeout watchdog, stderr draining, process-group
kill) now lives in ExecutionEngine.stream — this module just wires tools to
SSE events, so the timeout/deadlock logic exists in exactly one place.
"""
import json, threading
from config import Config
from database.manager import ScanDB, ResultDB
from core.engine import ExecutionEngine
from intelligence.correlator import Correlator, Scorer
from tools.registry import ToolRegistry
from utils.logger import log
from utils.security import scan_limiter

# Track active scans
active_scans = {}
_lock = threading.Lock()


def sse(etype, data):
    return f"event: {etype}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _count_active():
    with _lock:
        return sum(1 for s in active_scans.values() if not s.get("stop"))


def _blend_confidence(item):
    """Combine an adapter's own confidence with the Scorer's corroboration."""
    adapter_conf = item.get("confidence", 0)
    scorer_conf = Scorer.calculate(item["value"], item["source"], item["type"])
    if adapter_conf > 0:
        return round(min(1.0, (adapter_conf + scorer_conf) / 2
                         + Scorer.corroboration_bonus(item["value"])), 2)
    return scorer_conf


def run_tool_scan(tool_name, target, module, **opts):
    """Generator that runs a tool scan and yields SSE events."""
    # Rate limit
    if not scan_limiter.allow("scan"):
        log.warning(f"Rate limit hit for {tool_name}/{target}")
        yield sse("log", {"type": "err", "msg": "Rate limit: too many scans. Wait a moment."})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
        return

    # Concurrency limit
    if _count_active() >= Config.MAX_CONCURRENT_SCANS:
        log.warning(f"Concurrency limit hit ({Config.MAX_CONCURRENT_SCANS})")
        yield sse("log", {"type": "err", "msg": f"Max {Config.MAX_CONCURRENT_SCANS} concurrent scans. Wait for one to finish."})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
        return

    tool = ToolRegistry.get(tool_name)
    if not tool:
        log.error(f"Unknown tool requested: {tool_name}")
        yield sse("log", {"type": "err", "msg": f"Unknown tool: {tool_name}"})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
        return

    # Create scan record
    scan_id = ScanDB.create(module, target, tool.name)
    scan_ref = {"stop": False, "process": None, "count": 0}
    with _lock:
        active_scans[scan_id] = scan_ref

    log.info(f"Scan {scan_id[:8]} started: {tool.name} -> {target}")
    yield sse("scan_start", {"scan_id": scan_id, "tool": tool.name, "target": target})

    cmd = tool.build_command(target, **opts)
    yield sse("log", {"type": "info", "msg": f"$ {' '.join(cmd)}"})
    yield sse("progress", {"pct": 5, "label": f"Initializing {tool.name}"})

    # ExifTool is non-streaming (JSON dumped at once)
    if tool_name.lower() == "exiftool":
        yield from _run_exiftool(tool, cmd, scan_id, target, scan_ref)
        return

    context = {"target": target, "section": None, "checked": 0}
    found_values = set()
    timed_out = aborted = False

    try:
        for kind, payload in ExecutionEngine.stream(
                cmd, env=tool.get_env(), scan_ref=scan_ref,
                stop_check=lambda: scan_ref.get("stop")):

            if kind == "done":
                timed_out = payload.get("timed_out")
                aborted = payload.get("aborted")
                if payload.get("truncated"):
                    yield sse("log", {"type": "warn", "msg": "Output limit reached — terminated"})
                if payload.get("error"):
                    yield sse("log", {"type": "err", "msg": payload["error"]})
                break

            # kind == "line"
            parsed = tool.parse_line(payload, context)

            # Parser may attach a single log message
            if "_log" in context:
                lt, lm = context.pop("_log")
                yield sse("log", {"type": lt, "msg": lm})

            for item in parsed:
                val = item["value"]
                if val in found_values:
                    continue
                found_values.add(val)
                item["confidence"] = _blend_confidence(item)

                if ResultDB.add(scan_id, val, item["source"], item["type"],
                                item["confidence"], item.get("extra")):
                    scan_ref["count"] += 1
                    Correlator.process_result(val, item["type"], item["source"], target)
                    yield sse("result", item)
                    pct = min(90, 10 + scan_ref["count"] * 3)
                    yield sse("progress", {"pct": pct, "label": f"Found {scan_ref['count']} results"})

    except Exception as e:
        log.error(f"Scan {scan_id[:8]} error: {e}")
        yield sse("log", {"type": "err", "msg": str(e)})
    finally:
        with _lock:
            active_scans.pop(scan_id, None)

    if timed_out:
        yield sse("log", {"type": "warn", "msg": f"Timed out after {Config.TOOL_TIMEOUT}s"})

    found_count = scan_ref["count"]
    status = "aborted" if (aborted or scan_ref.get("stop")) else "complete"
    ScanDB.finish(scan_id, status, found_count)
    log.info(f"Scan {scan_id[:8]} {status}: {found_count} results")
    yield sse("progress", {"pct": 100, "label": "Complete"})
    yield sse("log", {"type": "info", "msg": f"Scan complete — {found_count} results found"})
    yield sse("scan_done", {"total": found_count, "scan_id": scan_id})


def _run_exiftool(tool, cmd, scan_id, target, scan_ref):
    """ExifTool needs capture mode since it outputs JSON all at once."""
    result = ExecutionEngine.run_capture(cmd, timeout=30)

    if not result["success"]:
        yield sse("log", {"type": "err", "msg": result["stderr"] or "ExifTool failed"})
        ScanDB.finish(scan_id, "error", 0, result["stderr"])
        yield sse("scan_done", {"total": 0, "scan_id": scan_id})
        with _lock:
            active_scans.pop(scan_id, None)
        return

    yield sse("progress", {"pct": 50, "label": "Parsing metadata"})
    items = tool.parse_json(result["stdout"])
    count = 0

    for item in items:
        item["confidence"] = _blend_confidence(item)
        if ResultDB.add(scan_id, item["value"], item["source"], item["type"],
                        item["confidence"], item.get("extra")):
            count += 1
            scan_ref["count"] = count
            Correlator.process_result(item["value"], item["type"], item["source"], target)
            yield sse("result", item)
            extra = item.get("extra", "")
            if extra and extra in ("GPS", "AUTHOR", "DEVICE", "SOFTWARE", "DATE", "WARNING", "SUMMARY"):
                val = item["value"]
                yield sse("log", {"type": "found", "msg": f"<span class='hl'>[{extra}]</span> {val[:80]}"})
            elif extra and extra not in ("BASIC", "STATS", "OTHER"):
                yield sse("log", {"type": "found", "msg": f"<span class='hl'>{extra}</span> -> {item['value'][:80]}"})
            pct = min(95, 50 + count * 2)
            yield sse("progress", {"pct": pct, "label": f"Extracted {count} fields"})

    ScanDB.finish(scan_id, "complete", count)
    yield sse("progress", {"pct": 100, "label": "Complete"})
    yield sse("log", {"type": "info", "msg": f"Extraction complete — {count} fields found"})
    yield sse("scan_done", {"total": count, "scan_id": scan_id})
    with _lock:
        active_scans.pop(scan_id, None)


def abort_scan(scan_id):
    """Abort a running scan: flag it, kill its process immediately, finalize DB.

    The kill happens here (via the stored Popen handle) so abort works even if
    the SSE generator is paused because the client disconnected. ScanDB.finish
    refuses to overwrite a terminal state, so the generator's own finish (if it
    later resumes) becomes a harmless no-op — no double-finish race.
    """
    with _lock:
        ref = active_scans.get(scan_id)
        if ref:
            ref["stop"] = True
    if not ref:
        return False
    proc = ref.get("process")
    if proc and proc.poll() is None:
        ExecutionEngine._kill_process(proc)
    ScanDB.finish(scan_id, "aborted", ref.get("count", 0))
    return True


def run_cli_scan(cmd_parts):
    """Raw CLI mode — run the command directly (no tool adapter), stream output."""
    if not scan_limiter.allow("scan"):
        yield sse("log", {"type": "err", "msg": "Rate limit. Wait a moment."})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
        return

    raw_cmd = " ".join(cmd_parts)
    scan_id = ScanDB.create("cli", raw_cmd, cmd_parts[0])
    scan_ref = {"stop": False, "process": None, "count": 0}
    with _lock:
        active_scans[scan_id] = scan_ref

    yield sse("scan_start", {"scan_id": scan_id, "tool": "CLI", "target": raw_cmd})
    yield sse("log", {"type": "info", "msg": f"$ {raw_cmd}"})
    yield sse("progress", {"pct": 10, "label": f"Running {cmd_parts[0]}"})

    line_count = 0
    timed_out = False
    rc = None
    try:
        for kind, payload in ExecutionEngine.stream(
                cmd_parts, scan_ref=scan_ref, merge_stderr=True,
                stop_check=lambda: scan_ref.get("stop")):
            if kind == "done":
                timed_out = payload.get("timed_out")
                rc = payload.get("return_code")
                if payload.get("truncated"):
                    yield sse("log", {"type": "warn", "msg": "Output limit reached"})
                if payload.get("error"):
                    yield sse("log", {"type": "err", "msg": payload["error"]})
                break
            line_count += 1
            scan_ref["count"] = line_count
            yield sse("log", {"type": "info", "msg": payload})
    except Exception as e:
        yield sse("log", {"type": "err", "msg": str(e)})
        ScanDB.finish(scan_id, "error", 0)
        yield sse("scan_done", {"total": 0, "scan_id": scan_id})
        with _lock:
            active_scans.pop(scan_id, None)
        return
    finally:
        with _lock:
            active_scans.pop(scan_id, None)

    if timed_out:
        yield sse("log", {"type": "warn", "msg": f"Timed out after {Config.TOOL_TIMEOUT}s"})
    status = "aborted" if scan_ref.get("stop") else "complete"
    ScanDB.finish(scan_id, status, line_count)
    yield sse("progress", {"pct": 100, "label": "Complete"})
    yield sse("log", {"type": "info", "msg": f"Exit code: {rc}"})
    yield sse("scan_done", {"total": line_count, "scan_id": scan_id})
