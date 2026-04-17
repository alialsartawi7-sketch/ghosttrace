"""
Scan Orchestrator — Manages the full lifecycle of a scan
Connects: Validator → DB → Engine → Tool Adapter → Intelligence → SSE Output
"""
import json, threading, subprocess, time, os, signal
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

def run_tool_scan(tool_name, target, module, **opts):
    """
    Generator that runs a tool scan and yields SSE events.
    This is the main scan function used by all API endpoints.
    """
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
    scan_ref = {"stop": False, "process": None}
    with _lock:
        active_scans[scan_id] = scan_ref

    log.info(f"Scan {scan_id[:8]} started: {tool.name} → {target}")
    yield sse("scan_start", {"scan_id": scan_id, "tool": tool.name, "target": target})

    # Build command
    cmd = tool.build_command(target, **opts)
    yield sse("log", {"type": "info", "msg": f"$ {' '.join(cmd)}"})
    yield sse("progress", {"pct": 5, "label": f"Initializing {tool.name}"})

    # Special handling for ExifTool (non-streaming)
    if tool_name.lower() == "exiftool":
        yield from _run_exiftool(tool, cmd, scan_id, target, scan_ref)
        return

    # Streaming execution
    context = {"target": target, "section": None, "checked": 0}
    found_count = 0
    found_values = set()

    def on_line(line):
        nonlocal found_count
        # Let the tool adapter parse this line
        parsed = tool.parse_line(line, context)

        # Check for log messages from parser
        if "_log" in context:
            log_type, log_msg = context.pop("_log")
            # We can't yield from here, store for later
            context.setdefault("_pending_logs", []).append((log_type, log_msg))

        for item in parsed:
            val = item["value"]
            if val in found_values:
                continue
            found_values.add(val)

            # Score — combine adapter confidence with Scorer's corroboration
            adapter_conf = item.get("confidence", 0)
            scorer_conf = Scorer.calculate(val, item["source"], item["type"])
            # Blend: adapter weight (if available) with scorer corroboration
            if adapter_conf > 0:
                confidence = round(min(1.0, (adapter_conf + scorer_conf) / 2 + Scorer.corroboration_bonus(val)), 2)
            else:
                confidence = scorer_conf
            item["confidence"] = confidence

            # Save to DB (dedup built in)
            if ResultDB.add(scan_id, val, item["source"], item["type"], confidence, item.get("extra")):
                found_count += 1
                # Correlate
                Correlator.process_result(val, item["type"], item["source"], target)
                # Store for SSE
                context.setdefault("_pending_results", []).append(item)

    def on_error(msg):
        context.setdefault("_pending_logs", []).append(("err", msg))

    def _kill(p):
        try:
            if os.name != 'nt':
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            else:
                p.terminate()
        except Exception:
            pass

    popen_kw = {}
    if os.name != 'nt':
        popen_kw['preexec_fn'] = os.setsid
    # Inject API keys if tool provides them
    tool_env = tool.get_env()
    if tool_env:
        popen_kw['env'] = tool_env

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1, **popen_kw)
        scan_ref["process"] = proc
        start_time = time.time()
        line_count = 0

        for line in proc.stdout:
            elapsed = time.time() - start_time
            if elapsed > Config.TOOL_TIMEOUT:
                _kill(proc)
                yield sse("log", {"type": "warn", "msg": f"Timed out after {Config.TOOL_TIMEOUT}s"})
                break

            if scan_ref.get("stop"):
                _kill(proc)
                yield sse("log", {"type": "warn", "msg": "Aborted by user"})
                break

            line_count += 1
            if line_count > Config.TOOL_MAX_OUTPUT_LINES:
                _kill(proc)
                yield sse("log", {"type": "warn", "msg": "Output limit reached"})
                break

            cleaned = line.rstrip()
            if not cleaned: continue
            on_line(cleaned)

            # Flush pending logs
            for lt, lm in context.pop("_pending_logs", []):
                yield sse("log", {"type": lt, "msg": lm})

            # Flush pending results
            for item in context.pop("_pending_results", []):
                yield sse("result", item)
                pct = min(90, 10 + found_count * 3)
                yield sse("progress", {"pct": pct, "label": f"Found {found_count} results"})

        proc.wait(timeout=5)

    except FileNotFoundError:
        yield sse("log", {"type": "err", "msg": f"{tool.name} not found! Is it installed?"})
        ScanDB.finish(scan_id, "error", 0, f"{tool.name} not found")
        yield sse("scan_done", {"total": 0, "scan_id": scan_id})
        return
    except Exception as e:
        yield sse("log", {"type": "err", "msg": str(e)})
    finally:
        with _lock:
            active_scans.pop(scan_id, None)

    # Finish
    status = "complete" if not scan_ref.get("stop") else "aborted"
    ScanDB.finish(scan_id, status, found_count)
    log.info(f"Scan {scan_id[:8]} {status}: {found_count} results")
    yield sse("progress", {"pct": 100, "label": "Complete"})
    yield sse("log", {"type": "info", "msg": f"Scan complete — {found_count} results found"})
    yield sse("scan_done", {"total": found_count, "scan_id": scan_id})


def _run_exiftool(tool, cmd, scan_id, target, scan_ref):
    """ExifTool needs capture mode since it outputs JSON all at once"""
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
        adapter_conf = item.get("confidence", 0)
        scorer_conf = Scorer.calculate(item["value"], item["source"], item["type"])
        if adapter_conf > 0:
            confidence = round(min(1.0, (adapter_conf + scorer_conf) / 2 + Scorer.corroboration_bonus(item["value"])), 2)
        else:
            confidence = scorer_conf
        item["confidence"] = confidence
        if ResultDB.add(scan_id, item["value"], item["source"], item["type"], confidence, item.get("extra")):
            count += 1
            Correlator.process_result(item["value"], item["type"], item["source"], target)
            yield sse("result", item)
            extra = item.get("extra", "")
            if extra and extra in ("GPS", "AUTHOR", "DEVICE", "SOFTWARE", "DATE", "WARNING", "SUMMARY"):
                val = item["value"]
                yield sse("log", {"type": "found", "msg": f"<span class='hl'>[{extra}]</span> {val[:80]}"})
            elif extra and extra not in ("BASIC", "STATS", "OTHER"):
                yield sse("log", {"type": "found", "msg": f"<span class='hl'>{extra}</span> → {item['value'][:80]}"})
            pct = min(95, 50 + count * 2)
            yield sse("progress", {"pct": pct, "label": f"Extracted {count} fields"})

    ScanDB.finish(scan_id, "complete", count)
    yield sse("progress", {"pct": 100, "label": "Complete"})
    yield sse("log", {"type": "info", "msg": f"Extraction complete — {count} fields found"})
    yield sse("scan_done", {"total": count, "scan_id": scan_id})
    with _lock:
        active_scans.pop(scan_id, None)


def abort_scan(scan_id):
    with _lock:
        ref = active_scans.get(scan_id)
        if ref:
            ref["stop"] = True
    if ref:
        proc = ref.get("process")
        if proc and proc.poll() is None:
            try:
                if os.name != 'nt':
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                else:
                    proc.terminate()
            except Exception:
                pass
        ScanDB.finish(scan_id, "aborted", 0)
        return True
    return False


def run_cli_scan(cmd_parts):
    """
    BUG 6 FIX: CLI mode runs the raw command directly without going through
    tool adapters. This avoids passing joined args as 'target'.
    """
    if not scan_limiter.allow("scan"):
        yield sse("log", {"type": "err", "msg": "Rate limit. Wait a moment."})
        yield sse("scan_done", {"total": 0, "scan_id": "none"})
        return

    raw_cmd = " ".join(cmd_parts)
    scan_id = ScanDB.create("cli", raw_cmd, cmd_parts[0])
    scan_ref = {"stop": False, "process": None}
    with _lock:
        active_scans[scan_id] = scan_ref

    yield sse("scan_start", {"scan_id": scan_id, "tool": "CLI", "target": raw_cmd})
    yield sse("log", {"type": "info", "msg": f"$ {raw_cmd}"})
    yield sse("progress", {"pct": 10, "label": f"Running {cmd_parts[0]}"})

    popen_kw = {}
    if os.name != 'nt':
        popen_kw['preexec_fn'] = os.setsid

    try:
        proc = subprocess.Popen(
            cmd_parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, **popen_kw
        )
        scan_ref["process"] = proc
        line_count = 0
        start = time.time()

        for line in proc.stdout:
            if time.time() - start > Config.TOOL_TIMEOUT:
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                except Exception:
                    pass
                yield sse("log", {"type": "warn", "msg": f"Timed out after {Config.TOOL_TIMEOUT}s"})
                break

            if scan_ref.get("stop"):
                try:
                    if os.name != 'nt':
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                except Exception:
                    pass
                yield sse("log", {"type": "warn", "msg": "Aborted by user"})
                break

            line = line.rstrip()
            if line:
                line_count += 1
                yield sse("log", {"type": "info", "msg": line})

        proc.wait(timeout=5)
        status = "complete" if not scan_ref.get("stop") else "aborted"
        ScanDB.finish(scan_id, status, line_count)
        yield sse("progress", {"pct": 100, "label": "Complete"})
        yield sse("log", {"type": "info", "msg": f"Exit code: {proc.returncode}"})
        yield sse("scan_done", {"total": line_count, "scan_id": scan_id})

    except FileNotFoundError:
        yield sse("log", {"type": "err", "msg": f"{cmd_parts[0]} not found"})
        ScanDB.finish(scan_id, "error", 0)
        yield sse("scan_done", {"total": 0, "scan_id": scan_id})
    except Exception as e:
        yield sse("log", {"type": "err", "msg": str(e)})
        ScanDB.finish(scan_id, "error", 0)
        yield sse("scan_done", {"total": 0, "scan_id": scan_id})
    finally:
        with _lock:
            active_scans.pop(scan_id, None)
