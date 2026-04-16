"""
Tool Execution Engine — Sandboxed subprocess management
Handles timeouts, resource limits, output sanitization, process lifecycle
"""
import subprocess, threading, time, os, signal
from config import Config
from utils.logger import log
from utils.security import OutputSanitizer

def _popen_kwargs():
    """Platform-safe kwargs for subprocess — setsid only on POSIX"""
    kwargs = {}
    if os.name != 'nt':
        kwargs['preexec_fn'] = os.setsid
    return kwargs

class ExecutionResult:
    def __init__(self):
        self.lines = []
        self.return_code = None
        self.timed_out = False
        self.error = None

class ExecutionEngine:
    """Controlled execution of OSINT tools with safety guarantees"""

    @staticmethod
    def run_streaming(cmd, on_line, on_error=None, timeout=None, scan_ref=None):
        timeout = timeout or Config.TOOL_TIMEOUT
        result = ExecutionResult()
        tool_name = cmd[0] if cmd else "unknown"
        start_time = time.time()  # BUG 1 FIX: initialize before try block

        log.info(f"Executing: {' '.join(cmd)} (timeout={timeout}s)")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                **_popen_kwargs()  # BUG 2 FIX: platform-safe
            )

            if scan_ref is not None:
                scan_ref["process"] = proc

            line_count = 0

            for line in proc.stdout:
                elapsed = time.time() - start_time
                if elapsed > timeout:
                    result.timed_out = True
                    log.warning(f"{tool_name} timed out after {timeout}s")
                    ExecutionEngine._kill_process(proc)
                    if on_error:
                        on_error(f"Timed out after {timeout}s")
                    break

                if scan_ref and scan_ref.get("stop"):
                    log.info(f"{tool_name} aborted by user")
                    ExecutionEngine._kill_process(proc)
                    break

                line_count += 1
                if line_count > Config.TOOL_MAX_OUTPUT_LINES:
                    log.warning(f"{tool_name} output exceeded {Config.TOOL_MAX_OUTPUT_LINES} lines")
                    ExecutionEngine._kill_process(proc)
                    if on_error:
                        on_error("Output too large — terminated")
                    break

                cleaned = OutputSanitizer.clean(line.rstrip())
                if cleaned:
                    result.lines.append(cleaned)
                    on_line(cleaned)

            try:
                stderr = proc.stderr.read()
                if stderr:
                    result.error = OutputSanitizer.clean(stderr.strip())
            except Exception:  # BUG 3 FIX: no bare except
                pass

            proc.wait(timeout=5)
            result.return_code = proc.returncode

        except FileNotFoundError:
            msg = f"{tool_name} not found. Is it installed?"
            result.error = msg
            log.error(msg)
            if on_error: on_error(msg)

        except Exception as e:
            msg = f"Execution error: {str(e)}"
            result.error = msg
            log.error(msg)
            if on_error: on_error(msg)

        duration = time.time() - start_time  # BUG 1 FIX: always valid now
        log.info(f"{tool_name} finished in {duration:.1f}s — {len(result.lines)} lines, exit={result.return_code}")
        return result

    @staticmethod
    def run_capture(cmd, timeout=None):
        """Execute and capture all output at once (for ExifTool etc.)"""
        timeout = timeout or Config.TOOL_TIMEOUT
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                **_popen_kwargs()  # BUG 2 FIX
            )
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
                "success": proc.returncode == 0
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Timed out", "return_code": -1, "success": False}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"{cmd[0]} not found", "return_code": -1, "success": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "return_code": -1, "success": False}

    @staticmethod
    def check_tool(name, cmd=None):
        """Check if a tool is installed"""
        cmd = cmd or name
        try:
            r = subprocess.run(["which", cmd], capture_output=True, text=True, timeout=5)
            return {"installed": r.returncode == 0, "path": r.stdout.strip() or None}
        except Exception as e:  # BUG 3 FIX: log the error
            log.warning(f"check_tool({name}) failed: {e}")
            return {"installed": False, "path": None}

    @staticmethod
    def _kill_process(proc):
        """Kill process and entire process group"""
        if os.name == 'nt':
            proc.terminate()
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
