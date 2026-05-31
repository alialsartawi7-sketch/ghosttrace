"""
Tool Execution Engine — Sandboxed subprocess management
Handles timeouts (wall-clock watchdog, fires even with zero output),
concurrent stderr draining (no pipe-buffer deadlock), output sanitization,
and full process-group lifecycle.
"""
import subprocess, threading, queue, time, os, signal
from config import Config
from utils.logger import log
from utils.security import OutputSanitizer

_SENTINEL = object()


def _popen_kwargs():
    """Platform-safe kwargs — new session/process-group only on POSIX."""
    kwargs = {}
    if os.name != 'nt':
        # start_new_session is the thread-safe, picklable equivalent of
        # preexec_fn=os.setsid — puts the child in its own process group
        # so we can kill the whole tree on timeout/abort.
        kwargs['start_new_session'] = True
    return kwargs


class ExecutionEngine:
    """Controlled execution of OSINT tools with safety guarantees."""

    @staticmethod
    def _kill_process(proc):
        """Kill a process and its entire process group (best-effort)."""
        if proc is None or proc.poll() is not None:
            return
        if os.name == 'nt':
            try:
                proc.terminate()
            except Exception:
                pass
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except Exception:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    @staticmethod
    def stream(cmd, env=None, timeout=None, max_lines=None,
               stop_check=None, scan_ref=None, merge_stderr=False):
        """
        Robust streaming executor (generator).

        Yields:
          ('line', <cleaned str>)  for each stdout line as it arrives
          ('done', <dict>)         exactly once at the end, with keys:
                                   return_code, timed_out, aborted, truncated,
                                   error, line_count, stderr

        Guarantees:
          * timeout is enforced on wall-clock time even if the tool emits
            NO output (watchdog polls every second) — fixes the silent-hang bug.
          * stderr is drained on a background thread so a tool writing a lot
            to stderr can never deadlock on a full pipe buffer.
          * the whole process group is killed on timeout / abort / line-limit.

        stop_check: optional callable -> bool. When it returns True, abort.
        scan_ref:   optional dict; the live Popen is stored at scan_ref["process"]
                    so an external aborter can kill it immediately.
        merge_stderr: if True, stderr is folded into stdout (used by raw CLI mode).
        """
        timeout = timeout or Config.TOOL_TIMEOUT
        max_lines = max_lines or Config.TOOL_MAX_OUTPUT_LINES
        tool_name = cmd[0] if cmd else "unknown"
        log.info(f"Executing: {' '.join(cmd)} (timeout={timeout}s)")

        stderr_target = subprocess.STDOUT if merge_stderr else subprocess.PIPE
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=stderr_target,
                text=True, bufsize=1, env=env, **_popen_kwargs()
            )
        except FileNotFoundError:
            yield ('done', {"return_code": -1, "timed_out": False, "aborted": False,
                            "truncated": False, "error": f"{tool_name} not found. Is it installed?",
                            "line_count": 0, "stderr": ""})
            return
        except Exception as e:
            yield ('done', {"return_code": -1, "timed_out": False, "aborted": False,
                            "truncated": False, "error": f"Execution error: {e}",
                            "line_count": 0, "stderr": ""})
            return

        if scan_ref is not None:
            scan_ref["process"] = proc

        q = queue.Queue()
        stderr_buf = []

        def _drain_stdout():
            try:
                for line in proc.stdout:
                    q.put(('line', line))
            except Exception:
                pass
            finally:
                q.put(_SENTINEL)

        def _drain_stderr():
            try:
                for line in proc.stderr:
                    stderr_buf.append(line)
                    if sum(len(x) for x in stderr_buf) > 65536:  # cap memory
                        break
            except Exception:
                pass

        t_out = threading.Thread(target=_drain_stdout, daemon=True)
        t_out.start()
        if not merge_stderr:
            threading.Thread(target=_drain_stderr, daemon=True).start()

        start = time.time()
        line_count = 0
        timed_out = aborted = truncated = False

        while True:
            if time.time() - start > timeout:
                timed_out = True
                ExecutionEngine._kill_process(proc)
                break
            if stop_check and stop_check():
                aborted = True
                ExecutionEngine._kill_process(proc)
                break
            try:
                item = q.get(timeout=1.0)
            except queue.Empty:
                continue  # no output this second — re-check timeout/stop
            if item is _SENTINEL:
                break
            line_count += 1
            if line_count > max_lines:
                truncated = True
                ExecutionEngine._kill_process(proc)
                break
            cleaned = OutputSanitizer.clean(item[1].rstrip())
            if cleaned:
                yield ('line', cleaned)

        try:
            proc.wait(timeout=5)
        except Exception:
            ExecutionEngine._kill_process(proc)

        err = OutputSanitizer.clean("".join(stderr_buf).strip()) if stderr_buf else ""
        yield ('done', {
            "return_code": proc.returncode,
            "timed_out": timed_out,
            "aborted": aborted,
            "truncated": truncated,
            "error": err if (proc.returncode not in (0, None) and err) else None,
            "line_count": line_count,
            "stderr": err,
        })

    @staticmethod
    def run_capture(cmd, timeout=None, env=None):
        """Execute and capture all output at once (for ExifTool etc.)."""
        timeout = timeout or Config.TOOL_TIMEOUT
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                env=env, **_popen_kwargs()
            )
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
                "success": proc.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Timed out", "return_code": -1, "success": False}
        except FileNotFoundError:
            return {"stdout": "", "stderr": f"{cmd[0]} not found", "return_code": -1, "success": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "return_code": -1, "success": False}

    @staticmethod
    def check_tool(name, cmd=None):
        """Check if a tool is installed."""
        cmd = cmd or name
        try:
            r = subprocess.run(["which", cmd], capture_output=True, text=True, timeout=5)
            return {"installed": r.returncode == 0, "path": r.stdout.strip() or None}
        except Exception as e:
            log.warning(f"check_tool({name}) failed: {e}")
            return {"installed": False, "path": None}
