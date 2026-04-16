"""Security utilities — rate limiting, output sanitization"""
import time, re, threading
from collections import defaultdict

class RateLimiter:
    """Simple in-memory rate limiter"""
    def __init__(self, max_requests=10, window_sec=60):
        self.max = max_requests
        self.window = window_sec
        self._requests = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key="global"):
        now = time.time()
        with self._lock:
            self._requests[key] = [t for t in self._requests[key] if now - t < self.window]
            if len(self._requests[key]) >= self.max:
                return False
            self._requests[key].append(now)
            return True

class OutputSanitizer:
    """Sanitize tool output before sending to client"""
    _ANSI = re.compile(r'\x1B\[[0-9;]*[a-zA-Z]')
    _CONTROL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

    @classmethod
    def clean(cls, text):
        if not text: return ""
        text = cls._ANSI.sub('', text)
        text = cls._CONTROL.sub('', text)
        # Limit line length
        if len(text) > 1000:
            text = text[:1000] + "... (truncated)"
        return text

scan_limiter = RateLimiter(max_requests=20, window_sec=60)
