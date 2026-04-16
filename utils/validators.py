"""
Input Validation & Sanitization
All user input passes through here before reaching any tool
"""
import re, os
from html import escape as html_escape
from config import Config

class ValidationError(Exception):
    def __init__(self, message, field=None):
        self.message = message
        self.field = field
        super().__init__(message)

class Validators:
    # Compiled patterns for performance
    _DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
    _EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    _USERNAME = re.compile(r'^[a-zA-Z0-9._-]{1,64}$')
    _SAFE_PATH = re.compile(r'^[a-zA-Z0-9/_.\-~]+$')

    @classmethod
    def _check_length(cls, value, name, max_len=None):
        max_len = max_len or Config.MAX_INPUT_LENGTH
        if not value or not value.strip():
            raise ValidationError(f"{name} cannot be empty", name)
        if len(value) > max_len:
            raise ValidationError(f"{name} too long (max {max_len} chars)", name)
        return value.strip()

    @classmethod
    def domain(cls, value):
        """Validate and clean a domain name"""
        value = cls._check_length(value, "Domain")
        # Clean: remove protocol, email prefix, trailing slashes
        if "@" in value:
            value = value.split("@")[-1]
        for prefix in ["https://", "http://", "www."]:
            if value.lower().startswith(prefix):
                value = value[len(prefix):]
        # Strip URL path, query, fragment
        for sep in ["/", "?", "#"]:
            if sep in value:
                value = value.split(sep)[0]
        value = value.strip().lower()
        if not cls._DOMAIN.match(value):
            raise ValidationError(f"Invalid domain format: '{value}'", "domain")
        return value

    @classmethod
    def username(cls, value):
        """Validate a username"""
        value = cls._check_length(value, "Username", 64)
        value = value.strip().lstrip("@")  # Remove leading @ (Twitter style)
        if not cls._USERNAME.match(value):
            raise ValidationError("Invalid username (use letters, numbers, . _ - only)", "username")
        return value

    @classmethod
    def filepath(cls, value):
        """Validate and secure a file path"""
        value = cls._check_length(value, "File path", 512)
        value = os.path.normpath(value)
        # Block path traversal
        if ".." in value:
            raise ValidationError("Path traversal detected (..)", "filepath")
        # Allow ghosttrace uploads directory (even if under /root)
        upload_dir = os.path.normpath(os.path.join(Config.BASE_DIR, "uploads"))
        if not value.startswith(upload_dir):
            # Block dangerous paths
            for forbidden in Config.FORBIDDEN_PATHS:
                if forbidden in value.lower():
                    raise ValidationError("Access denied: restricted path", "filepath")
        # Must be absolute
        if not os.path.isabs(value):
            raise ValidationError("Use absolute file path (e.g., /home/kali/file.jpg)", "filepath")
        return value

    @classmethod
    def email(cls, value):
        """Validate an email and extract domain"""
        value = cls._check_length(value, "Email")
        value = value.strip().lower()
        if not cls._EMAIL.match(value):
            raise ValidationError(f"Invalid email format: '{value}'", "email")
        return value

    @classmethod
    def scan_source(cls, value, allowed_sources=None):
        """Validate a scan source name"""
        value = cls._check_length(value, "Source", 64).lower()
        if value in ("all", "all sources"):
            return "all"
        allowed = allowed_sources or Config.FREE_SOURCES
        if value not in allowed:
            raise ValidationError(f"Unknown source: '{value}'. Use: {', '.join(allowed[:5])}...", "source")
        return value

    # SEC 1 FIX: Per-tool argument whitelists (much safer than blacklist)
    _TOOL_ARG_WHITELIST = {
        "theharvester": re.compile(r'^[-a-zA-Z0-9@._,:/]+$'),
        "sherlock":     re.compile(r'^[-a-zA-Z0-9._]+$'),
        "exiftool":     re.compile(r'^[-a-zA-Z0-9/._~]+$'),
        "maigret":      re.compile(r'^[-a-zA-Z0-9._:/]+$'),
        "phoneinfoga":  re.compile(r'^[-a-zA-Z0-9+() ]+$'),
        "whois":        re.compile(r'^[-a-zA-Z0-9.]+$'),
        "dig":          re.compile(r'^[-a-zA-Z0-9.+]+$'),
        "openssl":      re.compile(r'^[-a-zA-Z0-9.:_]+$'),
    }

    @classmethod
    def cli_command(cls, value):
        """Validate a CLI command — whitelist per tool"""
        value = cls._check_length(value, "Command", 512)
        parts = value.split()
        if not parts:
            raise ValidationError("Empty command", "cli")
        tool = parts[0].lower()
        if tool not in Config.ALLOWED_TOOLS:
            raise ValidationError(
                f"'{tool}' not allowed. Allowed: {', '.join(Config.ALLOWED_TOOLS)}", "cli")
        # Whitelist each argument
        pattern = cls._TOOL_ARG_WHITELIST.get(tool)
        if pattern:
            for arg in parts[1:]:
                if not pattern.match(arg):
                    raise ValidationError(f"Invalid argument: '{arg}'", "cli")
        return parts

    @classmethod
    def limit(cls, value, min_v=1, max_v=5000):
        """Validate a numeric limit"""
        try:
            n = int(value)
            if n < min_v or n > max_v:
                raise ValidationError(f"Limit must be {min_v}-{max_v}", "limit")
            return str(n)
        except (ValueError, TypeError):
            raise ValidationError("Limit must be a number", "limit")

    @classmethod
    def filename(cls, value):
        """Validate a filename (no path traversal)"""
        value = cls._check_length(value, "Filename", 256)
        if ".." in value or "/" in value or "\\" in value:
            raise ValidationError("Invalid filename", "filename")
        return value

    _PHONE = re.compile(r'^\+?[0-9\s\-\(\)]{7,20}$')

    @classmethod
    def detect_input_type(cls, value):
        """Auto-detect what type of input this is"""
        value = value.strip()
        if not value:
            return "unknown", value
        if os.path.exists(value):
            return "file", value
        if "@" in value and cls._EMAIL.match(value.lower()):
            return "email", cls.domain(value)
        if cls._PHONE.match(value):
            return "phone", value
        if cls._DOMAIN.match(value.lower().replace("https://","").replace("http://","").strip("/")):
            return "domain", cls.domain(value)
        if "/" in value or value.startswith("~"):
            return "file", value
        return "username", value

    @classmethod
    def sanitize_html(cls, value):
        """Sanitize for HTML output"""
        return html_escape(str(value)) if value else ""
