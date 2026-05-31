"""
GhostTrace Configuration
Centralized config with environment support
"""
import os, json, secrets

class Config:
    VERSION = "6.2"
    BASE_DIR = os.path.expanduser("~/ghosttrace_data")
    DB_PATH = os.path.join(BASE_DIR, "ghosttrace.db")
    EXPORT_DIR = os.path.expanduser("~/ghosttrace_exports")
    CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
    LOG_DIR = os.path.join(BASE_DIR, "logs")

    TOR_PROXY = os.environ.get("GT_TOR_PROXY", "socks5://127.0.0.1:9050")
    # SECRET_KEY is resolved via get_secret_key() so sessions survive restarts:
    # env override > value stored in config.json > generated-and-persisted once.

    # Execution limits
    TOOL_TIMEOUT = 240         # Max seconds per tool
    TOOL_MAX_OUTPUT_LINES = 5000
    MAX_CONCURRENT_SCANS = 3
    SSE_KEEPALIVE_SEC = 15

    # Security
    ALLOWED_TOOLS = {"theharvester", "sherlock", "exiftool", "maigret", "phoneinfoga", "whois", "dig", "openssl"}
    FORBIDDEN_PATHS = ["/etc/shadow", "/etc/passwd", ".ssh", "id_rsa", "/root", "/proc", "/sys"]
    MAX_INPUT_LENGTH = 256

    # theHarvester free sources (v4.10.1)
    FREE_SOURCES = [
        "certspotter", "crtsh", "dnsdumpster", "duckduckgo", "hackertarget",
        "otx", "rapiddns", "robtex", "subdomaincenter", "threatcrowd",
        "urlscan", "waybackarchive", "yahoo"
    ]
    IGNORE_EMAILS = {"cmartorella@edge-security.com", "cmartorella@gmail.com"}

    # Intelligence
    SOURCE_WEIGHTS = {
        "crtsh": 0.9, "certspotter": 0.9, "dnsdumpster": 0.8,
        "hackertarget": 0.7, "rapiddns": 0.7, "duckduckgo": 0.5,
        "yahoo": 0.5, "otx": 0.8, "robtex": 0.7, "urlscan": 0.8,
        "waybackarchive": 0.6, "subdomaincenter": 0.6, "threatcrowd": 0.5,
        "theHarvester": 0.7, "Sherlock": 0.8, "ExifTool": 0.95
    }

    @classmethod
    def init(cls):
        for d in [cls.BASE_DIR, cls.EXPORT_DIR, cls.LOG_DIR]:
            os.makedirs(d, exist_ok=True)

    @classmethod
    def load_api_keys(cls):
        if os.path.exists(cls.CONFIG_FILE):
            with open(cls.CONFIG_FILE) as f:
                return json.load(f).get("api_keys", {})
        return {}

    @classmethod
    def save_api_keys(cls, keys):
        cfg = {}
        if os.path.exists(cls.CONFIG_FILE):
            with open(cls.CONFIG_FILE) as f: cfg = json.load(f)
        cfg["api_keys"] = keys
        with open(cls.CONFIG_FILE, "w") as f: json.dump(cfg, f, indent=2)
        try:
            os.chmod(cls.CONFIG_FILE, 0o600)
        except OSError:
            pass

    @classmethod
    def load_auth_hash(cls):
        if os.path.exists(cls.CONFIG_FILE):
            with open(cls.CONFIG_FILE) as f:
                return json.load(f).get("auth_hash")
        return None

    @classmethod
    def get_secret_key(cls):
        """Resolve the Flask session secret so it is STABLE across restarts.

        Priority: GT_SECRET_KEY env var > value stored in config.json >
        a freshly generated key that we then persist. Generating a new key
        on every boot (the old behaviour) silently logged every user out.
        Call after init() so BASE_DIR exists.
        """
        env_key = os.environ.get("GT_SECRET_KEY")
        if env_key:
            return env_key
        cfg = {}
        if os.path.exists(cls.CONFIG_FILE):
            with open(cls.CONFIG_FILE) as f:
                cfg = json.load(f)
        key = cfg.get("secret_key")
        if not key:
            key = secrets.token_hex(32)
            cfg["secret_key"] = key
            with open(cls.CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=2)
            try:
                os.chmod(cls.CONFIG_FILE, 0o600)  # secrets live here — lock it down
            except OSError:
                pass
        return key

    @classmethod
    def save_auth_hash(cls, hashed: str):
        cfg = {}
        if os.path.exists(cls.CONFIG_FILE):
            with open(cls.CONFIG_FILE) as f:
                cfg = json.load(f)
        cfg["auth_hash"] = hashed
        with open(cls.CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
        try:
            os.chmod(cls.CONFIG_FILE, 0o600)
        except OSError:
            pass
