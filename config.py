"""
GhostTrace Configuration
Centralized config with environment support
"""
import os, json, secrets

class Config:
    VERSION = "6.3"
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

    # theHarvester sources that REQUIRE an API key. Maps the config-key saved by
    # the settings UI -> (theHarvester "-b" source name, api-keys.yaml section).
    # theHarvester reads keys from ~/.theHarvester/api-keys.yaml, NOT env vars,
    # so keys saved in the UI are synced into that file (see sync_harvester_keys).
    HARVESTER_KEYED_SOURCES = {
        "shodan":         ("shodan",         "shodan"),
        "hunter":         ("hunter",         "hunter"),
        "securitytrails": ("securityTrails", "securityTrails"),
        "virustotal":     ("virustotal",     "virustotal"),
        "censys":         ("censys",         "censys"),  # value entered as "id:secret"
    }
    THEHARVESTER_KEYS_PATH = os.path.expanduser("~/.theHarvester/api-keys.yaml")

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
        # Propagate keys into theHarvester's own config so it actually uses them.
        try:
            cls.sync_harvester_keys(keys)
        except Exception:
            pass

    @classmethod
    def configured_key_sources(cls, keys=None):
        """theHarvester '-b' source names whose API key is set (non-empty)."""
        keys = cls.load_api_keys() if keys is None else keys
        out = []
        for cfg_name, (src, _section) in cls.HARVESTER_KEYED_SOURCES.items():
            if str(keys.get(cfg_name, "") or "").strip():
                out.append(src)
        return out

    @classmethod
    def sync_harvester_keys(cls, keys=None):
        """Write configured API keys into theHarvester's api-keys.yaml so the tool
        actually consumes them. Merges into the existing structure and never
        clobbers sections GhostTrace doesn't manage. Returns synced section names."""
        keys = cls.load_api_keys() if keys is None else keys
        try:
            import yaml
        except ImportError:
            return []
        path = cls.THEHARVESTER_KEYS_PATH
        data = {}
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
            except Exception:
                data = {}
        if not isinstance(data, dict):
            data = {}
        api = data.get("apikeys")
        if not isinstance(api, dict):
            api = {}
        synced = []
        for cfg_name, (_src, section) in cls.HARVESTER_KEYED_SOURCES.items():
            val = str(keys.get(cfg_name, "") or "").strip()
            if not val:
                continue
            if section == "censys":
                # Censys needs id + secret, entered in the UI as "id:secret"
                if ":" in val:
                    cid, _, csecret = val.partition(":")
                    api["censys"] = {"id": cid.strip(), "secret": csecret.strip()}
                    synced.append("censys")
                continue
            api[section] = {"key": val}
            synced.append(section)
        if not synced:
            return []
        data["apikeys"] = api
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception:
            return []
        return synced

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
