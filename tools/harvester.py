"""theHarvester Tool Adapter"""
import re
from tools.base import ToolAdapter
from config import Config

class HarvesterAdapter(ToolAdapter):
    name = "theHarvester"
    cmd = "theHarvester"
    result_type = "email"
    description = "Email and subdomain harvester"
    _EMAIL_RE = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')

    # theHarvester env var names for API keys
    KEY_ENV_MAP = {
        "shodan": "SHODAN_KEY",
        "hunter": "HUNTER_KEY",
        "sectrails": "SECURITYTRAILS_KEY",
        "virustotal": "VIRUSTOTAL_KEY",
        "censys": "CENSYS_API_ID",
    }

    def build_command(self, target, **opts):
        source = opts.get("source", "all")
        limit = opts.get("limit", "500")
        use_tor = opts.get("tor", False)
        cmd = [self.cmd, "-d", target, "-l", str(limit)]
        if source == "all":
            cmd += ["-b", ",".join(Config.FREE_SOURCES)]
        else:
            cmd += ["-b", source]
        if use_tor:
            cmd = ["proxychains4", "-q"] + cmd
        return cmd

    def get_env(self):
        """BUG 2 FIX: Inject API keys as env vars for theHarvester"""
        import os
        env = os.environ.copy()
        keys = Config.load_api_keys()
        for config_name, env_name in self.KEY_ENV_MAP.items():
            val = keys.get(config_name, "").strip()
            if val:
                env[env_name] = val
        return env

    # Q1 FIX: Compiled regex — survives output format changes
    _SEC_EMAIL = re.compile(r'\[\*\].*[Ee]mails?\s+found', re.I)
    _SEC_HOST = re.compile(r'\[\*\].*(Hosts?|IPs?)\s+found', re.I)

    def parse_line(self, line, context):
        results = []
        line = line.strip()
        if not line: return results

        # Track sections with regex
        if self._SEC_EMAIL.search(line):
            context["section"] = "emails"; return results
        elif self._SEC_HOST.search(line):
            context["section"] = "hosts"; return results
        elif line.startswith("[*]"):
            context["section"] = None
            context["_log"] = ("info", line.replace("[*] ", ""))
            return results
        elif line.startswith("[!]"):
            context["_log"] = ("warn", line.replace("[!] ", ""))
            return results

        section = context.get("section")

        if section == "emails":
            if "@" in line and not self.should_ignore(line):
                results.append({"value": line, "source": self.name, "type": "email",
                               "confidence": self.get_confidence(line)})
        elif section == "hosts":
            host = line.split(":")[0].strip() if ":" in line else line.strip()
            ip = line.split(":")[-1].strip() if ":" in line and line.count(":") == 1 else ""
            if host and "." in host:
                val = f"{host}" + (f" ({ip})" if ip and ip != host else "")
                results.append({"value": val, "source": self.name, "type": "subdomain",
                               "confidence": 0.8, "extra": ip})
        else:
            # Catch emails in any line
            for email in self._EMAIL_RE.findall(line):
                if not self.should_ignore(email):
                    results.append({"value": email, "source": self.name, "type": "email",
                                   "confidence": self.get_confidence(email)})
        return results

    def should_ignore(self, value):
        return value.lower() in Config.IGNORE_EMAILS

    # Smart confidence patterns
    _PERSONAL_EMAIL = re.compile(r'^[a-z]+[\._][a-z]+@', re.I)  # firstname.lastname@
    _GENERIC_EMAIL = re.compile(r'^(info|admin|support|contact|hr|sales|noreply|no-reply|webmaster|postmaster)@', re.I)
    _PRIVATE_IP = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)')
    _HIGH_VALUE_SUB = re.compile(r'(admin|vpn|mail|api|dev|staging|test|internal|jenkins|gitlab|grafana|backup|ftp|db|crm|portal)', re.I)

    def get_confidence(self, value, source=None):
        """Smart confidence based on result quality, not just source"""
        value = value.strip()

        # ── Emails ──
        if "@" in value:
            base = 0.7
            if self._PERSONAL_EMAIL.match(value):
                base = 0.9   # Real person — high value
            elif self._GENERIC_EMAIL.match(value):
                base = 0.6   # Generic alias — less useful
            # Subdomain email (user@sub.domain.com) is interesting
            parts = value.split("@")[1].split(".")
            if len(parts) > 3:
                base += 0.05  # Deep subdomain email
            return min(1.0, base)

        # ── Subdomains / Hosts ──
        # Wildcard entries
        if value.startswith("*"):
            return 0.2

        # Pure IP with no hostname
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            if self._PRIVATE_IP.match(value):
                return 0.15  # Private IP — noise
            return 0.4       # Public IP alone — low context

        # Has resolved IP in parentheses → more reliable
        has_ip = "(" in value and ")" in value
        hostname = value.split(" ")[0].split("(")[0].strip()

        base = 0.6
        if has_ip:
            base = 0.8   # Verified — DNS resolved
            # Check if IP is private
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', value)
            if ip_match and self._PRIVATE_IP.match(ip_match.group(1)):
                base = 0.35  # Resolved to private IP — suspicious

        # High-value subdomain names
        if self._HIGH_VALUE_SUB.search(hostname):
            base = min(1.0, base + 0.1)

        # Mail protection records (outlook, google) — confirmed infrastructure
        if "mail.protection" in value or "google" in value:
            base = min(1.0, base + 0.05)

        return round(base, 2)
