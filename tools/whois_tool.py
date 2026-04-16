"""Whois Tool Adapter — Domain registration lookup"""
import re
from tools.base import ToolAdapter

class WhoisAdapter(ToolAdapter):
    name = "Whois"
    cmd = "whois"
    result_type = "whois"
    description = "Domain registration and ownership lookup"

    _PATTERNS = {
        "Registrar": re.compile(r'(?:Registrar|registrar)[:\s]+(.+)', re.I),
        "Created": re.compile(r'(?:Creation Date|Created|created)[:\s]+(.+)', re.I),
        "Expires": re.compile(r'(?:Expir(?:y|ation) Date|expires)[:\s]+(.+)', re.I),
        "Updated": re.compile(r'(?:Updated Date|updated|last.modified)[:\s]+(.+)', re.I),
        "Nameserver": re.compile(r'(?:Name Server|nameserver|nserver)[:\s]+(.+)', re.I),
        "Registrant Org": re.compile(r'(?:Registrant Org(?:anization)?|org-name)[:\s]+(.+)', re.I),
        "Registrant Country": re.compile(r'(?:Registrant Country|country)[:\s]+(.+)', re.I),
        "Status": re.compile(r'(?:Domain Status|status)[:\s]+(.+)', re.I),
        "DNSSEC": re.compile(r'(?:DNSSEC)[:\s]+(.+)', re.I),
    }

    def build_command(self, target, **opts):
        return [self.cmd, target]

    def parse_line(self, line, context):
        results = []
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            return results

        for field, pattern in self._PATTERNS.items():
            m = pattern.match(line)
            if m:
                val = m.group(1).strip()
                if val and len(val) < 200:
                    # Dedup nameservers
                    key = f"{field}:{val.lower()}"
                    if key in context.get("_seen", set()):
                        return results
                    context.setdefault("_seen", set()).add(key)

                    conf = 0.95 if field in ("Registrar", "Created", "Expires") else 0.8
                    results.append({
                        "value": f"{field}: {val}",
                        "source": self.name,
                        "type": "whois",
                        "confidence": conf,
                        "extra": field
                    })
                    if field in ("Registrar", "Created", "Expires", "Registrant Org"):
                        context["_log"] = ("found", f"<span class='hl'>{field}</span> → {val}")
                break

        return results
