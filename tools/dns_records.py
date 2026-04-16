"""DNS Records Tool Adapter — MX, TXT, NS, SOA, A records via dig"""
import re
from tools.base import ToolAdapter

class DNSRecordsAdapter(ToolAdapter):
    name = "DNSRecords"
    cmd = "dig"
    result_type = "dns"
    description = "DNS record enumeration (MX, TXT, NS, SOA, A)"

    RECORD_TYPES = ["A", "MX", "TXT", "NS", "SOA", "AAAA", "CNAME"]

    def build_command(self, target, **opts):
        rtype = opts.get("record_type", "ANY")
        return [self.cmd, target, rtype, "+noall", "+answer", "+authority"]

    def parse_line(self, line, context):
        results = []
        line = line.strip()
        if not line or line.startswith(";"):
            return results

        # dig output format: domain. TTL CLASS TYPE VALUE
        parts = line.split()
        if len(parts) < 5:
            return results

        domain = parts[0].rstrip(".")
        rtype = parts[3] if len(parts) > 3 else ""
        value = " ".join(parts[4:]).rstrip(".")

        if not rtype or not value:
            return results

        # Confidence based on record type
        conf_map = {
            "MX": 0.95,     # Mail server — very valuable
            "TXT": 0.9,     # SPF/DKIM — security relevant
            "NS": 0.85,     # Nameservers
            "SOA": 0.85,    # Authority
            "A": 0.8,       # IP address
            "AAAA": 0.8,    # IPv6
            "CNAME": 0.8,   # Alias
        }

        conf = conf_map.get(rtype, 0.7)
        display = f"[{rtype}] {value}"

        results.append({
            "value": display,
            "source": self.name,
            "type": "dns",
            "confidence": conf,
            "extra": rtype
        })

        # Security checks on TXT records
        if rtype == "TXT":
            val_lower = value.lower()
            if "v=spf1" in val_lower:
                context["_log"] = ("found", f"<span class='hl'>SPF Record</span> → {value[:80]}")
            elif "v=dmarc1" in val_lower:
                context["_log"] = ("found", f"<span class='hl'>DMARC Record</span> → {value[:80]}")
            elif "v=dkim1" in val_lower:
                context["_log"] = ("found", f"<span class='hl'>DKIM Record</span> → {value[:80]}")
            else:
                context["_log"] = ("info", f"[TXT] {value[:80]}")
        elif rtype == "MX":
            context["_log"] = ("found", f"<span class='hl'>Mail Server</span> → {value}")
        elif rtype == "NS":
            context["_log"] = ("found", f"<span class='hl'>Nameserver</span> → {value}")
        elif rtype == "SOA":
            # SOA often contains admin email
            soa_parts = value.split()
            if len(soa_parts) >= 2:
                admin = soa_parts[1].replace(".", "@", 1)
                context["_log"] = ("found", f"<span class='hl'>SOA Admin</span> → {admin}")

        return results
