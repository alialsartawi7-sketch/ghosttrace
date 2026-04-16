"""PhoneInfoga Tool Adapter — Phone number OSINT"""
import re
from tools.base import ToolAdapter

class PhoneInfogaAdapter(ToolAdapter):
    name = "PhoneInfoga"
    cmd = "phoneinfoga"
    result_type = "phone"
    description = "Phone number intelligence lookup"

    _URL_RE = re.compile(r'https?://\S+')
    # Search engine domains to filter out (noise)
    _NOISE_DOMAINS = {'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com',
                      'search.yahoo.com', 'yandex.com', 'baidu.com',
                      'facebook.com', 'twitter.com', 'linkedin.com',
                      'instagram.com', 'youtube.com', 'reddit.com',
                      'pinterest.com', 'tiktok.com'}

    def _is_noise_url(self, url):
        """Check if URL is a search engine or social media generic link"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc.lower().replace('www.', '')
            return any(domain.endswith(n) for n in self._NOISE_DOMAINS)
        except Exception:
            return False
    _CARRIER_RE = re.compile(r'(?:carrier|operator|provider)[:\s]+(.+)', re.I)
    _COUNTRY_RE = re.compile(r'(?:country|region|location)[:\s]+(.+)', re.I)
    _FORMAT_RE = re.compile(r'(?:number|format|e164)[:\s]+([\+\d\s\-\(\)]+)', re.I)

    def build_command(self, target, **opts):
        return [self.cmd, "scan", "-n", target]

    def parse_line(self, line, context):
        results = []
        line = line.strip()
        if not line:
            return results

        # Carrier/operator
        m = self._CARRIER_RE.search(line)
        if m:
            val = m.group(1).strip()
            if val:
                results.append({"value": f"Carrier: {val}", "source": self.name,
                               "type": "phone", "confidence": 0.85, "extra": "carrier"})
                context["_log"] = ("found", f"<span class='hl'>Carrier</span> → {val}")

        # Country/region
        m = self._COUNTRY_RE.search(line)
        if m:
            val = m.group(1).strip()
            if val:
                results.append({"value": f"Country: {val}", "source": self.name,
                               "type": "phone", "confidence": 0.9, "extra": "country"})
                context["_log"] = ("found", f"<span class='hl'>Country</span> → {val}")

        # Phone format
        m = self._FORMAT_RE.search(line)
        if m:
            val = m.group(1).strip()
            if val and len(val) > 5:
                results.append({"value": f"Format: {val}", "source": self.name,
                               "type": "phone", "confidence": 0.95, "extra": "format"})

        # URLs in output — filter search engine noise
        for url in self._URL_RE.findall(line):
            if not self._is_noise_url(url):
                results.append({"value": url, "source": self.name,
                               "type": "phone", "confidence": 0.7, "extra": "url"})

        # Generic info lines
        if not results and ":" in line and not line.startswith("["):
            key, _, val = line.partition(":")
            val = val.strip()
            if val and len(val) > 1 and len(val) < 200:
                results.append({"value": f"{key.strip()}: {val}", "source": self.name,
                               "type": "phone", "confidence": 0.6})

        return results
