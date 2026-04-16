"""Sherlock Tool Adapter"""
from tools.base import ToolAdapter

class SherlockAdapter(ToolAdapter):
    name = "Sherlock"
    cmd = "sherlock"
    result_type = "username"
    description = "Username search across 400+ platforms"

    def build_command(self, target, **opts):
        cmd = [self.cmd, target, "--print-found", "--no-color"]
        if opts.get("tor"):
            cmd.append("--tor")
        sites = opts.get("sites")
        if sites:
            for site in sites.split(","):
                site = site.strip()
                if site:
                    cmd.extend(["--site", site])
        return cmd

    def parse_line(self, line, context):
        results = []
        line = line.strip()
        if not line: return results
        if line.startswith("[+]"):
            parts = line.replace("[+]", "").strip()
            if ":" in parts:
                platform = parts.split(":")[0].strip()
                url = ":".join(parts.split(":")[1:]).strip()
            else:
                platform = parts; url = ""
            results.append({
                "value": f"{context.get('target', '?')} @ {platform}",
                "source": platform, "type": "username",
                "confidence": self.get_confidence(None, platform),
                "extra": url
            })
            context["_log"] = ("found", f"<span class='hl'>{platform}</span> — profile found")
        elif line.startswith("[-]") or line.startswith("[*]"):
            context["checked"] = context.get("checked", 0) + 1
        return results

    def get_confidence(self, value, source=None):
        # Major platforms = higher confidence
        major = {"github","twitter","instagram","reddit","linkedin","facebook","youtube"}
        if source and source.lower() in major: return 0.9
        return 0.7
