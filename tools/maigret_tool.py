"""Maigret Tool Adapter — Better Sherlock alternative"""
import re
from tools.base import ToolAdapter
from config import Config

class MaigretAdapter(ToolAdapter):
    name = "Maigret"
    cmd = "maigret"
    result_type = "username"
    description = "Advanced username search across 2500+ sites (Sherlock fork)"

    # Known false positive patterns — sites that match ANY username
    FALSE_POSITIVE_PATTERNS = [
        r"OP\.GG.*LeagueOfLegends",    # All OP.GG regions
        r"OP\.GG.*\[",                  # Any OP.GG bracket variant
        r"authorSTREAM",               # Almost always false
        r"iXBT",                       # Russian tech site, unreliable
        r"Kaskus",                     # Indonesian forum, unreliable
        r"Livemaster",                 # Russian craft site, unreliable
        r"TechPowerUp",               # Forum, high false positive rate
        r"Tom's guide",               # Forum, unreliable
        r"mercadolivre",              # Marketplace, unreliable username check
    ]

    # High-reliability platforms — these results are trustworthy
    TRUSTED_PLATFORMS = {
        "instagram", "tiktok", "twitter", "x", "facebook", "youtube",
        "github", "gitlab", "reddit", "linkedin", "pinterest", "twitch",
        "telegram", "snapchat", "spotify", "medium", "deviantart",
        "vimeo", "soundcloud", "behance", "dribbble", "flickr",
        "tumblr", "discord", "steam", "xbox", "playstation",
        "roblox", "opensea.io", "kaggle", "stackoverflow",
        "hackerrank", "leetcode", "codepen", "replit",
    }

    _FP_COMPILED = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVE_PATTERNS]

    def build_command(self, target, **opts):
        cmd = [self.cmd, target, "--no-color", "--no-progressbar"]
        if opts.get("tor"):
            cmd.extend(["--tor-proxy", Config.TOR_PROXY])
        # Custom sites filter
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
        if not line:
            return results

        if line.startswith("[+]") or line.startswith("[*]"):
            is_found = line.startswith("[+]")
            parts = line[3:].strip()

            if ":" in parts:
                platform = parts.split(":")[0].strip()
                url = ":".join(parts.split(":")[1:]).strip()
            else:
                platform = parts
                url = ""

            if is_found and platform:
                # Check false positives
                if self.should_ignore(platform):
                    context["_log"] = ("warn", f"<span class='muted'>{platform}</span> — filtered (known false positive)")
                    context["checked"] = context.get("checked", 0) + 1
                    return results

                target = context.get("target", "?")
                confidence = self.get_confidence(None, platform)
                results.append({
                    "value": f"{target} @ {platform}",
                    "source": platform,
                    "type": "username",
                    "confidence": confidence,
                    "extra": url
                })
                conf_pct = f"{confidence:.0%}"
                context["_log"] = ("found", f"<span class='hl'>{platform}</span> — profile found ({conf_pct})")

            context["checked"] = context.get("checked", 0) + 1

        elif line.startswith("[-]"):
            context["checked"] = context.get("checked", 0) + 1

        return results

    def should_ignore(self, value):
        """Filter known false positive platforms"""
        for pattern in self._FP_COMPILED:
            if pattern.search(value):
                return True
        return False

    def get_confidence(self, value, source=None):
        if not source:
            return 0.5
        src_lower = source.lower().strip()
        if src_lower in self.TRUSTED_PLATFORMS:
            return 0.9
        # Medium confidence for recognized but not major platforms
        if any(c in src_lower for c in ["forum", "blog", "community"]):
            return 0.4
        return 0.6

