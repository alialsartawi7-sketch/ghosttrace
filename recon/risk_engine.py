"""
Risk Scoring Engine
Transforms raw OSINT data into actionable risk assessments

Scores consider:
- Asset type (admin panel vs static page)
- Exposure level (open ports, missing headers)
- Validation status (alive, verified)
- Multi-source confirmation
- Technology risk (outdated, misconfigured)
"""
from datetime import datetime
from utils.logger import log

class RiskLevel:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @staticmethod
    def from_score(score):
        if score >= 85: return RiskLevel.CRITICAL
        if score >= 65: return RiskLevel.HIGH
        if score >= 40: return RiskLevel.MEDIUM
        if score >= 20: return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def color(level):
        return {
            "critical": "#ff1744", "high": "#f16060",
            "medium": "#e8a838", "low": "#4f8ef7", "info": "#8a96aa"
        }.get(level, "#8a96aa")


class RiskScorer:
    """Dynamic risk analysis based on multiple factors"""

    @staticmethod
    def score_asset(asset):
        """
        Score a single asset (subdomain/host) based on recon data.

        asset dict should contain:
            hostname, dns, http, ports, attack_surface, technology
        """
        score = 0
        reasons = []
        hostname = asset.get("hostname", "unknown")

        # ── 1. Alive check (+10 base if alive) ──
        if asset.get("alive"):
            score += 10
        else:
            return {"hostname": hostname, "score": 0, "level": RiskLevel.INFO,
                    "reasons": ["Asset appears dead/unreachable"]}

        # ── 2. Open ports analysis ──
        ports = asset.get("ports", [])
        risky_ports = {
            21: ("FTP exposed", 15),
            22: ("SSH exposed", 10),
            23: ("Telnet exposed (critical)", 25),
            445: ("SMB exposed", 20),
            3306: ("MySQL exposed", 20),
            5432: ("PostgreSQL exposed", 20),
            3389: ("RDP exposed", 25),
            6379: ("Redis exposed (no auth likely)", 25),
            27017: ("MongoDB exposed", 25),
            5900: ("VNC exposed", 20),
        }
        for p in ports:
            port_num = p.get("port", 0)
            if port_num in risky_ports:
                reason, points = risky_ports[port_num]
                score += points
                reasons.append(reason)
            elif p.get("state") == "open":
                score += 3

        # ── 3. Admin panels / Login pages ──
        attack = asset.get("attack_surface", {})
        admin_panels = attack.get("admin_panels", [])
        login_pages = attack.get("login_pages", [])
        api_endpoints = attack.get("api_endpoints", [])

        if admin_panels:
            score += 20
            paths = [a["path"] for a in admin_panels]
            reasons.append(f"Admin panel(s) found: {', '.join(paths)}")

        if login_pages:
            score += 10
            paths = [l["path"] for l in login_pages]
            reasons.append(f"Login page(s) found: {', '.join(paths)}")

        if api_endpoints:
            score += 15
            paths = [a["path"] for a in api_endpoints]
            reasons.append(f"API endpoint(s) exposed: {', '.join(paths)}")

        # ── 4. Missing security headers ──
        missing = asset.get("missing_security_headers", [])
        if "strict-transport-security" in missing:
            score += 10
            reasons.append("Missing HSTS — vulnerable to SSL stripping")
        if "content-security-policy" in missing:
            score += 8
            reasons.append("Missing CSP — XSS risk increased")
        if "x-frame-options" in missing:
            score += 5
            reasons.append("Missing X-Frame-Options — clickjacking possible")

        # ── 5. Technology risk ──
        tech = asset.get("technology", [])
        risky_tech = {
            "WordPress": ("WordPress detected — check for plugin vulns", 10),
            "Joomla": ("Joomla detected — known vulnerability history", 10),
            "Drupal": ("Drupal detected — check version", 8),
            "PHP": ("PHP backend — check version", 5),
            "ASP.NET": ("ASP.NET detected", 3),
        }
        for t in tech:
            if t in risky_tech:
                reason, points = risky_tech[t]
                score += points
                reasons.append(reason)

        # ── 6. HTTP behavior ──
        http = asset.get("http_info", {})
        if http:
            status = http.get("status", 0)
            if status == 403:
                score += 5
                reasons.append("403 Forbidden — restricted but accessible")
            elif status == 401:
                score += 8
                reasons.append("401 Unauthorized — auth required (potential target)")

        # ── 7. Hostname patterns ──
        h = hostname.lower()
        sensitive_patterns = {
            "admin": ("Admin subdomain", 15),
            "api": ("API subdomain", 12),
            "dev": ("Development environment exposed", 15),
            "staging": ("Staging environment exposed", 18),
            "test": ("Test environment exposed", 15),
            "internal": ("Internal asset exposed", 20),
            "vpn": ("VPN endpoint", 10),
            "mail": ("Mail server", 8),
            "ftp": ("FTP service", 12),
            "db": ("Database service", 15),
            "backup": ("Backup service exposed", 18),
            "jenkins": ("Jenkins CI exposed", 20),
            "gitlab": ("GitLab exposed", 15),
            "grafana": ("Grafana dashboard", 12),
        }
        for pattern, (reason, points) in sensitive_patterns.items():
            if pattern in h:
                score += points
                reasons.append(reason)
                break

        # Cap at 100
        score = min(100, score)
        level = RiskLevel.from_score(score)

        scored_result = {
            "hostname": hostname,
            "score": score,
            "level": level,
            "reasons": reasons,
            "assessed_at": datetime.now().isoformat()
        }

        # Generate attack paths
        scored_result["attack_paths"] = AttackPathGenerator.generate(asset, scored_result)
        return scored_result

    @staticmethod
    def assess_all(assets):
        """Score multiple assets and return sorted by risk"""
        scored = [RiskScorer.score_asset(a) for a in assets]
        scored.sort(key=lambda x: x["score"], reverse=True)
        log.info(f"Risk assessment: {len(scored)} assets scored")
        return scored

    @staticmethod
    def executive_summary(scored_assets):
        """Generate actionable summary from scored assets"""
        if not scored_assets:
            return {"summary": "No assets to assess", "top_risks": [], "stats": {}}

        critical = [a for a in scored_assets if a["level"] == RiskLevel.CRITICAL]
        high = [a for a in scored_assets if a["level"] == RiskLevel.HIGH]
        medium = [a for a in scored_assets if a["level"] == RiskLevel.MEDIUM]
        low = [a for a in scored_assets if a["level"] == RiskLevel.LOW]

        top5 = scored_assets[:5]

        # Generate recommendations
        recommendations = []
        if critical:
            recommendations.append(f"IMMEDIATE: {len(critical)} critical asset(s) require urgent review")
        if high:
            recommendations.append(f"HIGH PRIORITY: {len(high)} high-risk asset(s) should be investigated")
        if any("RDP exposed" in str(a.get("reasons")) for a in scored_assets):
            recommendations.append("Restrict RDP access — use VPN or whitelist IPs")
        if any("Admin panel" in str(a.get("reasons")) for a in scored_assets):
            recommendations.append("Admin panels should not be publicly accessible")
        if any("staging" in str(a.get("reasons","")).lower() or "dev" in str(a.get("reasons","")).lower() for a in scored_assets):
            recommendations.append("Remove staging/dev environments from public access")
        if any("Missing HSTS" in str(a.get("reasons")) for a in scored_assets):
            recommendations.append("Enable HSTS on all HTTPS endpoints")

        return {
            "total_assets": len(scored_assets),
            "stats": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "info": len(scored_assets) - len(critical) - len(high) - len(medium) - len(low)
            },
            "top_risks": [{
                "hostname": a["hostname"],
                "score": a["score"],
                "level": a["level"],
                "top_reason": a["reasons"][0] if a["reasons"] else "General exposure"
            } for a in top5],
            "recommendations": recommendations,
            "assessed_at": datetime.now().isoformat()
        }


class AttackPathGenerator:
    """
    Generates advisory attack paths based on recon findings.
    No network calls — purely analytical. Steps are for authorized pentest only.
    """

    @staticmethod
    def generate(asset, scored):
        """
        Analyze asset + risk score and return actionable attack paths.
        Returns list of dicts with: path, steps, preconditions, severity
        """
        paths = []
        attack = asset.get("attack_surface", {})
        ports = asset.get("ports", [])
        open_port_nums = {p.get("port", 0) for p in ports if p.get("state") == "open"}
        admin_panels = attack.get("admin_panels", [])
        login_pages = attack.get("login_pages", [])
        api_endpoints = attack.get("api_endpoints", [])
        score = scored.get("score", 0)
        reasons = scored.get("reasons", [])

        # Rule 1 — Brute Force Candidate
        if login_pages and (22 in open_port_nums or 21 in open_port_nums or 3389 in open_port_nums):
            services = [s for p, s in [(22, "SSH"), (21, "FTP"), (3389, "RDP")] if p in open_port_nums]
            paths.append({
                "path": "Brute Force Candidate",
                "steps": [
                    "Enumerate valid usernames via timing or error messages",
                    "Test default credentials for detected service/CMS",
                    "Run credential stuffing with rockyou or custom wordlist",
                    "Check if rate limiting exists on login endpoint"
                ],
                "preconditions": [
                    f"Login page(s): {', '.join(l['path'] for l in login_pages)}",
                    f"Auth service(s): {', '.join(services)}"
                ],
                "severity": "high"
            })

        # Rule 2 — Admin Panel Exposed
        if admin_panels:
            paths.append({
                "path": "Admin Panel Exposed",
                "steps": [
                    "Test default admin credentials (admin/admin, admin/password)",
                    "Search NVD for CVEs matching detected technology stack",
                    "Attempt authentication bypass via SQLi on login form",
                    "Check for directory listing under admin path"
                ],
                "preconditions": [
                    f"Admin panel(s): {', '.join(a['path'] for a in admin_panels)}",
                    f"Status codes: {', '.join(str(a['status']) for a in admin_panels)}"
                ],
                "severity": "critical" if score >= 65 else "high"
            })

        # Rule 3 — API Enumeration
        if api_endpoints:
            paths.append({
                "path": "API Enumeration",
                "steps": [
                    "Enumerate endpoints with ffuf + api wordlist",
                    "Check /swagger, /openapi.json, /api-docs for schema",
                    "Test for IDOR by manipulating object IDs",
                    "Verify auth enforced on all HTTP methods"
                ],
                "preconditions": [
                    f"API endpoint(s): {', '.join(a['path'] for a in api_endpoints)}"
                ],
                "severity": "high"
            })

        # Rule 4 — Legacy Service
        legacy = {21: "FTP", 23: "Telnet"}
        found_legacy = {p: s for p, s in legacy.items() if p in open_port_nums}
        if found_legacy:
            paths.append({
                "path": "Legacy Service Exploitation",
                "steps": [
                    "Test anonymous FTP login (username: anonymous)",
                    "Telnet is unencrypted — attempt credential capture",
                    "Search CVEs for detected service version",
                    "Check if write access to web root is possible"
                ],
                "preconditions": [
                    f"Legacy service(s): {', '.join(f'{s} (port {p})' for p, s in found_legacy.items())}"
                ],
                "severity": "critical"
            })

        # Rule 5 — Chained Risk
        if score >= 65 and len(reasons) >= 3:
            paths.append({
                "path": "Chained Risk — High-Value Target",
                "steps": [
                    "Multiple weak signals — prioritize this target first",
                    "Map full attack surface before exploitation",
                    "Combine exposed admin + open ports for lateral movement",
                    "Document all findings — this is a high-value target"
                ],
                "preconditions": [
                    f"Risk score: {score}/100",
                    f"Contributing factors: {len(reasons)}"
                ],
                "severity": "critical"
            })

        return paths
