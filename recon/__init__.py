"""
Active Reconnaissance Module
DNS resolution, HTTP probing, port scanning, live asset detection

This module validates passive OSINT results by actively checking:
- Is the domain/subdomain actually alive?
- What HTTP status does it return?
- What ports are open?
- What technology is it running?
"""
import socket
import ssl
import json
import re
import concurrent.futures
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime
from utils.logger import log

# ═══════════════ DNS RESOLVER ═══════════════
class DNSResolver:
    """Validates domains by resolving them to IPs"""

    @staticmethod
    def resolve(hostname, timeout=3):
        """Resolve hostname → IP. Returns dict with results."""
        hostname = hostname.strip().split(" ")[0]  # Clean "host (ip)" format
        if not hostname or hostname.startswith("("):
            return None
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
            unique_ips = list(set(ip[4][0] for ip in ips))
            return {
                "hostname": hostname,
                "ips": unique_ips,
                "alive": True,
                "resolved_at": datetime.now().isoformat()
            }
        except socket.gaierror:
            return {"hostname": hostname, "ips": [], "alive": False, "resolved_at": datetime.now().isoformat()}
        except Exception as e:
            log.debug(f"DNS resolve failed for {hostname}: {e}")
            return {"hostname": hostname, "ips": [], "alive": False, "resolved_at": datetime.now().isoformat()}

    @staticmethod
    def bulk_resolve(hostnames, max_workers=20, timeout=3):
        """Resolve multiple hostnames concurrently"""
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(DNSResolver.resolve, h, timeout): h for h in hostnames}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results[result["hostname"]] = result
        alive = sum(1 for r in results.values() if r["alive"])
        log.info(f"DNS resolved {len(hostnames)} hosts: {alive} alive, {len(hostnames)-alive} dead")
        return results

    @staticmethod
    def is_wildcard(domain):
        """Detect wildcard DNS — if random subdomain resolves, it's wildcard"""
        import random, string
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=12)) + '.' + domain
        result = DNSResolver.resolve(random_sub, timeout=2)
        return result and result["alive"]


# ═══════════════ HTTP PROBER ═══════════════
class HTTPProber:
    """Probes HTTP/HTTPS endpoints for status, headers, tech detection"""

    INTERESTING_HEADERS = [
        "server", "x-powered-by", "x-aspnet-version", "x-generator",
        "x-cms", "via", "x-frame-options", "content-security-policy",
        "strict-transport-security", "x-xss-protection",
        "x-content-type-options", "access-control-allow-origin"
    ]

    SECURITY_HEADERS = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options",
        "x-xss-protection", "referrer-policy",
        "permissions-policy"
    ]

    @staticmethod
    def probe(hostname, timeout=5):
        """Probe a host via HTTP/HTTPS and extract info"""
        result = {
            "hostname": hostname,
            "http": None,
            "https": None,
            "alive": False,
            "technology": [],
            "security_headers": {},
            "missing_security_headers": [],
            "title": None,
            "redirect": None,
            "probed_at": datetime.now().isoformat()
        }

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}"
            try:
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml"
                })
                resp = urlopen(req, timeout=timeout)
                status = resp.getcode()
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = ""
                try:
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                except Exception:
                    pass

                info = {
                    "status": status,
                    "url": resp.geturl(),
                    "headers": {}
                }

                # Extract interesting headers
                for h in HTTPProber.INTERESTING_HEADERS:
                    if h in headers:
                        info["headers"][h] = headers[h]

                result[scheme] = info
                result["alive"] = True

                # Detect redirect
                if resp.geturl() != url:
                    result["redirect"] = resp.geturl()

                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.I)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                # Technology detection
                result["technology"] = HTTPProber._detect_tech(headers, body)

                # Security header check
                for sh in HTTPProber.SECURITY_HEADERS:
                    if sh in headers:
                        result["security_headers"][sh] = headers[sh]
                    else:
                        result["missing_security_headers"].append(sh)

                break  # Success — don't try other scheme

            except HTTPError as e:
                result[scheme] = {"status": e.code, "url": url, "headers": {}}
                result["alive"] = True
                # 403/401 still means it's alive and interesting
                break
            except (URLError, socket.timeout, ConnectionError, OSError):
                continue
            except Exception as e:
                log.debug(f"HTTP probe failed for {url}: {e}")
                continue

        return result

    @staticmethod
    def _detect_tech(headers, body):
        """Detect web technologies from headers and body"""
        tech = []
        server = headers.get("server", "").lower()
        powered = headers.get("x-powered-by", "").lower()

        # Server
        server_map = {
            "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
            "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
            "openresty": "OpenResty", "caddy": "Caddy"
        }
        for key, name in server_map.items():
            if key in server:
                tech.append(name)

        # Framework
        if "php" in powered: tech.append("PHP")
        if "asp.net" in powered or "asp.net" in headers.get("x-aspnet-version", "").lower(): tech.append("ASP.NET")
        if "express" in powered: tech.append("Express.js")

        # Body analysis
        body_lower = body.lower()
        body_tech = {
            "wp-content": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
            "shopify": "Shopify", "react": "React", "angular": "Angular",
            "vue.js": "Vue.js", "next.js": "Next.js", "laravel": "Laravel",
            "django": "Django", "flask": "Flask", "spring": "Spring"
        }
        for pattern, name in body_tech.items():
            if pattern in body_lower and name not in tech:
                tech.append(name)

        return tech

    @staticmethod
    def bulk_probe(hostnames, max_workers=10, timeout=5):
        """Probe multiple hosts concurrently"""
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(HTTPProber.probe, h, timeout): h for h in hostnames}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results[result["hostname"]] = result
        alive = sum(1 for r in results.values() if r["alive"])
        log.info(f"HTTP probed {len(hostnames)} hosts: {alive} alive")
        return results


# ═══════════════ PORT SCANNER ═══════════════
class PortScanner:
    """Lightweight port scanner — top common ports only"""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt2", 9090: "WebApp", 27017: "MongoDB"
    }

    @staticmethod
    def scan(host, ports=None, timeout=1):
        """Scan specific ports on a host"""
        ports = ports or PortScanner.COMMON_PORTS.keys()
        # Resolve hostname to IP first
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return {"host": host, "ip": None, "ports": [], "scanned_at": datetime.now().isoformat()}

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = PortScanner.COMMON_PORTS.get(port, "Unknown")
                    open_ports.append({"port": port, "service": service, "state": "open"})
                sock.close()
            except Exception:
                pass

        return {
            "host": host, "ip": ip,
            "ports": open_ports,
            "scanned_at": datetime.now().isoformat()
        }

    @staticmethod
    def bulk_scan(hosts, max_workers=5, timeout=1):
        """Scan multiple hosts"""
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(PortScanner.scan, h, None, timeout): h for h in hosts}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results[result["host"]] = result
        total_open = sum(len(r["ports"]) for r in results.values())
        log.info(f"Port scan {len(hosts)} hosts: {total_open} open ports found")
        return results


# ═══════════════ ATTACK SURFACE DETECTOR ═══════════════
class AttackSurfaceDetector:
    """Detects admin panels, login pages, APIs, exposed services"""

    ADMIN_PATHS = [
        "/admin", "/administrator", "/admin/login", "/wp-admin",
        "/cpanel", "/phpmyadmin", "/dashboard", "/manage",
        "/panel", "/control", "/cms", "/backend"
    ]

    LOGIN_PATHS = [
        "/login", "/signin", "/auth", "/sso", "/oauth",
        "/wp-login.php", "/user/login", "/account/login",
        "/api/auth", "/auth/login"
    ]

    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/graphql",
        "/rest", "/swagger", "/api-docs", "/openapi.json",
        "/.well-known", "/healthz", "/status"
    ]

    @staticmethod
    def detect(hostname, timeout=3):
        """Check for interesting endpoints on a host"""
        findings = {
            "hostname": hostname,
            "admin_panels": [],
            "login_pages": [],
            "api_endpoints": [],
            "detected_at": datetime.now().isoformat()
        }

        # Check admin paths
        for path in AttackSurfaceDetector.ADMIN_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout)
            if status and status in (200, 301, 302, 401, 403):
                findings["admin_panels"].append({"path": path, "status": status})

        # Check login paths
        for path in AttackSurfaceDetector.LOGIN_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout)
            if status and status in (200, 301, 302):
                findings["login_pages"].append({"path": path, "status": status})

        # Check API paths
        for path in AttackSurfaceDetector.API_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout)
            if status and status in (200, 301, 302, 401, 403):
                findings["api_endpoints"].append({"path": path, "status": status})

        total = len(findings["admin_panels"]) + len(findings["login_pages"]) + len(findings["api_endpoints"])
        if total > 0:
            log.info(f"Attack surface {hostname}: {total} interesting endpoints found")

        return findings

    @staticmethod
    def _check_path(hostname, path, timeout=3):
        """Check if a path exists on a host"""
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}{path}"
            try:
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                })
                resp = urlopen(req, timeout=timeout)
                return resp.getcode()
            except HTTPError as e:
                return e.code
            except Exception:
                continue
        return None


# ═══════════════ DATA QUALITY ═══════════════
class DataQuality:
    """Cleans and validates OSINT results"""

    PRIVATE_IP_RANGES = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^0\.'),
        re.compile(r'^169\.254\.'),
    ]

    @staticmethod
    def is_private_ip(ip):
        """Check if an IP is private/internal"""
        return any(p.match(ip) for p in DataQuality.PRIVATE_IP_RANGES)

    @staticmethod
    def filter_results(results, domain=None):
        """Clean and filter a list of results"""
        seen = set()
        filtered = []
        wildcard = False

        # Check wildcard DNS
        if domain:
            wildcard = DNSResolver.is_wildcard(domain)
            if wildcard:
                log.warning(f"Wildcard DNS detected for {domain} — filtering aggressively")

        for r in results:
            val = r.get("value", "").strip()
            if not val:
                continue

            # Dedup
            if val in seen:
                continue
            seen.add(val)

            # Filter private IPs
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', val)
            if ip_match and DataQuality.is_private_ip(ip_match.group(1)):
                continue

            # Skip pure IPs without hostname (less useful)
            if r.get("type") == "subdomain" and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', val):
                r["confidence"] = r.get("confidence", 0.5) * 0.5  # Lower confidence for bare IPs

            filtered.append(r)

        log.info(f"Data quality: {len(results)} → {len(filtered)} after filtering")
        return filtered
