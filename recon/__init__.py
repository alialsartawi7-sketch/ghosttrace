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
import ipaddress
import concurrent.futures
import http.client
from urllib.request import (urlopen, Request, build_opener, HTTPRedirectHandler,
                            HTTPHandler, HTTPSHandler)
from urllib.error import URLError, HTTPError
from datetime import datetime
from utils.logger import log


# ═══════════════ SSRF GUARD ═══════════════
class _NoRedirect(HTTPRedirectHandler):
    """Refuse to auto-follow redirects — a scanned target could 30x to an
    internal address (e.g. cloud metadata 169.254.169.254) and exfiltrate it
    into the report. We surface the redirect target instead of chasing it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Opener that does NOT follow redirects
_NO_REDIRECT_OPENER = build_opener(_NoRedirect)


def _ip_is_internal(ip):
    """Classify an ipaddress object as non-routable / not-safe-to-reach.
    Shared by _is_internal_host (validation) and _safe_pinned_ip (connect)."""
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _is_internal_host(hostname):
    """True if the hostname resolves to (or is) a private/loopback/link-local/
    reserved address — used to block SSRF-style probes of internal services."""
    try:
        host = hostname.strip().split(" ")[0]
        try:
            return _ip_is_internal(ipaddress.ip_address(host))  # IP literal
        except ValueError:
            pass
        for info in socket.getaddrinfo(host, None):   # resolve, check every address
            try:
                if _ip_is_internal(ipaddress.ip_address(info[4][0])):
                    return True
            except ValueError:
                continue
        return False
    except Exception:
        # If we can't resolve, treat as non-internal (DNS step handles dead hosts)
        return False


def _safe_pinned_ip(host, family=None):
    """Resolve `host` ONCE and decide whether it's safe to connect to, returning
    (verdict, ip):
      ("internal", None) — at least one resolved address is non-routable (covers
                           an internal IPv6 address even when family=AF_INET).
      ("dead", None)     — nothing resolved, or nothing in the requested family.
      ("ok", ip)         — every resolved address is public; `ip` is the address
                           to PIN the connection to.

    Connecting to the returned `ip` instead of re-resolving the hostname closes
    the validate-then-connect (DNS-rebinding) window: the address we vetted is
    the exact address we dial. Conservative — any single internal address in the
    DNS answer rejects the whole host."""
    host = (host or "").strip().split(" ")[0]
    if not host:
        return ("dead", None)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return ("dead", None)
    pinned = None
    for info in infos:
        fam, addr = info[0], info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_internal(ip):
            return ("internal", None)
        if (family is None or fam == family) and pinned is None:
            pinned = addr
    return ("ok", pinned) if pinned else ("dead", None)


# ── DNS-pinned HTTP(S): dial a pre-validated IP while keeping the original Host
#    header + SNI, so a rebind between validation and connect can't send us to an
#    internal address. ──
class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, pinned_ip, **kw):
        super().__init__(host, **kw)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, pinned_ip, **kw):
        super().__init__(host, **kw)
        self._pinned_ip = pinned_ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), self.timeout, self.source_address)
        # server_hostname = the real host → SNI + certificate validation intact
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPHandler(HTTPHandler):
    def __init__(self, pinned_ip):
        super().__init__()
        self._pinned_ip = pinned_ip

    def http_open(self, req):
        return self.do_open(
            lambda h, **kw: _PinnedHTTPConnection(h, self._pinned_ip, **kw), req)


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, pinned_ip):
        super().__init__()
        self._pinned_ip = pinned_ip

    def https_open(self, req):
        return self.do_open(
            lambda h, **kw: _PinnedHTTPSConnection(h, self._pinned_ip, **kw),
            req, context=self._context)


def _pinned_opener(pinned_ip):
    """A no-redirect opener that dials only `pinned_ip`. Built per-probe because
    the pinned address is host-specific."""
    return build_opener(_PinnedHTTPHandler(pinned_ip),
                        _PinnedHTTPSHandler(pinned_ip),
                        _NoRedirect)

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

        # SSRF guard + DNS pinning: resolve once, refuse internal hosts, and pin
        # the connection to the vetted IP so a rebind can't redirect the probe.
        verdict, pinned_ip = _safe_pinned_ip(hostname)
        if verdict == "internal":
            log.warning(f"HTTP probe skipped for internal host: {hostname}")
            result["blocked"] = "internal address"
            return result
        if verdict == "dead":
            return result  # unresolvable — not alive, not blocked
        opener = _pinned_opener(pinned_ip)

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}"
            try:
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml"
                })
                # Pinned, non-redirect opener: dials the vetted IP, keeps Host +
                # SNI, and reports a 30x to an internal target instead of chasing.
                resp = opener.open(req, timeout=timeout)
                status = resp.getcode()
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = ""
                try:
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                finally:
                    try:
                        resp.close()
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
                # Capture (but do not follow) redirects; record the target.
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location", "") if e.headers else ""
                    result["redirect"] = loc
                    result[scheme] = {"status": e.code, "url": url, "headers": {}}
                    result["alive"] = True
                    break
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
    """Lightweight port scanner with banner grabbing"""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt2", 9090: "WebApp", 27017: "MongoDB"
    }

    # Probes to send to different port types for banner grabbing
    _PROBES = {
        80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        443: b"",  # SSL — skip raw banner
        8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        8443: b"",
    }

    @staticmethod
    def grab_banner(ip, port, timeout=2):
        """Grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            # Send probe if we have one, otherwise just listen
            probe = PortScanner._PROBES.get(port)
            if probe:
                sock.send(probe.replace(b"target", ip.encode()))
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            # Clean up — take first meaningful line
            for line in banner.splitlines():
                line = line.strip()
                if line and len(line) > 3:
                    return line[:200]
            return banner[:200] if banner else None
        except Exception:
            return None

    @staticmethod
    def scan(host, ports=None, timeout=1):
        """Scan specific ports on a host"""
        # SSRF guard + DNS pinning: one resolution decides the verdict AND gives
        # the IPv4 we scan, so we never re-resolve to a rebind target. (Was two
        # lookups — _is_internal_host + gethostbyname — leaving a rebind window.)
        verdict, ip = _safe_pinned_ip(host, family=socket.AF_INET)
        if verdict == "internal":
            log.warning(f"Port scan skipped for internal host: {host}")
            return {"host": host, "ip": None, "ports": [], "blocked": "internal address",
                    "scanned_at": datetime.now().isoformat()}
        if verdict == "dead":
            return {"host": host, "ip": None, "ports": [], "scanned_at": datetime.now().isoformat()}
        ports = ports or PortScanner.COMMON_PORTS.keys()

        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = PortScanner.COMMON_PORTS.get(port, "Unknown")
                    banner = PortScanner.grab_banner(ip, port)
                    entry = {"port": port, "service": service, "state": "open"}
                    if banner:
                        entry["banner"] = banner
                    open_ports.append(entry)
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

        # SSRF guard + DNS pinning: resolve once, refuse internal hosts, and reuse
        # one pinned opener for every path probe (was re-resolving per request).
        verdict, pinned_ip = _safe_pinned_ip(hostname)
        if verdict != "ok":
            if verdict == "internal":
                log.warning(f"Attack-surface scan skipped for internal host: {hostname}")
            return findings
        opener = _pinned_opener(pinned_ip)

        # Check admin paths
        for path in AttackSurfaceDetector.ADMIN_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout, opener)
            if status and status in (200, 301, 302, 401, 403):
                findings["admin_panels"].append({"path": path, "status": status})

        # Check login paths
        for path in AttackSurfaceDetector.LOGIN_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout, opener)
            if status and status in (200, 301, 302):
                findings["login_pages"].append({"path": path, "status": status})

        # Check API paths
        for path in AttackSurfaceDetector.API_PATHS:
            status = AttackSurfaceDetector._check_path(hostname, path, timeout, opener)
            if status and status in (200, 301, 302, 401, 403):
                findings["api_endpoints"].append({"path": path, "status": status})

        total = len(findings["admin_panels"]) + len(findings["login_pages"]) + len(findings["api_endpoints"])
        if total > 0:
            log.info(f"Attack surface {hostname}: {total} interesting endpoints found")

        return findings

    @staticmethod
    def _check_path(hostname, path, timeout=3, opener=None):
        """Check if a path exists on a host (no redirect following). `opener` is
        the host's DNS-pinned opener; falls back to the shared no-redirect opener
        if called without one."""
        opener = opener or _NO_REDIRECT_OPENER
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}{path}"
            try:
                req = Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                })
                resp = opener.open(req, timeout=timeout)
                code = resp.getcode()
                try:
                    resp.close()
                except Exception:
                    pass
                return code
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
