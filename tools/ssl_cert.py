"""SSL Certificate Tool Adapter — Extract SANs, issuer, expiry via openssl"""
import re
import subprocess
from datetime import datetime
from tools.base import ToolAdapter
from utils.logger import log

class SSLCertAdapter(ToolAdapter):
    name = "SSLCert"
    cmd = "openssl"
    result_type = "ssl"
    description = "SSL certificate analysis — SANs, issuer, expiry"

    def build_command(self, target, **opts):
        # openssl needs special handling — we use run_capture mode
        port = opts.get("port", "443")
        return [self.cmd, "s_client", "-connect", f"{target}:{port}",
                "-servername", target, "-showcerts"]

    def parse_line(self, line, context):
        # SSL cert is parsed as a whole, not line by line
        return []

    def parse_cert(self, target, port="443", timeout=10):
        """Parse SSL certificate and extract all useful info"""
        results = []

        try:
            # Step 1: Get raw cert
            proc1 = subprocess.run(
                ["openssl", "s_client", "-connect", f"{target}:{port}",
                 "-servername", target],
                input="", capture_output=True, text=True, timeout=timeout
            )

            cert_pem = ""
            in_cert = False
            for line in proc1.stdout.splitlines():
                if "BEGIN CERTIFICATE" in line:
                    in_cert = True
                if in_cert:
                    cert_pem += line + "\n"
                if "END CERTIFICATE" in line and in_cert:
                    break

            if not cert_pem:
                return [{"value": f"No SSL certificate found on {target}:{port}",
                         "source": self.name, "type": "ssl", "confidence": 0.3}]

            # Step 2: Parse cert details
            proc2 = subprocess.run(
                ["openssl", "x509", "-noout", "-text", "-nameopt", "utf8"],
                input=cert_pem, capture_output=True, text=True, timeout=10
            )
            cert_text = proc2.stdout

            # Extract Subject (CN)
            cn_match = re.search(r'Subject:.*?CN\s*=\s*([^\n,]+)', cert_text)
            if cn_match:
                cn = cn_match.group(1).strip()
                results.append({"value": f"Common Name: {cn}", "source": self.name,
                               "type": "ssl", "confidence": 0.95, "extra": "CN"})

            # Extract Issuer
            issuer_match = re.search(r'Issuer:.*?(?:O\s*=\s*([^\n,]+))', cert_text)
            if issuer_match:
                issuer = issuer_match.group(1).strip()
                results.append({"value": f"Issuer: {issuer}", "source": self.name,
                               "type": "ssl", "confidence": 0.95, "extra": "Issuer"})

            # Extract validity dates
            not_before = re.search(r'Not Before\s*:\s*(.+)', cert_text)
            not_after = re.search(r'Not After\s*:\s*(.+)', cert_text)
            if not_before:
                results.append({"value": f"Valid From: {not_before.group(1).strip()}",
                               "source": self.name, "type": "ssl", "confidence": 0.9, "extra": "ValidFrom"})
            if not_after:
                expiry_str = not_after.group(1).strip()
                results.append({"value": f"Expires: {expiry_str}",
                               "source": self.name, "type": "ssl", "confidence": 0.9, "extra": "Expires"})
                # Check if expired
                try:
                    exp_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    if exp_date < datetime.now():
                        results.append({"value": "⚠ CERTIFICATE EXPIRED",
                                       "source": self.name, "type": "ssl", "confidence": 1.0, "extra": "Warning"})
                except Exception:
                    pass

            # Extract SANs — THE GOLD
            san_section = re.search(r'Subject Alternative Name:\s*\n\s*(.+)', cert_text)
            if san_section:
                sans_raw = san_section.group(1)
                sans = re.findall(r'DNS:([^\s,]+)', sans_raw)
                for san in sans:
                    san = san.strip().rstrip(".")
                    if san and san != target:
                        # Wildcard entries
                        if san.startswith("*."):
                            conf = 0.7
                        else:
                            conf = 0.9
                        results.append({"value": f"SAN: {san}", "source": self.name,
                                       "type": "subdomain", "confidence": conf, "extra": "SAN"})

                results.append({"value": f"Total SANs: {len(sans)} domains in certificate",
                               "source": self.name, "type": "ssl", "confidence": 0.95, "extra": "SANCount"})

            # Extract Organization
            org_match = re.search(r'Subject:.*?O\s*=\s*([^\n,]+)', cert_text)
            if org_match:
                org = org_match.group(1).strip()
                results.append({"value": f"Organization: {org}", "source": self.name,
                               "type": "ssl", "confidence": 0.9, "extra": "Org"})

        except subprocess.TimeoutExpired:
            results.append({"value": f"SSL connection timed out for {target}",
                           "source": self.name, "type": "ssl", "confidence": 0.3})
        except FileNotFoundError:
            results.append({"value": "openssl not found",
                           "source": self.name, "type": "ssl", "confidence": 0.0})
        except Exception as e:
            log.error(f"SSL parse error for {target}: {e}")
            results.append({"value": f"SSL error: {str(e)[:100]}",
                           "source": self.name, "type": "ssl", "confidence": 0.2})

        return results
