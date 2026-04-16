# GhostTrace API Reference

Base URL: `http://127.0.0.1:5000`

All endpoints require authentication (except `/login`). Session-based auth via `/login`.

---

## 🔐 Authentication

### `POST /login`
Login with password.

**Form data:** `password`

**Response:** Redirects to `/` on success, returns 401 on failure.

### `GET /logout`
Clear session and redirect to `/login`.

---

## 🔍 Scanning Endpoints

All scan endpoints return **Server-Sent Events (SSE)** stream with these event types:
- `scan_start` — `{scan_id, tool, target}`
- `log` — `{type, msg}` (type: info/found/warn/err/sys)
- `progress` — `{pct, label}`
- `result` — `{value, source, type, confidence, extra}`
- `scan_done` — `{total, scan_id}`
- `scan_error` — `{error}`

### `GET /api/scan/email`
Harvest emails and subdomains via theHarvester.

**Params:**
- `domain` (required) — target domain
- `tor` (optional) — `1` to route through Tor

**Example:** `/api/scan/email?domain=example.com&tor=1`

### `GET /api/scan/username`
Search for username across social platforms.

**Params:**
- `username` (required) — target username
- `tool` (optional) — `maigret` (default) or `sherlock`
- `tor` (optional) — `1` for Tor

**Example:** `/api/scan/username?username=johndoe&tool=maigret`

### `GET /api/scan/metadata`
Extract metadata from a file using ExifTool.

**Params:**
- `filepath` (required) — absolute path to file

**Example:** `/api/scan/metadata?filepath=/home/kali/photo.jpg`

### `GET /api/scan/phone`
Phone number OSINT via PhoneInfoga.

**Params:**
- `phone` (required) — phone number (digits, +, -, spaces, parens)

**Example:** `/api/scan/phone?phone=%2B1234567890`

### `GET /api/scan/subdomain`
Discover subdomains via theHarvester.

**Params:**
- `domain` (required)
- `tor` (optional) — `1` for Tor

### `GET /api/scan/whois`
Domain WHOIS lookup.

**Params:**
- `domain` (required)

### `GET /api/scan/dns`
DNS records (MX, TXT, NS, SOA, A) via `dig`.

**Params:**
- `domain` (required)

### `GET /api/scan/ssl`
SSL certificate analysis — SANs, issuer, expiry.

**Params:**
- `domain` (required)

### `GET /api/scan/dorks`
Generate Google dork queries.

**Params:**
- `domain` (required)

**Returns:** 28 pre-built dork queries as results.

### `GET /api/auto-detect`
Auto-detect target type and run appropriate tool.

**Params:**
- `input` (required) — domain, email, username, or file path

---

## 🛡️ Active Reconnaissance

### `GET /api/recon/validate`
Full recon pipeline: DNS → HTTP → Ports → Attack Surface → Risk.

**Params:**
- `scan_id` (optional) — use targets from existing scan
- `domain` (optional) — scan a specific domain
- `ports` (optional) — `1` to include port scanning
- `attack_surface` (optional) — `1` to include attack surface detection

**Additional SSE events:**
- `recon_done` — `{total, summary, scored_assets}`

### `GET /api/recon/quick`
Quick recon on a single host — returns JSON (not SSE).

**Params:**
- `host` (required)

---

## 📊 History & Stats

### `GET /api/history`
List all past scans (paginated).

**Params:**
- `page` (optional, default: 1)
- `per_page` (optional, default: 50)
- `q` (optional) — search query

**Response:**
```json
{
  "items": [
    {"id": "abc123", "target": "example.com", "module": "email",
     "tool": "theHarvester", "status": "complete",
     "started_at": "2026-04-13T...", "total_results": 42}
  ],
  "total": 100, "page": 1, "per_page": 50
}
```

### `GET /api/history/<scan_id>`
Get scan details.

### `GET /api/history/<scan_id>/results`
Get all results from a specific scan.

### `DELETE /api/history/<scan_id>`
Delete a scan and all its results.

### `GET /api/history/<scan_id>/notes`
Get notes for a scan.

### `POST /api/history/<scan_id>/notes`
Save notes.

**Body:** `{"notes": "text here"}`

### `GET /api/diff?old=<id>&new=<id>`
Compare two scans — added/removed/common results.

### `GET /api/stats`
Aggregate statistics across all scans.

### `GET /api/search?q=<query>`
Search across all results.

---

## 📄 Reports & Exports

### `POST /api/report`
Generate HTML report.

**Body:**
```json
{
  "results": [...],
  "target": "example.com",
  "module": "auto",
  "recon_data": {...}  // optional — includes risk assessment section
}
```

**Response:** `{"filepath": "...", "filename": "ghosttrace_report_YYYYMMDD_HHMMSS.html"}`

### `POST /api/report/pdf`
Convert HTML report to PDF.

**Body:** `{"html_filename": "ghosttrace_report_20260413_123456.html"}`

### `GET /api/report/download/<filename>`
Download generated HTML report.

### `GET /api/report/pdf/download/<filename>`
Download generated PDF report.

### `POST /api/export`
Export results as JSON/CSV/TXT.

**Body:**
```json
{
  "results": [...],
  "format": "json"  // or "csv", "txt"
}
```

---

## ⚙️ System & Tools

### `GET /api/check-tools`
Check which external tools are installed.

**Response:**
```json
{
  "theHarvester": {"installed": true, "path": "/usr/bin/theHarvester"},
  "maigret": {"installed": true, "path": "..."},
  "PDF Engine": {"installed": true, "path": "weasyprint (Python)"}
}
```

### `GET /api/settings` / `POST /api/settings`
Read/write API keys and configuration.

**POST body:**
```json
{
  "api_keys": {
    "shodan": "...",
    "hunter": "...",
    "securitytrails": "...",
    "virustotal": "...",
    "censys": "..."
  }
}
```

### `GET /api/cli?cmd=<command>`
Execute whitelisted CLI commands.

**Whitelisted tools:** `theharvester`, `sherlock`, `exiftool`, `maigret`, `phoneinfoga`, `whois`, `dig`, `openssl`

### `POST /api/abort/<scan_id>`
Abort a running scan.

### `GET /api/graph`
Get graph data for all results (nodes + edges).

---

## 🔒 Rate Limits

- **Scan endpoints:** 20 scans / 60 seconds
- **Other endpoints:** No hard limit

---

## 📦 Result Object Schema

All scan results follow this schema:

```json
{
  "value": "admin@example.com",      // The discovered value
  "source": "theHarvester",          // Tool that found it
  "type": "email",                   // email|username|subdomain|metadata|phone|whois|dns|ssl|dork
  "confidence": 0.9,                 // 0.0–1.0 (smart scored)
  "extra": "optional context"        // Type-specific field
}
```

## 🛡️ Risk Asset Schema (Active Recon)

```json
{
  "hostname": "admin.example.com",
  "score": 85,                       // 0–100
  "level": "critical",               // critical|high|medium|low|info
  "reasons": ["Admin subdomain", "SSH exposed", "Missing HSTS"],
  "attack_paths": [
    {
      "path": "Admin Panel Exposed",
      "severity": "critical",
      "steps": ["Test default creds", "Check CVEs", "SQLi bypass"],
      "preconditions": ["Admin panel(s): /admin"]
    }
  ]
}
```

---

## 🧪 Example Usage (cURL)

```bash
# Login first (saves cookie)
curl -c cookies.txt -X POST http://127.0.0.1:5000/login \
  -d "password=yourpassword"

# Run scan (stream)
curl -b cookies.txt -N \
  "http://127.0.0.1:5000/api/scan/dns?domain=example.com"

# Get history
curl -b cookies.txt http://127.0.0.1:5000/api/history

# Delete scan
curl -b cookies.txt -X DELETE \
  http://127.0.0.1:5000/api/history/abc123def
```

---

**For full details, see the source code at `api/routes.py` and `api/recon_routes.py`.**
