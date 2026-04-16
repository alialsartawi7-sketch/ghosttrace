<img width="1920" height="1080" alt="Screenshot_2026-04-13_09_04_03" src="https://github.com/user-attachments/assets/2b4892ca-45ab-4df8-b05e-0d2f7b33034a" />

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green)
![Status Active](https://img.shields.io/badge/Status-Active-brightgreen)
![Platform Linux](https://img.shields.io/badge/Platform-Linux%20(Kali%20recommended)-orange?logo=linux&logoColor=white)
![Tools 9](https://img.shields.io/badge/Tools-9%20Integrated-purple)
![Routes 29](https://img.shields.io/badge/API%20Routes-29-blue)
![Themes 12](https://img.shields.io/badge/Themes-12-ff6b35)
![Tests](https://img.shields.io/badge/Tests-6%20Files-success)

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗████████╗██████╗  █████╗  ██████╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║  ███╗███████║██║   ██║███████╗   ██║      ██║   ██████╔╝███████║██║     █████╗  
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                                          v5.0 by Alsartawi
```

**OSINT made simple — from beginner to professional.**

GhostTrace is a modular OSINT intelligence platform that wraps 9 Linux tools into a single web interface with real-time streaming, active reconnaissance, risk scoring, attack path analysis, and professional PDF reports. No cloud dependencies. No telemetry. Runs entirely on your machine.

"⭐ If you find this useful, a star helps a lot!"
"🐛 Found a bug? Open an issue — I actively fix them."

---

## ⚡ What Makes GhostTrace Different

- 🔍 **9 integrated tools** — not just wrappers, full intelligence pipeline
- 🛡️ **Active Recon** — DNS validation, HTTP probing, port scanning, attack surface detection
- 📊 **Risk Scoring Engine** — 0-100 dynamic scoring with actionable reasons
- 🗺️ **Attack Path Generator** — 5 rules that map real exploitation paths
- 🧠 **Smart Confidence** — scores based on result quality, not just source
- 🔬 **Intelligent Metadata Analysis** — auto-detects WhatsApp/Telegram metadata stripping, classifies findings by intelligence value
- 📄 **Professional Reports** — PDF with Key Findings, risk assessment, confidence distribution bars
- 🌐 **Interactive Graph** — clustered force layout with shapes, legend, PNG export
- 🔐 **Authentication** — bcrypt password protection with session management
- 🎨 **12 Premium Themes** — including Royal Gold and Midnight Silver
- 🔄 **Cross-Scan Diff** — compare two scans to detect new exposures
- 📝 **Scan Notes & History** — SQLite-backed with load, notes, delete
- 📤 **File Upload** — drag-and-drop file upload for metadata analysis

---

## 🧰 Integrated Tools (9)

| # | Tool | Tab | What It Finds |
|---|------|-----|---------------|
| 1 | **theHarvester** | Email / Subs | Emails, subdomains, IPs from 13 free sources |
| 2 | **Maigret** | Username | Social media profiles across 2500+ sites |
| 3 | **Sherlock** | Username | Username search across 400+ sites |
| 4 | **ExifTool** | Metadata | Hidden metadata in files — GPS, author, device, software (with smart classification) |
| 5 | **PhoneInfoga** | Phone | Phone number carrier, country, format (search engine noise auto-filtered) |
| 6 | **Whois** | Auto/CLI | Domain registration, registrar, expiry, nameservers |
| 7 | **dig** | DNS | MX, TXT (SPF/DKIM/DMARC), NS, SOA, A, AAAA, CNAME records (each type queried separately) |
| 8 | **openssl** | SSL | Certificate SANs (hidden subdomains), issuer, expiry |
| 9 | **Google Dorks** | Dorks | 28 targeted queries — clickable links that open Google directly |

---

## 🎛️ 10 Scan Modules

| Module | Input | Tool Used | Example |
|--------|-------|-----------|---------|
| **Auto** | Anything | Auto-detects type, chains DNS+SSL for domains | `microsoft.com` → theHarvester → DNS → SSL |
| **Email** | Domain | theHarvester | `example.com` |
| **Username** | Username | Maigret / Sherlock | `johndoe` |
| **Metadata** | File path or Upload | ExifTool (smart classification) | Upload button or `/home/kali/photo.jpg` |
| **Phone** | Phone number | PhoneInfoga (noise-filtered) | `+1234567890` |
| **Subdomain** | Domain | theHarvester | `google.com` |
| **DNS** | Domain | dig (7 record types) | `example.com` → MX, TXT, NS, SOA, A, AAAA, CNAME |
| **SSL** | Domain | openssl | `example.com` → SANs, issuer, expiry |
| **Dorks** | Domain | Generator | `example.com` → 28 clickable Google dork queries |
| **Recon** | Domain | Built-in | DNS resolve → HTTP probe → Ports → Risk |

---

## 🛡️ Active Reconnaissance Pipeline

After passive OSINT, GhostTrace validates and enriches results:

```
📡 DNS Resolution     → Remove dead domains, validate alive hosts
🌐 HTTP Probing       → Status codes, technology detection, security headers
🔌 Port Scanning      → Top 25 common ports (SSH, RDP, MySQL, Redis...)
🎯 Attack Surface     → Admin panels, login pages, API endpoints
📊 Risk Scoring       → 0-100 dynamic score with explanations
🗺️ Attack Paths       → 5 rules: Brute Force, Admin Panel, API, Legacy, Chained
```

### Risk Scoring

Every host gets a dynamic risk score based on:

| Factor | Points | Example |
|--------|--------|---------|
| Alive host | +10 | Base score for reachable targets |
| RDP exposed | +25 | Port 3389 open |
| Admin panel found | +20 | `/admin` returns 200/401/403 |
| Missing HSTS | +10 | No Strict-Transport-Security header |
| Staging/dev exposed | +18 | `staging.example.com` publicly accessible |
| WordPress detected | +10 | Known vulnerability history |

### Attack Path Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force Candidate | Login page + SSH/FTP/RDP open | HIGH |
| Admin Panel Exposed | Any admin panel found | CRITICAL (score≥65) |
| API Enumeration | API endpoint detected | HIGH |
| Legacy Service | FTP (21) or Telnet (23) open | CRITICAL |
| Chained Risk | Score≥65 + 3 contributing factors | CRITICAL |

---

## 🧠 Smart Confidence System

Unlike tools that give static confidence, GhostTrace scores each result individually:

| Result | Old Score | Smart Score | Why |
|--------|-----------|-------------|-----|
| `Personal email pattern (firstname.lastname)` | 72% | **90%** | Personal email (firstname.lastname) |
| `Generic service alias` | 72% | **60%** | Generic alias |
| `Vulnerable admin subdomain detected` | 70% | **90%** | Admin subdomain + DNS resolved |
| `No IP confirmation on staging environment` | 70% | **60%** | No IP confirmation |
| `Loopback address - Filtered noise` | 70% | **15%** | Private IP — noise |
| `Broad wildcard entry` | 70% | **20%** | Wildcard entry |

---

## 🔬 Smart Metadata Analysis

ExifTool results are classified by intelligence value — not dumped as raw data:

| Classification | Confidence | Examples |
|---------------|-----------|----------|
| 📍 **GPS** | 98% | Latitude, longitude, altitude |
| 👤 **AUTHOR** | 95% | Owner name, copyright, artist |
| 📱 **DEVICE** | 92% | iPhone 14 Pro, Samsung, Canon |
| 💻 **SOFTWARE** | 85% | iOS 17.2, Photoshop, GIMP |
| 📅 **DATE** | 85% | Original capture date/time |
| 📄 **BASIC** | 40% | File size, dimensions, type |

**Auto-detects metadata stripping** from: WhatsApp, Telegram, Signal, Facebook, Twitter, Screenshots — and tells you explicitly instead of showing empty results.

---

## 📄 Professional PDF Reports

Reports include **all 9 result types** with:

- 🎯 **Key Findings** — Top 10 highest-priority results (confidence ≥50% only)
- 📊 Stat cards (dynamic — only show categories with results)
- 📈 Confidence distribution bar (high/medium/low)
- 📝 Executive summary (auto-generated)
- 🛡️ Risk Assessment section (if recon was performed)
- 🗺️ Attack paths with severity and steps
- ⚠️ Recommendations

---

## ✨ Additional Features

| Feature | Description |
|---------|-------------|
| 🔐 **Authentication** | bcrypt password with `--setup`, session-based |
| 🎨 **12 Premium Themes** | Ghost Blue, Matrix, Cyberpunk, Ocean, Sunset, Toxic, Blood, Stealth, Arctic, Light, **Royal Gold**, **Midnight Silver** |
| 🌙 **Dark/Light Toggle** | Quick toggle button in navbar |
| 📤 **File Upload** | Upload button in Metadata tab — no need to type file paths |
| 📋 **Copy Button** | Hover any result → click ⎘ to copy |
| 📝 **Scan Notes** | Add notes to any scan from History |
| 🗑️ **Delete Scans** | Remove old scans from History with one click |
| 🔄 **Cross-Scan Diff** | Compare two scans: added/removed/unchanged |
| 🌐 **Interactive Graph** | Clustered force layout, shapes per type, legend, click highlight, PNG export |
| ⛶ **Fullscreen Graph** | Dedicated fullscreen mode with proper resizing |
| 🔎 **Result Search** | Filter results in real-time |
| 💾 **Scan History** | SQLite-backed — load, search, delete past scans |
| 🔌 **Tor Integration** | One toggle — routes traffic through Tor |
| 📦 **Export** | JSON, CSV, TXT, HTML, PDF |
| 🖥️ **CLI Mode** | Direct commands in the terminal bar |

---

## 🧪 Quality Assurance

GhostTrace is continuously tested and verified:

| Category | Details |
|----------|---------|
| ✅ **6 Test Files** | validators, harvester, correlator, risk_engine, recon, new_tools |
| ✅ **Linting** | flake8 checks for syntax errors and undefined names |
| ✅ **API Documentation** | Full reference at [`docs/API.md`](docs/API.md) — all 29 endpoints, schemas, cURL examples |

Run tests locally:
```bash
pytest tests/ -v
```

---

## Architecture

```
                           GhostTrace v5.0

 ┌──────────┐    ┌────────────┐    ┌──────────────┐    ┌──────────┐
 │  Web UI   │───→│ Validators  │───→│ Tool Adapters │───→│ Execution│
 │ 10 tabs   │    │ whitelist   │    │ 9 tools       │    │ Engine   │
 └──────────┘    └────────────┘    └──────────────┘    └────┬─────┘
       ↑                                                     │
       │ SSE      ┌────────────┐    ┌──────────────┐   subprocess
       │←─────────│  Scanner    │←───│   Parser      │←───────┘
       │          └─────┬──────┘    └──────────────┘
       │                │
       │          ┌─────↓──────┐    ┌──────────────┐
       │          │ Correlator  │───→│   SQLite DB   │
       │          │ + Scorer    │    │  WAL mode     │
       │          └─────┬──────┘    └──────────────┘
       │                │
       │          ┌─────↓──────┐    ┌──────────────┐
       │          │ Active Recon│───→│ Risk Engine   │
       │          │ DNS+HTTP+   │    │ Score 0-100   │
       │          │ Ports+Attack│    │ Attack Paths  │
       │          └────────────┘    └──────────────┘
```

**Project Structure (35+ files):**

```
ghosttrace/
├── docs/
│   └── API.md                  # Full REST API documentation
├── app.py                      # Flask entry + authentication
├── config.py                   # Centralized config
├── core/
│   ├── engine.py               # Sandboxed subprocess execution
│   ├── scanner.py              # Scan orchestrator + CLI + abort
│   └── differ.py               # Cross-scan diff comparison
├── tools/
│   ├── base.py                 # ToolAdapter abstract interface (with get_env)
│   ├── harvester.py            # theHarvester (smart confidence, API key env injection)
│   ├── sherlock_tool.py        # Sherlock adapter
│   ├── maigret_tool.py         # Maigret (false positive filter, Tor)
│   ├── exiftool.py             # ExifTool (smart classification: GPS/Author/Device/Basic)
│   ├── phoneinfoga_tool.py     # PhoneInfoga (search engine URL noise filtered)
│   ├── whois_tool.py           # Whois lookup adapter
│   ├── dns_records.py          # DNS records via dig (7 types queried separately)
│   ├── ssl_cert.py             # SSL certificate SANs extraction
│   ├── google_dorks.py         # Google dork generator (28 clickable queries)
│   └── registry.py             # Plugin registry (9 tools)
├── api/
│   ├── routes.py               # 4 Blueprints, 29+ endpoints (incl. upload)
│   └── recon_routes.py         # Active recon pipeline
├── database/
│   └── manager.py              # SQLite WAL + migrations + notes
├── intelligence/
│   └── correlator.py           # Entity linking + smart scoring
├── recon/
│   ├── __init__.py             # DNS, HTTP, Port, AttackSurface, DataQuality
│   └── risk_engine.py          # RiskScorer + AttackPathGenerator
├── reports/
│   └── html_report.py          # Professional reports (9 types + risk + key findings)
├── utils/
│   ├── validators.py           # Whitelist per-tool regex + upload path whitelisting
│   ├── security.py             # Rate limiter + output sanitizer
│   └── logger.py               # Rotating file logger
├── templates/
│   └── index.html              # Single-page dashboard (12 themes)
├── tests/                      # 6 test files
│   ├── test_validators.py
│   ├── test_harvester.py
│   ├── test_correlator.py
│   ├── test_risk_engine.py
│   ├── test_recon.py
│   └── test_new_tools.py
├── build.sh
├── requirements.txt
└── LICENSE
```

---

## Installation

**Target:** Kali Linux 2025+ / Ubuntu 22.04+

### 1. Clone and install Python deps

```bash
git clone https://github.com/alialsartawi7-sketch/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt --break-system-packages
```

### 2. Install OSINT tools

```bash
# Required
sudo apt update
sudo apt install -y pkg-config libcairo2-dev python3-dev build-essential
sudo apt install theharvester exiftool -y
pip install sherlock-project maigret --break-system-packages

# PhoneInfoga
wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
tar xzf /tmp/phoneinfoga.tar.gz -C /tmp/
sudo mv /tmp/phoneinfoga /usr/local/bin/

# Optional — for PDF reports
pip install weasyprint --break-system-packages

# Optional — for Tor routing
sudo apt install tor -y
sudo service tor start
```

### 3. Verify tools

```bash
theHarvester -h
sherlock --version
maigret --version
exiftool -ver
phoneinfoga version
dig -v
openssl version
```

### 4. Set password (recommended)

```bash
python3 app.py --setup
```

---

## Usage

```bash
python3 app.py
# Open http://127.0.0.1:5000
```

### Tor

| Tool | Tor Method |
|------|-----------|
| Maigret | `--tor-proxy socks5://127.0.0.1:9050` |
| Sherlock | `--tor` |
| theHarvester | `proxychains4 -q` wrapper |
| ExifTool | N/A (local file processing) |

### CLI Mode

```
ghost $ maigret johndoe --site Instagram --site GitHub
ghost $ theHarvester -d example.com -b crtsh -l 100
ghost $ whois example.com
ghost $ dig example.com MX
```

---

## 📸 Screenshots

**The themes:**

<img width="1920" height="1080" alt="theme1" src="https://github.com/user-attachments/assets/efd9d27d-5af3-40c8-a620-ca2b37654551" />
<img width="1920" height="1080" alt="theme2" src="https://github.com/user-attachments/assets/abf50782-1828-4ae8-9c97-de054da10732" />
<img width="1920" height="1080" alt="theme3" src="https://github.com/user-attachments/assets/56fdfbb7-05ad-4327-87ae-a18ba2e14105" />

All themes — try it 😉

<img width="233" height="397" alt="themes" src="https://github.com/user-attachments/assets/879655e8-35b5-4200-b3a7-e98823a32164" />

**The scans:**

<img width="1920" height="1080" alt="scan" src="https://github.com/user-attachments/assets/74174ebd-f7f8-45e7-8376-af1e401b2a01" />

**The Graph:**

<img width="1914" height="874" alt="graph1" src="https://github.com/user-attachments/assets/04eb5f3a-bad0-47cb-9bde-17dcd913f7fe" />
<img width="1914" height="874" alt="graph2" src="https://github.com/user-attachments/assets/a35cd86a-1d11-4068-8233-d4e21f41f461" />

**The PDF Reports:**

<img width="1182" height="729" alt="image" src="https://github.com/user-attachments/assets/bd47d49f-39d9-469f-b331-6d428fc9b6ed" />

---

## Security Model

| Layer | Implementation |
|-------|---------------|
| Authentication | bcrypt password hashing, session-based auth |
| Input validation | Per-field regex: domain, email, username, filepath, phone |
| CLI validation | **Whitelist** regex per tool (not a blacklist) |
| Path traversal | Blocks `..`, `/etc/shadow`, `/root`, `.ssh` (uploads dir whitelisted) |
| Output sanitization | Strips ANSI codes + control characters |
| Rate limiting | 20 scans per 60 seconds |
| Process isolation | `os.setsid` + process group kill on timeout/abort |
| File upload | Sanitized filename, safe directory, 16MB limit |

---

## Known Limitations

- Instagram/Facebook block automated checks (Cloudflare) — even with Tor
- Maigret + Tor on all 2500+ sites is slow — use `--site` targeting
- Google Dorks generates queries only — user must search manually
- PhoneInfoga requires separate installation from GitHub releases
- PDF requires `weasyprint` (recommended) or `wkhtmltopdf`
- WhatsApp/Telegram/Signal strip metadata from shared images — this is by design, not a tool limitation
- Linux only — Windows not supported

---

## Disclaimer

GhostTrace is intended for **authorized security research, penetration testing, and educational purposes only**.

The author assumes no liability for misuse. Always obtain proper authorization before performing OSINT operations on targets you do not own.

**Use responsibly. Respect privacy. Follow your country's laws.**

---

## License

MIT License — see [LICENSE](LICENSE)

---

**Built with ❤️ by Alsartawi**
