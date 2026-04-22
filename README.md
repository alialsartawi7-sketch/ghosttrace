<img width="1920" height="1080" alt="Screenshot_2026-04-13_09_04_03" src="https://github.com/user-attachments/assets/2b4892ca-45ab-4df8-b05e-0d2f7b33034a" />

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green)
![Version 6.0](https://img.shields.io/badge/Version-6.0-ff6b35)
![Platform Linux](https://img.shields.io/badge/Platform-Linux%20(Kali%20recommended)-orange?logo=linux&logoColor=white)
![Tools 9](https://img.shields.io/badge/Tools-9%20Integrated-purple)
![Routes 36](https://img.shields.io/badge/API%20Routes-36-blue)
![Themes 12](https://img.shields.io/badge/Themes-12-ff6b35)
![Tests 9](https://img.shields.io/badge/Tests-9%20Files-success)

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗████████╗██████╗  █████╗  ██████╗███████╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
  ██║  ███╗███████║██║   ██║███████╗   ██║      ██║   ██████╔╝███████║██║     █████╗  
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║      ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                                          v6.0 by Alsartawi
```

**OSINT made simple — from beginner to professional.**

GhostTrace is a modular OSINT intelligence platform that wraps 9 Linux tools into a single web interface with real-time streaming, active reconnaissance, risk scoring, attack path analysis, and professional PDF reports. No cloud dependencies. No telemetry. Runs entirely on your machine.

"⭐ If you find this useful, a star helps a lot!"
"🐛 Found a bug? Open an issue — I actively fix them."

---

## 🆕 What's New in v6.0

| Feature | Description |
|---------|-------------|
| ⭐ **Starred Scans** | Pin important scans to the top of History — they're protected from auto-cleanup |
| ⌨️ **Keyboard Shortcuts** | Enter, Esc, Ctrl+K/H/L/,, 1-9, Ctrl+/ for power users |
| 🔗 **Deep Links** | URL updates when loading scan — share `?scan=<id>` with colleagues |
| 🗑️ **DB Cleanup** | Auto-remove scans older than N days (keeps starred), vacuum reclaims space |
| 📊 **DB Info** | View database size, scan counts, starred counts via API |
| 📦 **Bulk Operations** | Delete multiple scans at once via API |
| 💾 **Export All History** | Full backup as JSON for archiving or transfer |
| 📝 **Better Logging** | Scan lifecycle tracked in logs — start, complete, errors |
| 🔒 **CSRF Fixes** | 3 security bugs fixed — null token rejection, proper flow, jsonify import |
| 🐛 **AttackPath Crash Fix** | `KeyError: 'status'` on incomplete admin panel data |

---

## ⚡ What Makes GhostTrace Different

- 🔍 **9 integrated tools** — not just wrappers, full intelligence pipeline
- 🛡️ **Active Recon** — DNS validation, HTTP probing, port scanning with **banner grabbing**
- 📊 **Risk Scoring Engine** — 0-100 dynamic scoring with actionable reasons
- 🗺️ **Attack Path Generator** — 5 rules that map real exploitation paths
- 🧠 **Smart Confidence** — scores based on result quality, not just source
- 🔬 **Intelligent Metadata Analysis** — auto-detects WhatsApp/Telegram metadata stripping
- 📄 **Professional Reports** — PDF with Key Findings, SVG charts, Entity Timeline, risk assessment
- 🌐 **Interactive Graph** — Quadtree O(n log n) force layout, PNG export, fullscreen
- 🔐 **Authentication + CSRF** — bcrypt password, session-based, CSRF tokens on all POST/DELETE
- 🎨 **12 Premium Themes** — including Royal Gold and Midnight Silver
- 🔄 **Cross-Scan Diff** — compare two scans to detect new exposures
- 📤 **File Upload + Drag & Drop** — no need to type paths for metadata extraction

---

## 🧰 Integrated Tools (9)

| # | Tool | Tab | What It Finds |
|---|------|-----|---------------|
| 1 | **theHarvester** | Email / Subs | Emails, subdomains, IPs from 13 free sources |
| 2 | **Maigret** | Username | Social media profiles across 2500+ sites |
| 3 | **Sherlock** | Username | Username search across 400+ sites |
| 4 | **ExifTool** | Metadata | Hidden metadata — GPS, author, device (smart classification) |
| 5 | **PhoneInfoga** | Phone | Phone number carrier, country (search engine noise filtered) |
| 6 | **Whois** | Auto/CLI | Domain registration, registrar, expiry, nameservers |
| 7 | **dig** | DNS | MX, TXT (SPF/DKIM/DMARC), NS, SOA, A, AAAA, CNAME records |
| 8 | **openssl** | SSL | Certificate SANs (hidden subdomains), issuer, expiry |
| 9 | **Google Dorks** | Dorks | 28 targeted clickable queries |

---

## 🎛️ 10 Scan Modules

| Module | Input | Tool Used | Example |
|--------|-------|-----------|---------|
| **Auto** | Anything | Auto-detects, chains DNS+SSL for domains | `microsoft.com` → 3-phase pipeline |
| **Email** | Domain | theHarvester | `example.com` |
| **Username** | Username | Maigret / Sherlock | `johndoe` |
| **Metadata** | File path or Upload (drag&drop) | ExifTool (smart classification) | Drag file or browse |
| **Phone** | Phone number | PhoneInfoga (noise-filtered) | `+1234567890` |
| **Subdomain** | Domain | theHarvester | `google.com` |
| **DNS** | Domain | dig (7 record types) | `example.com` |
| **SSL** | Domain | openssl | `example.com` |
| **Dorks** | Domain | Generator (clickable) | `example.com` |
| **Recon** | Domain | Built-in | Full pipeline with banner grabbing |

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Start scan |
| `Esc` | Abort scan |
| `Ctrl + K` | Focus filter |
| `Ctrl + /` | Show help |
| `Ctrl + H` | Open History |
| `Ctrl + ,` | Settings |
| `Ctrl + L` | Clear console |
| `1` – `9` | Switch tabs |

---

## 🛡️ Active Reconnaissance Pipeline

After passive OSINT, GhostTrace validates and enriches results:

```
📡 DNS Resolution     → Remove dead domains, validate alive hosts
🌐 HTTP Probing       → Status codes, technology detection, security headers
🔌 Port Scanning      → Top 25 ports + banner grabbing (OpenSSH, Apache, nginx...)
🎯 Attack Surface     → Admin panels, login pages, API endpoints
📊 Risk Scoring       → 0-100 dynamic score with explanations
🗺️ Attack Paths       → 5 rules: Brute Force, Admin Panel, API, Legacy, Chained
```

### Risk Scoring

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

| Result | Old Score | Smart Score | Why |
|--------|-----------|-------------|-----|
| `john.doe@example.com` | 72% | **90%** | Personal email (firstname.lastname) |
| `info@example.com` | 72% | **60%** | Generic alias |
| `admin.example.com` | 70% | **90%** | Admin subdomain + DNS resolved |
| `blog.example.com` | 70% | **60%** | No IP confirmation |
| `0.0.0.0` | 70% | **15%** | Private IP — noise |
| `*.example.com` | 70% | **20%** | Wildcard entry |

---

## 🔬 Smart Metadata Analysis

ExifTool results classified by intelligence value:

| Classification | Confidence | Examples |
|---------------|-----------|----------|
| 📍 **GPS** | 98% | Latitude, longitude, altitude |
| 👤 **AUTHOR** | 95% | Owner name, copyright, artist |
| 📱 **DEVICE** | 92% | iPhone 14 Pro, Samsung, Canon |
| 💻 **SOFTWARE** | 85% | iOS 17.2, Photoshop, GIMP |
| 📅 **DATE** | 85% | Original capture date/time |
| 📄 **BASIC** | 40% | File size, dimensions, type |

**Auto-detects metadata stripping** from: WhatsApp, Telegram, Signal, Facebook, Twitter, Screenshots.

---

## 📄 Professional PDF Reports

Reports include **all 9 result types** with:

- 🎯 **Key Findings** — Top 10 highest-priority results (confidence ≥50% only)
- 📊 **SVG Charts** — Bar chart of results by type
- 🕐 **Entity Timeline** — Recurring findings with first_seen/last_seen/count
- 📈 Confidence distribution bar (high/medium/low)
- 📝 Executive summary (auto-generated)
- 🛡️ Risk Assessment section (if recon was performed)
- 🗺️ Attack paths with severity and steps
- ⚠️ Recommendations

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **Authentication** | bcrypt password with `--setup`, session-based |
| 🔒 **CSRF Protection** | Token per session, auto-injected on all POST/DELETE |
| 🎨 **12 Premium Themes** | Ghost Blue, Matrix, Cyberpunk, Ocean, Sunset, Toxic, Blood, Stealth, Arctic, Light, **Royal Gold**, **Midnight Silver** |
| 🌙 **Dark/Light Toggle** | Quick toggle button in navbar |
| ⭐ **Starred Scans** | Pin important scans — protected from auto-cleanup |
| 🔗 **Deep Links** | URL updates on scan load — shareable links |
| 📤 **File Upload + Drag & Drop** | Drop files into metadata tab directly |
| 📋 **Copy Button** | Hover any result → click ⎘ to copy |
| 📝 **Scan Notes** | Add notes to any scan from History |
| 🗑️ **Delete / Bulk Delete** | Remove old scans one-by-one or in batch |
| 🧹 **Auto Cleanup** | Remove scans older than N days (keeps starred) |
| 💾 **Full DB Backup** | Export entire history as JSON |
| 🔄 **Cross-Scan Diff** | Compare two scans: added/removed/unchanged |
| 🌐 **Interactive Graph** | Quadtree O(n log n), clustering, shapes, PNG export |
| ⛶ **Fullscreen Graph** | Dedicated fullscreen mode |
| 🔎 **Result Search** | Filter results in real-time |
| 💾 **Scan History** | SQLite-backed with starred ordering |
| 🔌 **Tor Integration** | One toggle — routes traffic through Tor |
| 📦 **Export** | JSON, CSV, TXT, HTML, PDF |
| 🖥️ **CLI Mode** | Direct commands in the terminal bar |
| ⌨️ **Keyboard Shortcuts** | Power user workflow |

---

## 🧪 Quality Assurance

| Category | Details |
|----------|---------|
| ✅ **9 Test Files** | validators, harvester, correlator, risk_engine, recon, new_tools, database, report, integration |
| ✅ **Linting** | flake8 checks for syntax errors and undefined names |
| ✅ **API Documentation** | Full reference at [`docs/API.md`](docs/API.md) — all 36 endpoints |
| ✅ **Contributing Guide** | [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to add tools, run tests, code style |
| ✅ **Type Hints** | Key modules typed: base, risk_engine, correlator, validators |

Run tests locally:
```bash
pytest tests/ -v
```

---

## Architecture

```
                           GhostTrace v6.0

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
       │          │ + Scorer    │    │  WAL + starred│
       │          └─────┬──────┘    └──────────────┘
       │                │
       │          ┌─────↓──────┐    ┌──────────────┐
       │          │ Active Recon│───→│ Risk Engine   │
       │          │ DNS+HTTP+   │    │ Score 0-100   │
       │          │ Ports+Attack│    │ Attack Paths  │
       │          └────────────┘    └──────────────┘
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
sudo apt install -y pipx dnsutils whois libimage-exiftool-perl \
  openssl git libcairo2-dev pkg-config python3-dev build-essential

# pipx PATH
pipx ensurepath

# OSINT tools
pipx install maigret sherlock-project

# PhoneInfoga
wget https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz -O /tmp/phoneinfoga.tar.gz
tar xzf /tmp/phoneinfoga.tar.gz -C /tmp/
sudo mv /tmp/phoneinfoga /usr/local/bin/

# Clone and run
git clone https://github.com/alialsartawi7-sketch/ghosttrace.git
cd ghosttrace
pip install -r requirements.txt --break-system-packages
python3 app.py

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
| **CSRF Protection** | Token per session, validated on all POST/DELETE |
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
- WhatsApp/Telegram/Signal strip metadata from shared images — by design
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
