# GhostTrace v6.3 — Professional OSINT Intelligence Platform
# by Alsartawi

"""
Architecture (reflects the actual modules in this package):

ghosttrace/
├── app.py                  ← Entry point (Flask app, auth, CSRF, blueprints)
├── config.py               ← Config + at-rest key encryption (Fernet)
├── build.sh                ← Build script (package into a single executable)
├── api/
│   ├── routes.py           ← Scan / history / export / system endpoints (Blueprints)
│   └── recon_routes.py     ← Active recon pipeline endpoint (SSE)
├── core/
│   ├── engine.py           ← Sandboxed subprocess execution engine (timeouts, kill)
│   ├── scanner.py          ← Scan orchestrator
│   └── differ.py           ← Scan-to-scan diffing
├── tools/                  ← Plugin adapters (one per OSINT tool)
│   ├── base.py             ← Base tool adapter (plugin interface)
│   ├── registry.py         ← Plugin registry
│   ├── harvester.py        ← theHarvester
│   ├── sherlock_tool.py    ← Sherlock
│   ├── maigret_tool.py     ← Maigret
│   ├── exiftool.py         ← ExifTool
│   ├── phoneinfoga_tool.py ← PhoneInfoga
│   ├── whois_tool.py       ← WHOIS
│   ├── dns_records.py      ← DNS records (dig)
│   ├── ssl_cert.py         ← SSL certificate (openssl)
│   └── google_dorks.py     ← Google dorks
├── database/
│   └── manager.py          ← SQLite operations + connection handling
├── intelligence/
│   └── correlator.py       ← Entity correlation, confidence scoring, graph builder
├── recon/
│   ├── __init__.py         ← Active recon (DNS / HTTP / port probing, SSRF guard)
│   └── risk_engine.py      ← Risk scoring, attack paths, executive summary
├── reports/
│   └── html_report.py      ← HTML / PDF report generator (weasyprint → wkhtmltopdf)
├── utils/
│   ├── validators.py       ← Input validation & sanitization
│   ├── security.py         ← Output sanitization & security utilities
│   └── logger.py           ← Logging
├── templates/
│   └── index.html          ← Frontend (single-page UI)
├── static/                 ← Icons, favicons, PWA assets
├── tests/                  ← pytest suite
├── requirements.txt
├── requirements-dev.txt
└── README.md
"""
