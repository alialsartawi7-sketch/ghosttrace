# GhostTrace v5.0 — Professional OSINT Intelligence Platform
# by Alsartawi

"""
Architecture:
ghosttrace/
├── app.py                  ← Entry point
├── config.py               ← Configuration management
├── core/
│   ├── __init__.py
│   ├── engine.py           ← Tool execution engine (sandboxed)
│   ├── scanner.py          ← Scan orchestrator
│   └── pipeline.py         ← Auto-pipeline & scan templates
├── tools/
│   ├── __init__.py
│   ├── base.py             ← Base tool adapter (plugin interface)
│   ├── harvester.py        ← theHarvester adapter
│   ├── sherlock_tool.py    ← Sherlock adapter
│   ├── exiftool.py         ← ExifTool adapter
│   └── registry.py         ← Plugin registry
├── api/
│   ├── __init__.py
│   ├── scans.py            ← Scan endpoints (Blueprint)
│   ├── history.py          ← History endpoints
│   ├── exports.py          ← Export/Report endpoints
│   ├── system.py           ← System/settings endpoints
│   └── cli.py              ← CLI mode endpoint
├── database/
│   ├── __init__.py
│   ├── models.py           ← Database models (structured layer)
│   ├── manager.py          ← DB operations with connection pooling
│   └── migrations.py       ← Schema management
├── intelligence/
│   ├── __init__.py
│   ├── correlator.py       ← Entity correlation engine
│   ├── scorer.py           ← Confidence scoring
│   └── graph.py            ← Graph data builder
├── reports/
│   ├── __init__.py
│   ├── html_report.py      ← HTML report generator
│   └── pdf_report.py       ← PDF converter
├── utils/
│   ├── __init__.py
│   ├── validators.py       ← Input validation & sanitization
│   ├── security.py         ← Security utilities
│   └── logger.py           ← Logging system
├── templates/
│   └── index.html          ← Frontend
├── requirements.txt
└── README.md
"""
