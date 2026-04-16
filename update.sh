#!/bin/bash
# GhostTrace Auto-Update Script
# Run this from the directory where ghosttrace-v4.5-pdf.tar.gz is located

echo "╔══════════════════════════════════════════╗"
echo "║    GhostTrace Auto-Update                ║"
echo "╚══════════════════════════════════════════╝"

# 1. Kill old instance
echo "[*] Stopping old GhostTrace..."
kill $(lsof -t -i:5000) 2>/dev/null
sleep 1

# 2. Remove old folder completely
echo "[*] Removing old files..."
rm -rf ghosttrace/

# 3. Extract fresh
echo "[*] Extracting new version..."
tar xzf ghosttrace-v4.5-pdf.tar.gz

# 4. Verify key fix
if grep -q "PDF Engine" ghosttrace/tools/registry.py 2>/dev/null; then
    echo "[✓] PDF Engine fix confirmed"
else
    echo "[✗] ERROR: Fix not found in extracted files!"
    exit 1
fi

if grep -q "weasyprint" ghosttrace/reports/html_report.py 2>/dev/null; then
    echo "[✓] WeasyPrint support confirmed"
else
    echo "[✗] ERROR: WeasyPrint not in report generator!"
    exit 1
fi

# 5. Launch
echo "[*] Starting GhostTrace v4.5..."
echo ""
cd ghosttrace && python3 app.py
