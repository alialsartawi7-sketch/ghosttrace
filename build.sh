#!/bin/bash
# ═══════════════════════════════════════════════
#  GhostTrace Build Script
#  by Alsartawi
#  يحول المشروع لملف تنفيذي واحد
# ═══════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║    GhostTrace Build System               ║"
echo "║    by Alsartawi                          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 0. Pre-flight check ──
MISSING_TOOLS=()
for tool in dig whois exiftool openssl; do
    if ! command -v $tool &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "[!] Missing system tools: ${MISSING_TOOLS[@]}"
    echo "[!] GhostTrace will build but these tools won't work at runtime."
    echo "[!] Run this first:  ./install-deps.sh"
    echo ""
    read -p "    Continue build anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "[*] Build cancelled. Run ./install-deps.sh first."
        exit 1
    fi
fi

# ── 1. Check PyInstaller ──
if ! command -v pyinstaller &> /dev/null; then
    echo "[*] Installing PyInstaller..."
    pip install pyinstaller --break-system-packages 2>/dev/null || pip install pyinstaller
fi

echo "[*] Building GhostTrace..."

# ── 2. Build ──
pyinstaller \
    --name GhostTrace \
    --onefile \
    --add-data "templates:templates" \
    --add-data "static:static" \
    --hidden-import flask \
    --hidden-import sqlite3 \
    --hidden-import json \
    --hidden-import bcrypt \
    --hidden-import weasyprint \
    --collect-submodules tools \
    --collect-submodules core \
    --collect-submodules api \
    --collect-submodules database \
    --collect-submodules intelligence \
    --collect-submodules reports \
    --collect-submodules recon \
    --collect-submodules utils \
    --noconfirm \
    --clean \
    app.py

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║    ✓ Build Successful!                   ║"
    echo "║                                          ║"
    echo "║    Output: dist/GhostTrace               ║"
    echo "║    Run:    ./dist/GhostTrace             ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "[*] File size: $(du -h dist/GhostTrace | cut -f1)"
    echo ""
    echo "[!] Note: The binary only contains GhostTrace itself."
    echo "[!] Runtime dependencies (dig, exiftool, theHarvester, etc.)"
    echo "[!] must be installed separately via: ./install-deps.sh"
else
    echo ""
    echo "[✗] Build failed!"
    echo "[*] Try: pip install pyinstaller --break-system-packages"
fi
