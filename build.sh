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

# 1. Check PyInstaller
if ! command -v pyinstaller &> /dev/null; then
    echo "[*] Installing PyInstaller..."
    pip install pyinstaller --break-system-packages
fi

echo "[*] Building GhostTrace..."

# 2. Build
pyinstaller \
    --name GhostTrace \
    --onefile \
    --add-data "templates:templates" \
    --add-data "static:static" \
    --hidden-import flask \
    --hidden-import sqlite3 \
    --hidden-import json \
    --collect-submodules tools \
    --collect-submodules core \
    --collect-submodules api \
    --collect-submodules database \
    --collect-submodules intelligence \
    --collect-submodules reports \
    --collect-submodules utils \
    --noconfirm \
    --clean \
    app.py

if [ $? -eq 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════╗"
    echo "║    ✓ Build Successful!                    ║"
    echo "║                                          ║"
    echo "║    Output: dist/GhostTrace               ║"
    echo "║    Run:    ./dist/GhostTrace              ║"
    echo "╚══════════════════════════════════════════╝"
    echo ""
    echo "[*] File size: $(du -h dist/GhostTrace | cut -f1)"
    echo "[*] To distribute, share only: dist/GhostTrace"
    echo "[*] Users need: theHarvester, maigret, sherlock, exiftool installed"
else
    echo ""
    echo "[✗] Build failed!"
    echo "[*] Try: pip install pyinstaller --break-system-packages"
fi
