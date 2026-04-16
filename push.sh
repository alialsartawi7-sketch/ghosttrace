#!/bin/bash
MSG="${1:-update}"
git add .
git commit -m "$MSG"
git pull --rebase origin main
git push
echo "✅ Done!"

