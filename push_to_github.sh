#!/usr/bin/env bash
# Instructor: publish this folder as the public repo unlv-cs789-f26/A8 (run once, on your Mac).
# instructor/, *.docx/*.pdf and the instructor tools are excluded by .gitignore.
set -e
cd "$(dirname "$0")"
rm -f .git/*.lock .git/objects/*.lock 2>/dev/null || true
[ -d .git ] || git init -b main
git add -A
git commit -m "CS 789 A8: red-team and harden the SOC Copilot" || true
gh repo create unlv-cs789-f26/A8 --public --source=. --remote=origin --push || git push -u origin main
echo "Students open: https://colab.research.google.com/github/unlv-cs789-f26/A8/blob/main/A8_Red_Team_the_Copilot.ipynb"
