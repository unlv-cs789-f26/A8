#!/usr/bin/env bash
# CS 789 A8 -- start script for your OWN computer (Linux, or Windows via WSL2; NVIDIA GPU >= 16 GB).
# On Google Colab you do not need this: open A8_Red_Team_the_Copilot.ipynb from GitHub in Colab instead.
#
#   ./start.sh            create .venv, install packages, check the machine, open Jupyter Lab
#   ./start.sh --vllm     also install vLLM (the copilot needs a local model server)
#   ./start.sh --check    only run the environment check
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
if [ "$1" = "--check" ]; then $PY check_environment.py; exit 0; fi
[ -d .venv ] || { echo "== creating .venv"; $PY -m venv .venv; }
. .venv/bin/activate
python -m pip -q install --upgrade pip
echo "== installing packages (first time: a few minutes)"
python -m pip -q install -r requirements.txt jupyterlab ipykernel matplotlib pandas
for a in "$@"; do
  [ "$a" = "--vllm" ] && bash install_vllm.sh
done
python check_environment.py || true
echo "== opening Jupyter Lab: open A8_Red_Team_the_Copilot.ipynb"
exec jupyter lab A8_Red_Team_the_Copilot.ipynb
