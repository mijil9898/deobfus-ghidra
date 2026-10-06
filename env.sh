#!/usr/bin/env bash
# env.sh -- Chay script nay de setup moi truong lam viec
# Cach dung: source env.sh

export GHIDRA_INSTALL_DIR=~/ghidra_12.1.4_PUBLIC

# Kich hoat virtual environment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"

echo "[+] GHIDRA_INSTALL_DIR = $GHIDRA_INSTALL_DIR"
echo "[+] Python = $(which python3)"
echo "[+] pyghidra = $(python3 -c 'import pyghidra; print(pyghidra.__version__)' 2>/dev/null || echo 'CHUA CAI')"
echo "[+] Moi truong san sang!"
