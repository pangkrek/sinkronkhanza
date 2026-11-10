#!/bin/bash
# SinkronKhanza - jalankan di Linux/macOS (membuat virtualenv .venv otomatis)
cd "$(dirname "$0")" || exit 1

PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python tidak ditemukan. Pasang Python 3.9+ dulu."; exit 1; }

if [ ! -x .venv/bin/python ]; then
  echo "Menyiapkan virtualenv (sekali saja)..."
  "$PY" -m venv .venv || { echo "Gagal membuat venv. Di Debian/Ubuntu: sudo apt install python3-venv"; exit 1; }
fi

# Pasang dependensi hanya bila belum lengkap (aman untuk jaringan tanpa internet).
if ! .venv/bin/python -c "import flask, pymysql, cryptography" >/dev/null 2>&1; then
  echo "Memasang dependensi (perlu internet, sekali saja)..."
  .venv/bin/python -m pip install -q --disable-pip-version-check -r requirements.txt \
    || { echo "Gagal memasang dependensi. Periksa koneksi internet lalu jalankan lagi."; exit 1; }
fi

exec .venv/bin/python app.py
