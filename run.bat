@echo off
cd /d "%~dp0"
title SinkronKhanza

set "PY="
where python >nul 2>nul && set "PY=python"
if not defined PY ( where py >nul 2>nul && set "PY=py -3" )
if not defined PY (
  echo Python tidak ditemukan. Pasang dari https://www.python.org/downloads/ dan centang "Add Python to PATH".
  pause & exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Menyiapkan virtualenv ^(sekali saja^)...
  %PY% -m venv .venv || (echo Gagal membuat venv. & pause & exit /b 1)
)

rem Pasang dependensi hanya bila belum lengkap (aman untuk jaringan tanpa internet).
".venv\Scripts\python.exe" -c "import flask, pymysql, cryptography" >nul 2>nul || (
  echo Memasang dependensi ^(perlu internet, sekali saja^)...
  ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements.txt || (
    echo Gagal memasang dependensi. Periksa koneksi internet lalu jalankan lagi.
    pause & exit /b 1
  )
)

".venv\Scripts\python.exe" app.py
pause
