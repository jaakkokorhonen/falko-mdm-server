#!/bin/bash
# Falko MDM Server — Yksikkötestien suoritusskripti
set -e

echo "=== Ajetan Falko MDM Server -yksikkötestit ==="

# Luodaan virtuaaliympäristö tarvittaessa
if [ ! -d "venv" ]; then
  echo "Luodaan Python-virtuaaliympäristö (venv)..."
  python3 -m venv venv
fi

# Aktivoidaan virtuaaliympäristö ja asennetaan riippuvuudet
source venv/bin/activate
echo "Päivitetään riippuvuudet..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Suoritetaan pytest
echo "Suoritetaan testit..."
PYTHONPATH=. pytest -v

echo "=== Testit ajettu onnistuneesti! ==="
