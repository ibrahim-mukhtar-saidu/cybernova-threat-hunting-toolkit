#!/usr/bin/env bash

set -e

echo "=============================================="
echo "   CYBERNOVA AI THREAT HUNTING DEMO"
echo "=============================================="
echo

echo "[1/7] Threat Hunting"
echo "----------------------------------------------"
python3 main.py log samples/threat_hunting.log
echo

echo "[2/7] IOC Investigation"
echo "----------------------------------------------"
python3 main.py ioc 45.33.32.156
echo

echo "[3/7] Timeline Reconstruction"
echo "----------------------------------------------"
python3 main.py timeline \
    samples/threat_hunting.log \
    45.33.32.156
echo

echo "[4/7] Sigma Detection"
echo "----------------------------------------------"
python3 main.py sigma \
    samples/threat_hunting.log \
    rules/sigma/failed_login.yml
echo

echo "[5/7] YARA Analysis"
echo "----------------------------------------------"
python3 main.py yara \
    samples/update.bin \
    rules/yara/suspicious_sample.yar
echo

echo "[6/7] Hash Analysis"
echo "----------------------------------------------"
python3 main.py hash samples/update.bin
echo

echo "[7/7] Dashboard Generation"
echo "----------------------------------------------"
python3 dashboards/dashboard_generator.py
echo

echo "=============================================="
echo "   INVESTIGATION DEMO COMPLETE"
echo "=============================================="
echo
echo "Dashboard:"
echo "  dashboards/index.html"
echo
echo "Generated reports:"
echo "  reports/generated/"
