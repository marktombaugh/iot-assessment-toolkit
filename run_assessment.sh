#!/bin/bash

# Usage: ./run_assessment.sh <interface> <client_name>
INTERFACE=$1
CLIENT=$2
DATE=$(date +%Y-%m-%d)
OUT_DIR="output/${CLIENT}-${DATE}"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./run_assessment.sh <interface> <client_name>"
    exit 1
fi

echo "[+] Initializing CMMC Assessment for ${CLIENT}..."
mkdir -p "${OUT_DIR}/raw"

echo "[+] Step 1: Running ARP Discovery on ${INTERFACE}..."
./collectors/arp_scan.sh "$INTERFACE" "${OUT_DIR}/raw"

echo "[+] Step 2: Enriching data with OUI lookups..."
python3 analyzers/oui_lookup.py "${OUT_DIR}/raw/arp_scan_"*.csv "${OUT_DIR}/raw/arp_enriched.csv"

echo "[+] Step 3: Correlating network data..."
# This merges ARP, DHCP, and MAC tables into inventory.csv
python3 analyzers/correlate.py "${OUT_DIR}/raw" "${OUT_DIR}/inventory.csv"

echo "[+] Step 4: Running CMMC Anomaly Detection..."
python3 analyzers/find_anomalies.py "${OUT_DIR}/inventory.csv" "${OUT_DIR}/anomalies.csv"

echo "[+] Step 5: Generating Executive Summary..."
python3 analyzers/report_gen.py "${OUT_DIR}/inventory.csv" "${OUT_DIR}/anomalies.csv" "reference/cmmc_mapping.json" "${OUT_DIR}/CMMC_Executive_Summary.md"

echo "----------------------------------------------------"
echo "[SUCCESS] Assessment Complete."
echo "Final Report: ${OUT_DIR}/CMMC_Executive_Summary.md"
echo "Inventory:    ${OUT_DIR}/inventory.csv"
echo "----------------------------------------------------"
