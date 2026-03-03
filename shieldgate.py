#!/usr/bin/env python3
"""
ShieldGate IoT Assessment Toolkit - Master Launcher
Author: Mark Tombaugh (Raleigh, NC)
License: BSD 3-Clause

Orchestrates the full assessment pipeline:
1. Discovery (ARP/Network Scan)
2. Enrichment (OUI/Vendor Lookup)
3. Analysis (ShieldGate Deterministic Audit)
"""

import subprocess
import argparse
import sys
import os

def run_step(step_name, command):
    """Executes a shell command and handles errors gracefully."""
    print(f"[*] Running {step_name}...")
    try:
        # We use shell=True to support piping and shell expansions in bash scripts
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"[+] {step_name} completed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[!] Error during {step_name}: {e.stderr}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="ShieldGate IoT Assessment Toolkit")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to scan (e.g., eth0, wlan0)")
    parser.add_argument("-o", "--output", default="final_report.csv", help="Final anomaly report filename")
    
    args = parser.parse_args()

    print("--- ShieldGate IoT Toolkit Pipeline ---")

    # Step 1: Discovery (Runs your existing bash discovery script)
    # Output: raw_inventory.csv
    run_step("Discovery Scan", f"sudo bash scripts/discover.sh {args.interface} raw_inventory.csv")

    # Step 2: Enrichment (Runs OUI lookup script)
    # Output: enriched_inventory.csv
    run_step("Vendor Enrichment", "python3 scripts/oui_lookup.py raw_inventory.csv enriched_inventory.csv")

    # Step 3: Analysis (Your new Deterministic Auditor)
    # Output: final_report.csv (or user specified)
    run_step("Deterministic Analysis", f"python3 analyzers/find_anomalies.py enriched_inventory.csv {args.output}")

    print("-" * 39)
    print(f"[SUCCESS] Assessment complete. Report generated: {args.output}")
    print("[*] Review the report for CRITICAL PNT_HEARTBEAT signatures.")

if __name__ == "__main__":
    # Check for root privileges (required for ARP scanning)
    if os.geteuid() != 0:
        print("[!] ShieldGate requires root privileges to perform network discovery.")
        print("    Please run: sudo python3 shieldgate.py -i <interface>")
        sys.exit(1)
    
    main()
