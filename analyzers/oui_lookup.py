#!/usr/bin/env python3
"""
oui_lookup.py - Identify device vendors from MAC addresses
Part of the IoT/Physical Security Assessment Toolkit

Usage: 
    python3 oui_lookup.py [input_csv] [output_csv]
    python3 oui_lookup.py --update-db    # Download fresh OUI database

The OUI (Organizationally Unique Identifier) is the first 3 bytes of a MAC address.
It identifies the manufacturer of the network interface.

This is your first filter for finding interesting devices:
- Chinese OUIs on a US defense contractor's network? Flag it.
- Unknown OUI? Could be cheap IoT garbage. Flag it.
- Hikvision, Dahua, TP-Link on the production VLAN? Flag it.
"""

import csv
import os
import sys
import re
from pathlib import Path
from datetime import datetime
from urllib.request import urlretrieve

# Vendors of interest - these get flagged for extra attention
FLAGGED_VENDORS = {
    # Chinese manufacturers - not inherently bad, but worth noting
    'hikvision': 'Chinese surveillance equipment manufacturer',
    'dahua': 'Chinese surveillance equipment manufacturer',
    'huawei': 'Chinese telecommunications equipment',
    'zte': 'Chinese telecommunications equipment',
    'xiaomi': 'Chinese consumer electronics',
    'tp-link': 'Chinese networking equipment',
    'tenda': 'Chinese networking equipment',
    'shenzhen': 'Generic Shenzhen manufacturer - investigate',
    'hangzhou': 'Generic Hangzhou manufacturer - investigate',
    'guangzhou': 'Generic Guangzhou manufacturer - investigate',
    
    # IoT platforms that might indicate shadow IT
    'espressif': 'ESP32/ESP8266 IoT modules - homebrew or cheap IoT',
    'raspberry': 'Raspberry Pi - could be legitimate or shadow IT',
    'arduino': 'Arduino - maker hardware, unusual in enterprise',
    
    # Consumer gear that shouldn't be on production networks
    'nest': 'Google/Nest consumer IoT',
    'ring': 'Amazon Ring consumer IoT',
    'sonos': 'Consumer audio equipment',
    'roku': 'Streaming device',
    'amazon': 'Could be Echo/Alexa devices',
}

# Path to OUI database
SCRIPT_DIR = Path(__file__).parent.resolve()
OUI_DB_PATH = SCRIPT_DIR.parent / 'reference' / 'oui.csv'
OUI_URL = 'https://standards-oui.ieee.org/oui/oui.csv'


def normalize_mac(mac):
    """Convert any MAC format to lowercase with colons."""
    # Remove all separators
    mac_clean = re.sub(r'[.:\-]', '', mac.lower())
    
    if len(mac_clean) < 6:
        return None
    
    # Take first 6 chars (OUI) or full MAC
    if len(mac_clean) >= 12:
        # Full MAC - format as xx:xx:xx:xx:xx:xx
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    else:
        # Partial - just return cleaned
        return mac_clean


def get_oui(mac):
    """Extract OUI (first 3 bytes) from MAC address."""
    mac_clean = re.sub(r'[.:\-]', '', mac.lower())
    if len(mac_clean) >= 6:
        return mac_clean[:6].upper()
    return None


def load_oui_database():
    """Load OUI database from CSV file."""
    oui_db = {}
    
    if not OUI_DB_PATH.exists():
        print(f"Warning: OUI database not found at {OUI_DB_PATH}")
        print("Run with --update-db to download it, or working offline with limited data")
        return oui_db
    
    try:
        with open(OUI_DB_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            
            for row in reader:
                if len(row) >= 3:
                    # IEEE format: Registry, Assignment (OUI), Organization Name
                    oui = row[1].strip().upper()
                    vendor = row[2].strip()
                    
                    # Normalize OUI (remove hyphens if present)
                    oui = oui.replace('-', '')
                    
                    if len(oui) == 6:
                        oui_db[oui] = vendor
    except Exception as e:
        print(f"Error loading OUI database: {e}")
    
    print(f"Loaded {len(oui_db)} OUI entries")
    return oui_db


def update_oui_database():
    """Download fresh OUI database from IEEE."""
    print(f"Downloading OUI database from IEEE...")
    print(f"URL: {OUI_URL}")
    
    # Create directory if needed
    OUI_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        urlretrieve(OUI_URL, OUI_DB_PATH)
        print(f"Saved to: {OUI_DB_PATH}")
        
        # Count entries
        with open(OUI_DB_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            count = sum(1 for _ in f) - 1  # Subtract header
        print(f"Database contains {count} entries")
        
    except Exception as e:
        print(f"Error downloading OUI database: {e}")
        print("You can manually download from:")
        print(f"  {OUI_URL}")
        print(f"And save to: {OUI_DB_PATH}")
        sys.exit(1)


def check_vendor_flags(vendor):
    """Check if vendor matches any flagged patterns."""
    if not vendor:
        return None, None
    
    vendor_lower = vendor.lower()
    
    for keyword, reason in FLAGGED_VENDORS.items():
        if keyword in vendor_lower:
            return keyword, reason
    
    return None, None


def process_file(input_path, output_path, oui_db):
    """Process a CSV file, adding vendor information."""
    
    results = []
    unknown_count = 0
    flagged_count = 0
    
    with open(input_path, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        
        # We need a MAC address column
        mac_col = None
        for col in ['mac_address', 'mac', 'MAC', 'MAC Address', 'hardware_address']:
            if col in fieldnames:
                mac_col = col
                break
        
        if not mac_col:
            print(f"Error: No MAC address column found in {input_path}")
            print(f"Columns present: {fieldnames}")
            return
        
        for row in reader:
            mac = row.get(mac_col, '')
            oui = get_oui(mac)
            
            vendor = 'UNKNOWN'
            flag = ''
            flag_reason = ''
            
            if oui and oui in oui_db:
                vendor = oui_db[oui]
            elif oui:
                unknown_count += 1
            
            # Check for flagged vendors
            keyword, reason = check_vendor_flags(vendor)
            if keyword:
                flag = keyword.upper()
                flag_reason = reason
                flagged_count += 1
            
            results.append({
                **row,
                'oui': oui or '',
                'vendor': vendor,
                'flag': flag,
                'flag_reason': flag_reason
            })
    
    # Write output
    if results:
        output_fields = list(results[0].keys())
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=output_fields)
            writer.writeheader()
            writer.writerows(results)
    
    return len(results), unknown_count, flagged_count


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--update-db':
        update_oui_database()
        return
    
    if len(sys.argv) < 2:
        print("OUI Lookup - Identify device vendors from MAC addresses")
        print("")
        print("Usage:")
        print(f"  {sys.argv[0]} [input.csv] [output.csv]")
        print(f"  {sys.argv[0]} --update-db")
        print("")
        print("Input CSV must have a 'mac_address' column (or similar).")
        print("Output will include: oui, vendor, flag, flag_reason")
        print("")
        print("Example:")
        print(f"  {sys.argv[0]} ../output/raw/arp_scan_20260127.csv ../output/inventory_enriched.csv")
        return
    
    input_path = sys.argv[1]
    
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        # Default output name
        base = os.path.splitext(input_path)[0]
        output_path = f"{base}_enriched.csv"
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    print("=== OUI Lookup ===")
    print(f"Input: {input_path}")
    print(f"Output: {output_path}")
    print("")
    
    # Load database
    oui_db = load_oui_database()
    
    if not oui_db:
        print("Warning: Operating with empty OUI database. Run --update-db first.")
    
    # Process file
    total, unknown, flagged = process_file(input_path, output_path, oui_db)
    
    print("")
    print("=== Results ===")
    print(f"Devices processed: {total}")
    print(f"Unknown vendors: {unknown}")
    print(f"Flagged devices: {flagged}")
    print(f"Output saved to: {output_path}")
    
    if flagged > 0:
        print("")
        print("⚠️  FLAGGED DEVICES FOUND - Review output for details")


if __name__ == '__main__':
    main()
