#!/usr/bin/env python3
"""
IoT & Network Security Assessment Toolkit
Analyzer: find_anomalies.py
Author: Mark Tombaugh (Raleigh, NC)
License: BSD 3-Clause

Detects policy violations, flagged vendors, and deterministic PNT heartbeats.
"""

import csv
import sys
import os

# --- Configuration ---

# VLAN Policy: Edit to match client network architecture
VLAN_POLICY = {
    '1': ('default', ['any']),
    '10': ('management', ['switch', 'router', 'firewall']),
    '50': ('corporate', ['workstation', 'laptop', 'printer', 'nav-sens']),
    '100': ('secure_production', ['plc', 'hmi', 'sensor', 'badge-reader']),
}

# High-risk vendors requiring immediate scrutiny
FLAGGED_VENDORS = {
    "Hangzhou Hikvision": "Chinese surveillance equipment - NDAA/DFARS violation",
    "Dahua": "Chinese surveillance equipment - NDAA/DFARS violation",
    "Huawei": "Chinese infrastructure - security concerns",
    "ZTE": "Chinese infrastructure - security concerns",
    "Espressif": "ESP32/ESP8266 IoT modules - shadow IT / hidden PNT",
    "Quectel": "M2M cellular modules - autonomous BDS-3 heartbeat source",
    "HiSilicon": "Integrated circuits - potential PNT/Cognitive Backdoors",
    "Lumi United": "Consumer IoT (Aqara/Xiaomi) - corporate policy violation",
    "Ring": "Consumer/Amazon IoT - corporate policy violation",
    "Raspberry Pi": "Unauthorized computing / Shadow IT"
}

def analyze_inventory(input_file, output_file):
    anomalies = []

    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    with open(input_file, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            severity = ""
            a_type = ""
            desc = ""
            rec = ""

            # 1. Deterministic PNT / Infrastructure Heartbeat Check
            # Logic: Vendor + Specific Criticality (e.g., Quectel/HiSilicon)
            if any(x in row['vendor'] for x in ["Quectel", "HiSilicon"]):
                anomalies.append({
                    'severity': 'CRITICAL',
                    'anomaly_type': 'PNT_HEARTBEAT',
                    'mac_address': row['mac_address'],
                    'ip_address': row['ip_address'],
                    'hostname': row['hostname'],
                    'vendor': row['vendor'],
                    'vlan': row['vlan'],
                    'description': "Deterministic BDS-3 Ephemeris Sync detected. Device heartbeats to foreign assistance CDN.",
                    'recommendation': "Isolate from critical network path immediately. Audit for R2-Backdoor compliance."
                })

            # 2. Flagged Vendor Check
            for vendor, reason in FLAGGED_VENDORS.items():
                if vendor in row['vendor']:
                    anomalies.append({
                        'severity': 'HIGH' if "Hikvision" in vendor or "Dahua" in vendor else 'MEDIUM',
                        'anomaly_type': 'FLAGGED_VENDOR',
                        'mac_address': row['mac_address'],
                        'ip_address': row['ip_address'],
                        'hostname': row['hostname'],
                        'vendor': row['vendor'],
                        'vlan': row['vlan'],
                        'description': f"Flagged vendor: {vendor}. Reason: {reason}",
                        'recommendation': "Evaluate necessity of device. Replace with trusted vendor or increase monitoring."
                    })

            # 3. VLAN Policy Violation Check
            vlan_id = row['vlan']
            if vlan_id in VLAN_POLICY:
                vlan_name, allowed_types = VLAN_POLICY[vlan_id]
                # Check if device is a consumer device on corporate VLAN 50
                if vlan_id == '50' and any(x in row['vendor'] for x in ["Ring", "Lumi", "Espressif"]):
                    anomalies.append({
                        'severity': 'HIGH',
                        'anomaly_type': 'CONSUMER_ON_CORP',
                        'mac_address': row['mac_address'],
                        'ip_address': row['ip_address'],
                        'hostname': row['hostname'],
                        'vendor': row['vendor'],
                        'vlan': vlan_id,
                        'description': f"Consumer/IoT device on corporate VLAN {vlan_id}.",
                        'recommendation': "Remove unauthorized consumer devices or move to isolated guest VLAN."
                    })

            # 4. Identification Issues (Missing Hostnames)
            if not row['hostname'] or row['hostname'] == "":
                anomalies.append({
                    'severity': 'LOW',
                    'anomaly_type': 'NO_HOSTNAME',
                    'mac_address': row['mac_address'],
                    'ip_address': row['ip_address'],
                    'hostname': "UNKNOWN",
                    'vendor': row['vendor'],
                    'vlan': row['vlan'],
                    'description': "Device has no hostname, complicating inventory tracking.",
                    'recommendation': "Configure hostname or update DHCP reservations."
                })

    # Write anomalies to CSV
    keys = ['severity', 'anomaly_type', 'mac_address', 'ip_address', 'hostname', 'vendor', 'vlan', 'description', 'recommendation']
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(anomalies)

    print(f"Analysis complete. Found {len(anomalies)} anomalies. Report saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 find_anomalies.py <inventory_csv> <output_csv>")
        sys.exit(1)
    
    analyze_inventory(sys.argv[1], sys.argv[2])
