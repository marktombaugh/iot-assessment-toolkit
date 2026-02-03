#!/usr/bin/env python3
"""
correlate.py - Combine collected data into unified device inventory
Part of the IoT/Physical Security Assessment Toolkit

Usage:
    python3 correlate.py [raw_data_dir] [output_file]

This script takes the output from all collectors and builds a single
device inventory by correlating on MAC address.

A device might appear in:
- ARP scan (MAC + IP)
- DHCP leases (MAC + IP + hostname)
- MAC table (MAC + VLAN + port)
- CDP/LLDP (device ID + IP + platform + port)

This script merges all that into one row per device.
"""

import csv
import os
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def find_files(directory, pattern):
    """Find all files matching a pattern in directory."""
    p = Path(directory)
    return list(p.glob(pattern))


def normalize_mac(mac):
    """Normalize MAC to lowercase with colons."""
    if not mac:
        return None
    import re
    mac_clean = re.sub(r'[.:\-]', '', mac.lower())
    if len(mac_clean) >= 12:
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    elif len(mac_clean) >= 6:
        return ':'.join(mac_clean[i:i+2] for i in range(0, 6, 2))
    return None


def load_csv_files(files, key_field, fields_to_extract):
    """Load data from multiple CSV files, keyed by a field."""
    data = defaultdict(dict)
    
    for f in files:
        try:
            with open(f, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    key = row.get(key_field, '')
                    key = normalize_mac(key) if key_field == 'mac_address' else key
                    
                    if not key:
                        continue
                    
                    for field in fields_to_extract:
                        if field in row and row[field]:
                            # Don't overwrite with empty values
                            if field not in data[key] or not data[key][field]:
                                data[key][field] = row[field]
        except Exception as e:
            print(f"  Warning: Error reading {f}: {e}")
    
    return data


def main():
    if len(sys.argv) < 2:
        print("Correlate - Combine collected data into unified inventory")
        print("")
        print("Usage:")
        print(f"  {sys.argv[0]} [raw_data_dir] [output_file]")
        print("")
        print("Example:")
        print(f"  {sys.argv[0]} ../output/client-2026-01-27/raw ../output/client-2026-01-27/inventory.csv")
        return
    
    raw_dir = sys.argv[1]
    
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        output_path = os.path.join(os.path.dirname(raw_dir), 'inventory.csv')
    
    if not os.path.isdir(raw_dir):
        print(f"Error: Directory not found: {raw_dir}")
        sys.exit(1)
    
    print("=== Data Correlation ===")
    print(f"Raw data directory: {raw_dir}")
    print(f"Output: {output_path}")
    print("")
    
    # Device inventory keyed by MAC
    devices = defaultdict(lambda: {
        'mac_address': '',
        'ip_address': '',
        'hostname': '',
        'vlan': '',
        'switch_port': '',
        'device_type': '',
        'vendor': '',
        'oui': '',
        'flag': '',
        'flag_reason': '',
        'discovery_sources': [],
    })
    
    # Load ARP scan data
    print("[+] Loading ARP scan data...")
    arp_files = find_files(raw_dir, 'arp_scan_*.csv')
    print(f"    Found {len(arp_files)} file(s)")
    
    for f in arp_files:
        with open(f, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                mac = normalize_mac(row.get('mac_address', ''))
                if mac:
                    devices[mac]['mac_address'] = mac
                    if row.get('ip_address'):
                        devices[mac]['ip_address'] = row['ip_address']
                    if row.get('hostname'):
                        devices[mac]['hostname'] = row['hostname']
                    if 'arp' not in devices[mac]['discovery_sources']:
                        devices[mac]['discovery_sources'].append('arp')
    
    # Load DHCP lease data
    print("[+] Loading DHCP lease data...")
    dhcp_files = find_files(raw_dir, 'dhcp_leases_*.csv')
    print(f"    Found {len(dhcp_files)} file(s)")
    
    for f in dhcp_files:
        with open(f, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                mac = normalize_mac(row.get('mac_address', ''))
                if mac:
                    devices[mac]['mac_address'] = mac
                    if row.get('ip_address'):
                        devices[mac]['ip_address'] = row['ip_address']
                    if row.get('hostname'):
                        devices[mac]['hostname'] = row['hostname']
                    if 'dhcp' not in devices[mac]['discovery_sources']:
                        devices[mac]['discovery_sources'].append('dhcp')
    
    # Load MAC table data
    print("[+] Loading MAC table data...")
    mac_files = find_files(raw_dir, 'mac_table_*.csv')
    print(f"    Found {len(mac_files)} file(s)")
    
    for f in mac_files:
        with open(f, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                mac = normalize_mac(row.get('mac_address', ''))
                if mac:
                    devices[mac]['mac_address'] = mac
                    if row.get('vlan'):
                        devices[mac]['vlan'] = row['vlan']
                    if row.get('port'):
                        devices[mac]['switch_port'] = row['port']
                    if 'switch' not in devices[mac]['discovery_sources']:
                        devices[mac]['discovery_sources'].append('switch')
    
    # Load CDP/LLDP neighbor data (these are typically infrastructure devices)
    print("[+] Loading CDP/LLDP neighbor data...")
    cdp_files = find_files(raw_dir, 'cdp_neighbors_*.csv')
    print(f"    Found {len(cdp_files)} file(s)")
    
    # CDP data is keyed by device_id, not MAC - we'll add as separate entries
    for f in cdp_files:
        with open(f, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Use IP as key if available, otherwise device_id
                ip = row.get('ip_address', '')
                device_id = row.get('device_id', '')
                
                if ip:
                    # Try to find existing entry by IP
                    found_mac = None
                    for mac, dev in devices.items():
                        if dev.get('ip_address') == ip:
                            found_mac = mac
                            break
                    
                    if found_mac:
                        if row.get('platform'):
                            devices[found_mac]['device_type'] = row['platform']
                        if row.get('local_port'):
                            devices[found_mac]['switch_port'] = row['local_port']
                        if 'cdp' not in devices[found_mac]['discovery_sources']:
                            devices[found_mac]['discovery_sources'].append('cdp')
    
    # Load any enriched data (from OUI lookup)
    print("[+] Loading enriched data...")
    enriched_files = find_files(raw_dir, '*_enriched.csv')
    print(f"    Found {len(enriched_files)} file(s)")
    
    for f in enriched_files:
        with open(f, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                mac = normalize_mac(row.get('mac_address', ''))
                if mac and mac in devices:
                    if row.get('vendor'):
                        devices[mac]['vendor'] = row['vendor']
                    if row.get('oui'):
                        devices[mac]['oui'] = row['oui']
                    if row.get('flag'):
                        devices[mac]['flag'] = row['flag']
                    if row.get('flag_reason'):
                        devices[mac]['flag_reason'] = row['flag_reason']
    
    # Convert to list and sort
    print("")
    print("[+] Building inventory...")
    
    inventory = []
    for mac, data in devices.items():
        data['discovery_sources'] = ','.join(data['discovery_sources'])
        inventory.append(data)
    
    # Sort by VLAN, then IP
    def sort_key(d):
        vlan = d.get('vlan', '9999')
        try:
            vlan = int(vlan)
        except:
            vlan = 9999
        
        ip = d.get('ip_address', '255.255.255.255')
        ip_parts = ip.split('.')
        try:
            ip_num = sum(int(p) * (256 ** (3-i)) for i, p in enumerate(ip_parts))
        except:
            ip_num = 0
        
        return (vlan, ip_num)
    
    inventory.sort(key=sort_key)
    
    # Write output
    fieldnames = [
        'mac_address',
        'ip_address', 
        'hostname',
        'vendor',
        'vlan',
        'switch_port',
        'device_type',
        'flag',
        'flag_reason',
        'discovery_sources',
        'oui',
    ]
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(inventory)
    
    # Summary
    print("")
    print("=== Correlation Complete ===")
    print(f"Total devices: {len(inventory)}")
    print(f"Output saved to: {output_path}")
    
    # Stats
    flagged = sum(1 for d in inventory if d.get('flag'))
    unknown_vendor = sum(1 for d in inventory if d.get('vendor') == 'UNKNOWN')
    no_hostname = sum(1 for d in inventory if not d.get('hostname'))
    
    print("")
    print("Summary:")
    print(f"  Flagged devices: {flagged}")
    print(f"  Unknown vendors: {unknown_vendor}")
    print(f"  No hostname: {no_hostname}")
    
    if flagged > 0:
        print("")
        print("⚠️  FLAGGED DEVICES:")
        for d in inventory:
            if d.get('flag'):
                print(f"  {d['mac_address']} ({d['ip_address']}) - {d['vendor']} - {d['flag_reason']}")


if __name__ == '__main__':
    main()
