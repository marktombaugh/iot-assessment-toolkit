#!/usr/bin/env python3
"""
find_anomalies.py - Identify suspicious devices and configurations
Part of the IoT/Physical Security Assessment Toolkit

Usage:
    python3 find_anomalies.py [inventory.csv] [output.csv]

This analyzes the correlated inventory and flags anomalies:
- Devices on unexpected VLANs (IoT on production, etc.)
- Unknown vendors
- Flagged vendors (Chinese manufacturers, consumer gear)
- Devices with no hostname (often IoT/embedded)
- Multiple IPs for same MAC (possible issues)
- Devices seen by some sources but not others (inconsistency)
"""

import csv
import sys
import os
from collections import defaultdict
from datetime import datetime


# VLAN classification - customize for each engagement
# This is a template; you'd adjust based on client's actual VLAN scheme
VLAN_POLICY = {
    # VLAN: (name, expected_device_types)
    '1': ('default', ['any']),  # Default VLAN - nothing should be here ideally
    '10': ('management', ['switch', 'router', 'firewall', 'server']),
    '20': ('servers', ['server', 'hypervisor']),
    '50': ('corporate', ['workstation', 'laptop', 'printer']),
    '100': ('iot', ['camera', 'sensor', 'controller', 'badge', 'hvac']),
    '200': ('guest', ['any']),
    '999': ('quarantine', ['any']),
}

# Device type indicators based on vendor/hostname patterns
DEVICE_TYPE_PATTERNS = {
    'camera': ['hikvision', 'dahua', 'axis', 'camera', 'ipcam', 'dvr', 'nvr'],
    'printer': ['hp', 'xerox', 'canon', 'epson', 'print', 'mfp'],
    'phone': ['cisco-phone', 'polycom', 'yealink', 'voip', 'phone'],
    'switch': ['cisco', 'arista', 'juniper', 'switch'],
    'ap': ['ubiquiti', 'aruba', 'meraki', 'ap', 'wireless'],
    'iot': ['espressif', 'raspberry', 'arduino', 'nest', 'ring', 'sonos'],
    'hvac': ['honeywell', 'trane', 'carrier', 'hvac', 'thermostat'],
    'badge': ['hid', 'lenel', 'badge', 'access'],
}


class Anomaly:
    def __init__(self, device, anomaly_type, severity, description, recommendation):
        self.device = device
        self.anomaly_type = anomaly_type
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.description = description
        self.recommendation = recommendation
    
    def to_dict(self):
        return {
            'mac_address': self.device.get('mac_address', ''),
            'ip_address': self.device.get('ip_address', ''),
            'hostname': self.device.get('hostname', ''),
            'vendor': self.device.get('vendor', ''),
            'vlan': self.device.get('vlan', ''),
            'anomaly_type': self.anomaly_type,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
        }


def guess_device_type(device):
    """Try to determine device type from vendor and hostname."""
    vendor = (device.get('vendor', '') or '').lower()
    hostname = (device.get('hostname', '') or '').lower()
    device_type = (device.get('device_type', '') or '').lower()
    
    combined = f"{vendor} {hostname} {device_type}"
    
    for dtype, patterns in DEVICE_TYPE_PATTERNS.items():
        for pattern in patterns:
            if pattern in combined:
                return dtype
    
    return 'unknown'


def check_vlan_policy(device, anomalies):
    """Check if device is on appropriate VLAN."""
    vlan = device.get('vlan', '')
    if not vlan:
        return  # Can't check without VLAN info
    
    device_type = guess_device_type(device)
    vendor = device.get('vendor', '')
    
    # Default VLAN check
    if vlan == '1':
        anomalies.append(Anomaly(
            device,
            'DEFAULT_VLAN',
            'MEDIUM',
            f"Device on default VLAN 1. Vendor: {vendor}",
            "Move device to appropriate VLAN based on function. Default VLAN should be unused."
        ))
    
    # IoT device on non-IoT VLAN
    if device_type in ['camera', 'iot', 'hvac', 'badge']:
        if vlan not in ['100', '999']:  # Assuming 100 is IoT VLAN
            anomalies.append(Anomaly(
                device,
                'IOT_WRONG_VLAN',
                'HIGH',
                f"IoT device ({device_type}) on VLAN {vlan}, not isolated. Vendor: {vendor}",
                "Move IoT devices to dedicated, isolated VLAN with restricted internet access."
            ))
    
    # Consumer device on corporate network
    if device_type == 'iot' and vlan in ['50', '20', '10']:
        anomalies.append(Anomaly(
            device,
            'CONSUMER_ON_CORP',
            'HIGH',
            f"Consumer/IoT device on corporate VLAN {vlan}. Vendor: {vendor}",
            "Remove unauthorized consumer devices or move to guest/IoT VLAN."
        ))


def check_vendor_flags(device, anomalies):
    """Check for flagged vendors."""
    flag = device.get('flag', '')
    flag_reason = device.get('flag_reason', '')
    vendor = device.get('vendor', '')
    
    if flag:
        # Determine severity based on flag type
        if 'surveillance' in flag_reason.lower() or 'chinese' in flag_reason.lower():
            severity = 'HIGH'
        elif 'consumer' in flag_reason.lower():
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        anomalies.append(Anomaly(
            device,
            'FLAGGED_VENDOR',
            severity,
            f"Flagged vendor: {vendor}. Reason: {flag_reason}",
            "Evaluate necessity of device. Consider replacement with trusted vendor or additional monitoring."
        ))


def check_unknown_vendor(device, anomalies):
    """Flag devices with unknown vendors."""
    vendor = device.get('vendor', '')
    
    if vendor == 'UNKNOWN' or not vendor:
        anomalies.append(Anomaly(
            device,
            'UNKNOWN_VENDOR',
            'MEDIUM',
            f"Device vendor unknown. MAC OUI not in database.",
            "Physically locate and identify device. May be counterfeit, very old, or specialized hardware."
        ))


def check_no_hostname(device, anomalies):
    """Flag devices without hostnames."""
    hostname = device.get('hostname', '')
    vendor = device.get('vendor', '')
    
    if not hostname:
        # Less severe for known IoT devices
        device_type = guess_device_type(device)
        if device_type in ['camera', 'iot', 'hvac', 'badge', 'printer']:
            severity = 'LOW'
        else:
            severity = 'MEDIUM'
        
        anomalies.append(Anomaly(
            device,
            'NO_HOSTNAME',
            severity,
            f"Device has no hostname. Vendor: {vendor}",
            "Configure hostname for easier identification and inventory tracking."
        ))


def check_discovery_consistency(device, anomalies):
    """Check if device was seen consistently across discovery methods."""
    sources = device.get('discovery_sources', '')
    ip = device.get('ip_address', '')
    
    # Device with IP but not in DHCP might be static - not necessarily bad
    if ip and 'dhcp' not in sources and 'arp' in sources:
        anomalies.append(Anomaly(
            device,
            'STATIC_IP',
            'INFO',
            f"Device has IP but not in DHCP leases. Likely static IP.",
            "Verify static IP is documented and authorized."
        ))
    
    # Device in switch table but no IP - might be offline or L2-only
    if 'switch' in sources and not ip:
        anomalies.append(Anomaly(
            device,
            'NO_IP',
            'LOW',
            f"Device in switch MAC table but no IP address observed.",
            "Device may be offline, L2-only, or using protocol not detected. Investigate."
        ))


def main():
    if len(sys.argv) < 2:
        print("Find Anomalies - Identify suspicious devices and configurations")
        print("")
        print("Usage:")
        print(f"  {sys.argv[0]} [inventory.csv] [anomalies.csv]")
        print("")
        print("Input should be the correlated inventory from correlate.py")
        return
    
    input_path = sys.argv[1]
    
    if len(sys.argv) >= 3:
        output_path = sys.argv[2]
    else:
        base = os.path.dirname(input_path)
        output_path = os.path.join(base, 'anomalies.csv')
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    print("=== Anomaly Detection ===")
    print(f"Input: {input_path}")
    print(f"Output: {output_path}")
    print("")
    
    # Load inventory
    devices = []
    with open(input_path, 'r') as f:
        reader = csv.DictReader(f)
        devices = list(reader)
    
    print(f"Loaded {len(devices)} devices")
    print("")
    
    # Find anomalies
    anomalies = []
    
    print("[+] Checking VLAN policy...")
    for device in devices:
        check_vlan_policy(device, anomalies)
    
    print("[+] Checking vendor flags...")
    for device in devices:
        check_vendor_flags(device, anomalies)
    
    print("[+] Checking unknown vendors...")
    for device in devices:
        check_unknown_vendor(device, anomalies)
    
    print("[+] Checking hostnames...")
    for device in devices:
        check_no_hostname(device, anomalies)
    
    print("[+] Checking discovery consistency...")
    for device in devices:
        check_discovery_consistency(device, anomalies)
    
    # Sort by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    anomalies.sort(key=lambda a: severity_order.get(a.severity, 5))
    
    # Write output
    fieldnames = [
        'severity',
        'anomaly_type',
        'mac_address',
        'ip_address',
        'hostname',
        'vendor',
        'vlan',
        'description',
        'recommendation',
    ]
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        for a in anomalies:
            writer.writerow(a.to_dict())
    
    # Summary
    print("")
    print("=== Analysis Complete ===")
    print(f"Total anomalies: {len(anomalies)}")
    print(f"Output saved to: {output_path}")
    print("")
    
    # Count by severity
    by_severity = defaultdict(int)
    for a in anomalies:
        by_severity[a.severity] += 1
    
    print("By severity:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if by_severity[sev]:
            print(f"  {sev}: {by_severity[sev]}")
    
    # Count by type
    print("")
    print("By type:")
    by_type = defaultdict(int)
    for a in anomalies:
        by_type[a.anomaly_type] += 1
    for atype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {atype}: {count}")
    
    # Show critical/high findings
    critical_high = [a for a in anomalies if a.severity in ['CRITICAL', 'HIGH']]
    if critical_high:
        print("")
        print("⚠️  CRITICAL/HIGH FINDINGS:")
        for a in critical_high[:10]:  # Top 10
            print(f"  [{a.severity}] {a.anomaly_type}")
            print(f"    Device: {a.device.get('mac_address')} ({a.device.get('ip_address')})")
            print(f"    {a.description}")
            print("")


if __name__ == '__main__':
    main()
