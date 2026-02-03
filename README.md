# IoT & Network Security Assessment Toolkit

A portable, open-source toolkit for on-site network discovery and security assessment.

**Designed for transparency** — clients can review exactly what runs on their network before engagement.

**Designed for air-gapped operation** — no cloud dependencies, no data exfiltration, everything stays on-site.

## What This Does

1. **Discovers every device on the network** via ARP scanning, switch MAC tables, and DHCP leases
2. **Identifies vendors** using IEEE OUI database lookups
3. **Flags concerning devices** — Chinese surveillance equipment, consumer IoT on corporate networks, unknown manufacturers
4. **Detects policy violations** — devices on wrong VLANs, missing hostnames, configuration issues
5. **Produces actionable reports** — CSV output ready for Excel, remediation recommendations included

## Quick Start

```bash
# 1. Clone and enter the repo
git clone https://github.com/marktombaugh/iot-assessment-toolkit.git
cd iot-assessment-toolkit

# 2. Download OUI database (do this before going on-site)
python3 analyzers/oui_lookup.py --update-db

# 3. Create engagement directory
mkdir -p output/clientname-$(date +%Y-%m-%d)/raw

# 4. Run discovery (from a host on their network)
./collectors/arp_scan.sh eth0 output/clientname-$(date +%Y-%m-%d)/raw

# 5. If you have switch access, collect more data
./collectors/mac_table.sh file output/clientname-$(date +%Y-%m-%d)/raw switch_output.txt
./collectors/dhcp_leases.sh file output/clientname-$(date +%Y-%m-%d)/raw dhcp_dump.txt

# 6. Enrich, correlate, analyze
python3 analyzers/oui_lookup.py output/clientname-*/raw/arp_scan_*.csv output/clientname-*/raw/arp_enriched.csv
python3 analyzers/correlate.py output/clientname-*/raw output/clientname-*/inventory.csv
python3 analyzers/find_anomalies.py output/clientname-*/inventory.csv output/clientname-*/anomalies.csv
```

## Sample Output

The `sample-data/` directory contains a simulated small manufacturing network with intentional security issues:

- 4 Hikvision cameras on the corporate VLAN (should be isolated)
- Consumer IoT (Ring doorbell, Nest thermostat) on production network
- Espressif/Raspberry Pi devices (shadow IT)
- Unknown OUI devices
- Missing hostnames

Run the pipeline against sample data to see what the output looks like:

```bash
python3 analyzers/oui_lookup.py sample-data/raw/arp_scan_20260202_100000.csv sample-data/raw/arp_enriched.csv
python3 analyzers/correlate.py sample-data/raw sample-data/inventory.csv
python3 analyzers/find_anomalies.py sample-data/inventory.csv sample-data/anomalies.csv
```

## Directory Structure

```
iot-assessment-toolkit/
├── collectors/           # Data gathering scripts (bash)
│   ├── arp_scan.sh       # Network discovery via ARP
│   ├── dhcp_leases.sh    # Parse DHCP lease data
│   ├── mac_table.sh      # Parse switch MAC tables
│   └── cdp_neighbors.sh  # Parse CDP/LLDP neighbor data
├── analyzers/            # Data processing scripts (Python)
│   ├── oui_lookup.py     # MAC to vendor lookup + flagging
│   ├── correlate.py      # Merge all data sources
│   └── find_anomalies.py # Detect policy violations
├── reference/            # Static reference data
│   └── oui.csv           # IEEE OUI database
├── sample-data/          # Example engagement data
│   ├── raw/              # Raw collector output
│   ├── inventory.csv     # Correlated device inventory
│   └── anomalies.csv     # Flagged findings
└── output/               # Your engagement data (gitignored)
```

## Flagged Vendors

The toolkit automatically flags devices from manufacturers that warrant extra scrutiny:

| Vendor | Reason |
|--------|--------|
| Hikvision | Chinese surveillance equipment — NDAA banned |
| Dahua | Chinese surveillance equipment — NDAA banned |
| Huawei | Chinese telecommunications — security concerns |
| ZTE | Chinese telecommunications — security concerns |
| TP-Link | Chinese networking equipment |
| Espressif | ESP32/ESP8266 IoT modules — often shadow IT |
| Raspberry Pi | Could be legitimate or unauthorized |
| Ring/Nest/Sonos | Consumer IoT — shouldn't be on corporate networks |

Edit `analyzers/oui_lookup.py` to customize the flag list for your engagements.

## VLAN Policy Checking

Edit `analyzers/find_anomalies.py` to match each client's VLAN scheme:

```python
VLAN_POLICY = {
    '1': ('default', ['any']),        # Nothing should be here
    '10': ('management', ['switch', 'router', 'firewall']),
    '50': ('corporate', ['workstation', 'laptop', 'printer']),
    '100': ('iot', ['camera', 'sensor', 'badge', 'hvac']),
}
```

The analyzer will flag any device that appears on a VLAN inappropriate for its type.

## Requirements

- Bash (Linux/macOS)
- Python 3.6+
- Standard tools: ping, arp, grep, awk
- Optional: arp-scan (better discovery)

No external Python dependencies — runs on any system with a standard Python install.

## Operational Security

1. **Update OUI database before going on-site** — you won't have internet there
2. **All data stays local** — nothing phones home, no cloud, no telemetry
3. **Delete raw data before leaving** — only take inventory.csv and anomalies.csv
4. **Document access limitations** — note what you couldn't collect in your report
5. **Get written authorization** — never run on a network without explicit permission

## CMMC / DIB Relevance

For defense contractors and manufacturers pursuing CMMC certification, this toolkit helps identify:

- Unauthorized devices on CUI-handling network segments
- Foreign-manufactured equipment that may violate DFARS/NDAA requirements
- Shadow IT and policy violations
- Network segmentation gaps

## License

MIT License — use it, modify it, sell services with it. Attribution appreciated but not required.

## Author

Bath McCollough | IoT & Physical Security Assessment
Raleigh, NC

---

*"Trust but verify" — except with network security, skip the trust part.*
