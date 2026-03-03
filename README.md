# IoT & Network Security Assessment Toolkit

A portable, open-source toolkit for on-site network discovery, security assessment, and **deterministic infrastructure verification.**

**Designed for transparency** — clients can review exactly what runs on their network before engagement.

**Designed for air-gapped operation** — no cloud dependencies, no data exfiltration, everything stays on-site.

**Designed for Zero Trust** — moves beyond probabilistic "AI" assessments to deterministic, packet-level evidence.

## What This Does

1. **Discovers every device on the network** via ARP scanning, switch MAC tables, and DHCP leases.
2. **Identifies vendors** using IEEE OUI database lookups.
3. **Flags concerning devices** — Chinese surveillance equipment, consumer IoT on corporate networks, unknown manufacturers.
4. **Detects PNT/Navigation Backdoors** — identifies devices performing autonomous "pre-lookups" or "heartbeats" to foreign satellite assistance (BDS/BeiDou-3) infrastructure.
5. **Flags policy violations** — devices on wrong VLANs, missing hostnames, configuration issues.
6. **Produces actionable reports** — CSV output ready for Excel, remediation recommendations included.

## Feature Spotlight: Deterministic PNT Verification

In a modern threat environment, observing device *presence* is not enough; one must observe *intent*. This toolkit includes specific signatures to detect devices communicating with "The Architect's" infrastructure.

### The Clock-Sync Heartbeat

Foreign-manufactured IoT modules (HiSilicon, MediaTek, Quectel) often utilize **Assisted GNSS (A-GNSS)** to maintain precision. These lookups are strictly cyclic, occurring every 2–4 hours and synchronized to **Beijing Date Time (BDT)**.

* **Detection Strategy**: The toolkit identifies outbound bursts to known CDN assistance nodes that correlate with the BDT hour-start, providing a "Signature of Intent" for foreign PNT reliance.

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
│   ├── find_anomalies.py # Detect policy violations
│   └── pnt_audit.py      # NEW: Correlate NetFlow with BDT clock-sync
├── signatures/           # Network IDS Rules (Suricata/Snort)
│   ├── beidou-lookups.txt# Signatures for SUPL/LPP/BDS-3
│   └── ip_reputation.lst # CIDR blocks for foreign assistance infrastructure
├── reference/            # Static reference data
│   └── oui.csv           # IEEE OUI database
├── sample-data/          # Example engagement data
└── output/               # Your engagement data (gitignored)

```

## Usage: PNT & Infrastructure Detection

To audit a network for "Cognitive Backdoors" (directional infrastructure reliance), deploy the signatures found in `signatures/beidou-lookups.txt`.

### Key Signatures Included:

* **SUPL/LPP Initiation (Port 7275)**: Detects the `msSUPLSTART` message used by cellular-connected IoT to fetch orbital data.
* **Infrastructure Reputation**: Flags traffic to identified CIDR blocks for regional egress points in Singapore, Hong Kong, and Shenzhen (e.g., `114.119.128.0/19`).
* **TLS Fingerprinting (JA4)**: Identifies the unique handshake permutations of Chinese-manufactured GNSS client libraries.

## Flagged Vendors

The toolkit automatically flags devices from manufacturers that warrant extra scrutiny:

| Vendor | Primary Concern | Secondary Concern |
| --- | --- | --- |
| **Hikvision / Dahua** | Surveillance | NDAA Banned |
| **Huawei / ZTE** | Infrastructure | Telecommunications Backdoors |
| **TP-Link** | Consumer Networking | Firmware Vulnerabilities |
| **Quectel / SIMCom** | M2M Modules | Autonomous BDS-3 "Heartbeats" |
| **Espressif** | IoT / ESP32 | Shadow IT / Hidden PNT Lookups |

## Operational Security & Verification

1. **Verify the Deterministic**: Do not rely on AI assistants for threat assessment; cross-reference AI findings with the raw packet captures flagged by this toolkit.
2. **Clock Correlation**: If an alert fires, check if the timestamp matches the top of the hour in Beijing. This confirms a PNT sync.
3. **Regional Egress**: Monitor traffic for the "directional" drift described in the `ip_reputation.lst`.

## CMMC / DIB Relevance

For defense contractors and manufacturers, this toolkit provides the evidence required for **Zero Trust** compliance:

* Identifying unauthorized devices on CUI segments.
* Documenting foreign-manufactured equipment violating DFARS/NDAA.
* **Auditing "Human-in-the-Loop" accuracy** by providing the ground-truth data needed to verify AI threat assessments.

## Licensing & Attribution

This project is a dual-licensed research initiative intended to foster "Zero Trust" transparency in maritime and IoT security.

* **Software/Scripts**: Licensed under the **BSD 3-Clause License**.
* **Research & Documentation**: Licensed under **Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)**.

### Professional Commendation Requirement
If this toolkit or the associated "ShieldGate" conceptual framework is used for commercial security assessments, government inquiries, or published research, **attribution to Mark Tombaugh is legally required** under the terms of the CC BY-SA 4.0 license. 

For inquiries regarding commercial implementation or to discuss career opportunities in National Security/IoT Defense, please contact me directly via GitHub or LinkedIn.

## Author

Mark Tombaugh | IoT & Physical Security Assessment
Raleigh, NC

---

*"The human in the loop is the last auditable layer. Preserve it. Verify everything. Trust the deterministic."*
