# ShieldGate IoT Assessment Toolkit

**Deterministic Network Auditing for Zero-Trust & National Security Environments**

## Overview

ShieldGate is a modular, "boots-on-the-ground" assessment pipeline designed for security operators and automated agents to identify high-risk IoT infrastructure. Unlike probabilistic AI-based scanners, ShieldGate utilizes **deterministic verification** to identify hardware-level dependencies, specifically targeting **Beijing Time (BDT) synchronized heartbeats** and unauthorized foreign PNT (Position, Navigation, and Timing) reliance.

### Key Capabilities

* **PNT Heartbeat Detection**: Identifies autonomous BDS-3 (BeiDou) ephemeris sync cycles (UTC+8 alignment).
* **NDAA Compliance Auditing**: Automatically flags Hikvision, Dahua, and other restricted vendors.
* **VLAN Policy Enforcement**: Detects shadow IT and consumer devices (Nest, Ring, ESP32) on corporate/secure segments.
* **Agent-Ready Design**: Structured CSV outputs designed for ingestion by both human analysts and LLM-based security agents.

---

## Architecture

The toolkit follows a strictly decoupled **Identify-then-Verify** framework to ensure auditability and precision.

1. **Discovery**: Passive and active network enumeration.
2. **Enrichment**: Hardware origin verification via OUI signatures.
3. **Analysis**: Correlating vendor data with temporal patterns (e.g., BDT clock syncs) to find "hidden" dependencies.

---

## Quick Start

ShieldGate is designed for air-gapped or field environments.

### 1. Installation

```bash
git clone https://github.com/marktombaugh/iot-assessment-toolkit.git
cd iot-assessment-toolkit

```

### 2. Run the Full Pipeline

The master launcher automates the scan, enrichment, and anomaly detection.

```bash
sudo python3 shieldgate.py -i eth0 -o engagement_report.csv

```

---

## Licensing & Attribution

This project is dual-licensed to ensure professional accountability:

* **Software/Scripts**: Licensed under the **BSD 3-Clause License**.
* **Research & Methodology**: The "ShieldGate" conceptual framework and BDT-correlation research are licensed under **CC BY-SA 4.0**.

**Mandatory Attribution**: Commercial use or publication of this research requires attribution to **Mark Tombaugh**.

---

## Contact & Careers

I am a Security Researcher based in Raleigh, NC, specializing in IoT integrity and deterministic threat verification. I am currently seeking opportunities in **National Security, CMMC Auditing, or Critical Infrastructure Defense.**
