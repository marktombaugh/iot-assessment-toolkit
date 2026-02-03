#!/bin/bash
#
# arp_scan.sh - Network discovery via ARP
# Part of the IoT/Physical Security Assessment Toolkit
#
# Usage: ./arp_scan.sh [interface] [output_dir]
# Example: ./arp_scan.sh eth0 ../output/clientname-2026-01-27/raw
#
# Requirements: arping, arp-scan (optional), or falls back to ping + arp
#
# Note: Run with appropriate permissions. Some methods require root.
#

set -e

# Defaults
INTERFACE="${1:-eth0}"
OUTPUT_DIR="${2:-../output/raw}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/arp_scan_${TIMESTAMP}.csv"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}=== ARP Network Discovery ===${NC}"
echo "Interface: $INTERFACE"
echo "Output: $OUTPUT_FILE"
echo ""

# Get our IP and subnet
OUR_IP=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
SUBNET=$(ip -4 addr show "$INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}/\d+')

if [ -z "$OUR_IP" ]; then
    echo -e "${RED}Error: Could not determine IP address for $INTERFACE${NC}"
    exit 1
fi

echo "Our IP: $OUR_IP"
echo "Subnet: $SUBNET"
echo ""

# CSV header
echo "mac_address,ip_address,hostname,discovery_method,timestamp" > "$OUTPUT_FILE"

# Function to add entry to CSV
add_entry() {
    local mac="$1"
    local ip="$2"
    local hostname="$3"
    local method="$4"
    
    # Normalize MAC to lowercase with colons
    mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]' | sed 's/-/:/g')
    
    # Skip if MAC is empty or incomplete
    if [ -z "$mac" ] || [ "$mac" == "(incomplete)" ]; then
        return
    fi
    
    echo "${mac},${ip},${hostname},${method},${TIMESTAMP}" >> "$OUTPUT_FILE"
}

# Method 1: arp-scan (most reliable if available)
if command -v arp-scan &> /dev/null; then
    echo -e "${GREEN}[+] Running arp-scan...${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}    Warning: arp-scan works best as root. Trying anyway...${NC}"
    fi
    
    # Run arp-scan and parse output
    arp-scan --interface="$INTERFACE" --localnet 2>/dev/null | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
    while read -r ip mac vendor; do
        add_entry "$mac" "$ip" "" "arp-scan"
        echo "    Found: $ip -> $mac"
    done
    
    echo ""
fi

# Method 2: Ping sweep + ARP table (works without special tools)
echo -e "${GREEN}[+] Running ping sweep to populate ARP cache...${NC}"

# Extract base network for ping sweep
NETWORK_BASE=$(echo "$OUR_IP" | cut -d. -f1-3)

# Ping sweep (background, fast)
echo "    Sweeping ${NETWORK_BASE}.0/24..."
for i in $(seq 1 254); do
    ping -c 1 -W 1 "${NETWORK_BASE}.$i" &>/dev/null &
    
    # Limit concurrent pings
    if [ $((i % 50)) -eq 0 ]; then
        wait
        echo "    Progress: $i/254"
    fi
done
wait

echo ""
echo -e "${GREEN}[+] Reading ARP table...${NC}"

# Parse ARP table
arp -an | grep -v "incomplete" | while read -r line; do
    # Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
    ip=$(echo "$line" | grep -oP '\(\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=\))')
    mac=$(echo "$line" | grep -oP '(?<=at\s)[0-9a-fA-F:]{17}')
    
    if [ -n "$ip" ] && [ -n "$mac" ]; then
        add_entry "$mac" "$ip" "" "arp-table"
        echo "    Found: $ip -> $mac"
    fi
done

# Method 3: Try to resolve hostnames via reverse DNS
echo ""
echo -e "${GREEN}[+] Attempting reverse DNS lookups...${NC}"

# Create temp file with unique IPs
TEMP_FILE=$(mktemp)
cut -d',' -f2 "$OUTPUT_FILE" | tail -n +2 | sort -u > "$TEMP_FILE"

# New output with hostnames
TEMP_OUTPUT=$(mktemp)
head -1 "$OUTPUT_FILE" > "$TEMP_OUTPUT"

while IFS=',' read -r mac ip hostname method ts; do
    # Skip header
    if [ "$mac" == "mac_address" ]; then
        continue
    fi
    
    # Try reverse DNS
    if [ -z "$hostname" ]; then
        hostname=$(host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | sed 's/\.$//')
        if [ -n "$hostname" ]; then
            echo "    Resolved: $ip -> $hostname"
        fi
    fi
    
    echo "${mac},${ip},${hostname},${method},${ts}" >> "$TEMP_OUTPUT"
done < "$OUTPUT_FILE"

mv "$TEMP_OUTPUT" "$OUTPUT_FILE"
rm -f "$TEMP_FILE"

# Summary
echo ""
echo -e "${GREEN}=== Discovery Complete ===${NC}"
DEVICE_COUNT=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Devices found: $DEVICE_COUNT"
echo "Output saved to: $OUTPUT_FILE"
echo ""

# Deduplicate (same MAC might be found by multiple methods)
echo -e "${GREEN}[+] Deduplicating results...${NC}"
TEMP_DEDUP=$(mktemp)
head -1 "$OUTPUT_FILE" > "$TEMP_DEDUP"
tail -n +2 "$OUTPUT_FILE" | sort -t',' -k1,1 -u >> "$TEMP_DEDUP"
mv "$TEMP_DEDUP" "$OUTPUT_FILE"

UNIQUE_COUNT=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Unique devices: $UNIQUE_COUNT"
echo ""
echo "Next step: Run oui_lookup.py to identify vendors"
