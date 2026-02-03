#!/bin/bash
#
# cdp_neighbors.sh - Collect CDP/LLDP neighbor information
# Part of the IoT/Physical Security Assessment Toolkit
#
# Usage: ./cdp_neighbors.sh [output_dir] [input_file]
#
# This helps map network topology - what devices see each other
# Useful for finding undocumented switches, APs, phones, etc.
#
# Workflow:
#   1. SSH into switch/router
#   2. Run: show cdp neighbors detail (Cisco)
#      Or:  show lldp neighbors detail
#   3. Copy output to file
#   4. Run this script
#

set -e

OUTPUT_DIR="${1:-../output/raw}"
INPUT_FILE="${2:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/cdp_neighbors_${TIMESTAMP}.csv"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}=== CDP/LLDP Neighbor Collection ===${NC}"
echo "Output: $OUTPUT_FILE"
echo ""

# CSV header
echo "device_id,ip_address,platform,local_port,remote_port,capabilities,source" > "$OUTPUT_FILE"

parse_cdp_detail() {
    local input="$1"
    
    local device_id=""
    local ip_address=""
    local platform=""
    local local_port=""
    local remote_port=""
    local capabilities=""
    
    while IFS= read -r line; do
        # New device entry
        if echo "$line" | grep -qi "^Device ID:"; then
            # Save previous entry if exists
            if [ -n "$device_id" ]; then
                echo "${device_id},${ip_address},${platform},${local_port},${remote_port},${capabilities},cdp" >> "$OUTPUT_FILE"
                echo "  Found: $device_id ($platform) on $local_port"
            fi
            
            # Reset for new entry
            device_id=$(echo "$line" | sed 's/Device ID: *//' | tr -d '\r')
            ip_address=""
            platform=""
            local_port=""
            remote_port=""
            capabilities=""
        fi
        
        # IP Address (might be multiple, take first)
        if echo "$line" | grep -qi "IP address:" && [ -z "$ip_address" ]; then
            ip_address=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        fi
        
        # Platform
        if echo "$line" | grep -qi "^Platform:"; then
            platform=$(echo "$line" | sed 's/Platform: *//' | cut -d',' -f1 | tr -d '\r')
        fi
        
        # Interface (local and remote)
        if echo "$line" | grep -qi "^Interface:"; then
            # Format: Interface: GigabitEthernet0/1,  Port ID (outgoing port): GigabitEthernet0/2
            local_port=$(echo "$line" | sed 's/Interface: *//' | cut -d',' -f1)
            remote_port=$(echo "$line" | grep -oP 'Port ID.*: *\K.*' | tr -d '\r')
        fi
        
        # Capabilities
        if echo "$line" | grep -qi "^Capabilities:"; then
            capabilities=$(echo "$line" | sed 's/Capabilities: *//' | tr -d '\r')
        fi
        
    done < "$input"
    
    # Don't forget the last entry
    if [ -n "$device_id" ]; then
        echo "${device_id},${ip_address},${platform},${local_port},${remote_port},${capabilities},cdp" >> "$OUTPUT_FILE"
        echo "  Found: $device_id ($platform) on $local_port"
    fi
}

parse_lldp_detail() {
    local input="$1"
    
    local device_id=""
    local ip_address=""
    local platform=""
    local local_port=""
    local remote_port=""
    local capabilities=""
    
    while IFS= read -r line; do
        # Local port indicates new entry
        if echo "$line" | grep -qi "^Local Intf:"; then
            # Save previous entry if exists
            if [ -n "$device_id" ]; then
                echo "${device_id},${ip_address},${platform},${local_port},${remote_port},${capabilities},lldp" >> "$OUTPUT_FILE"
                echo "  Found: $device_id ($platform) on $local_port"
            fi
            
            local_port=$(echo "$line" | sed 's/Local Intf: *//' | tr -d '\r')
            device_id=""
            ip_address=""
            platform=""
            remote_port=""
            capabilities=""
        fi
        
        # Chassis ID or System Name as device ID
        if echo "$line" | grep -qi "^System Name:" || echo "$line" | grep -qi "^Chassis id:"; then
            if [ -z "$device_id" ]; then
                device_id=$(echo "$line" | sed 's/.*: *//' | tr -d '\r')
            fi
        fi
        
        # Management Address
        if echo "$line" | grep -qi "Management Address" && [ -z "$ip_address" ]; then
            # Next line often has the IP, or it's on this line
            ip_address=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        fi
        if echo "$line" | grep -qE '^[[:space:]]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' && [ -z "$ip_address" ]; then
            ip_address=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
        fi
        
        # System Description as platform
        if echo "$line" | grep -qi "^System Description:"; then
            platform=$(echo "$line" | sed 's/System Description: *//' | cut -c1-50 | tr -d '\r')
        fi
        
        # Port ID
        if echo "$line" | grep -qi "^Port id:"; then
            remote_port=$(echo "$line" | sed 's/Port id: *//' | tr -d '\r')
        fi
        
        # Capabilities
        if echo "$line" | grep -qi "^System Capabilities:"; then
            capabilities=$(echo "$line" | sed 's/System Capabilities: *//' | tr -d '\r')
        fi
        
    done < "$input"
    
    # Last entry
    if [ -n "$device_id" ] || [ -n "$local_port" ]; then
        echo "${device_id},${ip_address},${platform},${local_port},${remote_port},${capabilities},lldp" >> "$OUTPUT_FILE"
        echo "  Found: $device_id ($platform) on $local_port"
    fi
}

if [ -z "$INPUT_FILE" ]; then
    echo -e "${YELLOW}No input file specified.${NC}"
    echo ""
    echo "To collect neighbor information:"
    echo ""
    echo "  Cisco CDP:"
    echo "    switch# show cdp neighbors detail"
    echo ""
    echo "  LLDP:"
    echo "    switch# show lldp neighbors detail"
    echo ""
    echo "Copy output to a file and run:"
    echo "  ./cdp_neighbors.sh [output_dir] [filename]"
    echo ""
    echo "Or paste output below (Ctrl+D when done):"
    echo ""
    
    TEMP_INPUT=$(mktemp)
    cat > "$TEMP_INPUT"
    INPUT_FILE="$TEMP_INPUT"
fi

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}Error: File not found: $INPUT_FILE${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Parsing: $INPUT_FILE${NC}"

# Detect format
if grep -qi "Device ID:" "$INPUT_FILE"; then
    echo "  Detected: CDP format"
    parse_cdp_detail "$INPUT_FILE"
elif grep -qi "LLDP" "$INPUT_FILE" || grep -qi "Chassis id:" "$INPUT_FILE"; then
    echo "  Detected: LLDP format"
    parse_lldp_detail "$INPUT_FILE"
else
    echo -e "${YELLOW}  Format unclear, trying CDP parser...${NC}"
    parse_cdp_detail "$INPUT_FILE"
fi

# Cleanup temp
if [ -n "$TEMP_INPUT" ] && [ -f "$TEMP_INPUT" ]; then
    rm -f "$TEMP_INPUT"
fi

# Summary
echo ""
echo -e "${GREEN}=== Collection Complete ===${NC}"
NEIGHBOR_COUNT=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Neighbors found: $NEIGHBOR_COUNT"
echo "Output saved to: $OUTPUT_FILE"
echo ""

if [ "$NEIGHBOR_COUNT" -gt 0 ]; then
    echo "Device types found:"
    tail -n +2 "$OUTPUT_FILE" | cut -d',' -f3 | sort | uniq -c | sort -rn
fi
