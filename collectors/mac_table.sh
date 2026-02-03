#!/bin/bash
#
# mac_table.sh - Collect MAC address table from switches
# Part of the IoT/Physical Security Assessment Toolkit
#
# Usage: ./mac_table.sh [source_type] [output_dir] [input_file]
#
# Source types:
#   cisco-ios   - Parse 'show mac address-table' from Cisco IOS
#   cisco-nxos  - Parse from Cisco Nexus
#   file        - Parse from a file you've already captured
#
# Workflow:
#   1. SSH into switch, run 'show mac address-table' (IOS) or 'show mac address-table dynamic' (NX-OS)
#   2. Copy output to a text file
#   3. Run this script against that file
#
# Example: ./mac_table.sh file ../output/raw switch_output.txt
#

set -e

SOURCE_TYPE="${1:-file}"
OUTPUT_DIR="${2:-../output/raw}"
INPUT_FILE="${3:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/mac_table_${TIMESTAMP}.csv"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}=== MAC Address Table Collection ===${NC}"
echo "Source type: $SOURCE_TYPE"
echo "Output: $OUTPUT_FILE"
echo ""

# CSV header
echo "mac_address,vlan,port,type,source" > "$OUTPUT_FILE"

# Function to normalize MAC and add entry
add_entry() {
    local mac="$1"
    local vlan="$2"
    local port="$3"
    local type="$4"
    
    # Normalize MAC to lowercase with colons
    # Handle Cisco format: 0011.2233.4455
    if echo "$mac" | grep -qE '^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$'; then
        mac=$(echo "$mac" | sed 's/\.//g' | sed 's/\(..\)/\1:/g' | sed 's/:$//' | tr '[:upper:]' '[:lower:]')
    else
        mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]' | sed 's/-/:/g')
    fi
    
    if [ -z "$mac" ] || [ ${#mac} -lt 11 ]; then
        return
    fi
    
    echo "${mac},${vlan},${port},${type},${SOURCE_TYPE}" >> "$OUTPUT_FILE"
}

parse_cisco_ios() {
    local input="$1"
    
    # Cisco IOS format:
    # Vlan    Mac Address       Type        Ports
    # ----    -----------       --------    -----
    #    1    0011.2233.4455    DYNAMIC     Gi0/1
    #  100    aabb.ccdd.eeff    STATIC      Gi0/24
    
    while read -r line; do
        # Skip headers, separators, empty lines
        if echo "$line" | grep -qiE '^vlan|^-|^$|Total Mac|Multicast'; then
            continue
        fi
        
        # Parse the line - handle variable whitespace
        vlan=$(echo "$line" | awk '{print $1}')
        mac=$(echo "$line" | awk '{print $2}')
        type=$(echo "$line" | awk '{print $3}')
        port=$(echo "$line" | awk '{print $4}')
        
        # Validate we got something useful
        if echo "$vlan" | grep -qE '^[0-9]+$' && [ -n "$mac" ]; then
            add_entry "$mac" "$vlan" "$port" "$type"
            echo "  VLAN $vlan: $mac -> $port ($type)"
        fi
    done < "$input"
}

parse_cisco_nxos() {
    local input="$1"
    
    # Cisco NX-OS format can vary, but typically:
    # * 100    0011.2233.4455    dynamic    0          F    F  Eth1/1
    # Legend: * - primary entry, + - sp-proxy, G - Gateway MAC...
    
    while read -r line; do
        # Skip headers, legend, empty lines
        if echo "$line" | grep -qiE '^VLAN|^-|^$|Legend|Total|Note'; then
            continue
        fi
        
        # Remove leading * or + if present
        line=$(echo "$line" | sed 's/^[*+] *//')
        
        vlan=$(echo "$line" | awk '{print $1}')
        mac=$(echo "$line" | awk '{print $2}')
        type=$(echo "$line" | awk '{print $3}')
        # Port is usually later, position varies
        port=$(echo "$line" | awk '{print $NF}')
        
        if echo "$vlan" | grep -qE '^[0-9]+$' && [ -n "$mac" ]; then
            add_entry "$mac" "$vlan" "$port" "$type"
            echo "  VLAN $vlan: $mac -> $port ($type)"
        fi
    done < "$input"
}

case "$SOURCE_TYPE" in
    cisco-ios|cisco-nxos|file)
        if [ -z "$INPUT_FILE" ]; then
            echo -e "${YELLOW}No input file specified.${NC}"
            echo ""
            echo "To collect MAC table from a Cisco switch:"
            echo ""
            echo "  IOS:"
            echo "    switch# show mac address-table"
            echo ""
            echo "  NX-OS:"
            echo "    switch# show mac address-table dynamic"
            echo ""
            echo "Copy the output to a file and run:"
            echo "  ./mac_table.sh file [output_dir] [filename]"
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
        
        # Auto-detect format based on content
        if grep -qiE 'Eth[0-9]|Po[0-9]|nve' "$INPUT_FILE"; then
            echo "  Detected: NX-OS format"
            parse_cisco_nxos "$INPUT_FILE"
        else
            echo "  Detected: IOS format"
            parse_cisco_ios "$INPUT_FILE"
        fi
        
        # Clean up temp file if we created one
        if [ -n "$TEMP_INPUT" ] && [ -f "$TEMP_INPUT" ]; then
            rm -f "$TEMP_INPUT"
        fi
        ;;
        
    *)
        echo -e "${RED}Unknown source type: $SOURCE_TYPE${NC}"
        echo "Valid types: cisco-ios, cisco-nxos, file"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${GREEN}=== Collection Complete ===${NC}"
ENTRY_COUNT=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "MAC entries collected: $ENTRY_COUNT"
echo "Output saved to: $OUTPUT_FILE"
echo ""

# Show VLAN summary
echo "VLAN distribution:"
tail -n +2 "$OUTPUT_FILE" | cut -d',' -f2 | sort | uniq -c | sort -rn | head -10
