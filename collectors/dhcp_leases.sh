#!/bin/bash
#
# dhcp_leases.sh - Collect DHCP lease information
# Part of the IoT/Physical Security Assessment Toolkit
#
# Usage: ./dhcp_leases.sh [source_type] [output_dir]
# 
# Source types:
#   cisco    - Connect to Cisco device and pull 'show ip dhcp binding'
#   windows  - Export from Windows DHCP server
#   linux    - Parse /var/lib/dhcp/dhcpd.leases or dnsmasq
#   file     - Parse a file you've already pulled (provide path as $3)
#
# Example: ./dhcp_leases.sh cisco ../output/clientname-2026-01-27/raw
# Example: ./dhcp_leases.sh file ../output/raw dhcp_dump.txt
#

set -e

SOURCE_TYPE="${1:-file}"
OUTPUT_DIR="${2:-../output/raw}"
INPUT_FILE="${3:-}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/dhcp_leases_${TIMESTAMP}.csv"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

mkdir -p "$OUTPUT_DIR"

echo -e "${GREEN}=== DHCP Lease Collection ===${NC}"
echo "Source type: $SOURCE_TYPE"
echo "Output: $OUTPUT_FILE"
echo ""

# CSV header
echo "mac_address,ip_address,hostname,lease_expiry,source" > "$OUTPUT_FILE"

# Function to normalize and add entry
add_entry() {
    local mac="$1"
    local ip="$2"
    local hostname="$3"
    local expiry="$4"
    
    # Normalize MAC
    mac=$(echo "$mac" | tr '[:upper:]' '[:lower:]' | sed 's/-/:/g')
    
    # Clean hostname (remove domain if present, handle empty)
    hostname=$(echo "$hostname" | cut -d'.' -f1)
    
    if [ -z "$mac" ] || [ ${#mac} -lt 11 ]; then
        return
    fi
    
    echo "${mac},${ip},${hostname},${expiry},${SOURCE_TYPE}" >> "$OUTPUT_FILE"
}

case "$SOURCE_TYPE" in
    cisco)
        echo -e "${YELLOW}Cisco DHCP Binding Collection${NC}"
        echo ""
        echo "To collect from a Cisco device:"
        echo "  1. SSH/console into the device"
        echo "  2. Run: show ip dhcp binding"
        echo "  3. Copy output to a file"
        echo "  4. Run: ./dhcp_leases.sh file [output_dir] [filename]"
        echo ""
        echo "Or paste the output below (Ctrl+D when done):"
        echo ""
        
        TEMP_INPUT=$(mktemp)
        cat > "$TEMP_INPUT"
        
        # Parse Cisco format:
        # IP address       Client-ID/              Lease expiration        Type
        #                  Hardware address
        # 192.168.1.100    0100.1234.5678.90       Jan 27 2026 09:00 AM    Automatic
        
        while read -r line; do
            # Skip headers and empty lines
            if echo "$line" | grep -qE '^IP address|^-|^$'; then
                continue
            fi
            
            ip=$(echo "$line" | awk '{print $1}')
            mac=$(echo "$line" | awk '{print $2}')
            
            # Cisco format might be 0100.1234.5678.90 (with leading 01 for ethernet)
            # Convert to standard format
            if echo "$mac" | grep -qE '^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}'; then
                mac=$(echo "$mac" | sed 's/\.//g' | sed 's/\(..\)/\1:/g' | sed 's/:$//')
            fi
            # Remove leading 01 if present (hardware type indicator)
            mac=$(echo "$mac" | sed 's/^01//')
            
            # Extract expiry (columns 3-6 typically)
            expiry=$(echo "$line" | awk '{print $3" "$4" "$5" "$6}')
            
            if [ -n "$ip" ] && [ -n "$mac" ]; then
                add_entry "$mac" "$ip" "" "$expiry"
                echo "  Found: $ip -> $mac"
            fi
        done < "$TEMP_INPUT"
        
        rm -f "$TEMP_INPUT"
        ;;
        
    windows)
        echo -e "${YELLOW}Windows DHCP Server Collection${NC}"
        echo ""
        echo "To export from Windows DHCP Server:"
        echo "  1. Open DHCP Management Console"
        echo "  2. Right-click scope -> Export List"
        echo "  3. Or run PowerShell:"
        echo "     Get-DhcpServerv4Lease -ScopeId 192.168.1.0 | Export-Csv leases.csv"
        echo "  4. Run: ./dhcp_leases.sh file [output_dir] leases.csv"
        echo ""
        ;;
        
    linux)
        echo -e "${GREEN}[+] Checking for Linux DHCP lease files...${NC}"
        
        # Try common locations
        LEASE_FILES=(
            "/var/lib/dhcp/dhcpd.leases"
            "/var/lib/dhcpd/dhcpd.leases"
            "/var/lib/dnsmasq/dnsmasq.leases"
            "/var/lib/misc/dnsmasq.leases"
            "/tmp/dnsmasq.leases"
        )
        
        for lf in "${LEASE_FILES[@]}"; do
            if [ -f "$lf" ]; then
                echo "  Found: $lf"
                
                if echo "$lf" | grep -q "dnsmasq"; then
                    # dnsmasq format: timestamp mac ip hostname clientid
                    while read -r ts mac ip hostname clientid; do
                        expiry=$(date -d "@$ts" 2>/dev/null || echo "$ts")
                        add_entry "$mac" "$ip" "$hostname" "$expiry"
                        echo "  Found: $ip -> $mac ($hostname)"
                    done < "$lf"
                else
                    # ISC DHCP format - more complex, lease blocks
                    current_ip=""
                    current_mac=""
                    current_hostname=""
                    current_expiry=""
                    
                    while read -r line; do
                        if echo "$line" | grep -q "^lease "; then
                            current_ip=$(echo "$line" | awk '{print $2}')
                        elif echo "$line" | grep -q "hardware ethernet"; then
                            current_mac=$(echo "$line" | awk '{print $3}' | tr -d ';')
                        elif echo "$line" | grep -q "client-hostname"; then
                            current_hostname=$(echo "$line" | awk '{print $2}' | tr -d '";')
                        elif echo "$line" | grep -q "ends "; then
                            current_expiry=$(echo "$line" | sed 's/ends [0-9] //' | tr -d ';')
                        elif echo "$line" | grep -q "^}"; then
                            if [ -n "$current_ip" ] && [ -n "$current_mac" ]; then
                                add_entry "$current_mac" "$current_ip" "$current_hostname" "$current_expiry"
                                echo "  Found: $current_ip -> $current_mac ($current_hostname)"
                            fi
                            current_ip=""
                            current_mac=""
                            current_hostname=""
                            current_expiry=""
                        fi
                    done < "$lf"
                fi
                
                break
            fi
        done
        ;;
        
    file)
        if [ -z "$INPUT_FILE" ]; then
            echo -e "${RED}Error: No input file specified${NC}"
            echo "Usage: ./dhcp_leases.sh file [output_dir] [input_file]"
            exit 1
        fi
        
        if [ ! -f "$INPUT_FILE" ]; then
            echo -e "${RED}Error: File not found: $INPUT_FILE${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}[+] Parsing file: $INPUT_FILE${NC}"
        
        # Try to auto-detect format and parse
        # Look for common patterns
        
        if head -5 "$INPUT_FILE" | grep -qE 'IP address.*Hardware'; then
            echo "  Detected: Cisco format"
            # Re-run with cisco parser logic
            cat "$INPUT_FILE" | while read -r line; do
                if echo "$line" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
                    ip=$(echo "$line" | awk '{print $1}')
                    mac=$(echo "$line" | awk '{print $2}')
                    if echo "$mac" | grep -qE '^[0-9a-fA-F]{4}\.'; then
                        mac=$(echo "$mac" | sed 's/\.//g' | sed 's/\(..\)/\1:/g' | sed 's/:$//')
                    fi
                    mac=$(echo "$mac" | sed 's/^01//')
                    add_entry "$mac" "$ip" "" ""
                    echo "  Found: $ip -> $mac"
                fi
            done
            
        elif head -1 "$INPUT_FILE" | grep -qE 'ScopeId|IPAddress|ClientId'; then
            echo "  Detected: Windows CSV format"
            # Parse CSV (skip header)
            tail -n +2 "$INPUT_FILE" | while IFS=',' read -r scopeid ip mask mac hostname lease_expiry type state; do
                add_entry "$mac" "$ip" "$hostname" "$lease_expiry"
                echo "  Found: $ip -> $mac ($hostname)"
            done
            
        else
            echo "  Format not auto-detected, attempting generic parse..."
            # Look for MAC and IP patterns on each line
            grep -oE '([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$INPUT_FILE" | \
            paste - - | while read -r item1 item2; do
                if echo "$item1" | grep -qE '^[0-9]+\.'; then
                    ip="$item1"
                    mac="$item2"
                else
                    mac="$item1"
                    ip="$item2"
                fi
                if [ -n "$ip" ] && [ -n "$mac" ]; then
                    add_entry "$mac" "$ip" "" ""
                fi
            done
        fi
        ;;
        
    *)
        echo -e "${RED}Unknown source type: $SOURCE_TYPE${NC}"
        echo "Valid types: cisco, windows, linux, file"
        exit 1
        ;;
esac

# Summary
echo ""
echo -e "${GREEN}=== Collection Complete ===${NC}"
LEASE_COUNT=$(tail -n +2 "$OUTPUT_FILE" | wc -l)
echo "Leases collected: $LEASE_COUNT"
echo "Output saved to: $OUTPUT_FILE"
