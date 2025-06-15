#!/bin/bash

# WireGuard Client Management Script
# Run this on the VPS to manage client connections

# Only use strict error handling for command line mode, not interactive
if [[ $# -gt 0 ]]; then
    set -e
fi

# Configuration
WIREGUARD_DIR="/etc/wireguard"
CLIENT_NETWORK="10.100.0.0/24"  # Default client network range

# Function to get server configuration
get_server_config() {
    # Try to get server public key from config
    SERVER_PUBLIC_KEY=$(grep "^PrivateKey" "$WG_CONFIG" 2>/dev/null | awk '{print $3}' | wg pubkey 2>/dev/null)
    if [[ -z "$SERVER_PUBLIC_KEY" ]]; then
        echo -e "${RED}Error: Could not find server public key in config${NC}"
        return 1
    fi
    
    # Try to get server IP from keys file
    SERVER_IP=$(grep "VPS Public IP:" "$VPS_KEYS_FILE" 2>/dev/null | awk '{print $4}')
    if [[ -z "$SERVER_IP" ]]; then
        # Try to detect the public IP using ip route
        SERVER_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)
        if [[ -n "$SERVER_IP" ]]; then
            echo "Detected server public IP using ip route: $SERVER_IP"
        else
            # Fallback to internet detection
            echo "No saved server IP found, detecting from internet..."
            SERVER_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || curl -s --max-time 10 ipinfo.io/ip 2>/dev/null)
            if [[ -z "$SERVER_IP" ]]; then
                read -p "Could not auto-detect server public IP. Please enter the VPS public IP or hostname: " SERVER_IP
                if [[ -z "$SERVER_IP" ]]; then
                    echo -e "${RED}Error: No server IP provided.${NC}"
                    return 1
                fi
            fi
        fi
    fi
    
    # Get port from config or keys file
    SERVER_PORT=$(grep "WireGuard Port:" "$VPS_KEYS_FILE" 2>/dev/null | awk '{print $3}' || echo "$WG_PORT")
    if [[ -z "$SERVER_PORT" ]]; then
        echo -e "${RED}Error: Could not determine server port${NC}"
        return 1
    fi
    
    return 0
}

# Auto-detect WireGuard interface if not specified
if [[ -z "$WG_INTERFACE" ]]; then
    # Look for any active WireGuard interface
    WG_INTERFACE=$(wg show interfaces 2>/dev/null | head -1)
    
    # If no active interface, look for config files
    if [[ -z "$WG_INTERFACE" ]]; then
        for conf in "$WIREGUARD_DIR"/*.conf; do
            if [[ -f "$conf" ]]; then
                WG_INTERFACE=$(basename "$conf" .conf)
                break
            fi
        done
    fi
    
    # Default to wg0 if nothing found
    if [[ -z "$WG_INTERFACE" ]]; then
        WG_INTERFACE="wg0"
    fi
fi

CLIENT_DIR="$WIREGUARD_DIR/clients-${WG_INTERFACE}"
WG_CONFIG="$WIREGUARD_DIR/${WG_INTERFACE}.conf"
VPS_KEYS_FILE="$WIREGUARD_DIR/vps-keys-${WG_INTERFACE}.txt"
WG_PORT="${WG_PORT:-51820}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}" 
   exit 1
fi

# Function to display usage
show_usage() {
    echo -e "${BLUE}WireGuard Client Manager${NC}"
    echo ""
    echo "Usage: [WG_INTERFACE=wgX] $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  add <client_name>     - Add a new client"
    echo "  remove <client_name>  - Remove a client"
    echo "  list                  - List all clients"
    echo "  show <client_name>    - Show client config"
    echo "  status                - Show WireGuard status"
    echo "  qr <client_name>      - Generate QR code for client"
    echo "  backup                - Backup all client configs"
    echo "  validate              - Validate WireGuard configuration"
    echo ""
    echo "Environment Variables:"
    echo "  WG_INTERFACE          - WireGuard interface name (auto-detected if not set)"
    echo ""
    echo "Current interface: $WG_INTERFACE"
    echo ""
}

# Function to check if IP is in use
check_ip_in_use() {
    local ip=$1
    local interface=$2
    ip -o addr show "$interface" | grep -q "$ip"
    return $?
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a ip_parts <<< "$ip"
        for part in "${ip_parts[@]}"; do
            if [[ $part -lt 0 || $part -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to validate client name
validate_client_name() {
    local name=$1
    if [[ $name =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 0
    fi
    return 1
}

# Function to check if client exists
check_client_exists() {
    local name=$1
    if [[ -f "$CLIENT_DIR/${name}.conf" ]]; then
        return 0
    fi
    return 1
}

# Function to get next available client IP
get_next_client_ip() {
    local base_ip="10.100.0"
    local last_octet=2  # Start from .2 since .1 is the VPS
    
    # Get list of existing client IPs
    local existing_ips=$(grep -h "Address = 10.100.0." "$CLIENT_DIR"/*.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
    
    # Find the next available IP
    while [[ $last_octet -lt 255 ]]; do
        local test_ip="$base_ip.$last_octet"
        if ! echo "$existing_ips" | grep -q "^$test_ip$"; then
            echo "$test_ip"
            return 0
        fi
        ((last_octet++))
    done
    
    echo "Error: No available IP addresses in range"
    return 1
}

# Function to backup client config
backup_client_config() {
    local name=$1
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="$CLIENT_DIR/backups"
    mkdir -p "$backup_dir"
    cp "$CLIENT_DIR/${name}.conf" "$backup_dir/${name}_${timestamp}.conf"
}

# Function to rotate backups
rotate_backups() {
    local backup_dir="$CLIENT_DIR/backups"
    local max_backups=5
    
    if [[ -d "$backup_dir" ]]; then
        # Keep only the most recent backups
        ls -t "$backup_dir"/*.conf 2>/dev/null | tail -n +$((max_backups + 1)) | xargs -r rm
    fi
}

# Function to check system requirements
check_system_requirements() {
    echo -e "\n${BLUE}=== Checking System Requirements ===${NC}"
    
    # Check for WireGuard kernel module
    if ! modprobe wireguard 2>/dev/null; then
        echo -e "${YELLOW}Installing WireGuard...${NC}"
        apt update
        apt install -y wireguard wireguard-tools
        echo -e "${GREEN}✓ WireGuard installed${NC}"
    else
        echo -e "${GREEN}✓ WireGuard already installed${NC}"
    fi
    
    # Check and install required packages
    local required_packages=("wireguard-tools" "qrencode" "iptables-persistent")
    for pkg in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            echo -e "${YELLOW}Installing $pkg...${NC}"
            apt install -y "$pkg"
            echo -e "${GREEN}✓ $pkg installed${NC}"
        else
            echo -e "${GREEN}✓ $pkg already installed${NC}"
        fi
    done
    
    # Check for required commands
    local required_commands=("wg" "wg-quick" "ip" "iptables" "qrencode")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${RED}Error: Required command '$cmd' not found after installation${NC}"
            exit 1
        fi
    done
    
    echo -e "${GREEN}✓ All system requirements satisfied${NC}\n"
}

# Function to validate CIDR
validate_cidr() {
    local cidr=$1
    if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        IFS='/' read -r ip prefix <<< "$cidr"
        IFS='.' read -r -a ip_parts <<< "$ip"
        local valid=1
        for part in "${ip_parts[@]}"; do
            if [[ $part -lt 0 || $part -gt 255 ]]; then
                valid=0
                break
            fi
        done
        if [[ $valid -eq 1 && $prefix -ge 0 && $prefix -le 32 ]]; then
            return 0
        fi
    fi
    return 1
}

# Function to check if interface exists (improved)
check_interface_exists() {
    local interface=$1
    echo -e "\n${BLUE}=== Checking WireGuard Interface ===${NC}"
    
    # Check if interface exists in system
    if ! ip link show "$interface" >/dev/null 2>&1; then
        echo -e "${YELLOW}Interface $interface not found in system${NC}"
        return 1
    fi
    
    # Check if interface is configured in WireGuard
    if ! wg show "$interface" >/dev/null 2>&1; then
        echo -e "${YELLOW}Warning: Interface $interface exists but is not configured in WireGuard${NC}"
        return 0  # Don't fail, just warn
    fi
    
    echo -e "${GREEN}✓ Interface $interface found and configured${NC}\n"
    return 0
}

# Function to validate client config (improved)
validate_client_config() {
    local config_file=$1
    local required_sections=("Interface" "Peer")
    local required_fields=("PrivateKey" "Address" "PublicKey" "AllowedIPs" "Endpoint")
    
    # Check if file exists
    if [[ ! -f "$config_file" ]]; then
        return 1
    fi
    
    # Check for required sections
    for section in "${required_sections[@]}"; do
        if ! grep -q "^\[$section\]" "$config_file"; then
            echo "Warning: Missing section [$section] in config file"
            return 1
        fi
    done
    
    # Check for required fields
    for field in "${required_fields[@]}"; do
        if ! grep -q "^$field = " "$config_file"; then
            echo "Warning: Missing field $field in config file"
            return 1
        fi
    done
    
    return 0
}

# Function to cleanup temporary files
cleanup_temp_files() {
    local temp_dir="$CLIENT_DIR/temp"
    if [[ -d "$temp_dir" ]]; then
        rm -rf "$temp_dir"
    fi
}

# Function to add a client
add_client() {
    local client_name
    local client_ip
    
    echo -e "\n${BLUE}=== Adding New Client ===${NC}"
    
    # Get server configuration first
    if ! get_server_config; then
        echo -e "${RED}Error: Failed to get server configuration${NC}"
        return 1
    fi
    
    # Get client name
    read -p "Enter client name: " client_name
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}Error: Client name cannot be empty${NC}"
        return 1
    fi
    
    # Check if client already exists
    # Only check for existence in CLIENT_DIR, not in /etc/wireguard/
    if [[ -f "$CLIENT_DIR/${client_name}.conf" ]]; then
        echo -e "${RED}Error: Client '$client_name' already exists${NC}"
        return 1
    fi
    
    # Get next available IP
    echo "Finding next available client IP..."
    client_ip=$(get_next_client_ip)
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}$client_ip${NC}"
        return 1
    fi

    echo "Using client IP: $client_ip"

    # Validate SERVER_IP before writing config
    while [[ -z "$SERVER_IP" ]] || [[ ! "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^([a-zA-Z0-9.-]+)$ ]]; do
        read -p "Enter a valid VPS public IP or hostname (IPv4 or DNS, no brackets): " SERVER_IP
        if [[ -z "$SERVER_IP" ]]; then
            echo -e "${RED}Error: Invalid or missing SERVER_IP. Cannot create client config.${NC}"
            return 1
        fi
    done

    # Generate client keys
    local client_private_key=$(wg genkey)
    local client_public_key=$(echo "$client_private_key" | wg pubkey)

    # Create client config
    mkdir -p "$CLIENT_DIR"
    cat > "$CLIENT_DIR/${client_name}.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = $SERVER_IP:$SERVER_PORT
PersistentKeepalive = 25
EOF
    
    # Add client to server config
    if ! wg set "$WG_INTERFACE" peer "$client_public_key" allowed-ips "$client_ip/32"; then
        echo -e "${RED}Error: Failed to add client to server config${NC}"
        rm -f "$CLIENT_DIR/${client_name}.conf"
        return 1
    fi
    
    # Save server config
    if ! wg-quick save "$WG_INTERFACE"; then
        echo -e "${RED}Error: Failed to save server config${NC}"
        wg set "$WG_INTERFACE" peer "$client_public_key" remove
        rm -f "$CLIENT_DIR/${client_name}.conf"
        return 1
    fi
    
    echo -e "\n${GREEN}Client '$client_name' added successfully!${NC}"
    echo -e "Client config file: ${BLUE}$CLIENT_DIR/${client_name}.conf${NC}"
    
    # Generate QR code
    if command -v qrencode >/dev/null 2>&1; then
        echo -e "\nGenerating QR code..."
        qrencode -t ansiutf8 < "$CLIENT_DIR/${client_name}.conf"
    fi
}

# Function to remove a client
remove_client() {
    local client_name=$1
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}Error: Client name is required${NC}"
        exit 1
    fi
    
    # Validate client name
    if ! validate_client_name "$client_name"; then
        echo "Error: Invalid client name"
        exit 1
    fi
    
    # Check if client exists
    if ! check_client_exists "$client_name"; then
        echo "Error: Client '$client_name' not found"
        exit 1
    fi
    
    # Validate client config before removal (don't fail on warnings)
    if ! validate_client_config "$CLIENT_DIR/${client_name}.conf" 2>/dev/null; then
        echo "Warning: Client configuration may be invalid, proceeding with removal"
    fi
    
    # Backup client config before removal
    backup_client_config "$client_name"
    rotate_backups
    
    # Get client public key to remove from config with better error handling
    local client_private_key=$(grep -E "^PrivateKey\s*=" "$CLIENT_DIR/${client_name}.conf" | sed 's/^PrivateKey\s*=\s*//' | tr -d ' ')
    if [[ -z "$client_private_key" ]]; then
        echo -e "${RED}Error: Could not extract private key from client config${NC}"
        exit 1
    fi
    local client_public_key=$(echo "$client_private_key" | wg pubkey 2>/dev/null)
    if [[ -z "$client_public_key" ]]; then
        echo -e "${RED}Error: Could not generate public key from private key${NC}"
        exit 1
    fi
    
    # Remove client config file
    rm "$CLIENT_DIR/${client_name}.conf"
    
    # Remove client from VPS config
    # Create a temporary file without the client peer
    awk -v client="$client_name" -v pubkey="$client_public_key" '
        /^# Client: / && $3 == client { skip=1; next }
        /^\[Peer\]/ && skip { skip=2; next }
        /^PublicKey = / && skip==2 && $3 == pubkey { skip=3; next }
        /^AllowedIPs = / && skip==3 { skip=0; next }
        /^$/ && skip { skip=0; next }
        !skip { print }
    ' "$WG_CONFIG" > "$WG_CONFIG.tmp"
    
    mv "$WG_CONFIG.tmp" "$WG_CONFIG"
    
    echo -e "${GREEN}Client '$client_name' removed successfully!${NC}"
    
    # Check if WireGuard is running and offer to restart
    if systemctl is-active --quiet "wg-quick@$WG_INTERFACE"; then
        read -p "WireGuard is running. Restart to apply changes? (Y/n): " -r
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            systemctl restart "wg-quick@$WG_INTERFACE"
            echo -e "${GREEN}WireGuard restarted successfully${NC}"
        fi
    else
        echo -e "${BLUE}WireGuard is not running${NC}"
    fi
}

# Function to list all clients
list_clients() {
    echo -e "${BLUE}WireGuard Clients:${NC}"
    echo ""
    
    shopt -s nullglob
    client_files=("$CLIENT_DIR"/*.conf)
    if [[ ${#client_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No clients found${NC}"
        shopt -u nullglob
        return
    fi
    shopt -u nullglob
    
    printf "%-20s %-15s %-10s\n" "CLIENT NAME" "IP ADDRESS" "STATUS"
    printf "%-20s %-15s %-10s\n" "----------" "----------" "------"
    
    for config in "$CLIENT_DIR"/*.conf; do
        if [[ -f "$config" ]]; then
            local client_name=$(basename "$config" .conf)
            local client_ip=$(grep "^Address" "$config" | awk '{print $3}' | cut -d'/' -f1)
            local client_private_key=$(grep -E "^PrivateKey\s*=" "$config" | sed 's/^PrivateKey\s*=\s*//' | tr -d ' ')
            local client_pubkey=""
            if [[ -n "$client_private_key" ]]; then
                client_pubkey=$(echo "$client_private_key" | wg pubkey 2>/dev/null)
            fi
            
            # Check if client is connected
            local status="Offline"
            if wg show "$WG_INTERFACE" 2>/dev/null | grep -q "$client_pubkey"; then
                status="Online"
            fi
            
            printf "%-20s %-15s %-10s\n" "$client_name" "$client_ip" "$status"
        fi
    done
}

# Function to show client config
show_client() {
    local client_name=$1
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}Error: Client name is required${NC}"
        exit 1
    fi
    
    if [[ ! -f "$CLIENT_DIR/${client_name}.conf" ]]; then
        echo -e "${RED}Error: Client '$client_name' not found${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Client Config: $client_name${NC}"
    echo ""
    cat "$CLIENT_DIR/${client_name}.conf"
}

# Function to show WireGuard status
show_status() {
    echo -e "\n${BLUE}WireGuard Status:${NC}"
    if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        echo -e "${GREEN}Service is running${NC}"
        echo -e "\n${BLUE}Interface Information:${NC}"
        wg show "$WG_INTERFACE"
        echo -e "\n${BLUE}Routing Information:${NC}"
        ip route show dev "$WG_INTERFACE"
        echo -e "\n${BLUE}Connected Clients:${NC}"
        wg show "$WG_INTERFACE" | grep -A1 "peer" | grep -v "peer" | grep -v "\-\-" | while read -r line; do
            if [[ $line =~ latest\ handshake:\ ([0-9]+)\ seconds\ ago ]]; then
                local handshake="${BASH_REMATCH[1]}"
                if [[ $handshake -lt 180 ]]; then
                    echo -e "${GREEN}Connected${NC} (Last handshake: ${handshake}s ago)"
                else
                    echo -e "${YELLOW}Inactive${NC} (Last handshake: ${handshake}s ago)"
                fi
            fi
        done
    else
        echo -e "${RED}Service is not running${NC}"
    fi
    
    # Check if interface exists (don't fail on warnings)
    if ! check_interface_exists "$WG_INTERFACE" 2>/dev/null; then
        echo "Warning: Interface $WG_INTERFACE not found or not configured"
        return 0  # Don't exit, just show warning
    fi
}

# Function to generate QR code
generate_qr() {
    local client_name=$1
    
    if [[ -z "$client_name" ]]; then
        echo -e "${RED}Error: Client name is required${NC}"
        exit 1
    fi
    
    if [[ ! -f "$CLIENT_DIR/${client_name}.conf" ]]; then
        echo -e "${RED}Error: Client '$client_name' not found${NC}"
        exit 1
    fi
    
    # Check if qrencode is installed
    if ! command -v qrencode &> /dev/null; then
        echo -e "${YELLOW}qrencode not found. Install it? (Y/n):${NC}"
        read -r
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            apt update && apt install -y qrencode
        else
            echo -e "${RED}Cannot generate QR code without qrencode${NC}"
            return 1
        fi
    fi
    
    echo -e "${BLUE}QR Code for client: $client_name${NC}"
    echo ""
    qrencode -t ansiutf8 < "$CLIENT_DIR/${client_name}.conf"
}

# Function to backup client configs
backup_configs() {
    local backup_dir="/etc/wireguard/backup/$(date +%Y%m%d_%H%M%S)"
    
    if [[ ! -d "$CLIENT_DIR" ]] || [[ -z "$(ls -A "$CLIENT_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}No clients to backup${NC}"
        return
    fi
    
    mkdir -p "$backup_dir"
    
    # Copy client configs if they exist
    if ls "$CLIENT_DIR"/*.conf >/dev/null 2>&1; then
        cp "$CLIENT_DIR"/*.conf "$backup_dir/"
    fi
    
    # Copy main config if it exists
    if [[ -f "$WG_CONFIG" ]]; then
        cp "$WG_CONFIG" "$backup_dir/${WG_INTERFACE}.conf.backup"
    fi
    
    # Copy keys if they exist
    if [[ -f "$VPS_KEYS_FILE" ]]; then
        cp "$VPS_KEYS_FILE" "$backup_dir/"
    fi
    
    echo -e "${GREEN}Backup created: $backup_dir${NC}"
}

# Function to validate WireGuard configuration
validate_config() {
    echo -e "${BLUE}Validating WireGuard Configuration...${NC}"
    echo ""
    
    # Check if config file exists
    if [[ ! -f "$WG_CONFIG" ]]; then
        echo -e "${RED}Error: WireGuard config not found at $WG_CONFIG${NC}"
        return 1
    fi
    
    # Check config syntax
    if ! wg-quick strip "$WG_INTERFACE" >/dev/null 2>&1; then
        echo -e "${RED}Error: Invalid WireGuard configuration syntax${NC}"
        return 1
    fi
    
    # Check if interface is up
    if systemctl is-active --quiet "wg-quick@$WG_INTERFACE"; then
        echo -e "${GREEN}✓ WireGuard service is active${NC}"
    else
        echo -e "${YELLOW}⚠ WireGuard service is not active${NC}"
    fi
    
    # Check peer connections
    local peer_count=$(wg show "$WG_INTERFACE" 2>/dev/null | grep -c "peer:" || echo "0")
    echo -e "${BLUE}Active peer connections: $peer_count${NC}"
    
    # Check iptables rules
    if iptables -t nat -L | grep -q MASQUERADE; then
        echo -e "${GREEN}✓ NAT rules are present${NC}"
    else
        echo -e "${YELLOW}⚠ NAT rules may be missing${NC}"
    fi
    
    echo -e "${GREEN}Configuration validation complete${NC}"
}

# Function to validate client network range
validate_client_network() {
    local network=$1
    echo -e "\n${BLUE}=== Validating Client Network Range ===${NC}"
    
    if ! validate_cidr "$network"; then
        echo -e "${RED}Error: Invalid network range format${NC}"
        return 1
    fi
    
    # Check if it's the expected range
    if [[ "$network" != "10.100.0.0/24" ]]; then
        echo -e "${YELLOW}Warning: Client network range ($network) differs from default (10.100.0.0/24)${NC}"
        echo -e "${YELLOW}This may affect client connectivity${NC}"
    else
        echo -e "${GREEN}✓ Client network range is correct (10.100.0.0/24)${NC}"
    fi
    
    echo ""
    return 0
}

# Function to show interactive menu
show_interactive_menu() {
    # Check system requirements first
    check_system_requirements
    
    # Auto-detect interface
    echo -e "\n${BLUE}=== Auto-detecting WireGuard Interface ===${NC}"
    if [[ -z "$WG_INTERFACE" ]]; then
        # Look for any active WireGuard interface
        WG_INTERFACE=$(wg show interfaces 2>/dev/null | head -1)
        
        # If no active interface, look for config files
        if [[ -z "$WG_INTERFACE" ]]; then
            for conf in "$WIREGUARD_DIR"/*.conf; do
                if [[ -f "$conf" ]]; then
                    WG_INTERFACE=$(basename "$conf" .conf)
                    break
                fi
            done
        fi
        
        # Default to wg0 if nothing found
        if [[ -z "$WG_INTERFACE" ]]; then
            WG_INTERFACE="wg0"
            echo -e "${YELLOW}No WireGuard interface found, defaulting to wg0${NC}"
        else
            echo -e "${GREEN}✓ Detected WireGuard interface: $WG_INTERFACE${NC}"
        fi
    else
        echo -e "${GREEN}✓ Using specified interface: $WG_INTERFACE${NC}"
    fi
    
    # Verify interface exists
    if ! check_interface_exists "$WG_INTERFACE"; then
        echo -e "${RED}Error: WireGuard interface $WG_INTERFACE not found${NC}"
        echo -e "${YELLOW}Please run the VPS setup script first${NC}"
        exit 1
    fi
    
    # Validate client network range
    validate_client_network "$CLIENT_NETWORK"
    
    # Rest of the menu code...
    echo -e "${BLUE}=== WireGuard Client Manager ===${NC}"
    echo ""
    echo "Current interface: $WG_INTERFACE"
    echo ""
    echo "Available options:"
    echo "  1) Add client"
    echo "  2) Remove client"
    echo "  3) List all clients"
    echo "  4) Show client config"
    echo "  5) Generate QR code"
    echo "  6) Show WireGuard status"
    echo "  7) Backup configurations"
    echo "  8) Validate configuration"
    echo "  9) Change interface"
    echo " 10) Show help"
    echo " 11) Exit"
    echo ""
    
    while true; do
        read -p "Choose an option (1-11): " choice
        case $choice in
            1)
                echo ""
                add_client
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            2)
                echo ""
                read -p "Enter client name to remove: " client_name
                if [[ -n "$client_name" ]]; then
                    remove_client "$client_name"
                else
                    echo -e "${RED}Client name cannot be empty${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            3)
                echo ""
                list_clients
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            4)
                echo ""
                read -p "Enter client name: " client_name
                if [[ -n "$client_name" ]]; then
                    show_client "$client_name"
                else
                    echo -e "${RED}Client name cannot be empty${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            5)
                echo ""
                read -p "Enter client name for QR code: " client_name
                if [[ -n "$client_name" ]]; then
                    generate_qr "$client_name"
                else
                    echo -e "${RED}Client name cannot be empty${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            6)
                echo ""
                show_status
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            7)
                echo ""
                backup_configs
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            8)
                echo ""
                validate_config
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            9)
                echo ""
                configure_interface
                show_interactive_menu
                break
                ;;
            10)
                echo ""
                show_usage
                echo ""
                read -p "Press Enter to continue..."
                show_interactive_menu
                break
                ;;
            11)
                echo "Goodbye!"
                break
                ;;
            *)
                echo "Invalid option. Please choose 1-11."
                ;;
        esac
    done
}

# Function to configure interface interactively
configure_interface() {
    echo -e "${BLUE}=== Configure Interface ===${NC}"
    echo ""
    echo "Available WireGuard interfaces:"
    
    # Show available interfaces
    local interfaces=($(ls /etc/wireguard/*.conf 2>/dev/null | xargs -n1 basename -s .conf))
    if [[ ${#interfaces[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No WireGuard configurations found${NC}"
        return
    fi
    
    local i=1
    for iface in "${interfaces[@]}"; do
        if [[ "$iface" == "$WG_INTERFACE" ]]; then
            echo -e "  $i) $iface ${GREEN}(current)${NC}"
        else
            echo "  $i) $iface"
        fi
        ((i++))
    done
    echo ""
    
    read -p "Choose interface number (or press Enter to keep current): " iface_choice
    if [[ -n "$iface_choice" ]] && [[ "$iface_choice" =~ ^[0-9]+$ ]] && [[ "$iface_choice" -ge 1 ]] && [[ "$iface_choice" -le "${#interfaces[@]}" ]]; then
        WG_INTERFACE="${interfaces[$((iface_choice-1))]}"
        
        # Update related variables
        CLIENT_DIR="$WIREGUARD_DIR/clients-${WG_INTERFACE}"
        WG_CONFIG="$WIREGUARD_DIR/${WG_INTERFACE}.conf"
        VPS_KEYS_FILE="$WIREGUARD_DIR/vps-keys-${WG_INTERFACE}.txt"
        
        echo -e "${GREEN}Interface changed to: $WG_INTERFACE${NC}"
    fi
}

# Main script logic
if [[ $# -eq 0 ]]; then
    show_interactive_menu
else
    case "${1:-}" in
        add)
            add_client
            ;;
        remove)
            remove_client "$2"
            ;;
        list)
            list_clients
            ;;
        show)
            show_client "$2"
            ;;
        status)
            show_status
            ;;
        qr)
            generate_qr "$2"
            ;;
        backup)
            backup_configs
            ;;
        validate)
            validate_config
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
fi