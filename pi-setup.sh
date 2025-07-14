#!/bin/bash

# Pi WireGuard Server Management Script
# This script sets up or removes Pi as a WireGuard server that connects to a VPS relay
# The Pi will handle all client traffic routing while staying behind NAT

# Only use strict error handling for command line mode, not interactive
if [[ $# -gt 0 ]]; then
    set -e
fi

# Default values
WG_INTERFACE="wg0"
PI_WG_IP="10.99.0.2/24"
VPS_WG_IP="10.99.0.1"
CLIENT_NETWORK="10.100.0.0/24"
VPS_PORT="51820"

# Function to show usage
show_usage() {
    echo "Usage: $0 [options] [command]"
    echo ""
    echo "Options:"
    echo "  -i <interface>  WireGuard interface name (default: wg0)"
    echo "  -a <address>    Pi WireGuard IP address (default: 10.99.0.2/24)"
    echo "  -v <address>    VPS WireGuard IP address (default: 10.99.0.1)"
    echo "  -c <network>    Client network CIDR (default: 10.100.0.0/24)"
    echo "  -h             Show this help message"
    echo ""
    echo "Commands:"
    echo "  setup          Setup WireGuard connection to VPS"
    echo "  remove         Remove WireGuard configuration"
    echo "  status         Show WireGuard status"
    echo "  help           Show this help message"
    echo ""
    echo "If no command is provided, interactive mode will be started."
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

# Function to validate port number
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
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

# Function to check if interface exists
check_interface_exists() {
    local interface=$1
    ip link show "$interface" >/dev/null 2>&1
    return $?
}

# Function to check system requirements
check_system_requirements() {
    # Check for WireGuard kernel module
    if ! modprobe wireguard 2>/dev/null; then
        echo "Error: WireGuard kernel module not available"
        echo "Please install WireGuard first: https://www.wireguard.com/install/"
        return 1
    fi
    
    # Check for required commands
    local required_commands=("wg" "wg-quick" "ip" "iptables" "netstat")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: Required command '$cmd' not found"
            return 1
        fi
    done
}

# Function to check if iptables rule exists
check_iptables_rule() {
    local rule=$1
    # Escape special characters in the rule
    local escaped_rule=$(echo "$rule" | sed 's/[.*&$]/\\&/g')
    iptables -C $escaped_rule >/dev/null 2>&1
    return $?
}

# Function to add iptables rule
add_iptables_rule() {
    local rule=$1
    if ! check_iptables_rule "$rule"; then
        iptables $rule
    fi
}

# Function to remove iptables rule
remove_iptables_rule() {
    local rule=$1
    if check_iptables_rule "$rule"; then
        iptables $(echo "$rule" | sed 's/-A/-D/')
    fi
}

# Function to show WireGuard status
show_status() {
    echo "=== WireGuard Status ==="
    echo

    # Check if interface exists
    if ! check_interface_exists "$WG_INTERFACE"; then
        echo "WireGuard interface $WG_INTERFACE does not exist"
        return 1
    fi

    # Show interface status
    echo "Interface Status:"
    ip addr show "$WG_INTERFACE"
    echo

    # Show WireGuard status
    echo "WireGuard Status:"
    wg show "$WG_INTERFACE"
    echo

    # Show iptables rules
    echo "IPTables Rules:"
    echo "FORWARD Chain:"
    iptables -L FORWARD -n -v | grep -E "$WG_INTERFACE|$VPS_PORT"
    echo
    echo "INPUT Chain:"
    iptables -L INPUT -n -v | grep -E "$WG_INTERFACE|$VPS_PORT"
    echo
    echo "NAT Rules:"
    iptables -t nat -L POSTROUTING -n -v | grep "$WG_INTERFACE"
    echo

    # Show routing table
    echo "Routing Table:"
    ip route show table all | grep "$WG_INTERFACE"
    echo

    # Show connection status
    echo "Connection Status:"
    if ping -c 1 -W 1 "$VPS_WG_IP" >/dev/null 2>&1; then
        echo "✓ Connected to VPS ($VPS_WG_IP)"
    else
        echo "✗ Not connected to VPS ($VPS_WG_IP)"
    fi
    echo

    # Show service status
    echo "Service Status:"
    systemctl status "wg-quick@$WG_INTERFACE" --no-pager
}

# Function to remove WireGuard
remove_wireguard() {
    echo "=== Removing Pi WireGuard Configuration ==="
    echo "This will remove WireGuard configuration and restore original system state."
    echo "WARNING: This will:"
    echo "- Stop and disable WireGuard service ($WG_INTERFACE)"
    echo "- Remove WireGuard configuration files"
    echo "- Remove iptables rules added by WireGuard"
    echo "- Keep WireGuard packages installed (for safety)"
    echo ""
    
    read -p "Are you sure you want to continue? (type 'yes' to confirm): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Removal cancelled"
        return 1
    fi
    
    # Stop and disable WireGuard service
    echo "Stopping and disabling WireGuard service..."
    systemctl stop "wg-quick@$WG_INTERFACE" 2>/dev/null
    systemctl disable "wg-quick@$WG_INTERFACE" 2>/dev/null
    
    # Get the configuration file path
    local config_file="/etc/wireguard/${WG_INTERFACE}.conf"
    
    # Remove iptables rules
    echo "Removing iptables rules and routing rules..."
    remove_iptables_rule "-A FORWARD -i $WG_INTERFACE -j ACCEPT"
    remove_iptables_rule "-A FORWARD -o $WG_INTERFACE -j ACCEPT"
    remove_iptables_rule "-A INPUT -i $WG_INTERFACE -j ACCEPT"
    remove_iptables_rule "-A INPUT -p udp --dport $VPS_PORT -j ACCEPT"
    remove_iptables_rule "-t nat -A POSTROUTING -o $WG_INTERFACE -j MASQUERADE"
    
    # Backup and remove configuration files
    if [[ -f "$config_file" ]]; then
        local backup_dir="/root/wireguard-backup-$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp "$config_file" "$backup_dir/"
        cp "/etc/wireguard/pi-keys-${WG_INTERFACE}.txt" "$backup_dir/" 2>/dev/null
        rm -f "$config_file"
        rm -f "/etc/wireguard/pi-keys-${WG_INTERFACE}.txt"
    fi
    
    # Restore original sysctl.conf if backup exists
    if [[ -f "/etc/sysctl.conf.pre-wireguard" ]]; then
        echo "Restoring original sysctl.conf..."
        cp /etc/sysctl.conf.pre-wireguard /etc/sysctl.conf
        sysctl -p
    else
        echo "Warning: No original sysctl.conf backup found."
    fi
    
    echo ""
    echo "=== PI WIREGUARD REMOVAL COMPLETE ==="
    echo "✓ WireGuard service stopped and disabled"
    echo "✓ Configuration files removed and backed up to: $backup_dir"
    echo "✓ iptables rules removed"
    echo "WireGuard packages remain installed for future use."
    
    return 0
}

# Function to setup WireGuard
setup_wireguard() {
    echo "=== Pi WireGuard Client Setup ==="
    echo "Interface: $WG_INTERFACE"
    echo "Pi Address: $PI_WG_IP"
    echo "VPS Address: $VPS_WG_IP"
    echo ""

    # Get VPS information
    echo "Enter VPS Public Key:"
    read -r VPS_PUBLIC_KEY
    if [[ -z "$VPS_PUBLIC_KEY" ]]; then
        echo "Error: VPS Public Key is required"
        return 1
    fi

    echo "Enter VPS IP or hostname:"
    read -r VPS_IP
    if [[ -z "$VPS_IP" ]]; then
        echo "Error: VPS IP/hostname is required"
        return 1
    fi

    echo "Enter VPS WireGuard port:"
    read -r VPS_PORT
    if [[ -z "$VPS_PORT" ]]; then
        echo "Error: VPS WireGuard port is required"
        return 1
    fi
    if ! validate_port "$VPS_PORT"; then
        echo "Error: Invalid port number"
        return 1
    fi

    # Check system requirements
    check_system_requirements
    
    # Check if interface already exists
    if check_interface_exists "$WG_INTERFACE"; then
        echo "Error: Interface $WG_INTERFACE already exists"
        echo "Please remove it first using: $0 remove"
        return 1
    fi

    # Check if WireGuard is already installed
    if command -v wg >/dev/null 2>&1; then
        echo "WireGuard already installed, skipping installation..."
    else
        # Update system
        echo "Updating system packages..."
        apt update && apt upgrade -y

        # Install WireGuard and required packages
        echo "Installing WireGuard and required packages..."
        apt install -y wireguard wireguard-tools iptables-persistent resolvconf
    fi

    # Ensure resolvconf is installed
    if ! command -v resolvconf >/dev/null 2>&1; then
        echo "Installing resolvconf..."
        apt install -y resolvconf
    fi

    # Backup original sysctl.conf before making changes
    if [[ ! -f "/etc/sysctl.conf.pre-wireguard" ]]; then
        echo "Backing up original sysctl.conf..."
        cp /etc/sysctl.conf /etc/sysctl.conf.pre-wireguard
    fi

    # Enable IP forwarding
    echo "Enabling IP forwarding..."
    # Check if already enabled to avoid duplicates
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    fi
    sysctl -p

    # Create WireGuard directory
    mkdir -p /etc/wireguard

    # Generate Pi keys
    echo "Generating WireGuard keys for Pi..."
    PI_PRIVATE_KEY=$(wg genkey)
    PI_PUBLIC_KEY=$(echo "$PI_PRIVATE_KEY" | wg pubkey)

    # Save Pi keys
    echo "Saving Pi keys..."
    cat > "/etc/wireguard/pi-keys-${WG_INTERFACE}.txt" << EOF
Pi Private Key: $PI_PRIVATE_KEY
Pi Public Key: $PI_PUBLIC_KEY
EOF

    # Create WireGuard configuration
    echo "Creating WireGuard configuration..."
    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = $PI_PRIVATE_KEY
Address = $PI_WG_IP
DNS = 1.1.1.1, 1.0.0.1

# VPS Peer
[Peer]
PublicKey = $VPS_PUBLIC_KEY
Endpoint = $VPS_IP:$VPS_PORT
AllowedIPs = $VPS_WG_IP/32, $CLIENT_NETWORK
PersistentKeepalive = 25
EOF

    # Set proper permissions
    chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"

    # Add iptables rules
    echo "Adding iptables rules..."
    add_iptables_rule "-A FORWARD -i $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A FORWARD -o $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A INPUT -i $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A INPUT -p udp --dport $VPS_PORT -j ACCEPT"

    # Dynamically detect outbound (internet) interface
    OUT_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
    if [[ -z "$OUT_IF" ]]; then
        echo "Warning: Could not detect outbound interface, defaulting to eth0"
        OUT_IF="eth0"
    fi

    # Add NAT rule for outbound internet interface for the client network
    add_iptables_rule "-t nat -A POSTROUTING -s $CLIENT_NETWORK -o $OUT_IF -j MASQUERADE"

    # Ensure forwarding rules for client network between wg0 and outbound interface
    add_iptables_rule "-A FORWARD -i $WG_INTERFACE -o $OUT_IF -s $CLIENT_NETWORK -j ACCEPT"
    add_iptables_rule "-A FORWARD -i $OUT_IF -o $WG_INTERFACE -d $CLIENT_NETWORK -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

    # Enable and start WireGuard service
    echo "Enabling and starting WireGuard service..."
    systemctl enable "wg-quick@$WG_INTERFACE"
    
    # Try to start the service and capture any errors
    if ! systemctl start "wg-quick@$WG_INTERFACE"; then
        echo "Error: Failed to start WireGuard service"
        echo "Checking service status..."
        systemctl status "wg-quick@$WG_INTERFACE"
        echo "Checking journal logs..."
        journalctl -xeu "wg-quick@$WG_INTERFACE"
        return 1
    fi

    # Verify the interface is up
    if ! check_interface_exists "$WG_INTERFACE"; then
        echo "Error: Failed to create WireGuard interface"
        echo "Checking service status..."
        systemctl status "wg-quick@$WG_INTERFACE"
        echo "Checking journal logs..."
        journalctl -xeu "wg-quick@$WG_INTERFACE"
        return 1
    fi

    echo ""
    echo "=== PI WIREGUARD SETUP COMPLETE ==="
    echo "✓ WireGuard service installed and configured"
    echo "✓ Interface $WG_INTERFACE created"
    echo "✓ iptables rules added"
    echo "✓ NAT rules configured"
    echo ""
    echo "IMPORTANT: Save these values for future reference:"
    echo "Pi Public Key: $PI_PUBLIC_KEY"
    echo "Configuration backup: /etc/wireguard/pi-keys-${WG_INTERFACE}.txt"
    echo ""
    echo "NEXT STEPS:"
    echo ""
    echo "If this is the FIRST and ONLY Pi being set up with this VPS relay:"
    echo "1. On your VPS, edit /etc/wireguard/${WG_INTERFACE}.conf"
    echo "2. Find the [Peer] section for the Pi (or PI_PUBLIC_KEY_PLACEHOLDER) and set:"
    echo "   PublicKey = $PI_PUBLIC_KEY"
    echo "   AllowedIPs = $PI_WG_IP, $CLIENT_NETWORK"
    echo "3. Restart WireGuard on VPS: sudo systemctl restart wg-quick@$WG_INTERFACE"
    echo ""
    echo "If this is an ADDITIONAL Pi for this VPS relay:"
    echo "1. Choose a unique tunnel IP for this Pi (e.g., 10.99.0.X/24, not used by other Pi's)."
    echo "2. On your VPS, add a new [Peer] section to /etc/wireguard/${WG_INTERFACE}.conf:"
    echo "   [Peer]"
    echo "   PublicKey = $PI_PUBLIC_KEY"
    echo "   AllowedIPs = $PI_WG_IP, $CLIENT_NETWORK"
    echo "   PersistentKeepalive = 25"
    echo "3. Restart WireGuard on VPS: sudo systemctl restart wg-quick@$WG_INTERFACE"
    echo ""
    echo -e "\033[1;31mTo remove this setup, run: $0 remove\033[0m"
    
    return 0
}

# Function to configure settings
configure_settings() {
    echo "=== Configure Pi WireGuard Settings ==="
    echo ""
    
    # Interface
    echo "Current interface: $WG_INTERFACE"
    read -p "Enter new interface name (press Enter to keep current): " new_interface
    if [[ -n "$new_interface" ]]; then
        WG_INTERFACE="$new_interface"
    fi
    
    # Pi Address
    echo "Current Pi address: $PI_WG_IP"
    read -p "Enter new Pi address (press Enter to keep current): " new_pi_ip
    if [[ -n "$new_pi_ip" ]]; then
        if ! validate_cidr "$new_pi_ip"; then
            echo "Error: Invalid CIDR format"
            return 1
        fi
        PI_WG_IP="$new_pi_ip"
    fi
    
    # VPS Address
    echo "Current VPS address: $VPS_WG_IP"
    read -p "Enter new VPS address (press Enter to keep current): " new_vps_ip
    if [[ -n "$new_vps_ip" ]]; then
        if ! validate_ip "$new_vps_ip"; then
            echo "Error: Invalid IP address"
            return 1
        fi
        VPS_WG_IP="$new_vps_ip"
    fi
    
    # Client Network
    echo "Current client network: $CLIENT_NETWORK"
    read -p "Enter new client network (press Enter to keep current): " new_client_network
    if [[ -n "$new_client_network" ]]; then
        if ! validate_cidr "$new_client_network"; then
            echo "Error: Invalid CIDR format"
            return 1
        fi
        CLIENT_NETWORK="$new_client_network"
    fi
    
    echo "Settings updated!"
    return 0
}

# Function to show interactive menu
show_interactive_menu() {
    while true; do
        clear
        echo "=== Pi WireGuard Server Management ==="
        echo ""
        echo "Current settings:"
        echo "  Interface: $WG_INTERFACE"
        echo "  Pi Address: $PI_WG_IP"
        echo "  VPS Address: $VPS_WG_IP"
        echo "  Client Network: $CLIENT_NETWORK"
        echo ""
        echo "Available options:"
        echo "  1) Setup WireGuard connection to VPS"
        echo "  2) Show status"
        echo "  3) Remove configuration"
        echo "  4) Change settings"
        echo "  5) Show help"
        echo "  6) Exit"
        echo ""
        read -p "Choose an option (1-6): " choice
        echo ""

        case $choice in
            1)
                setup_wireguard
                read -p "Press Enter to continue..."
                ;;
            2)
                show_status
                read -p "Press Enter to continue..."
                ;;
            3)
                remove_wireguard
                read -p "Press Enter to continue..."
                ;;
            4)
                configure_settings
                read -p "Press Enter to continue..."
                ;;
            5)
                show_usage
                read -p "Press Enter to continue..."
                ;;
            6)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo "Invalid option. Please try again."
                read -p "Press Enter to continue..."
                ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Parse command line arguments
while getopts "i:a:v:c:h" opt; do
    case $opt in
        i) WG_INTERFACE="$OPTARG" ;;
        a) PI_WG_IP="$OPTARG" ;;
        v) VPS_WG_IP="$OPTARG" ;;
        c) CLIENT_NETWORK="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

shift $((OPTIND-1))
COMMAND="$1"

# Handle commands
case "$COMMAND" in
    setup)
        setup_wireguard
        ;;
    remove)
        remove_wireguard
        ;;
    status)
        show_status
        ;;
    help)
        show_usage
        ;;
    *)
        if [[ -z "$COMMAND" ]]; then
            show_interactive_menu
        else
            echo "Unknown command: $COMMAND"
            show_usage
            exit 1
        fi
        ;;
esac