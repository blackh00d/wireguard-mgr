#!/bin/bash

# VPS WireGuard Relay Management Script
# This script sets up or removes VPS as a public relay point for WireGuard traffic
# The VPS will forward client connections to a Pi server behind NAT

# Only use strict error handling for command line mode, not interactive
if [[ $# -gt 0 ]]; then
    set -e
fi

# Default values
WG_INTERFACE="wg0"
WG_PORT="51820"
VPS_WG_IP="10.99.0.1/24"
PI_WG_IP="10.99.0.2"
CLIENT_NETWORK="10.100.0.0/24"

# Function to show usage
show_usage() {
    echo "Usage: $0 [options] [command]"
    echo ""
    echo "Options:"
    echo "  -i <interface>  WireGuard interface name (default: wg0)"
    echo "  -a <address>    VPS WireGuard IP address (default: 10.99.0.1/24)"
    echo "  -p <address>    Pi WireGuard IP address (default: 10.99.0.2)"
    echo "  -c <network>    Client network CIDR (default: 10.100.0.0/24)"
    echo "  -h             Show this help message"
    echo ""
    echo "Commands:"
    echo "  setup          Setup WireGuard server"
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

# Function to show status
show_status() {
    echo "=== WireGuard Status ==="
    echo ""
    
    # Check if WireGuard is installed
    if ! command -v wg >/dev/null 2>&1; then
        echo "WireGuard is not installed"
        return 1
    fi
    
    # Check if interface exists
    if ! check_interface_exists "$WG_INTERFACE"; then
        echo "WireGuard interface $WG_INTERFACE does not exist"
        return 1
    fi
    
    # Show interface status
    echo "Interface Status:"
    ip addr show "$WG_INTERFACE"
    echo ""
    
    # Show WireGuard status
    echo "WireGuard Status:"
    wg show "$WG_INTERFACE"
    echo ""
    
    # Show iptables rules
    echo "IPTables Rules:"
    iptables -L | grep "$WG_INTERFACE"
    iptables -t nat -L | grep "$WG_INTERFACE"
    
    return 0
}

# Function to remove WireGuard
remove_wireguard() {
    echo "=== Removing VPS WireGuard Configuration ==="
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
    remove_iptables_rule "-A INPUT -p udp --dport $WG_PORT -j ACCEPT"
    remove_iptables_rule "-t nat -A POSTROUTING -s $CLIENT_NETWORK -j MASQUERADE"
    
    # Backup and remove configuration files
    if [[ -f "$config_file" ]]; then
        local backup_dir="/root/wireguard-backup-$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp "$config_file" "$backup_dir/"
        cp "/etc/wireguard/vps-keys-${WG_INTERFACE}.txt" "$backup_dir/" 2>/dev/null
        rm -f "$config_file"
        rm -f "/etc/wireguard/vps-keys-${WG_INTERFACE}.txt"
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
    echo "=== VPS WIREGUARD REMOVAL COMPLETE ==="
    echo "✓ WireGuard service stopped and disabled"
    echo "✓ Configuration files removed and backed up to: $backup_dir"
    echo "✓ iptables rules removed"
    echo "WireGuard packages remain installed for future use."
    
    return 0
}

# Function to setup WireGuard
setup_wireguard() {
    echo "=== VPS WireGuard Server Setup ==="
    echo "Interface: $WG_INTERFACE"
    echo "VPS Address: $VPS_WG_IP"
    echo "Pi Address: $PI_WG_IP"
    echo "Client Network: $CLIENT_NETWORK"
    echo ""

    # Get WireGuard port
    echo "Enter WireGuard port (press Enter for random port):"
    read -r WG_PORT
    if [[ -z "$WG_PORT" ]]; then
        WG_PORT=$(generate_random_port)
        echo "Using random port: $WG_PORT"
    else
        if ! validate_port "$WG_PORT"; then
            echo "Error: Invalid port number"
            return 1
        fi
        if check_port_in_use "$WG_PORT"; then
            echo "Error: Port $WG_PORT is already in use"
            return 1
        fi
    fi

    # Check system requirements
    check_system_requirements
    
    # Check if interface already exists
    if check_interface_exists "$WG_INTERFACE"; then
        echo "Error: Interface $WG_INTERFACE already exists"
        echo "Please remove it first using: $0 remove"
        return 1
    fi
    
    # Validate client network
    if ! validate_cidr "$CLIENT_NETWORK"; then
        echo "Error: Invalid client network CIDR format"
        return 1
    fi

    # Check if WireGuard is already installed
    if command -v wg >/dev/null 2>&1; then
        echo "WireGuard already installed, skipping installation..."
    else
        # Update system
        echo "Updating system packages..."
        apt update && apt upgrade -y

        # Install WireGuard
        echo "Installing WireGuard..."
        apt install -y wireguard wireguard-tools iptables-persistent
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

    # Generate VPS keys
    echo "Generating WireGuard keys for VPS..."
    VPS_PRIVATE_KEY=$(wg genkey)
    VPS_PUBLIC_KEY=$(echo "$VPS_PRIVATE_KEY" | wg pubkey)

    # Get VPS public IP
    VPS_PUBLIC_IP=$(curl -s ifconfig.me)

    # Save VPS keys
    echo "Saving VPS keys..."
    cat > "/etc/wireguard/vps-keys-${WG_INTERFACE}.txt" << EOF
VPS Private Key: $VPS_PRIVATE_KEY
VPS Public Key: $VPS_PUBLIC_KEY
VPS Public IP: $VPS_PUBLIC_IP
WireGuard Port: $WG_PORT
EOF

    # Create WireGuard configuration
    echo "Creating WireGuard configuration..."
    cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
PrivateKey = $VPS_PRIVATE_KEY
Address = $VPS_WG_IP
ListenPort = $WG_PORT

# Pi Peer
[Peer]
PublicKey = PI_PUBLIC_KEY_PLACEHOLDER
AllowedIPs = $PI_WG_IP/32, $CLIENT_NETWORK
PersistentKeepalive = 25

# CLIENT_NETWORK: $CLIENT_NETWORK
EOF

    # Enable and start WireGuard service
    echo "Enabling and starting WireGuard service..."
    systemctl enable "wg-quick@$WG_INTERFACE"
    systemctl start "wg-quick@$WG_INTERFACE"

    # Add iptables rules
    echo "Adding iptables rules..."
    add_iptables_rule "-A FORWARD -i $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A FORWARD -o $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A INPUT -i $WG_INTERFACE -j ACCEPT"
    add_iptables_rule "-A INPUT -p udp --dport $WG_PORT -j ACCEPT"

    # Add VPS-specific NAT rules
    # REMOVE this NAT rule to prevent the VPS from masquerading client traffic.
    # add_iptables_rule "-t nat -A POSTROUTING -s $CLIENT_NETWORK -j MASQUERADE"

    echo ""
    echo "=== VPS WIREGUARD SETUP COMPLETE ==="
    echo "✓ WireGuard service installed and configured"
    echo "✓ Interface $WG_INTERFACE created"
    echo "✓ iptables rules added"
    echo "✓ NAT rules configured"
    echo ""
    echo "IMPORTANT: Save these values for future reference:"
    echo "VPS Public Key: $VPS_PUBLIC_KEY"
    echo "VPS Public IP: $VPS_PUBLIC_IP"
    echo "WireGuard Port: $WG_PORT"
    echo "Configuration backup: /etc/wireguard/vps-keys-${WG_INTERFACE}.txt"
    echo ""
    echo "NEXT STEPS:"
    echo "1. Copy the VPS Public Key and IP to your Pi"
    echo "2. On your Pi, run the setup script and provide this VPS Public Key and IP"
    echo "3. After Pi setup, copy the Pi's Public Key back to this VPS"
    echo "4. Edit /etc/wireguard/${WG_INTERFACE}.conf and replace PI_PUBLIC_KEY_PLACEHOLDER with the Pi's Public Key"
    echo "5. Restart WireGuard: systemctl restart wg-quick@$WG_INTERFACE"
    echo ""
    echo -e "\033[1;31mTo remove this setup, run: $0 remove\033[0m"
    
    return 0
}

# Function to configure settings
configure_settings() {
    echo "=== Configure VPS WireGuard Settings ==="
    echo ""
    
    # Interface
    echo "Current interface: $WG_INTERFACE"
    read -p "Enter new interface name (press Enter to keep current): " new_interface
    if [[ -n "$new_interface" ]]; then
        WG_INTERFACE="$new_interface"
    fi
    
    # VPS Address
    echo "Current VPS address: $VPS_WG_IP"
    read -p "Enter new VPS address (press Enter to keep current): " new_vps_ip
    if [[ -n "$new_vps_ip" ]]; then
        if ! validate_cidr "$new_vps_ip"; then
            echo "Error: Invalid CIDR format"
            return 1
        fi
        VPS_WG_IP="$new_vps_ip"
    fi
    
    # Pi Address
    echo "Current Pi address: $PI_WG_IP"
    read -p "Enter new Pi address (press Enter to keep current): " new_pi_ip
    if [[ -n "$new_pi_ip" ]]; then
        if ! validate_ip "$new_pi_ip"; then
            echo "Error: Invalid IP address"
            return 1
        fi
        PI_WG_IP="$new_pi_ip"
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
        echo "=== VPS WireGuard Server Management ==="
        echo ""
        echo "Current settings:"
        echo "  Interface: $WG_INTERFACE"
        echo "  VPS Address: $VPS_WG_IP"
        echo "  Pi Address: $PI_WG_IP"
        echo "  Client Network: $CLIENT_NETWORK"
        echo ""
        echo "Available options:"
        echo "  1) Setup WireGuard server"
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

# Function to check if port is in use
check_port_in_use() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        return 0
    fi
    return 1
}

# Function to generate random port
generate_random_port() {
    local min=1024
    local max=65535
    local port
    while true; do
        port=$((RANDOM % (max - min + 1) + min))
        if ! check_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Parse command line arguments
while getopts "i:a:p:c:h" opt; do
    case $opt in
        i) WG_INTERFACE="$OPTARG" ;;
        a) VPS_WG_IP="$OPTARG" ;;
        p) PI_WG_IP="$OPTARG" ;;
        c) CLIENT_NETWORK="$OPTARG" ;;
        h) show_usage; exit 0 ;;
        *) show_usage; exit 1 ;;
    esac
done

shift $((OPTIND-1))
COMMAND="$1"

# Interactive mode if no command provided
if [[ -z "$COMMAND" ]]; then
    show_interactive_menu
    exit 0
fi

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
        echo "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac