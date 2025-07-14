#!/bin/bash

# VPS WireGuard Health Check Script
# This script diagnoses common issues with the VPS's WireGuard relay setup.

# --- Configuration ---
WG_INTERFACE="wg0"
CLIENT_NETWORK="10.100.0.0/24"
PI_WG_IP_PREFIX="0.0.0.0/0" # This is the gateway peer

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Debug Mode ---
DEBUG=false
if [[ "$1" == "--debug" ]]; then
    DEBUG=true
    echo -e "${YELLOW}*** DEBUG MODE ENABLED ***${NC}"
fi

echo -e "${YELLOW}=== VPS WireGuard Health Check ===${NC}"

# --- Check 1: WireGuard Service Status ---
echo -e "\n${YELLOW}1. Checking WireGuard Service...${NC}"
if systemctl is-active --quiet "wg-quick@$WG_INTERFACE"; then
    echo -e "${GREEN}✓ Service wg-quick@$WG_INTERFACE is active.${NC}"
else
    echo -e "${RED}✗ Service wg-quick@$WG_INTERFACE is NOT active.${NC}"
    echo "  To fix, run: sudo systemctl start wg-quick@$WG_INTERFACE"
    exit 1
fi

# --- Check 2: Peer Connections ---
echo -e "\n${YELLOW}2. Checking Peer Connections...${NC}"

if [ "$DEBUG" = true ]; then
    echo "--- Raw 'wg show' output ---"
    sudo wg show "$WG_INTERFACE"
    echo "----------------------------"
fi

# Use a robust awk script to parse peers
PI_PEER_KEY=$(sudo wg show "$WG_INTERFACE" | awk -v prefix="$PI_WG_IP_PREFIX" '
/^[[:space:]]*peer:/ { current_peer = $2 }
/^[[:space:]]*allowed ips:/ {
    for (i = 3; i <= NF; i++) {
        # Remove trailing comma for comparison
        gsub(",", "", $i)
        if ($i == prefix) {
            print current_peer
            exit
        }
    }
}')

if [ -n "$PI_PEER_KEY" ]; then
    echo -e "${GREEN}✓ Found Pi gateway peer: $PI_PEER_KEY${NC}"
    sudo wg show "$WG_INTERFACE" | grep -A 4 "peer: $PI_PEER_KEY"
else
    echo -e "${RED}✗ No gateway peer found with 'AllowedIPs = 0.0.0.0/0'.${NC}"
    echo "  This peer is required to forward client traffic to the Pi."
fi

# --- Check 3: IP Forwarding ---
echo -e "\n${YELLOW}3. Checking IP Forwarding...${NC}"
IP_FORWARD=$(sysctl -n net.ipv4.ip_forward)
if [[ "$IP_FORWARD" -eq 1 ]]; then
    echo -e "${GREEN}✓ IP forwarding is enabled.${NC}"
else
    echo -e "${RED}✗ IP forwarding is disabled.${NC}"
    echo "  To fix, run: sudo sysctl -w net.ipv4.ip_forward=1"
    echo "  To make it permanent, add 'net.ipv4.ip_forward=1' to /etc/sysctl.conf"
fi

# --- Check 4: iptables NAT Rule (Should NOT exist) ---
echo -e "\n${YELLOW}4. Checking for incorrect iptables NAT Rule...${NC}"
if sudo iptables -t nat -C POSTROUTING -s "$CLIENT_NETWORK" -j MASQUERADE >/dev/null 2>&1; then
    echo -e "${RED}✗ Incorrect MASQUERADE rule found for $CLIENT_NETWORK.${NC}"
    echo "  The VPS should NOT masquerade client traffic; the Pi should."
    echo "  To fix, run:"
    echo "  sudo iptables -t nat -D POSTROUTING -s $CLIENT_NETWORK -j MASQUERADE"
else
    echo -e "${GREEN}✓ No incorrect MASQUERADE rule found for $CLIENT_NETWORK.${NC}"
fi

# --- Check 5: iptables FORWARD Rules ---
echo -e "\n${YELLOW}5. Checking iptables FORWARD Rules...${NC}"
FORWARD_OK=true
# Check for forwarding from the WireGuard interface
if ! sudo iptables -C FORWARD -i "$WG_INTERFACE" -j ACCEPT >/dev/null 2>&1; then
    echo -e "${RED}✗ FORWARD rule for traffic from $WG_INTERFACE is missing.${NC}"
    echo "  To fix, run: sudo iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT"
    FORWARD_OK=false
fi
# Check for forwarding to the WireGuard interface
if ! sudo iptables -C FORWARD -o "$WG_INTERFACE" -j ACCEPT >/dev/null 2>&1; then
    echo -e "${RED}✗ FORWARD rule for traffic to $WG_INTERFACE is missing.${NC}"
    echo "  To fix, run: sudo iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT"
    FORWARD_OK=false
fi

if [ "$FORWARD_OK" = true ]; then
    echo -e "${GREEN}✓ Correct FORWARD rules found for $WG_INTERFACE.${NC}"
fi
sudo iptables -L FORWARD -n -v | grep "$WG_INTERFACE"

echo -e "\n${GREEN}Health check complete.${NC}"