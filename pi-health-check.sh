#!/bin/bash

# Pi WireGuard Health Check Script
# This script diagnoses common issues with the Pi's WireGuard setup.

# --- Configuration ---
WG_INTERFACE="wg0"
PI_WG_IP_PREFIX="10.99.0"
VPS_WG_IP="10.99.0.1"
CLIENT_NETWORK="10.100.0.0/24"
OUTBOUND_IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Pi WireGuard Health Check ===${NC}"

# --- Check 1: WireGuard Service Status ---
echo -e "\n${YELLOW}1. Checking WireGuard Service...${NC}"
if systemctl is-active --quiet "wg-quick@$WG_INTERFACE"; then
    echo -e "${GREEN}✓ Service wg-quick@$WG_INTERFACE is active.${NC}"
else
    echo -e "${RED}✗ Service wg-quick@$WG_INTERFACE is NOT active.${NC}"
    echo "  To fix, run: sudo systemctl start wg-quick@$WG_INTERFACE"
    exit 1
fi

# --- Check 2: Tunnel Connectivity ---
echo -e "\n${YELLOW}2. Checking Tunnel Connectivity...${NC}"
if ping -c 2 -W 2 "$VPS_WG_IP" >/dev/null; then
    echo -e "${GREEN}✓ Successfully pinged VPS at $VPS_WG_IP.${NC}"
else
    echo -e "${RED}✗ Failed to ping VPS at $VPS_WG_IP.${NC}"
    echo "  This indicates a problem with the tunnel itself."
    echo "  - Check that the public keys on the Pi and VPS match."
    echo "  - Check that the VPS endpoint IP and port in /etc/wireguard/wg0.conf are correct."
fi
sudo wg show "$WG_INTERFACE" | grep 'latest handshake'

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

# --- Check 4: iptables NAT Rule ---
echo -e "\n${YELLOW}4. Checking iptables NAT Rule...${NC}"
if sudo iptables -t nat -C POSTROUTING -s "$CLIENT_NETWORK" -o "$OUTBOUND_IFACE" -j MASQUERADE >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Correct MASQUERADE rule found for $CLIENT_NETWORK.${NC}"
else
    echo -e "${RED}✗ MASQUERADE rule for $CLIENT_NETWORK is missing or incorrect.${NC}"
    echo "  To fix, run:"
    echo "  sudo iptables -t nat -A POSTROUTING -s $CLIENT_NETWORK -o $OUTBOUND_IFACE -j MASQUERADE"
fi
sudo iptables -t nat -L POSTROUTING -n -v | grep 'MASQUERADE'

# --- Check 5: iptables FORWARD Rules ---
echo -e "\n${YELLOW}5. Checking iptables FORWARD Rules...${NC}"
FORWARD_OK=true
# Check for outbound forwarding
if ! sudo iptables -C FORWARD -i "$WG_INTERFACE" -o "$OUTBOUND_IFACE" -s "$CLIENT_NETWORK" -j ACCEPT >/dev/null 2>&1; then
    echo -e "${RED}✗ Outbound FORWARD rule for $CLIENT_NETWORK is missing.${NC}"
    echo "  To fix, run:"
    echo "  sudo iptables -A FORWARD -i $WG_INTERFACE -o $OUTBOUND_IFACE -s $CLIENT_NETWORK -j ACCEPT"
    FORWARD_OK=false
fi
# Check for inbound forwarding
if ! sudo iptables -C FORWARD -i "$OUTBOUND_IFACE" -o "$WG_INTERFACE" -d "$CLIENT_NETWORK" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1; then
    echo -e "${RED}✗ Inbound FORWARD rule for $CLIENT_NETWORK is missing.${NC}"
    echo "  To fix, run:"
    echo "  sudo iptables -A FORWARD -i $OUTBOUND_IFACE -o $WG_INTERFACE -d $CLIENT_NETWORK -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    FORWARD_OK=false
fi

if [ "$FORWARD_OK" = true ]; then
    echo -e "${GREEN}✓ Correct FORWARD rules found for $CLIENT_NETWORK.${NC}"
fi
sudo iptables -L FORWARD -n -v | grep "$CLIENT_NETWORK"

echo -e "\n${GREEN}Health check complete.${NC}"