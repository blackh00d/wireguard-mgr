#!/bin/bash

# Remove MASQUERADE for client network (should NOT be present)
iptables -t nat -D POSTROUTING -s 10.100.0.0/24 -j MASQUERADE 2>/dev/null

# Ensure forwarding rules for WireGuard interface (replace wg0 if needed)
WG_INTERFACE="wg0"
iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
iptables -A INPUT -i $WG_INTERFACE -j ACCEPT

echo "Corrected iptables rules for VPS WireGuard relay. MASQUERADE for client network removed."