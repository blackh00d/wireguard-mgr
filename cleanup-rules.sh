#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Save current rules
echo "Saving current iptables rules..."
iptables-save > /tmp/iptables.backup

# Remove all existing rules for wg0
echo "Removing existing rules..."
iptables -F FORWARD
iptables -F INPUT
iptables -t nat -F POSTROUTING

# Add single rules for each chain
echo "Adding clean rules..."

# FORWARD chain rules
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -o wg0 -j ACCEPT

# INPUT chain rules
iptables -A INPUT -i wg0 -j ACCEPT
iptables -A INPUT -p udp --dport 51819 -j ACCEPT

# NAT rules
iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE

echo "Rules cleaned up. Backup saved to /tmp/iptables.backup"
echo "To restore original rules if needed: iptables-restore < /tmp/iptables.backup" 