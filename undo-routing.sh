#!/bin/bash
# Undo WireGuard and Zerotier routing/NAT changes

# Remove WireGuard NAT rules (IPv4)
iptables -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to-source 0.0.0.0 2>/dev/null
iptables -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE 2>/dev/null

# Remove Zerotier-specific NAT rules (if any)
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep '^zt'); do
  iptables -t nat -D POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null
done

# Remove IPv6 NAT rules
ip6tables -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to-source :: 2>/dev/null

# Restore default FORWARD policy
iptables -P FORWARD ACCEPT

# Remove any custom sysctl forwarding config
rm -f /etc/sysctl.d/99-wireguard-forward.conf

# Reload sysctl settings
sysctl -p

echo "Routing and Zerotier-related changes have been undone."