#!/bin/bash

echo "==== sysctl net.ipv4.ip_forward ===="
sysctl net.ipv4.ip_forward

echo
echo "==== iptables -t nat -L -n -v ===="
sudo iptables -t nat -L -n -v

echo
echo "==== iptables -L -n -v ===="
sudo iptables -L -n -v

echo
echo "==== ip route ===="
ip route

echo
echo "==== wg show ===="
sudo wg show

echo
echo "==== ifconfig ===="
ifconfig

echo
echo "==== /etc/wireguard/wg0.conf ===="
cat /etc/wireguard/wg0.conf