#!/bin/bash
#
# https://github.com/blackh00d/wg-mgr
#
# Copyright (c) 2020 Blackh00d. Released under the MIT License.

echo
echo "Welcome to the Digital Nomad WireGuard Manager!"
echo

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "Debian Testing and Debian Unstable are unsupported by this installer."
		exit
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
		exit
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
	# Not running inside a container
	use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
	# Running inside a container, but the wireguard kernel module is available
	use_boringtun="0"
else
	# Running inside a container and the wireguard kernel module is not available
	use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ "$use_boringtun" -eq 1 ]]; then
	architecture=$(uname -m)
	if [[ "$architecture" != "x86_64" && "$architecture" != "aarch64" ]]; then
		echo "In containerized systems without the wireguard kernel module, this installer
supports only x86_64 and aarch64 architectures.
The system runs on $architecture and is unsupported."
		exit
	fi
	# TUN device is required to use BoringTun
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

main_menu() {
	echo
	echo "=== Digital Nomad WireGuard Manager ==="
	echo "What would you like to do?"
	echo "   1) Set up a new WireGuard server"
	echo "   2) Update a WireGuard server after relocation"
	echo "   3) Create a WireGuard client configuration"
	echo "   4) Remove an existing client"
	echo "   5) Remove a specific WireGuard tunnel"
	echo "   6) Remove ALL WireGuard configurations"
	echo "   7) Show WireGuard status"
	echo "   8) Test WireGuard connectivity"
	echo "   9) Clean up conflicting services"
	echo "   10) Exit"
	read -p "Option [1]: " initial_option
	initial_option=${initial_option:-1} # Default to 1 if nothing is entered

	case "$initial_option" in
		1)
			setup_new_server
			;;
		2)
			update_wg_server_after_relocation
			;;
		3)
			add_new_client_to_existing_server
			;;
		4)
			remove_existing_client_from_server
			;;
		5)
			remove_specific_tunnel
			main_menu
			;;
		6)
			remove_wireguard_from_server
			;;
		7)
			show_wireguard_status
			main_menu
			;;
		8)
			test_wireguard_connectivity
			main_menu
			;;
		9)
			cleanup_all_wireguard_services
			main_menu
			;;
		10)
			echo "Exiting."
			exit 0
			;;
		*)
			echo "Invalid option. Please try again."
			main_menu
			;;
	esac
}

# Initialize variables
use_zerotier="n"
zt_pi_ip=""

setup_new_server() {
	echo
	echo "Setting up a new WireGuard server..."
	
	# Start the main server setup which handles tunnel naming and conflicts
	main_server_setup
}

update_wg_server_after_relocation() {
	if ! select_tunnel; then
		return
	fi
	
	echo "Updating tunnel '$selected_tunnel' configuration after relocation..."
	echo
	
	# Detect if this is a ZeroTier setup
	is_zerotier_setup="n"
	if grep -q "# ZeroTier setup" "$wg_conf_file" 2>/dev/null; then
		is_zerotier_setup="y"
	fi
	
	if [[ "$is_zerotier_setup" == "y" ]]; then
		echo "ZeroTier setup detected for tunnel: $selected_tunnel"
		echo "The ZeroTier IP endpoint doesn't change when relocating, so client configs don't need updates."
		echo "Only the physical interface for outbound internet needs to be reconfigured."
		echo
		
		# Update physical interface for outbound internet
		update_physical_interface_for_zerotier
	else
		echo "Regular (non-ZeroTier) setup detected for tunnel: $selected_tunnel"
		echo "The public IP endpoint has likely changed, so server and client configs need updates."
		echo
		
		# Update endpoint and regenerate client configs
		update_endpoint_and_regenerate_clients
	fi
	
	echo "Tunnel '$selected_tunnel' update completed!"
}

select_tunnel() {
	# Check if any WireGuard configurations exist
	if ! ls /etc/wireguard/*.conf 2>/dev/null >/dev/null; then
		echo "No WireGuard tunnels found on this system."
		echo "Please set up a new WireGuard server first."
		return 1
	fi
	
	# If only one tunnel exists, select it automatically
	local tunnel_files=(/etc/wireguard/*.conf)
	if [[ ${#tunnel_files[@]} -eq 1 ]]; then
		selected_tunnel=$(basename "${tunnel_files[0]}" .conf)
		wg_conf_file="/etc/wireguard/${selected_tunnel}.conf"
		wg_iface="$selected_tunnel"
		echo "Using tunnel: $selected_tunnel"
		return 0
	fi
	
	# Multiple tunnels - let user choose
	echo
	echo "Available WireGuard tunnels:"
	local tunnels=()
	local count=1
	for conf in /etc/wireguard/*.conf; do
		tunnel_name=$(basename "$conf" .conf)
		tunnels+=("$tunnel_name")
		echo "   $count) $tunnel_name"
		((count++))
	done
	
	echo
	read -p "Select tunnel: " tunnel_choice
	
	if [[ "$tunnel_choice" -ge 1 && "$tunnel_choice" -lt "$count" ]]; then
		selected_tunnel="${tunnels[$((tunnel_choice-1))]}"
		wg_conf_file="/etc/wireguard/${selected_tunnel}.conf"
		wg_iface="$selected_tunnel"
		echo "Selected tunnel: $selected_tunnel"
		return 0
	else
		echo "Invalid selection."
		return 1
	fi
}

add_new_client_to_existing_server() {
	if ! select_tunnel; then
		return
	fi
	
	echo
	echo "Adding client to tunnel: $selected_tunnel"
	echo "Provide a name for the client:"
	read -p "Name: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" "$wg_conf_file"; do
		echo "$client: invalid name."
		read -p "Name: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	done
	echo
	new_client_dns
	new_client_setup
	wg addconf ${wg_iface} <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$wg_conf_file")
	echo
	# Use the same tunnel prefix as in new_client_setup
	tunnel_prefix="${tunnel_name:-$selected_tunnel}"
	qrencode -t UTF8 < ~/"${tunnel_prefix}-${client}.conf" > ~/"${tunnel_prefix}-${client}"_qr.txt
	echo "A text-based QR code has also been saved to:" ~/"${tunnel_prefix}-${client}"_qr.txt
	qrencode -t ANSI256UTF8 < ~/"${tunnel_prefix}-${client}.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
	echo
	echo "$client added to tunnel $selected_tunnel. Configuration available in:" ~/"${tunnel_prefix}-${client}.conf"
}

remove_existing_client_from_server() {
	if ! select_tunnel; then
		return
	fi
	
	number_of_clients=$(grep -c '^# BEGIN_PEER' "$wg_conf_file")
	if [[ "$number_of_clients" = 0 ]]; then
		echo
		echo "There are no existing clients in tunnel: $selected_tunnel"
		return
	fi
	echo
	echo "Clients in tunnel $selected_tunnel:"
	grep '^# BEGIN_PEER' "$wg_conf_file" | cut -d ' ' -f 3 | nl -s ') '
	read -p "Client: " client_number
	until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
		echo "$client_number: invalid selection."
		read -p "Client: " client_number
	done
	client=$(grep '^# BEGIN_PEER' "$wg_conf_file" | cut -d ' ' -f 3 | sed -n "$client_number"p)
	echo
	read -p "Confirm $client removal from tunnel $selected_tunnel? [y/N]: " remove
	until [[ "$remove" =~ ^[yYnN]*$ ]]; do
		echo "$remove: invalid selection."
		read -p "Confirm $client removal from tunnel $selected_tunnel? [y/N]: " remove
	done
	if [[ "$remove" =~ ^[yY]$ ]]; then
		wg set ${wg_iface} peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "$wg_conf_file" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
		sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$wg_conf_file"
		# Remove client config files
		rm -f ~/"${selected_tunnel}-${client}.conf" 2>/dev/null
		rm -f ~/"${selected_tunnel}-${client}"_qr.txt 2>/dev/null
		echo
		echo "$client removed from tunnel $selected_tunnel!"
	else
		echo
		echo "$client removal aborted!"
	fi
}

remove_specific_tunnel() {
	while true; do
		# First, show any orphaned services that exist
		local orphaned_services=()
		
		# Method 1: Use systemctl list-unit-files with pattern
		systemctl list-unit-files "wg-quick@*.service" 2>/dev/null | grep "wg-quick@" | awk '{print $1}' | while read -r service; do
			if [[ -n "$service" && "$service" =~ ^wg-quick@.+\.service$ ]]; then
				tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
				# Skip empty tunnel names
				if [[ -n "$tunnel_name" && "$tunnel_name" != "" ]]; then
					config_file="/etc/wireguard/${tunnel_name}.conf"
					if [[ ! -e "$config_file" ]]; then
						echo "$service" >> /tmp/orphaned_services.tmp
					fi
				fi
			fi
		done
		
		# Read the temporary file into array
		if [[ -f /tmp/orphaned_services.tmp ]]; then
			while IFS= read -r service; do
				orphaned_services+=("$service")
			done < /tmp/orphaned_services.tmp
			rm -f /tmp/orphaned_services.tmp
		fi
		
		if [[ ${#orphaned_services[@]} -gt 0 ]]; then
			echo
			echo "Found orphaned WireGuard services (enabled but missing config files):"
			for service in "${orphaned_services[@]}"; do
				tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
				echo "  - $service (missing: /etc/wireguard/${tunnel_name}.conf)"
			done
			echo
			read -p "Clean up these orphaned services first? [Y/n]: " cleanup_orphans
			cleanup_orphans=${cleanup_orphans:-Y}
			
			if [[ "$cleanup_orphans" =~ ^[yY]$ ]]; then
				echo "Cleaning up orphaned services..."
				for service in "${orphaned_services[@]}"; do
					tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
					echo "  Completely removing $service (tunnel: $tunnel_name)"
					
					# Stop the service
					systemctl stop "$service" 2>/dev/null
					
					# Disable the service
					systemctl disable "$service" 2>/dev/null
					
					# Remove any override directories
					rm -rf "/etc/systemd/system/${service}.d/" 2>/dev/null
					
					# Remove any symlinks
					find /etc/systemd/system/ -name "${service}" -type l -delete 2>/dev/null
					find /etc/systemd/system/multi-user.target.wants/ -name "${service}" -type l -delete 2>/dev/null
					find /etc/systemd/system/default.target.wants/ -name "${service}" -type l -delete 2>/dev/null
					
					# Actually DELETE the service unit file if it exists
					if [[ -f "/etc/systemd/system/${service}" ]]; then
						echo "    Deleting service file: /etc/systemd/system/${service}"
						rm -f "/etc/systemd/system/${service}"
					fi
					
					if [[ -f "/lib/systemd/system/${service}" ]]; then
						echo "    Deleting system service file: /lib/systemd/system/${service}"
						rm -f "/lib/systemd/system/${service}"
					fi
					
					# Remove any generated unit files
					if [[ -f "/run/systemd/system/${service}" ]]; then
						echo "    Deleting runtime service file: /run/systemd/system/${service}"
						rm -f "/run/systemd/system/${service}"
					fi
				done
				
				# Force reload systemd
				systemctl daemon-reload
				systemctl reset-failed 2>/dev/null
				echo "Orphaned services completely deleted."
				echo
			fi
		fi
		
		# Check if any WireGuard configurations exist
		if ! ls /etc/wireguard/*.conf 2>/dev/null >/dev/null; then
			if [[ ${#orphaned_services[@]} -eq 0 ]]; then
				echo "No WireGuard tunnels found on this system."
			else
				echo "No active WireGuard tunnels with configuration files found."
				echo "All remaining services were orphaned (missing config files)."
			fi
			return
		fi
		
		echo
		echo "Available WireGuard tunnels:"
		local tunnels=()
		local count=1
		for conf in /etc/wireguard/*.conf; do
			tunnel_name=$(basename "$conf" .conf)
			tunnels+=("$tunnel_name")
			echo "   $count) $tunnel_name"
			((count++))
		done
		
		echo "   $count) Remove ALL tunnels"
		echo "   $((count+1))) Cancel"
		echo
		echo "You can select multiple tunnels by entering comma-separated numbers (e.g., 1,3,5)"
		read -p "Select tunnel(s) to remove: " tunnel_choice
		
		# Handle cancel option
		if [[ "$tunnel_choice" -eq "$((count+1))" ]] || [[ -z "$tunnel_choice" ]]; then
			echo "Operation cancelled."
			return
		fi
		
		# Handle remove all option
		if [[ "$tunnel_choice" -eq "$count" ]]; then
			echo
			echo "This will remove ALL WireGuard tunnels!"
			read -p "Confirm removal of ALL tunnels? [y/N]: " confirm_remove_all
			until [[ "$confirm_remove_all" =~ ^[yYnN]*$ ]]; do
				echo "$confirm_remove_all: invalid selection."
				read -p "Confirm removal of ALL tunnels? [y/N]: " confirm_remove_all
			done
			
			if [[ "$confirm_remove_all" =~ ^[yY]$ ]]; then
				echo "Removing all tunnels..."
				for tunnel in "${tunnels[@]}"; do
					echo "Removing tunnel: $tunnel"
					cleanup_specific_tunnel "$tunnel"
				done
				echo "All tunnels removed successfully!"
				return
			else
				echo "Operation cancelled."
				continue
			fi
		fi
		
		# Handle single or multiple tunnel selection
		IFS=',' read -ra selected_numbers <<< "$tunnel_choice"
		local selected_tunnels=()
		local invalid_selection=false
		
		# Validate all selections first
		for num in "${selected_numbers[@]}"; do
			# Trim whitespace
			num=$(echo "$num" | xargs)
			
			if [[ ! "$num" =~ ^[0-9]+$ ]] || [[ "$num" -lt 1 ]] || [[ "$num" -ge "$count" ]]; then
				echo "Invalid selection: $num"
				invalid_selection=true
				break
			fi
			
			selected_tunnels+=("${tunnels[$((num-1))]}")
		done
		
		if [[ "$invalid_selection" == true ]]; then
			echo "Please try again with valid tunnel numbers."
			continue
		fi
		
		# Show confirmation for selected tunnels
		echo
		if [[ ${#selected_tunnels[@]} -eq 1 ]]; then
			echo "Selected tunnel for removal: ${selected_tunnels[0]}"
		else
			echo "Selected tunnels for removal:"
			for tunnel in "${selected_tunnels[@]}"; do
				echo "  - $tunnel"
			done
		fi
		
		read -p "Confirm removal of selected tunnel(s)? [y/N]: " confirm_remove
		until [[ "$confirm_remove" =~ ^[yYnN]*$ ]]; do
			echo "$confirm_remove: invalid selection."
			read -p "Confirm removal of selected tunnel(s)? [y/N]: " confirm_remove
		done
		
		if [[ "$confirm_remove" =~ ^[yY]$ ]]; then
			echo "Removing selected tunnels..."
			for tunnel in "${selected_tunnels[@]}"; do
				echo "Removing tunnel: $tunnel"
				cleanup_specific_tunnel "$tunnel"
			done
			echo "Selected tunnel(s) removed successfully!"
		else
			echo "Tunnel removal aborted!"
		fi
		
		# Continue the loop to show the menu again
		echo
		read -p "Press Enter to continue or type 'q' to return to main menu: " continue_choice
		if [[ "$continue_choice" =~ ^[qQ]$ ]]; then
			return
		fi
	done
}

remove_wireguard_from_server() {
	# Check if any WireGuard configurations exist
	if ! ls /etc/wireguard/*.conf 2>/dev/null >/dev/null; then
		echo "No WireGuard configurations found on this system."
		return
	fi
	
	echo
	echo "This will remove ALL WireGuard configurations and services!"
	echo "All tunnels and client configurations will be permanently lost."
	echo
	read -p "Confirm COMPLETE WireGuard removal? [y/N]: " remove
	until [[ "$remove" =~ ^[yYnN]*$ ]]; do
		echo "$remove: invalid selection."
		read -p "Confirm COMPLETE WireGuard removal? [y/N]: " remove
	done
	
	if [[ "$remove" =~ ^[yY]$ ]]; then
		remove_wireguard_completely
		echo "All WireGuard configurations removed!"
	else
		echo "WireGuard removal aborted!"
	fi
}

cleanup_specific_tunnel() {
	local tunnel_name="$1"
	local tunnel_conf="/etc/wireguard/${tunnel_name}.conf"
	
	if [[ ! -e "$tunnel_conf" ]]; then
		echo "Tunnel '$tunnel_name' not found."
		return
	fi
	
	echo "Cleaning up tunnel: $tunnel_name"
	
	# Stop and disable the service
	systemctl stop wg-quick@${tunnel_name}.service 2>/dev/null
	systemctl disable wg-quick@${tunnel_name}.service 2>/dev/null
	
	# Get port for firewall cleanup
	local port=$(grep '^ListenPort' "$tunnel_conf" | cut -d " " -f 3 2>/dev/null)
	
	# Remove firewall rules if port is found
	if [[ -n "$port" ]]; then
		if systemctl is-active --quiet firewalld.service; then
			firewall-cmd --remove-port="$port"/udp 2>/dev/null
			firewall-cmd --permanent --remove-port="$port"/udp 2>/dev/null
			firewall-cmd --zone=trusted --remove-source=10.7.0.0/24 2>/dev/null
			firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24 2>/dev/null
		fi
	fi
	
	# Remove configuration files
	rm -f "$tunnel_conf"
	rm -f "/etc/systemd/system/wg-quick@${tunnel_name}.service.d/boringtun.conf"
	
	# Remove client configs from home directory that match this tunnel
	rm -f ~/*${tunnel_name}*.conf 2>/dev/null
	rm -f ~/*${tunnel_name}*_qr.txt 2>/dev/null
	
	# Reload systemd
	systemctl daemon-reload
	
	echo "Tunnel '$tunnel_name' removed successfully."
}

remove_wireguard_completely() {
	echo "Performing complete WireGuard cleanup..."
	
	# Stop all WireGuard services
	systemctl stop wg-quick@* 2>/dev/null
	systemctl disable wg-quick@* 2>/dev/null
	
	# Stop custom iptables service
	systemctl stop wg-iptables.service 2>/dev/null
	systemctl disable wg-iptables.service 2>/dev/null
	
	# Remove all WireGuard configurations
	rm -rf /etc/wireguard/
	
	# Remove systemd service files
	rm -f /etc/systemd/system/wg-iptables.service
	rm -rf /etc/systemd/system/wg-quick@*.service.d/
	
	# Remove sysctl configuration
	rm -f /etc/sysctl.d/99-wireguard-forward.conf
	
	# Clean up firewall rules
	if systemctl is-active --quiet firewalld.service; then
		# Remove common WireGuard ports and rules
		for port in 51820 51821 51822 51823 51824; do
			firewall-cmd --remove-port="$port"/udp 2>/dev/null
			firewall-cmd --permanent --remove-port="$port"/udp 2>/dev/null
		done
		firewall-cmd --zone=trusted --remove-source=10.7.0.0/24 2>/dev/null
		firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24 2>/dev/null
		firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64 2>/dev/null
		firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64 2>/dev/null
	else
		# Reset iptables NAT rules
		iptables -t nat -F POSTROUTING 2>/dev/null
		iptables -F FORWARD 2>/dev/null
	fi
	
	# Remove BoringTun if installed
	{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab - 2>/dev/null
	rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
	
	# Remove WireGuard packages (optional - commented out to preserve for other uses)
	# if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
	#     apt-get remove --purge -y wireguard wireguard-tools
	# elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
	#     dnf remove -y wireguard-tools
	# fi
	
	# Remove client config files from home directory
	rm -f ~/*.conf 2>/dev/null
	rm -f ~/*_qr.txt 2>/dev/null
	
	# Reload systemd
	systemctl daemon-reload
	
	echo "Complete WireGuard cleanup finished."
}

show_wireguard_status() {
	echo "=== WireGuard Status ==="
	echo
	
	# Show all WireGuard configurations
	echo "Installed tunnels:"
	if ls /etc/wireguard/*.conf 2>/dev/null; then
		for conf in /etc/wireguard/*.conf; do
			tunnel_name=$(basename "$conf" .conf)
			echo "  - $tunnel_name"
		done
	else
		echo "  No WireGuard configurations found."
		return
	fi
	
	echo
	echo "Active services:"
	systemctl list-units --type=service | grep wg-quick | while read line; do
		echo "  $line"
	done
	
	echo
	echo "WireGuard interfaces:"
	if command -v wg &> /dev/null; then
		sudo wg show 2>/dev/null || echo "  No active WireGuard interfaces."
	else
		echo "  WireGuard tools not installed."
	fi
	
	echo
	echo "Listening ports:"
	ss -ulnp | grep :518 | while read line; do
		echo "  $line"
	done
	
	echo "========================"
}

test_wireguard_connectivity() {
	if ! select_tunnel; then
		return
	fi
	
	echo "=== Testing WireGuard Connectivity for: $selected_tunnel ==="
	echo
	
	# Check if service is running
	echo "1. Service Status:"
	if systemctl is-active --quiet wg-quick@${selected_tunnel}.service; then
		echo "   ✓ Service wg-quick@${selected_tunnel}.service is running"
	else
		echo "   ✗ Service wg-quick@${selected_tunnel}.service is NOT running"
		echo "   Try: systemctl start wg-quick@${selected_tunnel}.service"
	fi
	
	# Check if interface is up
	echo
	echo "2. Interface Status:"
	if ip link show "$selected_tunnel" &>/dev/null; then
		echo "   ✓ Interface $selected_tunnel is up"
		ip addr show "$selected_tunnel" | grep inet
	else
		echo "   ✗ Interface $selected_tunnel is NOT up"
	fi
	
	# Check WireGuard status
	echo
	echo "3. WireGuard Status:"
	if command -v wg &>/dev/null; then
		wg_output=$(sudo wg show "$selected_tunnel" 2>/dev/null)
		if [[ -n "$wg_output" ]]; then
			echo "   ✓ WireGuard interface is active"
			echo "$wg_output" | sed 's/^/   /'
		else
			echo "   ✗ No WireGuard data for interface $selected_tunnel"
		fi
	else
		echo "   ⚠ WireGuard tools not available"
	fi
	
	# Check listening port
	echo
	echo "4. Port Status:"
	port=$(grep '^ListenPort' "$wg_conf_file" | cut -d " " -f 3)
	if [[ -n "$port" ]]; then
		if ss -ulnp | grep -q ":$port "; then
			echo "   ✓ Port $port is listening"
		else
			echo "   ✗ Port $port is NOT listening"
		fi
	else
		echo "   ⚠ Could not determine port from config"
	fi
	
	# Check IP forwarding
	echo
	echo "5. IP Forwarding:"
	if [[ $(cat /proc/sys/net/ipv4/ip_forward) -eq 1 ]]; then
		echo "   ✓ IPv4 forwarding is enabled"
	else
		echo "   ✗ IPv4 forwarding is DISABLED"
		echo "   Fix: echo 1 > /proc/sys/net/ipv4/ip_forward"
	fi
	
	# Check firewall rules
	echo
	echo "6. Firewall Status:"
	if systemctl is-active --quiet firewalld.service; then
		echo "   ✓ Firewalld is active"
		if firewall-cmd --list-ports | grep -q "$port/udp"; then
			echo "   ✓ Port $port/udp is allowed"
		else
			echo "   ✗ Port $port/udp may not be allowed"
		fi
	elif systemctl is-active --quiet wg-iptables.service; then
		echo "   ✓ Custom iptables service is active"
	else
		echo "   ⚠ No firewall service detected"
	fi
	
	echo
	echo "=== Test Complete ==="
	echo "If issues persist, check the logs with:"
	echo "  journalctl -u wg-quick@${selected_tunnel}.service"
}

cleanup_all_wireguard_services() {
	echo "Cleaning up all WireGuard services and conflicts..."
	
	# Stop and disable all running WireGuard services using better parsing
	echo "Stopping all active WireGuard services..."
	systemctl list-units --type=service --state=active | grep "wg-quick@" | awk '{print $1}' | while read -r service; do
		if [[ -n "$service" && "$service" != "●" ]]; then
			echo "  Stopping $service"
			systemctl stop "$service" 2>/dev/null
			systemctl disable "$service" 2>/dev/null
		fi
	done
	
	# Find and disable ALL WireGuard services using more robust method
	echo "Finding all WireGuard services..."
	
	# Method 1: Use systemctl list-unit-files with better filtering
	systemctl list-unit-files "wg-quick@*.service" 2>/dev/null | grep "wg-quick@" | awk '{print $1}' | while read -r service; do
		if [[ -n "$service" && "$service" =~ ^wg-quick@.+\.service$ ]]; then
			tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
			# Skip empty tunnel names
			if [[ -n "$tunnel_name" && "$tunnel_name" != "" ]]; then
				echo "  Completely removing service: $service (tunnel: $tunnel_name)"
				systemctl stop "$service" 2>/dev/null
				systemctl disable "$service" 2>/dev/null
				
				# Remove any symlinks
				find /etc/systemd/system/ -name "${service}" -type l -delete 2>/dev/null
				find /etc/systemd/system/multi-user.target.wants/ -name "${service}" -type l -delete 2>/dev/null
				find /etc/systemd/system/default.target.wants/ -name "${service}" -type l -delete 2>/dev/null
				
				# Actually DELETE the service unit file if it exists
				if [[ -f "/etc/systemd/system/${service}" ]]; then
					echo "    Deleting service file: /etc/systemd/system/${service}"
					rm -f "/etc/systemd/system/${service}"
				fi
				
				if [[ -f "/lib/systemd/system/${service}" ]]; then
					echo "    Deleting system service file: /lib/systemd/system/${service}"
					rm -f "/lib/systemd/system/${service}"
				fi
				
				# Remove any generated unit files
				if [[ -f "/run/systemd/system/${service}" ]]; then
					echo "    Deleting runtime service file: /run/systemd/system/${service}"
					rm -f "/run/systemd/system/${service}"
				fi
			fi
		fi
	done
	
	# Method 2: Directly find and DELETE service files in systemd directories
	echo "Completely removing all WireGuard service files..."
	for service_file in /etc/systemd/system/wg-quick@*.service /lib/systemd/system/wg-quick@*.service /run/systemd/system/wg-quick@*.service; do
		if [[ -e "$service_file" ]]; then
			service=$(basename "$service_file")
			tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
			if [[ -n "$tunnel_name" && "$tunnel_name" != "" ]]; then
				echo "  Deleting service file: $service_file"
				systemctl stop "$service" 2>/dev/null
				systemctl disable "$service" 2>/dev/null
				rm -f "$service_file"
			fi
		fi
	done
	
	# Remove any remaining service files and directories
	echo "Removing any remaining WireGuard service files and directories..."
	rm -rf /etc/systemd/system/wg-quick@*.service.d/ 2>/dev/null
	rm -f /etc/systemd/system/wg-quick@*.service 2>/dev/null
	rm -f /lib/systemd/system/wg-quick@*.service 2>/dev/null
	rm -f /run/systemd/system/wg-quick@*.service 2>/dev/null
	
	# Remove symlinks from all possible locations
	find /etc/systemd/system/ -name "wg-quick@*.service" -type l -delete 2>/dev/null
	
	# Stop custom iptables service
	systemctl stop wg-iptables.service 2>/dev/null
	systemctl disable wg-iptables.service 2>/dev/null
	rm -f /etc/systemd/system/wg-iptables.service 2>/dev/null
	
	# Clean up any orphaned WireGuard interfaces
	if command -v wg &> /dev/null; then
		echo "Removing any orphaned WireGuard interfaces..."
		for iface in $(ip link show type wireguard 2>/dev/null | awk -F: '{print $2}' | tr -d ' '); do
			if [[ -n "$iface" ]]; then
				echo "  Removing interface: $iface"
				ip link delete "$iface" 2>/dev/null
			fi
		done
	fi
	
	# Reload systemd to clear any cached unit files
	echo "Reloading systemd daemon..."
	systemctl daemon-reload
	systemctl reset-failed 2>/dev/null
	
	echo "Cleanup completed. You can now set up WireGuard cleanly."
}

# Function to automatically clean orphaned services before setup
auto_cleanup_orphaned_services() {
	echo "Checking for orphaned WireGuard services..."
	local found_orphans=false
	local orphaned_services=()
	
	# Use systemctl list-unit-files with pattern for better reliability
	systemctl list-unit-files "wg-quick@*.service" 2>/dev/null | grep "wg-quick@" | awk '{print $1}' | while read -r service; do
		if [[ -n "$service" && "$service" =~ ^wg-quick@.+\.service$ ]]; then
			tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
			# Skip empty tunnel names
			if [[ -n "$tunnel_name" && "$tunnel_name" != "" ]]; then
				config_file="/etc/wireguard/${tunnel_name}.conf"
				if [[ ! -e "$config_file" ]]; then
					echo "$service" >> /tmp/auto_orphaned_services.tmp
				fi
			fi
		fi
	done
	
	# Read the temporary file into array
	if [[ -f /tmp/auto_orphaned_services.tmp ]]; then
		while IFS= read -r service; do
			orphaned_services+=("$service")
			found_orphans=true
		done < /tmp/auto_orphaned_services.tmp
		rm -f /tmp/auto_orphaned_services.tmp
	fi
	
	if [[ "$found_orphans" == true ]]; then
		echo "Found orphaned WireGuard services (missing config files):"
		for service in "${orphaned_services[@]}"; do
			tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
			echo "  - $service (missing: /etc/wireguard/${tunnel_name}.conf)"
		done
		echo
		read -p "Clean up these orphaned services automatically? [Y/n]: " cleanup_choice
		cleanup_choice=${cleanup_choice:-Y}
		
		if [[ "$cleanup_choice" =~ ^[yY]$ ]]; then
			echo "Cleaning up orphaned services..."
			for service in "${orphaned_services[@]}"; do
				tunnel_name=$(echo "$service" | sed 's/wg-quick@\(.*\)\.service/\1/')
				echo "  Completely removing $service (tunnel: $tunnel_name)"
				
				# Stop the service
				systemctl stop "$service" 2>/dev/null
				
				# Disable the service
				systemctl disable "$service" 2>/dev/null
				
				# Remove any override directories
				rm -rf "/etc/systemd/system/${service}.d/" 2>/dev/null
				
				# Remove any symlinks
				find /etc/systemd/system/ -name "${service}" -type l -delete 2>/dev/null
				find /etc/systemd/system/multi-user.target.wants/ -name "${service}" -type l -delete 2>/dev/null
				find /etc/systemd/system/default.target.wants/ -name "${service}" -type l -delete 2>/dev/null
				
				# Actually DELETE the service unit file if it exists
				if [[ -f "/etc/systemd/system/${service}" ]]; then
					echo "    Deleting service file: /etc/systemd/system/${service}"
					rm -f "/etc/systemd/system/${service}"
				fi
				
				if [[ -f "/lib/systemd/system/${service}" ]]; then
					echo "    Deleting system service file: /lib/systemd/system/${service}"
					rm -f "/lib/systemd/system/${service}"
				fi
				
				# Remove any generated unit files
				if [[ -f "/run/systemd/system/${service}" ]]; then
					echo "    Deleting runtime service file: /run/systemd/system/${service}"
					rm -f "/run/systemd/system/${service}"
				fi
			done
			
			# Force reload systemd
			systemctl daemon-reload
			systemctl reset-failed 2>/dev/null
			echo "Orphaned services completely deleted successfully."
		else
			echo "Skipping orphaned service cleanup."
		fi
		echo
	fi
}

update_physical_interface_for_zerotier() {
	echo "Updating physical interface configuration for ZeroTier setup..."
	
	# Detect the new physical interface
	physical_iface_detected=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
	physical_ip_detected=""
	if [[ -n "$physical_iface_detected" ]]; then
		physical_ip_detected=$(ip -4 addr show dev "$physical_iface_detected" | grep -oE 'inet [0-9.]+/' | awk '{print $2}' | cut -d/ -f1 | head -n1)
	fi
	
	echo "Detected physical (internet-facing) interface: $physical_iface_detected"
	echo "Detected physical (internet-facing) IP: $physical_ip_detected"
	read -p "Select the physical (internet-facing) interface for outbound internet [$physical_iface_detected]: " physical_iface
	physical_iface="${physical_iface:-$physical_iface_detected}"
	read -p "Select the physical (internet-facing) IPv4 address for outbound internet [$physical_ip_detected]: " physical_ip
	physical_ip="${physical_ip:-$physical_ip_detected}"
	while ! echo "$physical_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; do
		echo "Invalid IP format. Please try again."
		read -p "Select the physical (internet-facing) IPv4 address for outbound internet: " physical_ip
	done
	
	# Update firewall rules for the new physical interface
	if systemctl is-active --quiet firewalld.service; then
		# Remove old masquerade rules
		firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE 2>/dev/null
		firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE 2>/dev/null
		
		# Add new masquerade rules for the new interface
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE
	else
		# Update iptables service file
		iptables_path=$(command -v iptables)
		sed -i "s|ExecStart=.*-o .* -j MASQUERADE|ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o $physical_iface -j MASQUERADE|" /etc/systemd/system/wg-iptables.service
		systemctl daemon-reload
		systemctl restart wg-iptables.service
	fi
	
	echo "Physical interface configuration updated to use $physical_iface ($physical_ip)"
	echo "Restarting WireGuard service..."
	systemctl restart wg-quick@${wg_iface}.service
}

update_endpoint_and_regenerate_clients() {
	echo "Updating endpoint and regenerating client configurations..."
	
	# Get the current endpoint from the config
	current_endpoint=$(grep '^# ENDPOINT' $wg_conf_file | cut -d " " -f 3)
	port=$(grep '^ListenPort' $wg_conf_file | cut -d " " -f 3)
	
	echo "Current endpoint: $current_endpoint"
	echo
	
	# Get the new public IP
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
	read -p "Enter the new public IPv4 address or hostname [$get_public_ip]: " new_endpoint
	new_endpoint="${new_endpoint:-$get_public_ip}"
	
	while [[ -z "$new_endpoint" ]]; do
		echo "Endpoint cannot be empty."
		read -p "Enter the new public IPv4 address or hostname: " new_endpoint
	done
	
	echo "Updating server configuration with new endpoint: $new_endpoint"
	
	# Update the endpoint in the server config
	sed -i "s/^# ENDPOINT .*/# ENDPOINT $new_endpoint/" "$wg_conf_file"
	
	# Get list of all clients
	clients=($(grep '^# BEGIN_PEER' "$wg_conf_file" | cut -d ' ' -f 3))
	
	if [[ ${#clients[@]} -eq 0 ]]; then
		echo "No clients found. Only server configuration updated."
	else
		echo "Found ${#clients[@]} client(s). Regenerating client configurations..."
		
		echo "Generating new client configurations with updated endpoint..."
		
		# Remove existing clients from server config and regenerate with new keys
		for client in "${clients[@]}"; do
			echo "Regenerating client: $client"
			
			# Remove old peer from server config
			sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$wg_conf_file"
			
			# Add new peer with new keys
			new_client_config "$client"
			
			echo "New config generated: $client_conf_file"
			
			# Generate QR code if qrencode is available
			if command -v qrencode >/dev/null; then
				qrencode -t ansiutf8 < "$client_conf_file"
				echo
				echo "QR code generated above for $client"
				echo "Config file: $client_conf_file"
			fi
			echo "---"
		done
	fi
	
	echo "Restarting WireGuard service..."
	systemctl restart wg-quick@${selected_tunnel}.service
	echo "Server update completed!"
}

configure_routing_and_traffic() {
	echo "Configuring routing and traffic forwarding..."
	
	# Enable IP forwarding temporarily
	echo "Enabling IP forwarding..."
	sudo sysctl -w net.ipv4.ip_forward=1
	
	# Make IP forwarding persistent by adding to /etc/sysctl.conf
	if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
		echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
		echo "Added net.ipv4.ip_forward=1 to /etc/sysctl.conf for persistence"
	else
		echo "net.ipv4.ip_forward=1 already present in /etc/sysctl.conf"
	fi
	
	# Also create the systemd override file for WireGuard-specific forwarding
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	
	# Reload sysctl configuration
	echo "Reloading sysctl configuration..."
	sudo sysctl -p
	
	# Detect the primary network interface for internet access
	if [[ "$use_zerotier" == "y" ]]; then
		# Use the physical interface for MASQUERADE when ZeroTier is enabled
		primary_interface="${physical_iface_confirmed:-$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)}"
	else
		# Use the interface associated with the selected IP
		primary_interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
	fi
	
	if [[ -z "$primary_interface" ]]; then
		echo "Warning: Could not detect primary network interface. Using eth0 as fallback."
		primary_interface="eth0"
	fi
	
	echo "Using interface '$primary_interface' for NAT masquerading"
	
	# Configure iptables for NAT masquerading
	echo "Setting up iptables NAT masquerading..."
	sudo iptables -t nat -A POSTROUTING -o "$primary_interface" -j MASQUERADE
	
	# Install iptables-persistent to save rules
	echo "Installing iptables-persistent to save firewall rules..."
	if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
		sudo apt update
		# Use DEBIAN_FRONTEND=noninteractive to avoid interactive prompts
		sudo DEBIAN_FRONTEND=noninteractive apt install -y iptables-persistent
	elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
		# For CentOS/Fedora, use firewalld which is typically preferred
		if ! systemctl is-active --quiet firewalld.service; then
			sudo systemctl enable --now firewalld
		fi
	fi
	
	# Save iptables rules
	echo "Saving iptables rules..."
	if command -v netfilter-persistent &> /dev/null; then
		sudo netfilter-persistent save
	elif command -v iptables-save &> /dev/null; then
		# Fallback for systems without netfilter-persistent
		sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
	fi
	
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	
	# Configure IPv6 forwarding if IPv6 is being used
	if [[ -n "$ip6" ]]; then
		echo "Configuring IPv6 forwarding..."
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	
	echo "Routing and traffic forwarding configuration completed."
}

get_ip() {
	# Get the primary IPv4 address
	ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -n1
}

new_client_dns () {
	echo "Select a DNS server for the client:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
		# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2)
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
	esac
}

new_client_setup () {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs "$wg_conf_file" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		echo "253 clients are already configured. The WireGuard internal subnet is full!"
		exit
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> "$wg_conf_file"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' "$wg_conf_file" && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	
	# Create client configuration with tunnel name prefix
	# Use tunnel_name if we're in setup, selected_tunnel if we're adding to existing
	local tunnel_prefix="${tunnel_name:-$selected_tunnel}"
	local client_config_name="${tunnel_prefix}-${client}.conf"
	cat << EOF > ~/"$client_config_name"
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' "$wg_conf_file" && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = ${server_public_key:-$(grep PrivateKey "$wg_conf_file" | sed 's/.*= *//' | wg pubkey)}
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${server_endpoint:-$(grep '^# ENDPOINT' "$wg_conf_file" | cut -d " " -f 3)}:${port:-$(grep ListenPort "$wg_conf_file" | cut -d " " -f 3)}
PersistentKeepalive = 25
EOF
	
	# Set the client_conf_file variable for use in other functions
	client_conf_file=~/"$client_config_name"
}

main_server_setup() {
	# Check for and clean up orphaned services first
	auto_cleanup_orphaned_services
	
	echo
	echo "Enter a name for this WireGuard tunnel (used for config file and service name):"
	read -p "Tunnel name [wg-server]: " tunnel_name
	tunnel_name=${tunnel_name:-wg-server}
	
	# Sanitize tunnel name to ensure it's safe for filesystem and systemd
	tunnel_name=$(echo "$tunnel_name" | sed 's/[^a-zA-Z0-9_-]/-/g' | cut -c-32)
	wg_conf_file="/etc/wireguard/${tunnel_name}.conf"
	wg_iface="$tunnel_name"
	
	# Check if this tunnel name already exists
	if [[ -e "$wg_conf_file" ]]; then
		echo
		echo "A WireGuard tunnel named '$tunnel_name' already exists."
		echo "Would you like to:"
		echo "   1) Choose a different name"
		echo "   2) Replace the existing tunnel (all data will be lost)"
		echo "   3) Cancel setup"
		read -p "Option [1]: " name_conflict_option
		name_conflict_option=${name_conflict_option:-1}
		
		case "$name_conflict_option" in
			1)
				main_server_setup
				return
				;;
			2)
				echo "Removing existing tunnel '$tunnel_name'..."
				cleanup_specific_tunnel "$tunnel_name"
				;;
			3)
				echo "Setup cancelled."
				return
				;;
			*)
				echo "Invalid option. Setup cancelled."
				return
				;;
		esac
	fi
	
	echo "Setting up WireGuard tunnel: $tunnel_name"
	echo "Configuration file: $wg_conf_file"
	echo
	
	read -p "Will you be using ZeroTier for this WireGuard server's endpoint? [y/N]: " use_zerotier_input
	use_zerotier_input=$(echo "$use_zerotier_input" | tr '[:upper:]' '[:lower:]') # Convert to lowercase

	if [[ "$use_zerotier_input" == "y" ]]; then
		use_zerotier="y"
		echo "ZeroTier selected. Checking dependencies..."

		# Check for curl and install if missing
		if ! command -v curl &> /dev/null; then
			echo "curl is not installed. Attempting to install curl..."
			if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
				apt-get update && apt-get install -y curl
			elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				dnf install -y curl
			else
				echo "Unsupported OS for automatic curl installation. Please install curl manually and re-run."
				exit 1
			fi
			if ! command -v curl &> /dev/null; then
				echo "Failed to install curl. Please install it manually and re-run."
				exit 1
			else
				echo "curl installed successfully."
			fi
		fi

		# Check for ZeroTier and install if missing
		if ! command -v zerotier-cli &> /dev/null; then
			echo "ZeroTier is not installed. Attempting to install ZeroTier..."
			if curl -s https://install.zerotier.com | sudo bash; then
				echo "ZeroTier installed successfully."
			else
				echo "ZeroTier installation failed. Please try installing it manually or check for errors."
				exit 1
			fi
		else
			echo "ZeroTier appears to be already installed."
		fi
	fi


	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		# If ZeroTier is being used, clarify the prompt
		if [[ "$use_zerotier" == "y" ]]; then
			# Do not prompt for ZeroTier IP here; it will be prompted after ZeroTier setup.
			:
		else
			echo "Select the physical IPv4 address to use for the WireGuard endpoint:"
			ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
			read -p "Address [1]: " ip_number
			until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
				echo "$ip_number: invalid selection."
				read -p "Address [1]: " ip_number
			done
			[[ -z "$ip_number" ]] && ip_number="1"
			ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
		fi
	fi

	# ZeroTier setup if enabled
	if [[ "$use_zerotier" == "y" ]]; then
		echo
		echo "Please enter your ZeroTier Network ID to join."
		read -p "ZeroTier Network ID: " zt_network_id
		until [[ -n "$zt_network_id" ]]; do
			echo "Network ID cannot be empty."
			read -p "ZeroTier Network ID: " zt_network_id
		done
	
		echo "Attempting to join ZeroTier network $zt_network_id..."
		if sudo zerotier-cli join "$zt_network_id"; then
			echo "Successfully sent join request to network $zt_network_id."
			echo "IMPORTANT: Please go to your ZeroTier Central (my.zerotier.com)"
			echo "and authorize this new device on the network."
			echo
			read -p "Press Enter once the device is authorized on the ZeroTier network..."
		else
			echo "Failed to join ZeroTier network $zt_network_id."
			echo "Please check the Network ID and your ZeroTier configuration."
			exit 1
		fi
		echo
	
		# Detect ZeroTier IP (for endpoint)
		zt_iface=$(ip -o link show | awk -F': ' '{print $2}' | grep '^zt' | head -n1)
		zt_ip_detected=""
		if [[ -n "$zt_iface" ]]; then
			zt_ip_detected=$(ip -4 addr show dev "$zt_iface" | grep -oE 'inet [0-9.]+/' | awk '{print $2}' | cut -d/ -f1 | head -n1)
		fi
		echo "Detected ZeroTier interface: $zt_iface"
		echo "Detected ZeroTier IP: $zt_ip_detected"
		read -p "ZeroTier IP to use for WireGuard endpoint [$zt_ip_detected]: " zt_ip
		zt_ip="${zt_ip:-$zt_ip_detected}"
		while ! echo "$zt_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; do
			echo "Invalid IP format. Please try again."
			read -p "ZeroTier IP to use for WireGuard endpoint: " zt_ip
		done
	
		echo
		echo "To verify ZeroTier connectivity, please enter another IP address"
		echo "of a device on the same ZeroTier network ($zt_network_id)."
		read -p "IP address to ping: " zt_ping_target
		if [[ -n "$zt_ping_target" ]]; then
			# Basic validation for IP format
			while ! echo "$zt_ping_target" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; do
				echo "Invalid IP format for ping target. Please try again."
				read -p "IP address to ping: " zt_ping_target
				# If user clears the input, break from validation to skip ping test
				if [[ -z "$zt_ping_target" ]]; then
					break
				fi
			done
	
			# Proceed with ping test only if zt_ping_target is still not empty after validation
			if [[ -n "$zt_ping_target" ]]; then
				while true; do
					echo "Attempting to ping $zt_ping_target..."
					if ping -c 3 "$zt_ping_target"; then
						echo "Successfully pinged $zt_ping_target. ZeroTier connection confirmed."
						break
					else
						echo "Failed to ping $zt_ping_target."
						echo "Please check your ZeroTier network configuration, ensure the target device is online,"
						echo "and that this device is authorized on the network $zt_network_id."
						read -p "Press Enter to try pinging again, or Ctrl+C to exit."
					fi
				done
			else
				echo "Skipping ZeroTier ping test as no target IP was provided."
			fi
		else
			echo "Skipping ZeroTier ping test as no target IP was provided."
		fi
		echo
	
		public_ip="$zt_ip"
		zt_iface_confirmed="$zt_iface"
	
		# Prompt for physical (internet-facing) interface and IP for outbound NAT
		physical_iface_detected=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
		physical_ip_detected=""
		if [[ -n "$physical_iface_detected" ]]; then
			physical_ip_detected=$(ip -4 addr show dev "$physical_iface_detected" | grep -oE 'inet [0-9.]+/' | awk '{print $2}' | cut -d/ -f1 | head -n1)
		fi
		echo "Detected physical (internet-facing) interface: $physical_iface_detected"
		echo "Detected physical (internet-facing) IP: $physical_ip_detected"
		read -p "Select the physical (internet-facing) interface for outbound internet [$physical_iface_detected]: " physical_iface
		physical_iface="${physical_iface:-$physical_iface_detected}"
		read -p "Select the physical (internet-facing) IPv4 address for outbound internet [$physical_ip_detected]: " physical_ip
		physical_ip="${physical_ip:-$physical_ip_detected}"
		while ! echo "$physical_ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; do
			echo "Invalid IP format. Please try again."
			read -p "Select the physical (internet-facing) IPv4 address for outbound internet: " physical_ip
		done
	
		physical_iface_confirmed="$physical_iface"
		physical_ip_confirmed="$physical_ip"
		echo "Using ZeroTier IP $public_ip as the endpoint."
		echo "Using $physical_iface_confirmed ($physical_ip_confirmed) for outbound internet."
	else
		# Get server's primary IP if ZeroTier is not used
		ip=$(get_ip)
		# If $ip is a private IP address, the server must be behind NAT
		if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
			echo
			echo "This server is behind NAT. What is the public IPv4 address or hostname?"
			# Get public IP and sanitize with grep
			get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
			read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
			# If the checkip service is unavailable and user didn't provide input, ask again
			until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
				echo "Invalid input."
				read -p "Public IPv4 address / hostname: " public_ip
			done
			[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
		else
			# Server has a public IP, use it directly
			public_ip="$ip"
		fi
	fi

	# IPv6 selection
	ip6="" # Initialize ip6 to empty
	
	# First, ensure an IPv4 address ($ip) has been determined.
	if [[ -n "$ip" ]]; then
		ipv4_interface=$(ip -o -4 addr show | grep -w "inet $ip/" | awk '{print $2}' | head -n 1)
		
		if [[ -n "$ipv4_interface" ]]; then
			echo # Blank line for readability
			echo "Looking for IPv6 addresses on interface '$ipv4_interface' (associated with IPv4 $ip)..."
			
			# Get global/unique IPv6 addresses on this specific interface, excluding link-local (fe80::) and loopback (::1)
			mapfile -t interface_ip6_addresses < <(ip -6 addr show dev "$ipv4_interface" | grep 'inet6 ' | grep -v ' fe80::' | grep -v ' ::1/' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
			number_of_interface_ip6=${#interface_ip6_addresses[@]}

			if [[ "$number_of_interface_ip6" -eq 1 ]]; then
				ip6="${interface_ip6_addresses[0]}"
				echo "Automatically selected IPv6 address $ip6 from interface $ipv4_interface for WireGuard."
			elif [[ "$number_of_interface_ip6" -gt 1 ]]; then
				echo "Multiple IPv6 addresses found on interface $ipv4_interface:"
				for i in "${!interface_ip6_addresses[@]}"; do
					printf "   %s) %s\n" "$((i+1))" "${interface_ip6_addresses[i]}"
				done
				read -p "Which IPv6 address should be used for WireGuard? (Enter for [1], 's' to skip) [1]: " ip6_choice_input
				
				if [[ "$ip6_choice_input" =~ ^[sS]$ ]]; then
					echo "Skipping IPv6 configuration for WireGuard."
				else
					ip6_number_to_use=${ip6_choice_input:-1} # Default to 1 if input is empty
					
					if [[ "$ip6_number_to_use" =~ ^[0-9]+$ && "$ip6_number_to_use" -ge 1 && "$ip6_number_to_use" -le "$number_of_interface_ip6" ]]; then
						ip6="${interface_ip6_addresses[$((ip6_number_to_use-1))]}"
						echo "Selected IPv6 address $ip6 for WireGuard."
					else
						echo "Invalid selection '$ip6_choice_input'. Skipping IPv6 configuration for WireGuard."
					fi
				fi
			else
				echo "No suitable (global/unique) IPv6 address found on interface $ipv4_interface. IPv6 will not be configured for WireGuard."
			fi
		else
			echo # Blank line
			echo "Could not determine the network interface for IPv4 $ip. IPv6 will not be configured for WireGuard."
		fi
	else
		echo # Blank line
		echo "No primary IPv4 address selected/determined. IPv6 will not be configured for WireGuard."
	fi

	echo
	echo "What port should WireGuard listen to?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited lenght and set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	
	# Set up automatic updates for BoringTun if the user is fine with that
	if [[ "$use_boringtun" -eq 1 ]]; then
		echo
		echo "BoringTun will be installed to set up WireGuard in the system."
		read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		done
		[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				cron="cronie"
			elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
				cron="cron"
			fi
		fi
	fi
	echo
	echo "WireGuard installation is ready to begin."
	
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."

	# Install WireGuard
	if [[ "$use_boringtun" -eq 0 ]]; then
		if [[ "$os" == "ubuntu" ]]; then
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" ]]; then
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "centos" ]]; then
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode $firewall
		elif [[ "$os" == "fedora" ]]; then
			dnf install -y wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		fi
	else
		# Install required packages for BoringTun
		if [[ "$os" == "ubuntu" ]]; then
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" ]]; then
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "centos" ]]; then
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
		elif [[ "$os" == "fedora" ]]; then
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		fi
		
		# Install BoringTun
		{ wget -qO- https://wg.blackh00d.be/1/latest/download 2>/dev/null || curl -sL https://wg.blackh00d.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
		mkdir /etc/systemd/system/wg-quick@${tunnel_name}.service.d/ 2>/dev/null
		echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@${tunnel_name}.service.d/boringtun.conf
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service
		fi
	fi
	
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi

	# Generate server private key first
	server_private_key=$(wg genkey)
	server_public_key=$(echo "$server_private_key" | wg pubkey)
	
	# Set endpoint for client configs
	server_endpoint=$([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")
	
	# Generate WireGuard configuration
	cat << EOF > $wg_conf_file
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $server_endpoint$(if [[ "$use_zerotier" == "y" ]]; then echo "
# ZeroTier setup"; fi)

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $server_private_key
ListenPort = $port

EOF
	chmod 600 $wg_conf_file
	
	# Configure routing and traffic forwarding
	configure_routing_and_traffic
	
	# Configure firewall rules
	if systemctl is-active --quiet firewalld.service; then
		# Configure firewalld
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
		
		# Set NAT for the VPN subnet
		firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip" 2>/dev/null
		firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip" 2>/dev/null
		
		if [[ "$use_zerotier" == "y" ]]; then
			physical_iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
			if [[ -z "$physical_iface" ]]; then
				echo "Could not detect the physical interface for outbound NAT. Please check your routing."
				exit 1
			fi
			firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE 2>/dev/null
			firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE 2>/dev/null
			firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE 2>/dev/null
			firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE 2>/dev/null
			firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE
			firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o "$physical_iface" -j MASQUERADE
		else
			firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
			firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		fi
		
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
		fi
	else
		# Configure iptables
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip || true" > /etc/systemd/system/wg-iptables.service

		if [[ "$use_zerotier" == "y" ]]; then
			physical_iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
			if [[ -z "$physical_iface" ]]; then
				echo "Could not detect the physical interface for outbound NAT. Please check your routing."
				exit 1
			fi
			echo "ExecStart=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE || true
ExecStart=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o $physical_iface -j MASQUERADE || true
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -o $physical_iface -j MASQUERADE" >> /etc/systemd/system/wg-iptables.service
		else
			echo "ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip" >> /etc/systemd/system/wg-iptables.service
		fi

		echo "ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service

		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi

		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service
	fi

	# Generate the first client configuration
	new_client_setup

	# Enable and start the wg-quick service
	echo "Starting WireGuard tunnel: $tunnel_name"
	systemctl enable wg-quick@${tunnel_name}.service
	if systemctl start wg-quick@${tunnel_name}.service; then
		echo "✓ WireGuard tunnel '$tunnel_name' started successfully"
		
		# Verify the service is running
		sleep 2
		if systemctl is-active --quiet wg-quick@${tunnel_name}.service; then
			echo "✓ Service is running properly"
		else
			echo "⚠ Warning: Service may not be running properly"
			echo "Check status with: systemctl status wg-quick@${tunnel_name}.service"
		fi
	else
		echo "✗ Failed to start WireGuard tunnel '$tunnel_name'"
		echo "Check the logs with: journalctl -u wg-quick@${tunnel_name}.service"
		echo "Check the configuration with: wg-quick up $tunnel_name"
	fi

	# Set up automatic updates for BoringTun if requested
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.blackh00d.be/1/latest 2>/dev/null || curl -sL https://wg.blackh00d.be/1/latest 2>/dev/null)
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	download="https://wg.blackh00d.be/1/latest/download"
	xdir=$(mktemp -d)
	if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@${tunnel_name}.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@${tunnel_name}.service
		echo "Successfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed"
	fi
	rm -rf "$xdir"
else
	echo "$current is up to date"
fi
EOF
		chmod +x /usr/local/sbin/boringtun-upgrade
		{ crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi

	echo
	qrencode -t ANSI256UTF8 < "$client_conf_file"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	qrencode -t UTF8 < "$client_conf_file" > ~/"${tunnel_name}-${client}"_qr.txt
	echo "A text-based QR code has also been saved to:" ~/"${tunnel_name}-${client}"_qr.txt
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in: $client_conf_file"
	echo "Tunnel name: $tunnel_name"
	echo "Service: wg-quick@${tunnel_name}.service"
	echo
	echo "To manage this tunnel:"
	echo "  Start:  systemctl start wg-quick@${tunnel_name}.service"
	echo "  Stop:   systemctl stop wg-quick@${tunnel_name}.service"
	echo "  Status: systemctl status wg-quick@${tunnel_name}.service"
	echo
	echo "New clients can be added by running this script again."
}

wg_iface_num=0
while [[ -e "/etc/wireguard/wg${wg_iface_num}.conf" ]]; do
	(( wg_iface_num++ ))
done
wg_iface="wg${wg_iface_num}"
wg_conf_file="/etc/wireguard/${wg_iface}.conf"

# Always show the main menu - the individual functions will check if WireGuard is installed
main_menu
