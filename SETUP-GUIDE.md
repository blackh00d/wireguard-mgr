# WireGuard VPS-Pi Relay Management Guide

This guide covers the complete setup process for creating a WireGuard relay system using a VPS and a Pi server.

## System Overview

```
[Clients] → [VPS Relay] → [Pi Server] → [Local Network]
```

### Network Architecture
- **VPS**: Public relay point with static IP (10.99.0.1/24)
- **Pi**: VPN server behind NAT (10.99.0.2/24)
- **Clients**: Connect to VPS (10.100.0.0/24)

### Key Components
- VPS setup script (`vps-setup.sh`)
- Pi setup script (`pi-setup.sh`)
- Client management script (`client-manager.sh`)

## Prerequisites

### VPS Requirements
- Ubuntu/Debian-based system
- Public IP address
- Root access
- Open UDP port (default: 51820)
- 1GB RAM minimum
- 10GB storage minimum

### Pi Requirements
- Raspberry Pi or similar Linux device
- Connected to home network
- Root access
- 512MB RAM minimum
- 5GB storage minimum

## Complete Setup Process

### Step 1: VPS Initial Setup

1. **Connect to VPS**
   ```bash
   ssh root@your-vps-ip
   ```

2. **Download Setup Script**
   ```bash
   wget https://raw.githubusercontent.com/your-repo/wireguard-mgr/main/vps-setup.sh
   chmod +x vps-setup.sh
   ```

3. **Run Setup Script**
   ```bash
   sudo ./vps-setup.sh
   ```

4. **Follow Interactive Menu**
   - Choose option 1 to start setup
   - The script will automatically install all required dependencies
   - Confirm auto-detected public IP
   - Confirm network interface
   - Note the generated VPS public key
   - Save the configuration backup location

5. **Verify Setup**
   - Interactive Menu: Run `sudo ./vps-setup.sh` and choose option 2 to check status
   - Quick CLI: Run `sudo ./vps-setup.sh status`
   - Verify that the WireGuard interface is up and running
   - Confirm that the VPS public key is displayed

### Step 2: Pi Server Setup

1. **Connect to Pi**
   ```bash
   ssh root@your-pi-ip
   ```

2. **Download Setup Script**
   ```bash
   wget https://raw.githubusercontent.com/your-repo/wireguard-mgr/main/pi-setup.sh
   chmod +x pi-setup.sh
   ```

3. **Run Setup Script**
   ```bash
   sudo ./pi-setup.sh
   ```

4. **Follow Interactive Menu**
   - Choose option 1 to start setup
   - The script will automatically install all required dependencies
   - Enter VPS public key (from Step 1)
   - Enter VPS public IP
   - Confirm local network interface
   - Confirm local subnet
   - Note the generated Pi public key
   - Save the configuration backup location

5. **Verify Setup**
   - Interactive Menu: Run `sudo ./pi-setup.sh` and choose option 2 to check status
   - Quick CLI: Run `sudo ./pi-setup.sh status`
   - Verify that the WireGuard interface is up and running
   - Confirm that the Pi public key is displayed

### Step 3: Connect VPS and Pi

1. **Update VPS Configuration**
   - Go back to VPS
   - Run `sudo ./vps-setup.sh`
   - Choose option 3 to configure settings
   - Enter the Pi's public key when prompted
   - The script will automatically update the configuration

2. **Start WireGuard on Both Systems**
   - On VPS: Run `sudo ./vps-setup.sh` and choose option 4 to restart service
   - On Pi: Run `sudo ./pi-setup.sh` and choose option 4 to restart service

3. **Test Connection**
   - On Pi: 
     - Interactive Menu: Run `sudo ./pi-setup.sh` and choose option 2
     - Quick CLI: Run `sudo ./pi-setup.sh status`
   - On VPS: 
     - Interactive Menu: Run `sudo ./vps-setup.sh` and choose option 2
     - Quick CLI: Run `sudo ./vps-setup.sh status`
   - Verify that both show an active connection

### Step 4: Client Manager Setup

1. **Install Client Manager**
   ```bash
   # On VPS
   wget https://raw.githubusercontent.com/your-repo/wireguard-mgr/main/client-manager.sh
   chmod +x client-manager.sh
   ```

2. **Initial Configuration**
   ```bash
   sudo ./client-manager.sh
   ```
   - The script will automatically install all required dependencies
   - The script will auto-detect your WireGuard interface
   - Verify the detected interface matches your setup
   - Check that the client network range is correct (10.100.0.0/24)

3. **Test Client Manager**
   - Choose option 1 from the menu to add a test client
   - Enter a name for the test client
   - The script will generate the client configuration
   - Choose option 2 to list clients and verify the test client was added
   - Choose option 3 to view the client's configuration

### Step 5: Add Clients

1. **Add New Client**
   - Run `sudo ./client-manager.sh`
   - Choose option 1 from the menu
   - Enter the client name
   - The script will generate the configuration

2. **Configure Client Device**
   - Choose option 3 from the menu to view the client's configuration
   - Copy the configuration file from the displayed path
   - For mobile devices, choose option 4 to generate a QR code
   - Import the configuration into the WireGuard client
   - Connect to VPS public IP

3. **Verify Client Connection**
   - Choose option 2 from the menu to list all clients
   - Verify that the new client appears in the list
   - Choose option 5 to check the overall system status

## Troubleshooting

### Common Issues

1. **WireGuard Interface Not Starting**
   - Interactive Menu: Run the appropriate script and choose option 2
   - Quick CLI: Run `sudo ./vps-setup.sh status` or `sudo ./pi-setup.sh status`
   - Review the error messages displayed

2. **Connection Issues**
   - Interactive Menu: Run the appropriate script and choose option 2
   - Quick CLI: Run `sudo ./vps-setup.sh status` or `sudo ./pi-setup.sh status`
   - Verify that the interface is up
   - Check that the routing is correct
   - Verify that the connection is established

3. **Client Connection Problems**
   - Interactive Menu: Run `sudo ./client-manager.sh` and choose option 2
   - Quick CLI: Run `sudo ./client-manager.sh status`
   - Verify the client configuration

### Recovery Procedures

1. **Reset WireGuard Interface**
   - Run the appropriate script
   - Choose option 4 to restart the service

2. **Restore Configuration**
   - Run the appropriate script
   - Choose option 3 to configure settings
   - Re-enter the configuration values

3. **Complete Reset**
   - Run the appropriate script
   - Choose option 5 to remove the configuration
   - Run the script again and choose option 1 to set up from scratch

## Security Considerations

1. **Key Management**
   - Private keys are stored in `/etc/wireguard/`
   - Backup keys are stored in `/etc/wireguard/*-keys-*.txt`
   - Keep backups secure and encrypted

2. **Network Security**
   - Only UDP port 51820 needs to be open on VPS
   - All traffic is encrypted end-to-end
   - No port forwarding needed on home router

3. **System Security**
   - Regular system updates recommended
   - Monitor system logs for unusual activity
   - Keep backup of all configurations

## Maintenance

1. **Regular Updates**
   ```bash
   sudo apt update
   sudo apt upgrade
   ```

2. **Configuration Backups**
   - Run `sudo ./client-manager.sh`
   - Choose option 6 to backup all client configurations

3. **Monitoring**
   - Interactive Menu: Run `sudo ./client-manager.sh` and choose option 5
   - Quick CLI: Run `sudo ./client-manager.sh status`
   - Review the connection information displayed