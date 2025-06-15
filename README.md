# WireGuard VPS Relay Setup

A complete solution for setting up WireGuard with a VPS relay, allowing a Pi server behind NAT to handle client connections without port forwarding.

## 🎯 What This Does

This setup creates a WireGuard relay system where:
- **VPS** acts as a public endpoint that clients connect to
- **Pi** (behind NAT at home) handles all the actual traffic routing
- **No port forwarding** needed on your home router
- **All client traffic** goes through your Pi at home
- **Interactive menus** for easy configuration
- **Complete safety features** including backups and validation

## 📁 Files Included

| File | Description |
|------|-------------|
| [`vps-setup.sh`](vps-setup.sh) | Automated VPS setup script |
| [`pi-setup.sh`](pi-setup.sh) | Automated Pi setup script |
| [`client-manager.sh`](client-manager.sh) | Client management tool for VPS |
| [`SETUP-GUIDE.md`](SETUP-GUIDE.md) | Complete setup instructions |

## 🚀 Quick Start

### 1. Set up the VPS
```bash
# On your VPS
wget https://raw.githubusercontent.com/yourusername/wireguard-mgr/main/vps-setup.sh
chmod +x vps-setup.sh
sudo ./vps-setup.sh
```

### 2. Set up the Pi
```bash
# On your Pi
wget https://raw.githubusercontent.com/yourusername/wireguard-mgr/main/pi-setup.sh
chmod +x pi-setup.sh
sudo ./pi-setup.sh
```

### 3. Link them together
Follow the output instructions to exchange public keys between VPS and Pi.

### 4. Add clients
```bash
# On your VPS
wget https://raw.githubusercontent.com/yourusername/wireguard-mgr/main/client-manager.sh
chmod +x client-manager.sh
sudo ./client-manager.sh add myclient
```

## 📖 Documentation

For detailed setup instructions, troubleshooting, and advanced configuration, see [`SETUP-GUIDE.md`](SETUP-GUIDE.md).

## 🔧 Client Management

The [`client-manager.sh`](client-manager.sh) script provides comprehensive client management capabilities:

### Core Features
- **Interactive Menu**: Easy-to-use interface for all operations
- **Command Line Mode**: Scriptable operations for automation
- **QR Code Generation**: Mobile-friendly setup with QR codes
- **Configuration Validation**: Automatic validation of all changes
- **Backup System**: Automatic backups before any modifications
- **Status Monitoring**: Real-time connection status tracking

### Common Operations
```bash
# Add a new client
sudo ./client-manager.sh add client1

# List all clients
sudo ./client-manager.sh list

# Show client config
sudo ./client-manager.sh show client1

# Generate QR code for mobile setup
sudo ./client-manager.sh qr client1

# Remove a client
sudo ./client-manager.sh remove client1

# Show WireGuard status
sudo ./client-manager.sh status
```

### Advanced Features
- **Multiple Interface Support**: Manage different WireGuard interfaces
- **Automatic IP Assignment**: Smart IP allocation within network range
- **Connection Monitoring**: Track client connection status
- **Configuration Backup**: Automatic backup before changes
- **Validation Checks**: Comprehensive validation of all operations

### Safety Features
- Automatic backup before any changes
- Configuration validation at every step
- Safe removal with system state restoration
- Comprehensive error handling
- Permission checks and validation

## 🏗️ Architecture

```
[Client Device] 
       ↓
[VPS Public IP:51820] (Relay)
       ↓
[Pi behind NAT] (Actual WireGuard Server)
       ↓
[Internet/Home Network]
```

**Network Ranges:**
- VPS ↔ Pi tunnel: `10.99.0.0/24`
- Client connections: `10.100.0.0/24`

## ✅ Features

- **No port forwarding required** on home router
- **Automated setup scripts** for both VPS and Pi
- **Interactive menus** for user-friendly configuration
- **Easy client management** with dedicated script
- **QR code generation** for mobile clients
- **Comprehensive logging** and status monitoring
- **Security best practices** built-in
- **Complete system backups** before any changes
- **Configuration validation** at every step
- **Safe removal** with system state restoration

## 🔒 Security

- All private keys are generated locally and stored securely
- Traffic is encrypted end-to-end via WireGuard
- No unnecessary ports exposed on home network
- Regular security updates recommended

## 🛠️ Requirements

**VPS:**
- Linux server (Ubuntu/Debian recommended)
- Public IP address
- Root access

**Pi:**
- Raspberry Pi or any Linux device
- Connected to home network
- Root access

## 📞 Support

If you encounter issues:

1. Check the [`SETUP-GUIDE.md`](SETUP-GUIDE.md) troubleshooting section
2. Verify all steps were followed correctly
3. Check WireGuard logs: `sudo journalctl -u wg-quick@wg0`

## 🤝 Contributing

Feel free to submit issues or pull requests to improve these scripts.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.