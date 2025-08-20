# OpenSSH Server Setup Guide Using a PowerShell Script

This README.md explains how to set up and use a secure SSH server created with PowerShell.

## Quick Start

### 1. Install and Configure SSH Server

Run PowerShell as Administrator and execute:

```powershell
.\simple-OpenSSH-Server.ps1
```

This will:
- Install OpenSSH Server
- Configure secure settings
- Generate SSH keys
- Configure Windows Firewall
- Start the SSH service

### 2. Check Server Status

```powershell
.\simple-OpenSSH-Server.ps1 -Action Status
```

## Usage Examples

### Basic Installation with Default Settings
```powershell
.\simple-OpenSSH-Server.ps1 -Action Install
```

### Install on Custom Port
```powershell
.\simple-OpenSSH-Server.ps1 -Action Install -Port 2222
```

### Install with Password Authentication Disabled (Key-only)
```powershell
.\simple-OpenSSH-Server.ps1 -Action Install -DisablePasswordAuth
```

### Allow Specific Users Only
```powershell
.\simple-OpenSSH-Server.ps1 -Action Install -AllowUsers "user1,user2,admin"
```

### Reconfigure Existing Installation
```powershell
.\simple-OpenSSH-Server.ps1 -Action Configure -Port 2222 -DisablePasswordAuth
```

### Server Management
```powershell
# Start the server
.\simple-OpenSSH-Server.ps1 -Action Start

# Stop the server
.\simple-OpenSSH-Server.ps1 -Action Stop

# Restart the server
.\simple-OpenSSH-Server.ps1 -Action Restart

# Check status
.\simple-OpenSSH-Server.ps1 -Action Status

# Uninstall completely
.\simple-OpenSSH-Server.ps1 -Action Uninstall
```

## Security Features

### Authentication
- **Key-based authentication**: RSA 4096-bit keys generated automatically
- **Password authentication**: Can be enabled/disabled
- **Multi-factor authentication**: Supports both key + password
- **Failed login protection**: Max 3 authentication attempts

### Access Control
- **User restrictions**: Only specified users can connect
- **Root login disabled**: No administrator remote login by default
- **Session limits**: Maximum 10 concurrent sessions
- **Connection timeouts**: Idle connections terminated after 5 minutes

### Network Security
- **Firewall integration**: Automatic Windows Firewall configuration
- **Port customization**: Run on non-standard ports
- **Protocol version**: SSH Protocol 2 only
- **Address binding**: IPv4 only by default

### File Permissions
- **SSH keys**: Proper Windows ACL permissions set automatically
- **Configuration files**: Secured against unauthorized access
- **User directories**: .ssh folders created with correct permissions

## Connecting to the SSH Server

### From Windows (PowerShell/Command Prompt)
```cmd
ssh username@server-ip-address
```

### From Linux/Mac Terminal
```bash
ssh username@server-ip-address
```

### Using SSH Keys
```bash
ssh -i ~/.ssh/id_rsa username@server-ip-address
```

### Custom Port
```bash
ssh -p 2222 username@server-ip-address
```

### SFTP File Transfer
```bash
sftp username@server-ip-address
```

## Configuration Files

### SSH Server Configuration
- **Location**: `C:\ProgramData\ssh\sshd_config`
- **Backup**: Automatic backup created before changes
- **Format**: Standard OpenSSH configuration format

### SSH Keys Location
- **User keys**: `C:\Users\[username]\.ssh\`
- **Private key**: `id_rsa`
- **Public key**: `id_rsa.pub`
- **Authorized keys**: `authorized_keys`

## Troubleshooting

### Common Issues

1. **Service won't start**
   - Check if running as Administrator
   - Verify Windows version compatibility
   - Check Windows Event Logs

2. **Connection refused**
   - Verify Windows Firewall rules
   - Check if service is running
   - Confirm correct port number

3. **Authentication failed**
   - Verify user is in AllowUsers list
   - Check SSH key permissions
   - Confirm password authentication settings

### Log Files
- **SSH Service Logs**: Windows Event Viewer → Applications and Services → OpenSSH
- **Connection Logs**: Check `LogLevel INFO` in configuration

### Useful Commands

```powershell
# Check service status
Get-Service sshd

# View SSH processes
Get-Process | Where-Object {$_.Name -like "*ssh*"}

# Check listening ports
netstat -an | findstr ":22"

# Test configuration
sshd -T

# View firewall rules
Get-NetFirewallRule -DisplayName "*SSH*"
```

## Security Best Practices

1. **Use Key Authentication**: Disable password authentication when possible
2. **Custom Ports**: Use non-standard ports to reduce automated attacks
3. **User Restrictions**: Limit SSH access to specific users only
4. **Regular Updates**: Keep Windows and SSH components updated
5. **Monitor Logs**: Regularly check SSH connection logs
6. **Network Restrictions**: Use firewall rules to limit source IPs if needed
7. **Strong Passwords**: If using password auth, enforce strong password policies

## Advanced Configuration

### Custom SSH Configuration
Edit `C:\ProgramData\ssh\sshd_config` for advanced settings:

```
# Allow specific IP ranges only
AllowUsers username@192.168.1.*

# Disable TCP forwarding
AllowTcpForwarding no

# Change login grace time
LoginGraceTime 30

# Set custom banner
Banner C:\ssh-banner.txt
```

### Multiple User Keys
Each user can have their own SSH keys in their profile:
- `C:\Users\[username]\.ssh\authorized_keys`

Remember to restart the SSH service after configuration changes:
```powershell
Restart-Service sshd
```
