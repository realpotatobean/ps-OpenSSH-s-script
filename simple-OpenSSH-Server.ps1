# SSH Server Setup and Management Script for Windows
# Run as Administrator

#-  Defines command-line parameters the script accepts
#-  ValidateSet ensures only valid actions can be used
#-  Default values are set (Install action, port 22, current user allowed)
#-  Uses [switch] for boolean parameters (true/false flags)


param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Configure", "Start", "Stop", "Status", "Restart", "Uninstall")]
    [string]$Action = "Install",
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 22,
    
    [Parameter(Mandatory=$false)]
    [string]$AllowUsers = $env:USERNAME,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableKeyAuth = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$DisablePasswordAuth = $false
)

#---------------------------------------------------------------------------------

# Check if running as Administrator

#-  Gets the current Windows identity
#-  Creates a security principal object
#-  Checks if the user has Administrator role
#-  Exits script with error code 1 if not running as admin

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "This script requires Administrator privileges. Please run PowerShell as Administrator." -ForegroundColor Red
    exit 1
}

#---------------------------------------------------------------------------------

# SSH Server Installation Function

#1. Check Installation Status: Uses Get-WindowsCapability to see if OpenSSH Server is already installed
#2. Install if Missing: Uses Add-WindowsCapability to install the Windows feature
#3. Configure Service: 
#-  Sets startup type to 'Automatic' (starts with Windows)
#-  Starts the service immediately
#4. Configure Firewall: 
#-  Checks if firewall rule exists
#-  Creates or updates the rule to allow incoming connections on the specified port

function Install-SSHServer {
    Write-Host "Installing OpenSSH Server..." -ForegroundColor Green
    
    # Check if OpenSSH Server is available
    $sshServerFeature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    
    if ($sshServerFeature.State -eq "NotPresent") {
        Write-Host "Installing OpenSSH Server capability..." -ForegroundColor Yellow
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    }
    else {
        Write-Host "OpenSSH Server is already installed." -ForegroundColor Green
    }
    
    # Enable and start the service
    Write-Host "Configuring SSH Server service..." -ForegroundColor Yellow
    Set-Service -Name sshd -StartupType 'Automatic'
    Start-Service sshd
    
    # Configure Windows Firewall
    Write-Host "Configuring Windows Firewall..." -ForegroundColor Yellow
    if (-not (Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $Port
    }
    else {
        Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -LocalPort $Port
    }
    
    Write-Host "OpenSSH Server installed and started successfully!" -ForegroundColor Green
}

#---------------------------------------------------------------------------------

# SSH Configuration Function

#-  Defines paths for the SSH configuration file
#-  Creates a timestamped backup of existing configuration
#-  Uses $env:ProgramData to get the system data directory


function Configure-SSHServer {
    Write-Host "Configuring SSH Server security settings..." -ForegroundColor Green
    
    $configPath = "$env:ProgramData\ssh\sshd_config"
    $backupPath = "$env:ProgramData\ssh\sshd_config.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    
    # Backup existing config
    if (Test-Path $configPath) {
        Copy-Item $configPath $backupPath
        Write-Host "Backed up existing config to: $backupPath" -ForegroundColor Yellow
    }

#---------------------------------------------------------------------------------

    
    # Create secure SSH configuration

#-  Here-string (@"..."@): Creates multi-line string with variable substitution
#-  Security settings: Disables root login, limits auth attempts, sets timeouts
#-  Variable substitution: $Port, $AllowUsers, and conditional password auth
#-  Access control: Specifies which users can/cannot connect

    $sshConfig = @"
# SSH Server Configuration - Enhanced Security
Port $Port
Protocol 2

# Authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication $(if ($DisablePasswordAuth) { "no" } else { "yes" })
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM no

# Security Settings
PermitRootLogin no
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# User/Group restrictions
AllowUsers $AllowUsers
DenyUsers Guest
DenyGroups Guests

# Network settings
AddressFamily inet
ListenAddress 0.0.0.0
TCPKeepAlive yes

# Logging
SyslogFacility AUTH
LogLevel INFO

# Disable unused features
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts no
X11Forwarding no
PermitTunnel no

# Windows specific settings
Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -NoLogo -NoProfile
Subsystem sftp sftp-server.exe

# Override default of no subsystems
Subsystem sftp sftp-server.exe
"@

#---------------------------------------------------------------------------------

    # Write configuration

#-  icacls: Windows command-line tool for setting file permissions
#-  /inheritance:r: Removes inherited permissions
#-  /grant: Grants specific permissions (F=Full, R=Read)
#-  Ensures only Administrators and SYSTEM can access SSH config

    $sshConfig | Out-File -FilePath $configPath -Encoding ASCII
    Write-Host "SSH configuration written to: $configPath" -ForegroundColor Green
    
    # Set proper permissions on SSH directory
    $sshDir = "$env:ProgramData\ssh"
    if (Test-Path $sshDir) {
        icacls $sshDir /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"
        icacls $configPath /inheritance:r /grant "Administrators:R" /grant "SYSTEM:R"
        Write-Host "Set secure permissions on SSH configuration directory" -ForegroundColor Green
    }
}

#---------------------------------------------------------------------------------

# SSH Key Setup Function

#-  Gets user's profile directory (C:\Users\username)
#-  Creates .ssh directory if it doesn't exist
#-  Sets secure permissions (only the user has full access)

function Setup-SSHKeys {
    Write-Host "Setting up SSH key authentication..." -ForegroundColor Green
    
    $userProfile = $env:USERPROFILE
    $sshDir = "$userProfile\.ssh"
    
    # Create .ssh directory if it doesn't exist
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force
        Write-Host "Created SSH directory: $sshDir" -ForegroundColor Yellow
    }
    
    # Set proper permissions on .ssh directory
    icacls $sshDir /inheritance:r /grant "$($env:USERNAME):F"
    
    #-------------------------------------

    #-  ssh-keygen: Standard SSH key generation tool
    #  -t rsa: RSA key type
    #  -b 4096: 4096-bit key length (very secure)
    #  -f $keyPath: Output file path
    #  -N '""': Empty passphrase
    #  -C: Comment (username@computername)


    $keyPath = "$sshDir\id_rsa"
    $pubKeyPath = "$sshDir\id_rsa.pub"
    $authorizedKeysPath = "$sshDir\authorized_keys"
    
    # Generate SSH key pair if it doesn't exist
    if (-not (Test-Path $keyPath)) {
        Write-Host "Generating SSH key pair..." -ForegroundColor Yellow
        ssh-keygen -t rsa -b 4096 -f $keyPath -N '""' -C "$env:USERNAME@$env:COMPUTERNAME"
        
        # Set proper permissions on private key
        icacls $keyPath /inheritance:r /grant "$($env:USERNAME):R"
        
        Write-Host "SSH key pair generated:" -ForegroundColor Green
        Write-Host "  Private key: $keyPath" -ForegroundColor White
        Write-Host "  Public key: $pubKeyPath" -ForegroundColor White
    }

    #-------------------------------------

    #-  Reads the generated public key
    #-  Adds it to authorized_keys file (allows this key to authenticate)
    #-  Sets secure permissions on the authorized_keys file
    
    # Add public key to authorized_keys if it exists
    if (Test-Path $pubKeyPath) {
        $pubKey = Get-Content $pubKeyPath
        if (-not (Test-Path $authorizedKeysPath) -or -not ((Get-Content $authorizedKeysPath -ErrorAction SilentlyContinue) -contains $pubKey)) {
            $pubKey | Add-Content $authorizedKeysPath
            icacls $authorizedKeysPath /inheritance:r /grant "$($env:USERNAME):R"
            Write-Host "Added public key to authorized_keys" -ForegroundColor Green
        }
    }
}

#---------------------------------------------------------------------------------

# Status Display Function

#-  Get-Service: Gets Windows service information
#-  Conditional coloring: Green for running, red for stopped
#-  Error handling: -ErrorAction SilentlyContinue prevents errors if service doesn't exist

function Show-SSHStatus {
    Write-Host "`nSSH Server Status:" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    
    # Service status
    $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($sshService) {
        Write-Host "Service Status: $($sshService.Status)" -ForegroundColor $(if ($sshService.Status -eq 'Running') { 'Green' } else { 'Red' })
        Write-Host "Startup Type: $($sshService.StartType)" -ForegroundColor White
    }
    else {
        Write-Host "SSH Server service not found" -ForegroundColor Red
    }

    #-------------------------------------
    
    # Firewall rule
    $firewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($firewallRule) {
        Write-Host "Firewall Rule: Enabled" -ForegroundColor Green
    }
    else {
        Write-Host "Firewall Rule: Not configured" -ForegroundColor Red
    }
    
    # Configuration file
    $configPath = "$env:ProgramData\ssh\sshd_config"
    if (Test-Path $configPath) {
        Write-Host "Config File: $configPath" -ForegroundColor Green
        $port = (Get-Content $configPath | Select-String "^Port" | Select-Object -First 1) -replace "Port ", ""
        if ($port) {
            Write-Host "SSH Port: $port" -ForegroundColor White
        }
    }
    else {
        Write-Host "Config File: Not found" -ForegroundColor Red
    }
    
    #-------------------------------------

    # Show connection info

    #-  Gets computer name from environment variable
    #-  Get-NetIPAddress: Gets network adapter IP addresses
    #-  Filters out loopback addresses (127.0.0.1)
    #-  Shows the SSH connection command users need

    $computerName = $env:COMPUTERNAME
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress
    Write-Host "`nConnection Information:" -ForegroundColor Cyan
    Write-Host "Computer Name: $computerName" -ForegroundColor White
    Write-Host "IP Address: $ipAddress" -ForegroundColor White
    Write-Host "SSH Command: ssh $env:USERNAME@$ipAddress" -ForegroundColor Yellow
}

#---------------------------------------------------------------------------------

# Main script logic ( switch statement )

#-  Switch statement: PowerShell's version of case/select
#-  Each action calls appropriate functions
#-  Install: Full setup process
#-  Configure: Just reconfiguration
#-  Start/Stop/Restart: Service management
#-  Status: Information display

switch ($Action) {
    "Install" {
        Install-SSHServer
        Configure-SSHServer
        if ($EnableKeyAuth) {
            Setup-SSHKeys
        }
        Restart-Service sshd
        Show-SSHStatus
    }
    "Configure" {
        Configure-SSHServer
        if ($EnableKeyAuth) {
            Setup-SSHKeys
        }
        Restart-Service sshd
        Write-Host "SSH Server reconfigured successfully!" -ForegroundColor Green
    }
    "Start" {
        Start-Service sshd
        Write-Host "SSH Server started" -ForegroundColor Green
    }
    "Stop" {
        Stop-Service sshd
        Write-Host "SSH Server stopped" -ForegroundColor Yellow
    }
    "Restart" {
        Restart-Service sshd
        Write-Host "SSH Server restarted" -ForegroundColor Green
    }
    "Status" {
        Show-SSHStatus
    }
    "Uninstall" {
        Stop-Service sshd -Force
        Set-Service -Name sshd -StartupType 'Disabled'
        Remove-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Remove-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
        Write-Host "SSH Server uninstalled" -ForegroundColor Yellow
    }
}



# Key PowerShell Concepts Used:

#1. Parameter validation: [ValidateSet()] ensures valid inputs
#2. Environment variables: $env:USERNAME, $env:COMPUTERNAME
#3. Error handling: -ErrorAction SilentlyContinue
#4. Conditional logic: if, switch, ternary operators
#5. File operations: Test-Path, New-Item, Copy-Item
#6. Service management: Get-Service, Start-Service, Set-Service
#7. Network configuration: Get-NetFirewallRule, New-NetFirewallRule
#8. Security permissions: icacls for Windows ACL management
#9. Here-strings: @"..."@ for multi-line text with variable substitution
#10. Pipeline operations: | for chaining commands