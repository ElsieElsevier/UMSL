# CCDC Initial Phase Scripts and Documentation

## Script Organization
Create this folder structure:

E:\Scripts\
├── 0-PreCheck\
│   └── Pre-Check.ps1
├── 1-Baseline\
│   └── Get-Baseline.ps1
├── 2-Passwords\
│   └── Set-InitialPasswords.ps1
├── 3-DHCP\
│   └── Configure-DHCP.ps1
├── 4-DNS\
│   └── Configure-DNS.ps1
├── 5-AdditionalHardening\
│   └── Additional-Hardening.ps1
├── 6-Monitoring\
│   └── Compare-Baseline.ps1
└── README.txt


## Individual Scripts

### 0. Pre-Check.ps1
```powershell
# E:\Scripts\0-PreCheck\Pre-Check.ps1
# Verify requirement checks

function Test-Requirements {
    Write-Host "Checking system requirements..." -ForegroundColor Yellow
    
    # Check Admin Rights
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "Admin Rights: $($isAdmin ? 'Yes' : 'No')" -ForegroundColor ($isAdmin ? 'Green' : 'Red')

    # Check Required Modules
    $modules = @('ActiveDirectory', 'DnsServer', 'DhcpServer')
    foreach ($module in $modules) {
        $modulePresent = Get-Module -ListAvailable $module
        Write-Host "$module Module: $($modulePresent ? 'Present' : 'Missing')" -ForegroundColor ($modulePresent ? 'Green' : 'Red')
    }

    # Check Services
    $services = @('DNS', 'DHCPServer', 'NTDS', 'Netlogon')
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        Write-Host "$service Service: $($svc ? $svc.Status : 'Not Found')" -ForegroundColor ($svc ? 'Green' : 'Red')
    }

    # Check if Server Core
    $isCore = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "InstallationType").InstallationType -eq "Server Core"
    Write-Host "Server Core Installation: $($isCore ? 'Yes' : 'No')" -ForegroundColor ($isCore ? 'Green' : 'Red')   

}

Test-Requirements
```

### 1. Get-Baseline.ps1
```powershell
# E:\Scripts\1-Baseline\Get-Baseline.ps1
# Purpose: Document initial system state with error handling

# Create log directory
$LogPath = "E:\Scripts\Logs"
$LogFile = "$LogPath\baseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting baseline documentation process..."

# Create backup directory
try {
    $BackupPath = "E:\Backups\Initial"
    New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
    Write-Log "Created backup directory: $BackupPath"
} catch {
    Write-Log "ERROR: Failed to create backup directory: $_"
    exit 1
}

# Function to safely export data
function Export-SafeData {
    param (
        $Command,
        $ExportPath,
        $Description
    )
    
    try {
        Write-Log "Getting $Description..."
        $data = Invoke-Expression $Command
        if ($null -eq $data) {
            Write-Log "WARNING: No data returned for $Description"
        } else {
            if ($ExportPath -like "*.xml") {
                $data | Export-Clixml -Path $ExportPath -Force
            } else {
                $data | Export-Csv -Path $ExportPath -Force -NoTypeInformation
            }
            Write-Log "Successfully exported $Description to $ExportPath"
        }
    } catch {
        Write-Log "ERROR: Failed to export $Description : $_"
    }
}

# DHCP Documentation
Export-SafeData -Command "Get-DhcpServerv4Scope" `
    -ExportPath "$BackupPath\dhcp_scopes.csv" `
    -Description "DHCP scopes"

Export-SafeData -Command "Get-DhcpServerv4Binding" `
    -ExportPath "$BackupPath\dhcp_bindings.csv" `
    -Description "DHCP bindings"

# DNS Documentation
Export-SafeData -Command "Get-DnsServerZone" `
    -ExportPath "$BackupPath\dns_zones.csv" `
    -Description "DNS zones"

Export-SafeData -Command "Get-DnsServerForwarder" `
    -ExportPath "$BackupPath\dns_forwarders.csv" `
    -Description "DNS forwarders"

# AD Documentation
Export-SafeData -Command "Get-ADDomain | Select-Object *" `
    -ExportPath "$BackupPath\ad_domain.xml" `
    -Description "AD domain information"

Export-SafeData -Command "Get-ADForest | Select-Object *" `
    -ExportPath "$BackupPath\ad_forest.xml" `
    -Description "AD forest information"

# Service Status
Export-SafeData -Command 'Get-Service -Name "*DNS*", "*DHCP*", "*NTDS*", "*Netlogon*"' `
    -ExportPath "$BackupPath\service_status.csv" `
    -Description "Service status"

Write-Log "Baseline documentation process completed. Check logs at $LogFile"
```

### 2. Set-InitialPasswords.ps1
```powershell
# E:\Scripts\2-Passwords\Set-InitialPasswords.ps1
# Purpose: Change critical system passwords with error handling

$LogPath = "E:\Scripts\Logs"
$LogFile = "$LogPath\password_changes_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting password change process..."

# Verify AD tools are available
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Log "Successfully loaded Active Directory module"
} catch {
    Write-Log "ERROR: Failed to load Active Directory module. Are you running as Administrator? Error: $_"
    exit 1
}

# Function to test AD account
function Test-ADAccount {
    param($Username, $Password)
    $encrypted = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($Username, $encrypted)
    
    try {
        $null = Get-ADUser -Identity $Username -Credential $credential
        return $true
    } catch {
        return $false
    }
}

# Change Administrator password
$newAdminPass = "YourSecurePassword123!@#"  # Replace with actual password
try {
    $securePass = ConvertTo-SecureString $newAdminPass -AsPlainText -Force
    Set-ADAccountPassword -Identity "Administrator" -NewPassword $securePass -Reset -ErrorAction Stop
    Write-Log "Administrator password changed successfully"
    
    # Verify the new password works
    if (Test-ADAccount -Username "Administrator" -Password $newAdminPass) {
        Write-Log "Verified Administrator password change was successful"
    } else {
        Write-Log "WARNING: Administrator password changed but verification failed"
    }
} catch {
    Write-Log "ERROR: Failed to change Administrator password: $_"
}

# Change DSRM password
try {
    Write-Log "Attempting to change DSRM password..."
    $process = Start-Process "ntdsutil.exe" -ArgumentList 'set dsrm password', 'reset password on server null', 'q', 'q' -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log "DSRM password changed successfully"
    } else {
        Write-Log "WARNING: DSRM password change may have failed. Exit code: $($process.ExitCode)"
    }
} catch {
    Write-Log "ERROR: Failed to change DSRM password: $_"
}

# Disable Guest account using net user
try {
    $process = Start-Process "net" -ArgumentList "user guest /active:no" -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log "Guest account disabled successfully"
        
        # Verify guest account is disabled
        $guestStatus = net user guest | Select-String "Account active"
        if ($guestStatus -match "No") {
            Write-Log "Verified Guest account is disabled"
        } else {
            Write-Log "WARNING: Guest account may still be enabled"
        }
    } else {
        Write-Log "ERROR: Failed to disable Guest account"
    }
} catch {
    Write-Log "ERROR: Failed to disable Guest account: $_"
}

Write-Log "Password change process completed. Check logs at $LogFile"
```

### 3. Configure-DHCP.ps1
```powershell
# E:\Scripts\3-DHCP\Configure-DHCP.ps1
# Purpose: Configure DHCP with error handling

$LogPath = "E:\Scripts\Logs"
$LogFile = "$LogPath\dhcp_config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting DHCP configuration..."

# Verify DHCP service is running
try {
    $dhcpService = Get-Service -Name "DHCPServer" -ErrorAction Stop
    if ($dhcpService.Status -ne "Running") {
        Start-Service -Name "DHCPServer" -ErrorAction Stop
        Write-Log "Started DHCP service"
    }
    Write-Log "DHCP service is running"
} catch {
    Write-Log "ERROR: Failed to verify/start DHCP service: $_"
    exit 1
}

# Function to test DHCP scope
function Test-DHCPScope {
    param($ScopeId)
    try {
        $scope = Get-DhcpServerv4Scope -ScopeId $ScopeId -ErrorAction Stop
        return $null -ne $scope
    } catch {
        return $false
    }
}

# Configure DHCP scope
try {
    # Remove existing scope if it exists
    if (Test-DHCPScope -ScopeId "172.20.242.0") {
        Remove-DhcpServerv4Scope -ScopeId "172.20.242.0" -Force
        Write-Log "Removed existing DHCP scope"
    }

    # Add new scope
    Add-DhcpServerv4Scope -Name "User_Segment" `
        -StartRange "172.20.242.100" `
        -EndRange "172.20.242.199" `
        -SubnetMask "255.255.255.0" `
        -LeaseDuration (New-TimeSpan -Hours 8) `
        -ErrorAction Stop
    Write-Log "Successfully created DHCP scope"

    # Configure scope options
    Set-DhcpServerv4OptionValue -ScopeId "172.20.242.0" `
        -Router "172.20.242.1" `
        -DnsServer "172.20.242.200" `
        -DnsDomain "internal.domain" `
        -ErrorAction Stop
    Write-Log "Successfully configured DHCP options"

    # Verify scope creation
    if (Test-DHCPScope -ScopeId "172.20.242.0") {
        Write-Log "Verified DHCP scope exists"
    } else {
        Write-Log "WARNING: DHCP scope verification failed"
    }
} catch {
    Write-Log "ERROR: Failed to configure DHCP scope: $_"
}

# Authorize DHCP server in AD
try {
    Add-DhcpServerInDC -ErrorAction Stop
    Write-Log "Successfully authorized DHCP server in AD"
} catch {
    Write-Log "ERROR: Failed to authorize DHCP server in AD: $_"
}

# Enable conflict detection
try {
    Set-DhcpServerv4Scope -ScopeId "172.20.242.0" -ConflictDetectionAttempts 2 -ErrorAction Stop
    Write-Log "Successfully enabled conflict detection"
} catch {
    Write-Log "ERROR: Failed to enable conflict detection: $_"
}

Write-Log "DHCP configuration completed. Check logs at $LogFile"
```

### 4. Configure-DNS.ps1
```powershell
# E:\Scripts\4-DNS\Configure-DNS.ps1
# Purpose: Configure DNS with error handling

$LogPath = "E:\Scripts\Logs"
$LogFile = "$LogPath\dns_config_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting DNS configuration..."

# Verify DNS service is running
try {
    $dnsService = Get-Service -Name "DNS" -ErrorAction Stop
    if ($dnsService.Status -ne "Running") {
        Start-Service -Name "DNS" -ErrorAction Stop
        Write-Log "Started DNS service"
    }
    Write-Log "DNS service is running"
} catch {
    Write-Log "ERROR: Failed to verify/start DNS service: $_"
    exit 1
}

# Configure DNS forwarders
try {
    $forwarders = @("8.8.8.8", "8.8.4.4")
    Set-DnsServerForwarder -IPAddress $forwarders -ErrorAction Stop
    
    # Verify forwarders
    $configuredForwarders = Get-DnsServerForwarder
    if (($configuredForwarders.IPAddress.IPAddressToString | Sort-Object) -eq ($forwarders | Sort-Object)) {
        Write-Log "Successfully configured and verified DNS forwarders"
    } else {
        Write-Log "WARNING: DNS forwarders may not be configured correctly"
    }
} catch {
    Write-Log "ERROR: Failed to configure DNS forwarders: $_"
}

# Configure secure cache
try {
    Set-DnsServerCache -StoreEmptyAuthenticationResponses $true -ErrorAction Stop
    Write-Log "Successfully enabled secure cache"
    
    # Verify cache settings
    $cacheSettings = Get-DnsServerCache
    if ($cacheSettings.StoreEmptyAuthenticationResponses) {
        Write-Log "Verified secure cache settings"
    } else {
        Write-Log "WARNING: Secure cache settings may not be applied correctly"
    }
} catch {
    Write-Log "ERROR: Failed to configure secure cache: $_"
}

# Configure zone transfers
try {
    Set-DnsServerPrimaryZone -Name "internal.domain" -SecureSecondaries "TransferToSecureServers" -ErrorAction Stop
    Write-Log "Successfully configured zone transfer security"
    
    # Verify zone settings
    $zoneSettings = Get-DnsServerZone -Name "internal.domain"
    if ($zoneSettings.SecureSecondaries -eq "TransferToSecureServers") {
        Write-Log "Verified zone transfer settings"
    } else {
        Write-Log "WARNING: Zone transfer settings may not be applied correctly"
    }
} catch {
    Write-Log "ERROR: Failed to configure zone transfers: $_"
}

Write-Log "DNS configuration completed. Check logs at $LogFile"
```

### 5. Additional-Hardening
```powershell

# E:\Scripts\5-AdditionalHardening\Additional-Hardening.ps1

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Script must run as Administrator. Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

# Create log directory with error checking
$LogPath = "E:\Scripts\Logs"
try {
    if (-not (Test-Path $LogPath)) {
        New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
    }
    $LogFile = Join-Path $LogPath "additional_hardening_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
} catch {
    Write-Error "Failed to create log directory: $_"
    exit 1
}

function Write-Log {
    param($Message)
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage
}

Write-Log "Starting additional hardening process..."

# Check required modules
Write-Log "Checking required modules..."
$requiredModules = @('ActiveDirectory', 'GroupPolicy')
foreach ($module in $requiredModules) {
    try {
        Import-Module $module -ErrorAction Stop
        Write-Log "Successfully loaded $module module"
    } catch {
        Write-Log "ERROR: Failed to load $module module. Script cannot continue."
        exit 1
    }
}

# Section 1: User and Group Audit
Write-Log "Starting user and group audit..."
$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
foreach ($group in $groups) {
    try {
        if (Get-ADGroup -Filter {Name -eq $group} -ErrorAction SilentlyContinue) {
            $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
            $exportPath = Join-Path $LogPath "$($group.ToLower() -replace '\s+', '_')_members.csv"
            $members | Export-Csv -Path $exportPath -NoTypeInformation
            Write-Log "Exported $group members to $exportPath"
        } else {
            Write-Log "WARNING: Group $group not found in AD"
        }
    } catch {
        Write-Log "ERROR: Failed to process group $group : $_"
    }
}

# Export enabled users
try {
    $enabledUsersPath = Join-Path $LogPath "enabled_users.csv"
    Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |
        Select-Object Name, Enabled, LastLogonDate |
        Export-Csv -Path $enabledUsersPath -NoTypeInformation
    Write-Log "Exported enabled users list to $enabledUsersPath"
} catch {
    Write-Log "ERROR: Failed to export enabled users: $_"
}

# Section 2: Account Policies
Write-Log "Configuring account policies..."
try {
    # Get current domain
    $domain = Get-ADDomain -ErrorAction Stop
    
    # Set domain password policy
    Set-ADDefaultDomainPasswordPolicy -Identity $domain `
        -LockoutDuration "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 `
        -MinPasswordLength 16 `
        -PasswordHistoryCount 24 `
        -ErrorAction Stop
    Write-Log "Successfully configured domain password policy"
    
    # Verify policy
    $policy = Get-ADDefaultDomainPasswordPolicy
    Write-Log "Verified policy settings:
        Lockout Duration: $($policy.LockoutDuration)
        Lockout Threshold: $($policy.LockoutThreshold)
        Min Password Length: $($policy.MinPasswordLength)"
} catch {
    Write-Log "ERROR: Failed to configure password policy: $_"
}

# Configure audit policies
$auditCategories = @(
    "Account Logon",
    "Account Management",
    "Directory Service Access",
    "Logon/Logoff",
    "Policy Change"
)

foreach ($category in $auditCategories) {
    try {
        $result = auditpol /set /category:"$category" /success:enable /failure:enable
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Successfully enabled auditing for $category"
        } else {
            Write-Log "WARNING: Failed to set audit policy for $category"
        }
    } catch {
        Write-Log "ERROR: Failed to configure audit policy for $category : $_"
    }
}

# Section 3: Service Security
Write-Log "Configuring service security..."
$services = @{
    "DNS" = "DNS Server"
    "Netlogon" = "Netlogon"
    "NTDS" = "Active Directory Domain Services"
    "DHCPServer" = "DHCP Server"
}

foreach ($service in $services.Keys) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Set-Service -Name $service -StartupType Automatic
            Start-Service -Name $service -ErrorAction Stop
            $status = Get-Service -Name $service
            Write-Log "Service $($services[$service]) configured: Status=$($status.Status), StartType=$($status.StartType)"
        } else {
            Write-Log "WARNING: Service $($services[$service]) not found"
        }
    } catch {
        Write-Log "ERROR: Failed to configure service $($services[$service]): $_"
    }
}

# Configure Windows Firewall using netsh
try {
    $profiles = @("domain", "private", "public")
    foreach ($profile in $profiles) {
        $process = Start-Process "netsh" -ArgumentList "advfirewall set $profile state on" -NoNewWindow -Wait -PassThru
        if ($process.ExitCode -eq 0) {
            Write-Log "Successfully enabled firewall for $profile profile"
        } else {
            Write-Log "WARNING: Failed to enable firewall for $profile profile"
        }
    }
    
    # Verify firewall status
    $verifyProcess = Start-Process "netsh" -ArgumentList "advfirewall show allprofiles state" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\fw_status.txt"
    $status = Get-Content "$env:TEMP\fw_status.txt"
    Write-Log "Firewall Status:"
    Write-Log ($status | Out-String)
    Remove-Item "$env:TEMP\fw_status.txt" -Force
} catch {
    Write-Log "ERROR: Failed to configure firewall: $_"
}

# Configure SMB Security
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    $smbConfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature
    Write-Log "SMB Security configured:
        SMB1 Disabled: $(-not $smbConfig.EnableSMB1Protocol)
        Signatures Required: $($smbConfig.RequireSecuritySignature)"
} catch {
    Write-Log "ERROR: Failed to configure SMB security: $_"
}


Write-Log "Additional hardening process completed. Check logs at $LogFile for details."

# Display final status
Write-Host "`nScript execution completed. Check the log file for details: $LogFile" -ForegroundColor Green

# Add to 5-AdditionalHardening\Additional-Hardening.ps1

# Network Interface Hardening using netsh
Write-Log "Configuring network interfaces..."
try {
    # Disable IPv6 using registry
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xff -Type DWord
    Write-Log "Disabled IPv6 via registry"

    # Set DNS servers using netsh
    $process = Start-Process "netsh" -ArgumentList 'interface ipv4 set dns name="Ethernet" static 172.20.242.200' -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log "Successfully set DNS server"
    } else {
        Write-Log "WARNING: Failed to set DNS server"
    }
} catch {
    Write-Log "ERROR: Failed to configure network interfaces: $_"
}

# Event Log Configuration
Write-Log "Configuring event logs..."
try {
    # Increase log sizes and retention
    Limit-EventLog -LogName "Application" -MaximumSize 4GB
    Limit-EventLog -LogName "Security" -MaximumSize 4GB
    Limit-EventLog -LogName "System" -MaximumSize 4GB
    
    Write-Log "Event log sizes increased"
} catch {
    Write-Log "ERROR: Failed to configure event logs: $_"
}

# Server Core specific hardening
Write-Log "Applying Server Core specific hardening..."
try {
    # Disable Server Manager remote management
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value 1
    Write-Log "Disabled Server Manager remote management"

    # Configure WinRM for secure remote management
    Write-Log "Configuring WinRM..."
    $process = Start-Process "winrm" -ArgumentList "quickconfig -quiet" -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -eq 0) {
        Write-Log "WinRM basic configuration completed"
        
        # Enable PSRemoting
        Enable-PSRemoting -Force
        Write-Log "Enabled PowerShell remoting"
    } else {
        Write-Log "WARNING: WinRM configuration failed"
    }
} catch {
    Write-Log "ERROR: Failed to apply Server Core specific hardening: $_"
}

```
### 6. Compare-Baseline.ps1
``` powershell
# E:\Scripts\6-Monitoring\Compare-Baseline.ps1
function Compare-SystemState {
    param(
        [string]$BaselinePath = "E:\Backups\Initial",
        [string]$CurrentPath = "E:\Backups\Current"
    )

    # Create directories if they don't exist
    New-Item -ItemType Directory -Force -Path $BaselinePath | Out-Null
    New-Item -ItemType Directory -Force -Path $CurrentPath | Out-Null

    Write-Host "Ensuring directories exist:"
    Write-Host "Baseline Path: $BaselinePath"
    Write-Host "Current Path: $CurrentPath"

    # Create new current state export
    Get-DhcpServerv4Scope | Export-Csv "$CurrentPath\dhcp_scopes.csv"
    Get-DnsServerZone | Export-Csv "$CurrentPath\dns_zones.csv"
    Get-ADGroupMember "Domain Admins" | Export-Csv "$CurrentPath\domain_admins.csv"
    Get-Service | Export-Csv "$CurrentPath\services.csv"

    # Compare files
    $comparisons = @(
        @{Name="DHCP Scopes"; File="dhcp_scopes.csv"}
        @{Name="DNS Zones"; File="dns_zones.csv"}
        @{Name="Domain Admins"; File="domain_admins.csv"}
        @{Name="Services"; File="services.csv"}
    )

    foreach ($comp in $comparisons) {
        Write-Host "`nChecking ${comp.Name}:" -ForegroundColor Yellow
        $baseline = Import-Csv "$BaselinePath\$($comp.File)"
        $current = Import-Csv "$CurrentPath\$($comp.File)"
        
        $diff = Compare-Object $baseline $current -Property *
        if ($diff) {
            Write-Host "Changes detected:" -ForegroundColor Red
            $diff | Format-Table -AutoSize
        } else {
            Write-Host "No changes detected" -ForegroundColor Green
        }
    }
}
```


## How to Use These Scripts

### Preparation (Before Competition):

cd E:\Scripts
mkdir "0-PreCheck", "1-Baseline", "2-Passwords", "3-DHCP", "4-DNS", "5-AdditionalHardening", "6-Monitoring"

1. Create the folder structure:
```powershell
New-Item -ItemType Directory -Force -Path "E:\Scripts\0-PreCheck"
New-Item -ItemType Directory -Force -Path "E:\Scripts\1-Baseline"
New-Item -ItemType Directory -Force -Path "E:\Scripts\2-Passwords"
New-Item -ItemType Directory -Force -Path "E:\Scripts\3-DHCP"
New-Item -ItemType Directory -Force -Path "E:\Scripts\4-DNS"
New-Item -ItemType Directory -Force -Path "E:\Scripts\5-AdditionalHardening"
New-Item -ItemType Directory -Force -Path "E:\Scripts\6-Monitoring"
```

2. Save each script to its respective folder using Notepad:
- Open Notepad as Administrator
- Copy script content
- Save with .ps1 extension in appropriate folder
- Verify file extension is .ps1 (not .ps1.txt)

### During Competition:

1. Open PowerShell as Administrator:
   - Windows key + X, then A
   - Or right-click Start, select "Windows PowerShell (Admin)"

2. Navigate to scripts directory:
```powershell
cd E:\Scripts
```

3. Run scripts individually:
```powershell
# 1. Run pre-check
.\0-PreCheck\Pre-Check.ps1

# 2. If all checks pass, then proceed with:
.\1-Baseline\Get-Baseline.ps1
.\2-Passwords\Set-InitialPasswords.ps1
.\3-DHCP\Configure-DHCP.ps1
.\4-DNS\Configure-DNS.ps1
.\5-AdditionalHardening\Additional-Hardening.ps1

# 3. Verify configuration
. .\6-Monitoring\Compare-Baseline.ps1
Compare-SystemState
```

### Troubleshooting:
- If scripts won't run, check execution policy:
```powershell
# View current policy
Get-ExecutionPolicy

# If needed, set to allow scripts
Set-ExecutionPolicy Bypass -Scope Process -Force
```

- If a script fails:
1. Read the error message carefully
2. Run individual commands from the script manually to identify the problem
3. Fix the issue and re-run the script

### Time Management:
- 0-5 minutes: Run Get-Baseline.ps1
- 5-15 minutes: Run Set-InitialPasswords.ps1
- 15-25 minutes: Run Configure-DHCP.ps1
- 25-30 minutes: Run Configure-DNS.ps1
