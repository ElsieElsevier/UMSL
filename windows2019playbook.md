# Phase 0: Password Management 
Priority: Lock down the most commonly exploited vulnerabilities

1. Password Security
   - Reset all default passwords
        Check for default admin password
        Identify all service accounts
        List and built-in account that are enabled

        # Check for active accounts
        Get-LocalUser | Where-Object {$_.Enabled -eq $true}

        # Change password for a specific account
        Set-LocalUserPassword -UserName "Administrator" -Password (ConvertTo-SecureString -AsPlainText "YourNewComplexPass2024!" -Force)
    
2. Lockout Prevention
    # Step 1: Define Variables
    $GpoName = "Standard Users Lockout Policy"
    $OUPath = "OU=Users,DC=YourDomain,DC=com"  # Modify based on your domain structure

    # Step 2: Create the GPO
    New-GPO -Name $GpoName | New-GPLink -Target $OUPath

    # Step 3: Get the GPO Path
    $GpoPath = "CN={$((Get-GPO -Name $GpoName).Id)},CN=Policies,CN=System,DC=YourDomain,DC=com"

    # Step 4: Set Account Lockout Policies (Modify values as needed)
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "MaxPasswordAge" -Type DWord -Value 30
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutThreshold" -Type DWord -Value 5
    Set-GPRegistryValue -Name $GpoName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutDuration" -Type DWord -Value 30

    # Step 5: Apply Policy to Standard Users Only
    $group = "Domain Users"
    $gpo = Get-GPO -Name $GpoName
    $gpo | Set-GPPermissions -TargetName $group -TargetType Group -PermissionLevel GpoApply

    # Step 6: Exclude Administrators from Lockout Policy
    $gpo | Set-GPPermissions -TargetName "Domain Admins" -TargetType Group -PermissionLevel None

    Write-Host "✅ Lockout Policy applied successfully to Standard Users. Admins are excluded!"

    

##################################################################################


# Phase 1: Critical Security Tools Update
Priority: Update and enable core security tools before hardening

1. Windows Defender Updates
    # Update signatures and enable protection
    Update-MpSignature -UpdateSource MicrosoftUpdateServer
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableScriptScanning $false

2. Critical Services Check
    # Verify and enable Windows Defender
    Get-Service WinDefend,SecurityHealthService | Select-Object Name,Status,StartType
    Set-Service WinDefend -StartupType Automatic -Status Running
    Set-Service SecurityHealthService -StartupType Automatic -Status Running

    # Verify and enable Windows Firewall
    Get-Service MpsSvc | Select-Object Name,Status,StartType
    Set-Service MpsSvc -StartupType Automatic -Status Running

    # Verify Cloud Protection is available
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent 2

3. Core Service Status Check
    # Check AD, DNS, and DHCP service status
    Get-WindowsFeature AD-Domain-Services, DNS, DHCP | Select-Object Name,InstallState

    # Verify AD services are running
    Get-Service NTDS, ADWS, DNS, DHCPServer | Select-Object Name,Status,StartType

    # Check disabled services
    Get-Service | Where-Object { $_.StartType -eq 'Disabled' }

4. Enable Critical Auditing
    # Enable PowerShell logging
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

    # Enable command line auditing
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

5. Quick Backup of Critical Settings
    # Export current GPO settings
    Backup-GPO -All -Path "C:\GPOBackup"

    # Export DNS zone data
    Export-DnsServerZone -Name * -FileName "C:\DNSBackup\zones.txt"

    # Export DHCP settings
    Export-DhcpServer -ComputerName $env:COMPUTERNAME -File "C:\DHCPBackup\dhcp.xml"

6. Verification Steps
    # Verify Windows Defender is properly configured
    Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled

    # Check service startup types
    Get-WmiObject Win32_Service | Where-Object {$_.Name -match 'Win|Sec|Mp|NTDS|DNS|DHCP'} | Select-Object Name, StartMode, State

    # Automate Validation 
    Get-MpComputerStatus | Format-List

7. User Accounts Export
    # Create a directory for storing only user count
    New-Item -Path "C:\Baseline" -ItemType Directory -Force

    # Get total user count at the start of the exercise
    (Get-ADUser -Filter *).Count | Out-File "C:\Baseline\user_count.txt"

8. Quick Comparison Commands
    # Open Notepad [Copy + Paste]
    # Load the original user count
    $originalCount = Get-Content "C:\Baseline\user_count.txt"

    # Get the current user count
    $currentCount = (Get-ADUser -Filter *).Count

    # Compare and display results
    if ($currentCount -eq $originalCount) {
        Write-Host "No new users have been created. Total users: $currentCount"
    } elseif ($currentCount -gt $originalCount) {
        Write-Host "Warning: User count has increased! Original: $originalCount, Current: $currentCount"
    } elseif ($currentCount -lt $originalCount) {
        Write-Host "Warning: Some user accounts have been removed! Original: $originalCount, Current: $currentCount"
    }

    # Save as Compare-UserCount.ps1 in C:\Baseline\

    # Set Alias
    Set-Alias -Name CheckUsers -Value C:\Baseline\Compare-UserCount.ps1

    # To Run
    CheckUsers

9. Network Config baseline
    # Create network baseline directory
    New-Item -Path "C:\Baseline\Network" -ItemType Directory -Force

    # Get IP configurations for all adapters
    Get-NetIPConfiguration -Detailed |
    Out-File "C:\Baseline\Network\ip_config.txt"

    # Get DHCP scope information
    Get-DhcpServerv4Scope |
    Out-File "C:\Baseline\Network\dhcp_scopes.txt"

    # Get DNS zone information
    Get-DnsServerZone |
    Out-File "C:\Baseline\Network\dns_zones.txt"

    # Get detailed routing table
    Get-NetRoute |
    Sort-Object -Property DestinationPrefix |
    Out-File "C:\Baseline\Network\routing_table.txt"

    # Get firewall rules
    Get-NetFirewallRule | 
    Where-Object Enabled -eq 'True' |
    Select-Object Name,Enabled,Direction,Action,Profile |
    Sort-Object Name |
    Out-File "C:\Baseline\Network\firewall_rules.txt"

    # Get network adapter information
    Get-NetAdapter |
    Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed |
    Out-File "C:\Baseline\Network\network_adapters.txt"

    # Encrypt Baseline in Zip
    Compress-Archive -Path "C:\Baseline\Network" -DestinationPath "C:\Baseline\Network.zip" -Password "StrongPass123!"


##################################################################################


# Phase 2: Firewall and Defender Config
1. Firewall Config
   - Enable Windows Firewall
        # Enable Windows Firewall on all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

        # Verify
        Get-NetFirewallProfile | Select-Object Name,Enabled

        # Verify Existing Traffic
        Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}

        # DNS Zone transfer restricted to Debian DNS
        Get-DnsServerZone | Select-Object ZoneName, ZoneType, SecondaryServers

        # Logging to detect misconfiguration
        Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True

   - Block all inbound except:
     - DNS (53)
     - LDAP (389)
     - Kerberos (88)
     - DHCP (67/68)
        
        # DNS (TCP/UDP 53)
        New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow
        New-NetFirewallRule -DisplayName "Allow DNS UDP" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow

        # LDAP (389)
        New-NetFirewallRule -DisplayName "Allow LDAP" -Direction Inbound -Protocol TCP -LocalPort 389 -Action Allow

        # Kerberos (88)
        New-NetFirewallRule -DisplayName "Allow Kerberos" -Direction Inbound -Protocol TCP -LocalPort 88 -Action Allow
        New-NetFirewallRule -DisplayName "Allow Kerberos UDP" -Direction Inbound -Protocol UDP -LocalPort 88 -Action Allow

        # DHCP (67/68)
        New-NetFirewallRule -DisplayName "Allow DHCP" -Direction Inbound -Protocol UDP -LocalPort 67,68 -Action Allow

        # Additional required AD ports
        # RPC (135)
        New-NetFirewallRule -DisplayName "Allow RPC" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow

        # SMB (445)
        New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

        # Global Catalog (3268)
        New-NetFirewallRule -DisplayName "Allow Global Catalog" -Direction Inbound -Protocol TCP -LocalPort 3268 -Action Allow

        # LDAP over SSL (636)
        New-NetFirewallRule -DisplayName "Allow LDAPS" -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow

        # DNS over TCP (for zone transfers)
        New-NetFirewallRule -DisplayName "Allow DNS Transfer" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow

        # Block all other RDP attempts
        New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Priority 1

    - Monitoring Dropped connections
        # Enable firewall logging
        Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

    - Block uncessarary traffic 
        # Set default inbound action to block
        Set-NetFirewallProfile -DefaultInboundAction Block -Profile Domain,Public,Private

        # Verify
        Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | Format-Table DisplayName,Direction,Action -AutoSize

        - Services that depend on this server (Ubuntu Web, Debian DNS/NTP, Docker, Ubuntu Workstation)
        - Monitor Event Viewer for dropped connections
        - Verify network topgraphy and create chart to map out communication paths


2. Advanced Windows Defender Firewall Rules

    - Enable Advanced Logging
        # Logging
        New-Item -ItemType Directory -Force -Path "C:\Windows\System32\LogFiles\Firewall"
        netsh advfirewall set allprofiles logging filename "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        netsh advfirewall set allprofiles logging maxfilesize 4096
        netsh advfirewall set allprofiles logging droppedconnections enable
        netsh advfirewall set allprofiles logging allowedconnections enable

    - Attack Surface Reduction
        # Windows Defender ASR
        Set-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled

    - Allow Required Internal Network Communication
        # Debian DNS/NTP Server
        New-NetFirewallRule -DisplayName "Allow Debian DNS/NTP" -Direction Inbound -Protocol UDP -LocalPort 53,123 -RemoteAddress 172.20.240.20 -Action Allow
        New-NetFirewallRule -DisplayName "Allow Debian DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -RemoteAddress 172.20.240.20 -Action Allow

        # Docker/Remote
        New-NetFirewallRule -DisplayName "Allow Docker Remote" -Direction Inbound -Protocol TCP -RemoteAddress 172.20.240.10 -Action Allow

    - Allow User Network Segment
        # Ubuntu Web Server
        New-NetFirewallRule -DisplayName "Allow Ubuntu Web DNS" -Direction Inbound -Protocol UDP,TCP -LocalPort 53 -RemoteAddress 172.20.242.10 -Action Allow

        # Ubuntu Workstation (DHCP Client)
        New-NetFirewallRule -DisplayName "Allow DHCP Clients" -Direction Inbound -Protocol UDP -LocalPort 67,68 -RemoteAddress 172.20.242.0/24 -Action Allow

    - Block Unnecessary Communication
        # CHECK FOR ACTIVE PUBLIC SEGMENT Communication
        Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like "172.20.241.*" } | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State

        # Block Public Segment by default except for DNS ONLY IF ABOVE HAS NO ACTIVE COMMUNICATION
        New-NetFirewallRule -DisplayName "Block Public Segment" -Direction Inbound -RemoteAddress 172.20.241.0/24 -Action Block -Priority 1
        New-NetFirewallRule -DisplayName "Allow Public DNS Only" -Direction Inbound -Protocol UDP,TCP -LocalPort 53 -RemoteAddress 172.20.241.0/24 -Action Allow

        # Explicitly block Windows 10 subnet except management
        New-NetFirewallRule -DisplayName "Block Win10 Subnet" -Direction Inbound -RemoteAddress 172.31.0.0/16 -Action Block -Priority 1
        New-NetFirewallRule -DisplayName "Allow Management PC" -Direction Inbound -RemoteAddress 172.20.242.150 -Action Allow -Priority 1

        # High Risk ports
        $highRiskPorts = @(21,23,25,1433,3306,5800,5900)
        New-NetFirewallRule -DisplayName "Block High-Risk Ports" -Direction Inbound -Protocol TCP -LocalPort $highRiskPorts -Action Block -Priority 2

    - Stateful Filtering Rules
        # Enable stateful filtering
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block
        New-NetFirewallRule -DisplayName "Allow Related Traffic" -Direction Inbound -Action Allow -Enabled True -Group "Core Networking" -Name "RelatedInbound"

    - Additional protection
        # Add monitoring for SMB attempts from unauthorized sources
        New-NetFirewallRule -DisplayName "Log SMB Attempts" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Priority 2 -Enabled True -Group "Security Monitoring"

        # Add protection against common reconnaissance ports
        $commonReconPorts = @(22,23,1433,3306,3389,5800,5900)
        New-NetFirewallRule -DisplayName "Block Recon Attempts" -Direction Inbound -Protocol TCP -LocalPort $commonReconPorts -Action Block -Priority 2

        # Add logging for authentication-related ports
        New-NetFirewallRule -DisplayName "Log Auth Attempts" -Direction Inbound -Protocol TCP -LocalPort 88,389,636 -Action Allow -Priority 2 -Group "Security Monitoring"

    - Function to check blocked connections
        # Create a function to quickly check recent blocked connections
        function Get-RecentBlockedConnections {
            Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" -Tail 50 | 
            Where-Object {$_ -match "DROP"} |
            FormatLogEntry
        }

        # Create a function to format log entries
        function FormatLogEntry {
            process {
                if ($_ -match "(.*?) (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (\w+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .*") {
                    [PSCustomObject]@{
                        Date = $matches[2]
                        Time = $matches[3]
                        Action = $matches[4]
                        Protocol = $matches[5]
                        SourceIP = $matches[6]
                        DestIP = $matches[7]
                    }
                }
            }
        }

    # C:\Windows\System32\LogFiles\Firewall\pfirewall.log
    Check logs for:
    - Suspicious connection attempts
    - Blocked connections from unauthorized IPs
    - Any legitimate traffic being blocked

    Watch for these specific events in Event Viewer:
    - Event ID 5152: Network Packet blocked
    - Event ID 5156: Network connection permitted
    - Event ID 5157: Network connection blocked

3. Basic Logging
   - Enable audit logging for:
     - Account logon events
     - Directory service access
     - Object access
     - Privilege use

    - Enable Powershell Logging
        # Enable PowerShell logging (critical for detecting malicious scripts)
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

        # Enable Command Line Process Auditing
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

        # Additional Critical Events to Monitor
        auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
        auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
        auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

    - Enable Advanced Audit Policy Configuration
        # Enable advanced audit policy configuration
        auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
        auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
        auditpol /set /subcategory:"Object Access" /success:enable /failure:enable
        auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable

    - Configure Event Log Sizes
        # Increase log sizes so we don't miss events
        wevtutil sl Security /ms:1024000000
        wevtutil sl System /ms:1024000000
        wevtutil sl Application /ms:1024000000
        wevtutil sl "Directory Service" /ms:1024000000

    - Configure Log Retention (Do I need this since it's only 8 hours, I can keep all logs)
        # Set logs to overwrite events as needed
        wevtutil sl Security /rt:false
        wevtutil sl System /rt:false
        wevtutil sl Application /rt:false
        wevtutil sl "Directory Service" /rt:false

    - Function for quick event checking
        # Powershell Function
        function Get-CriticalEvents {
            param(
                [int]$Minutes = 15
            )
            $StartTime = (Get-Date).AddMinutes(-$Minutes)
            Get-WinEvent -FilterHashtable @{
                LogName = 'Security','System','Directory Service'
                StartTime = $StartTime
                Level = 1,2,3
                ID = 4624,4625,4720,4738,5136,5141,7045,4776,4698,4699,4662,4740,4719,4697,4688,4946,4657 
            } -ErrorAction SilentlyContinue | 
            Select-Object TimeCreated,Id,LevelDisplayName,Message
        }

    # C:\Windows\System32\winevt\Logs\
    - Security.evtx
    - System.evtx
    - Application.evtx
    - Directory Service.evtx

    Account Logon Events:
        4624: Successful logon
        4625: Failed logon
        4648: Explicit credential logon

    Directory Service Access:
        5136: Directory service changes
        5137: Directory service object created
        5141: Directory service object deleted

    Object Access:
        4656: Handle to object requested
        4663: Object access attempt
        4670: Permissions changed on object

    Privilege Use:
        4673: Privileged service called
        4674: Privileged object operation
        4688: New process created

# eventvwr.msc (GUI)
Right click custom view and select create custom view
Under time range, select "Last Hour"
Check the boxes for Critical Error, Error, and Warning Levels
In the 'Event ID' field, enter:
    4624-4625, 4720-4738, 5136-5141, 7045, 4776, 4698-4699, 4662, 4688, 4719, 4765-4767, 4674, 4697, 4946, 4657, 4740
Under event logs, expand "Windows logs" and check "Security" and "System"
Expand "Application and Service Logs"
Check "Directory Service"
Name the view with a description

# Event Viewer ID
4624-4625,  # Logon/Logoff attempts
4720-4738,  # User account changes
5136-5141,  # Directory Service changes
7045,       # Service installation
4776,       # Credential validation
4698-4699,  # Scheduled tasks
4662,       # Object access
4688,       # Process creation (important for catching malicious commands)
4719,       # System audit policy changes
4765-4767,  # SID History changes (potential privilege escalation)
4674,       # Privileged operations
4697,       # Service installation
4946,       # Firewall rules changed
4657,       # Registry changes
4740        # Account lockouts

# Function Names
# Basic usage - will show last 5 minutes of critical events
    Get-CriticalEvents

# Or specify a different time window (e.g., last 10 minutes)
    Get-CriticalEvents -Minutes 10
# Shows the last 50 blocked connections
    Get-RecentBlockedConnections
# To save output
    Get-CriticalEvents -Minutes 15 | Out-File "C:\recent_events.txt"
    Get-RecentBlockedConnections | Out-File "C:\blocked_connections.txt"


#################################################################################


## Phase 2: Service Hardening
Secure critical services that red teams will target

1. Active Directory
   - Disable unused user accounts
   - Remove users from admin groups
   - Enable Protected Users group
   - Disable LLMNR and NetBIOS

    - Check and Disable Unused User Accounts
        # List all disabled users
        Get-ADUser -Filter {Enabled -eq $false}

        # List users who haven't logged in for 30 days
        $30DaysAgo = (Get-Date).AddDays(-30)
        Get-ADUser -Filter {LastLogonDate -lt $30DaysAgo} -Properties LastLogonDate | 
            Select-Object Name, LastLogonDate

        # Disable unused accounts (modify username)
        Disable-ADAccount -Identity "username" 

    - Review and Clean Admin Groups
        # List members of privileged groups
        Get-ADGroupMember "Domain Admins"
        Get-ADGroupMember "Enterprise Admins"
        Get-ADGroupMember "Schema Admins"

        # Remove user from admin group if needed 
        Remove-ADGroupMember -Identity "Domain Admins" -Members "username" -Confirm:$false

    - Enable Protected Users Group
        # Create Protected Users if not exists
        New-ADGroup -Name "Protected Users" -GroupScope Global -GroupCategory Security

        # Add critical accounts to Protected Users
        Add-ADGroupMember -Identity "Protected Users" -Members "critical_account"

    - Disable LLMNR and NetBIOS (Not familiar with LLMNR and NetBIOS and their vulnerabilities)
        # Check to see if NETBios is being used by legacy
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object Description, SettingID, TcpipNetbiosOptions

        # Disable LLMNR via Group Policy
        $Path = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
        New-Item -Path $Path -Force
        Set-ItemProperty -Path $Path -Name "EnableMulticast" -Value 0 -Type DWord

        # Disable NetBIOS via registry
        $NICs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
        foreach($NIC in $NICs) {
            $NIC.SetTcpipNetbios(2)
        }

    - Audit Policy Enhancement
        # Enable detailed tracking of all critical events
        auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
        auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
        auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Object Access" /success:enable /failure:enable

        # Verify the settings
        auditpol /get /category:*

    - AD Health Function
        # Create a function for quick AD health checks
        function Test-ADHealth {
            Write-Host "Testing AD Replication..." -ForegroundColor Yellow
            repadmin /showrepl
            
            Write-Host "`nTesting DC Diagnostics..." -ForegroundColor Yellow
            dcdiag /test:replications
            
            Write-Host "`nChecking Protected Users membership..." -ForegroundColor Yellow
            Get-ADGroupMember "Protected Users"
            
            Write-Host "`nChecking Domain Admin membership..." -ForegroundColor Yellow
            Get-ADGroupMember "Domain Admins"
        }

    # Functions
    Test-ADHealth

    - Critical Service/Admin Accounts to keep:
        # Internal Segment (172.20.240.x):
        administrator (Docker/Remote)
        root (Debian DNS/NTP)
        sysadmin (Debian DNS/NTP)

        # User Segment (172.20.242.x):
        sysadmin (Ubuntu Web)
        administrator (2019 AD/DNS/DHCP) - This is your server
        sysadmin (Ubuntu Workstation)

        # Public Segment (172.20.241.x):
        root (Splunk)
        sysadmin (Splunk)
        admin (Web UI)
        root (CentOS E-comm)
        sysadmin (CentOS E-comm)
        root (Fedora Webmail)

        # Management:
        admin (Palo Alto - 172.20.242.150)
        minion (Windows 10 - 172.31.xx.5)


2. DNS
    - Enable DNS debug logging
    - Restrict zone transfers
    - Enable DNS Query filtering
    - Block dynamic updates except secure
    - Enable DNS Debug Logging
        dnscmd /config /logLevel 0x1F
        dnscmd /config /debug 0x800F

    - Enable DNS Debug Logging - Safe
        dnscmd /config /logLevel 0x1F
        dnscmd /config /debug 0x800F

    - Configure Zone Transfers to Debian DNS - Safe but verify IP
        # First check current zone transfer settings
        Get-DnsServerZone | Select-Object ZoneName, ZoneType, SecondaryServers

        # Then restrict transfers only to Debian DNS
        foreach($zone in (Get-DnsServerZone)) {
            if ($zone.ZoneType -eq "Primary") {
                # Replace x with actual Debian DNS IP
                Set-DnsServerPrimaryZone -Name $zone.ZoneName -ZoneTransferServers @("172.20.240.x")
            }
        }

        # Disable everywhere but Debian DNS
        Get-DnsServerZone | Set-DnsServerPrimaryZone -ReplicationScope Forest -ZoneTransferPolicy "NoTransfer"


    - DNS Monitoring Function - Safe
        # Function
        function Watch-DNSActivity {
            param(
                [int]$Minutes = 15
            )
            $StartTime = (Get-Date).AddMinutes(-$Minutes)
            
            Get-WinEvent -FilterHashtable @{
                LogName = 'DNS Server'
                StartTime = $StartTime
                Level = 1,2,3
            } | Select-Object TimeCreated, Id, Message |
            Format-Table -AutoSize
        }

    - Quick DNS Health Check - Safe
        # Function
        function Test-DNSHealth {
            Write-Host "Checking Zone Transfer Settings..." -ForegroundColor Yellow
            Get-DnsServerZone | Select-Object ZoneName, ZoneType, SecondaryServers

            Write-Host "`nChecking Current Dynamic Update Settings..." -ForegroundColor Yellow
            Get-DnsServerZone | Select-Object ZoneName, DynamicUpdate

            Write-Host "`nTesting DNS Resolution..." -ForegroundColor Yellow
            Resolve-DnsName -Name $env:COMPUTERNAME -Type A
        }

3. DHCP
   - Review/remove suspicious reservations
   - Enable DHCP audit logging
   - Configure authorized DHCP servers
   - Set lease duration to 8 hours

    - Document current DHCP configuration
        # Function
        function Get-DHCPStatus {
            Write-Host "Scopes Configuration:" -ForegroundColor Yellow
            Get-DhcpServerv4Scope | Select-Object ScopeId, SubnetMask, Name, State

            Write-Host "`nScope Options:" -ForegroundColor Yellow
            Get-DhcpServerv4Scope | ForEach-Object {
                Get-DhcpServerv4OptionValue -ScopeId $_.ScopeId
            }

            Write-Host "`nLease Statistics:" -ForegroundColor Yellow
            Get-DhcpServerv4ScopeStatistics
        }

    - Monitor DHCP events
        # Function
        function Watch-DHCPActivity {
            param([int]$Minutes = 15)
            $StartTime = (Get-Date).AddMinutes(-$Minutes)
            
            Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-Dhcp-Server/Operational'
                StartTime = $StartTime
            } | Select-Object TimeCreated, Id, Message
        }

        # Enable DHCP audit logging
        Set-DhcpServerAuditLog -Enable $true -Type Periodic -Path "C:\Windows\System32\dhcp"

        # Enable DNS dynamic updates for DHCP clients
        Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRRonLeaseExpiry $True

        # Configure conflict detection
        Set-DhcpServerv4Binding -BindingState $true -ConflictDetection $true

        # Set lease duration appropriately (8 hours for exercise)
        Get-DhcpServerv4Scope | Set-DhcpServerv4Scope -LeaseDuration (New-TimeSpan -Hours 8)

        # Function to check for suspicious DHCP activities
        function Test-DHCPSecurity {
            Write-Host "Checking for duplicate IP addresses..." -ForegroundColor Yellow
            Get-DhcpServerv4ScopeStatistics | Where-Object {$_.InUse -gt $_.Reserved}

            Write-Host "`nChecking scope utilization..." -ForegroundColor Yellow
            Get-DhcpServerv4Statistics | Select-Object NoOfScopes, TotalAddresses, AddressesInUse

            Write-Host "`nChecking for unauthorized DHCP servers..." -ForegroundColor Yellow
            netsh dhcp show conf
        }


###################################################################################################

## Phase 3: Monitoring Setup
Establish visibility of attacks

1. Event Viewer Monitoring (Verify the correct Event IDs are created from phase 1)
   - Create custom views for:
     - Failed logons (Event ID 4625)
     - Account changes (4720-4738)
     - Service changes (7045)
     - DNS events (analytical log)

2. Performance Monitoring
   - Set up basic performance counters
   - Monitor CPU, Memory, Disk
   - Watch for resource exhaustion
   - Set alerts for threshold breaches

## Phase 4: Ongoing Defense
Active monitoring and quick response

1. Common Attack Indicators
   - Multiple failed logons
   - New service installations
   - Unusual DNS queries
   - PowerShell execution events
   - Account creation/modification
   - Unexpected privilege changes

2. Quick Response Actions
   - Block attacker IPs at firewall
   - Disable compromised accounts
   - Kill suspicious processes
   - Reset service accounts if compromised

## Common Red Team Attacks to Watch

1. Credential Attacks
   - Kerberoasting (watch for TGS requests)
   - Password spraying (multiple account failures)
   - Pass-the-hash (unexpected admin logons)

2. Service Attacks
   - DNS tunneling (large/frequent queries)
   - DHCP starvation (rapid lease requests)
   - LDAP injection (malformed queries)

3. Privilege Escalation
   - Service account compromise
   - Group policy modification
   - AdminSDHolder changes
   - DCSync attempts

## Emergency Response Steps

1. If Compromised:
   - Document the attack indicators
   - Take affected service offline
   - Reset service account passwords
   - Check for backdoor accounts
   - Review security logs

2. Quick Recovery:
   - Restore from backup if needed
   - Reset compromised credentials
   - Re-enable services
   - Document actions taken

## Quick Reference: Event IDs to Monitor

- 4624/4625: Logon/Failed logon
- 4720: Account created
- 4728/4732: Member added to group
- 4776: Credential validation
- 7045: New service installed
- 5136: Directory service changes
- 4698/4699: Scheduled task created/deleted
- 4662: Directory service access