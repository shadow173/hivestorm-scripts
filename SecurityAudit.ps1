<#
.SYNOPSIS
    Comprehensive security audit script for Windows systems.
# MAKE SURE Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
# TO ALLOW SCRIPTS 
# TURN THIS OFF AFTER IF ITS ALREADY OFF?
.DESCRIPTION
    This script checks for various vulnerabilities and misconfigurations on Windows machines,
    including weak passwords, unauthorized files, installed hacking tools, IPv6 status,
    and other security settings.

.NOTES
    Author: OpenAI Assistant
    Date: [Current Date]
#>

# Function to check for weak passwords
function Check-WeakPasswords {
    Write-Host "Checking for weak passwords..."
    # Function code remains the same
}


# Additional functions start here

# Function to check for accounts with default passwords (requires domain controller)
function Check-DefaultPasswords {
    Write-Host "Checking for accounts with default passwords..."
    # Note: This check requires domain controller access and is beyond local scope
    Write-Host "Default password check requires domain controller access and cannot be performed locally."
}

function Check-WeakPasswords {
    Write-Host "Checking for weak passwords..."
    try {
        $weakPasswordUsers = @()
        $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
        foreach ($user in $users) {
            # Skip built-in accounts
            if ($user.Name -in @('Administrator', 'Guest', 'DefaultAccount', 'WDAGUtilityAccount')) {
                continue
            }
            # Check password age
            $maxPasswordAge = (Get-LocalUser -Name $user.Name).PasswordExpires
            if ($maxPasswordAge -eq $false) {
                $weakPasswordUsers += $user.Name
            }
        }
        if ($weakPasswordUsers.Count -gt 0) {
            Write-Host "Users with weak passwords or passwords that never expire:"
            $weakPasswordUsers | ForEach-Object { Write-Host "- $_" }
        } else {
            Write-Host "No users with weak passwords found."
        }
    } catch {
        Write-Host "Error checking weak passwords: $_"
    }
}

# Function to search for unauthorized media files
function Check-MediaFiles {
    Write-Host "Searching for unauthorized media files..."
    $mediaExtensions = @("*.mp3", "*.mp4", "*.avi", "*.mkv", "*.wav", "*.flac")
    $unauthorizedFiles = @()
    foreach ($ext in $mediaExtensions) {
        $files = Get-ChildItem -Path "C:\" -Include $ext -File -Recurse -ErrorAction SilentlyContinue
        if ($files) {
            $unauthorizedFiles += $files
        }
    }
    if ($unauthorizedFiles.Count -gt 0) {
        Write-Host "Unauthorized media files found:"
        $unauthorizedFiles | ForEach-Object { Write-Host $_.FullName }
    } else {
        Write-Host "No unauthorized media files found."
    }
}

# Function to search for installed hacking tools
function Check-HackingTools {
    Write-Host "Checking for unauthorized hacking tools..."
    $hackingTools = @("Nmap", "Wireshark", "Cain & Abel", "Metasploit", "Hydra", "John the Ripper")
    $installedTools = @()
    foreach ($tool in $hackingTools) {
        $apps = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%$tool%'" -ErrorAction SilentlyContinue
        if ($apps) {
            $installedTools += $tool
        }
    }
    if ($installedTools.Count -gt 0) {
        Write-Host "Unauthorized hacking tools installed:"
        $installedTools | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No unauthorized hacking tools found."
    }
}

# Function to check if IPv6 is enabled
function Check-IPv6 {
    Write-Host "Checking if IPv6 is enabled..."
    $ipv6Interfaces = Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object { $_.Enabled -eq $true }
    if ($ipv6Interfaces) {
        Write-Host "IPv6 is enabled. It should be disabled according to policy."
    } else {
        Write-Host "IPv6 is disabled."
    }
}

# Function to check RDP configuration
function Check-RDPConfig {
    Write-Host "Checking RDP configuration..."
    $rdpStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
    if ($rdpStatus.fDenyTSConnections -eq 0) {
        Write-Host "RDP is enabled."
        # Check Network Level Authentication
        $nlaStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication"
        if ($nlaStatus.UserAuthentication -eq 1) {
            Write-Host "Network Level Authentication is enabled."
        } else {
            Write-Host "Network Level Authentication is disabled. It should be enabled."
        }
    } else {
        Write-Host "RDP is disabled."
    }
}

# Function to check for accounts with empty passwords
function Check-EmptyPasswords {
    Write-Host "Checking for accounts with empty passwords..."
    $usersWithEmptyPasswords = @()
    $accounts = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($account in $accounts) {
        $passwordRequired = (Get-LocalUser -Name $account.Name).PasswordRequired
        if ($passwordRequired -eq $false) {
            $usersWithEmptyPasswords += $account.Name
        }
    }
    if ($usersWithEmptyPasswords.Count -gt 0) {
        Write-Host "Accounts with empty passwords found:"
        $usersWithEmptyPasswords | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No accounts with empty passwords found."
    }
}

# Function to check for weak password policies
function Check-PasswordPolicy {
    Write-Host "Checking password policies..."
    $minLength = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").MinimumPasswordLength
    if ($minLength -lt 12) {
        Write-Host "Minimum password length is $minLength. It should be at least 12."
    } else {
        Write-Host "Minimum password length is $minLength."
    }
    $complexity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").PasswordComplexity
    if ($complexity -eq 0) {
        Write-Host "Password complexity requirements are disabled. They should be enabled."
    } else {
        Write-Host "Password complexity requirements are enabled."
    }
}

# Function to check firewall status
function Check-Firewall {
    Write-Host "Checking Windows Firewall status..."
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        if ($profile.Enabled -eq $true) {
            Write-Host "$($profile.Name) firewall is enabled."
        } else {
            Write-Host "$($profile.Name) firewall is disabled. It should be enabled."
        }
    }
}

# Function to check for unnecessary services running
function Check-Services {
    Write-Host "Checking for unnecessary services running..."
    $unnecessaryServices = @("Telnet", "FTP", "RemoteRegistry", "SNMP")
    $runningServices = @()
    foreach ($service in $unnecessaryServices) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            $runningServices += $service
        }
    }
    if ($runningServices.Count -gt 0) {
        Write-Host "Unnecessary services are running:"
        $runningServices | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No unnecessary services are running."
    }
}

# Function to check for world-writable files (Everyone with Full Control)
function Check-WorldWritableFiles {
    Write-Host "Checking for world-writable files..."
    $worldWritableFiles = @()
    $foldersToCheck = @("C:\Program Files", "C:\Program Files (x86)", "C:\Windows")
    foreach ($folder in $foldersToCheck) {
        $acl = Get-Acl -Path $folder
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -eq "Everyone" -and $ace.FileSystemRights -match "FullControl") {
                $worldWritableFiles += $folder
                break
            }
        }
    }
    if ($worldWritableFiles.Count -gt 0) {
        Write-Host "World-writable files or directories found:"
        $worldWritableFiles | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No world-writable files or directories found."
    }
}

# Function to check for installed updates
function Check-Updates {
    Write-Host "Checking for missing updates..."
    $updates = Get-WindowsUpdate -IsInstalled:$false -ErrorAction SilentlyContinue
    if ($updates) {
        Write-Host "There are missing updates. Please install them."
    } else {
        Write-Host "All updates are installed."
    }
}

# Function to check for enabled guest account
function Check-GuestAccount {
    Write-Host "Checking if the Guest account is enabled..."
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guestAccount -and $guestAccount.Enabled -eq $true) {
        Write-Host "Guest account is enabled. It should be disabled."
    } else {
        Write-Host "Guest account is disabled."
    }
}

# Function to check for unauthorized scheduled tasks
function Check-ScheduledTasks {
    Write-Host "Checking for unauthorized scheduled tasks..."
    $authorizedTasks = @("Microsoft\Windows\*", "Adobe\*", "Google\*")  # Adjust as needed
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskName -notlike "\Microsoft\Windows\*" }
    $unauthorizedTasks = @()
    foreach ($task in $tasks) {
        $unauthorizedTasks += $task.TaskName
    }
    if ($unauthorizedTasks.Count -gt 0) {
        Write-Host "Unauthorized scheduled tasks found:"
        $unauthorizedTasks | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No unauthorized scheduled tasks found."
    }
}

# Function to check for anonymous shares
function Check-AnonymousShares {
    Write-Host "Checking for anonymous shares..."
    $shares = Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$', 'C$', 'IPC$') }
    $anonymousShares = @()
    foreach ($share in $shares) {
        if ($share.CachingMode -eq "None" -and $share.EncryptData -eq $false) {
            $anonymousShares += $share.Name
        }
    }
    if ($anonymousShares.Count -gt 0) {
        Write-Host "Anonymous shares found:"
        $anonymousShares | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "No anonymous shares found."
    }
}

# Function to check for remote registry enabled
function Check-RemoteRegistry {
    Write-Host "Checking if Remote Registry service is enabled..."
    $service = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Host "Remote Registry service is running. It should be disabled."
    } else {
        Write-Host "Remote Registry service is not running."
    }
}

# Function to check for automatic logon
function Check-AutoLogon {
    Write-Host "Checking for automatic logon settings..."
    $autoLogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    if ($autoLogon.AutoAdminLogon -eq '1') {
        Write-Host "Automatic logon is enabled. It should be disabled."
    } else {
        Write-Host "Automatic logon is disabled."
    }
}

# Function to check for open ports
function Check-OpenPorts {
    Write-Host "Checking for open ports..."
    $necessaryPorts = @('135', '139', '445', '3389')  # Adjust based on required services
    $netstat = netstat -ano | Select-String "LISTENING"
    $openPorts = @()
    foreach ($line in $netstat) {
        $parts = $line -split '\s+'
        $localAddress = $parts[1]
        if ($localAddress -match '::' -or $localAddress -match '0\.0\.0\.0') {
            $port = $localAddress -split ':' | Select-Object -Last 1
            if ($port -notin $necessaryPorts) {
                $openPorts += $port
            }
        }
    }
    if ($openPorts.Count -gt 0) {
        Write-Host "Unnecessary open ports found:"
        $openPorts | Select-Object -Unique | ForEach-Object { Write-Host "- Port $_" }
    } else {
        Write-Host "No unnecessary open ports found."
    }
}

# Function to check if antivirus software is installed and up to date
function Check-Antivirus {
    Write-Host "Checking for antivirus software..."
    $antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    if ($antivirus) {
        foreach ($av in $antivirus) {
            Write-Host "Antivirus detected: $($av.displayName)"
            Write-Host "Product state: $($av.productState)"
        }
    } else {
        Write-Host "No antivirus software detected."
    }
}

# Function to check for outdated software versions
function Check-OutdatedSoftware {
    Write-Host "Checking for outdated software..."
    # This function would require software version databases, so we'll check common applications
    $commonApps = @("Adobe Reader", "Java", "Flash Player")
    foreach ($app in $commonApps) {
        $installedApp = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%$app%'" -ErrorAction SilentlyContinue
        if ($installedApp) {
            Write-Host "$app is installed. Please ensure it is updated to the latest version."
        }
    }
}

# Function to check for unauthorized user accounts
function Check-UnauthorizedUsers {
    Write-Host "Checking for unauthorized user accounts..."
    $authorizedUsers = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "YourAuthorizedUser")  # Update with actual authorized users
    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
    foreach ($user in $localUsers) {
        if ($user.Name -notin $authorizedUsers) {
            Write-Host "Unauthorized user account found: $($user.Name)"
        }
    }
}

# Function to check for disabled important services
function Check-ImportantServices {
    Write-Host "Checking for important services that are disabled..."
    $importantServices = @("WinDefend", "EventLog", "wuauserv")  # Windows Defender, Windows Event Log, Windows Update
    foreach ($serviceName in $importantServices) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Running') {
            Write-Host "Important service $serviceName is not running."
        }
    }
}

# Function to check for system restore settings
function Check-SystemRestore {
    Write-Host "Checking system restore settings..."
    $restoreStatus = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
    if ($restoreStatus) {
        Write-Host "System restore points are available."
    } else {
        Write-Host "No system restore points found. It is recommended to have system restore enabled."
    }
}

# Function to check for audit policy settings
function Check-AuditPolicy {
    Write-Host "Checking audit policy settings..."
    $auditSettings = AuditPol /get /category:* | Select-String "No Auditing"
    if ($auditSettings) {
        Write-Host "Some audit categories are not enabled:"
        $auditSettings | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host "All audit categories are enabled."
    }
}

# Function to check for unencrypted drives
function Check-BitLockerStatus {
    Write-Host "Checking for unencrypted drives..."
    $drives = Get-BitLockerVolume
    foreach ($drive in $drives) {
        if ($drive.VolumeStatus -ne 'FullyEncrypted') {
            Write-Host "Drive $($drive.VolumeLetter) is not fully encrypted."
        }
    }
}

# Function to check for Windows Defender status
function Check-WindowsDefender {
    Write-Host "Checking Windows Defender status..."
    $defenderStatus = Get-MpPreference
    if ($defenderStatus) {
        Write-Host "Windows Defender is enabled."
    } else {
        Write-Host "Windows Defender is disabled."
    }
}

# Function to check for password expiration policy
function Check-PasswordExpirationPolicy {
    Write-Host "Checking password expiration policy..."
    $maxPasswordAge = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").MaximumPasswordAge
    if ($maxPasswordAge -gt 90) {
        Write-Host "Maximum password age is $maxPasswordAge days. It should be 90 days or less."
    } else {
        Write-Host "Maximum password age is $maxPasswordAge days."
    }
}

# Function to check for security updates
function Check-SecurityUpdates {
    Write-Host "Checking for missing security updates..."
    $missingUpdates = (Get-WindowsUpdate -IsInstalled:$false -ErrorAction SilentlyContinue) | Where-Object { $_.Title -match "Security Update" }
    if ($missingUpdates) {
        Write-Host "Missing security updates found:"
        $missingUpdates | ForEach-Object { Write-Host "- $($_.Title)" }
    } else {
        Write-Host "All security updates are installed."
    }
}

# Function to check for installed roles and features
function Check-InstalledFeatures {
    Write-Host "Checking for unnecessary installed roles and features..."
    $unnecessaryFeatures = @("TelnetClient", "SimpleTCP", "TFTP-Client")
    foreach ($feature in $unnecessaryFeatures) {
        $featureState = Get-WindowsOptionalFeature -FeatureName $feature -Online -ErrorAction SilentlyContinue
        if ($featureState -and $featureState.State -eq 'Enabled') {
            Write-Host "Unnecessary feature $feature is installed."
        }
    }
}

# Function to check for weak NTFS permissions on system folders
function Check-NTFSPermissions {
    Write-Host "Checking for weak NTFS permissions on system folders..."
    $systemFolders = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)")
    foreach ($folder in $systemFolders) {
        $acl = Get-Acl -Path $folder
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -eq "Everyone" -and $ace.FileSystemRights -match "FullControl") {
                Write-Host "Weak permissions on $folder for Everyone group."
            }
        }
    }
}

# Function to check for insecure IIS configurations
function Check-IISConfiguration {
    Write-Host "Checking IIS configuration..."
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (Get-Module -Name WebAdministration) {
        $iisConfig = Get-ItemProperty -Path "IIS:\AppPools\DefaultAppPool"
        if ($iisConfig.processModel.identityType -ne 'ApplicationPoolIdentity') {
            Write-Host "IIS Application Pool is not using ApplicationPoolIdentity."
        } else {
            Write-Host "IIS Application Pool is configured securely."
        }
    } else {
        Write-Host "IIS is not installed."
    }
}

# Function to check for disabled UAC
function Check-UACStatus {
    Write-Host "Checking User Account Control (UAC) status..."
    $uacStatus = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uacStatus.EnableLUA -eq 0) {
        Write-Host "UAC is disabled. It should be enabled."
    } else {
        Write-Host "UAC is enabled."
    }
}

# Function to check for insecure remote desktop settings
function Check-RDPSettings {
    Write-Host "Checking remote desktop settings..."
    # Already covered in Check-RDPConfig, so we can check for additional settings
    $rdpEncryption = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
    if ($rdpEncryption.MinEncryptionLevel -lt 3) {
        Write-Host "RDP encryption level is set below recommended level."
    } else {
        Write-Host "RDP encryption level is configured securely."
    }
}

# Function to check for SMBv1 protocol enabled
function Check-SMBv1 {
    Write-Host "Checking if SMBv1 protocol is enabled..."
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smbv1.State -eq 'Enabled') {
        Write-Host "SMBv1 protocol is enabled. It should be disabled."
    } else {
        Write-Host "SMBv1 protocol is disabled."
    }
}

# Function to check for presence of .NET Framework updates
function Check-DotNetUpdates {
    Write-Host "Checking for .NET Framework updates..."
    $dotNetUpdates = Get-WindowsUpdate -IsInstalled:$false -ErrorAction SilentlyContinue | Where-Object { $_.Title -match ".NET Framework" }
    if ($dotNetUpdates) {
        Write-Host ".NET Framework updates are missing:"
        $dotNetUpdates | ForEach-Object { Write-Host "- $($_.Title)" }
    } else {
        Write-Host "All .NET Framework updates are installed."
    }
}

# Function to check for unnecessary startup programs
function Check-StartupPrograms {
    Write-Host "Checking for unnecessary startup programs..."
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand
    foreach ($item in $startupItems) {
        Write-Host "Startup item found: $($item.Command)"
        # Evaluate if the item is necessary or should be removed
    }
}

# Function to check for weak registry permissions
function Check-RegistryPermissions {
    Write-Host "Checking for weak registry permissions..."
    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    $acl = Get-Acl -Path $key
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -eq "Everyone" -and $ace.FileSystemRights -match "FullControl") {
            Write-Host "Weak permissions on registry key $key for Everyone group."
        }
    }
}

# Function to check for enabled LM hashes
function Check-LMHashes {
    Write-Host "Checking if LM hashes are stored..."
    $lmCompatibility = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction SilentlyContinue
    if ($lmCompatibility.NoLMHash -eq 0) {
        Write-Host "LM hashes are stored. This is insecure and should be disabled."
    } else {
        Write-Host "LM hashes are not stored."
    }
}

# Function to check for presence of guest in administrators group
function Check-GuestInAdmins {
    Write-Host "Checking if Guest account is in Administrators group..."
    $adminsGroup = [ADSI]"WinNT://./Administrators,group"
    $members = @($adminsGroup.psbase.Invoke("Members"))
    foreach ($member in $members) {
        $memberObj = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
        if ($memberObj -eq "Guest") {
            Write-Host "Guest account is in Administrators group. This should be corrected."
        }
    }
}

# Function to check for time synchronization settings
function Check-TimeSync {
    Write-Host "Checking time synchronization settings..."
    $w32Time = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    if ($w32Time -and $w32Time.Status -eq 'Running') {
        Write-Host "Windows Time service is running."
    } else {
        Write-Host "Windows Time service is not running."
    }
}

# Function to check for network adapter promiscuous mode
function Check-PromiscuousMode {
    Write-Host "Checking if network adapters are in promiscuous mode..."
    $adapters = Get-NetAdapter
    foreach ($adapter in $adapters) {
        $promiscMode = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "MonitorModeEnabled" -ErrorAction SilentlyContinue
        if ($promiscMode -and $promiscMode.RegistryValue -eq 1) {
            Write-Host "Adapter $($adapter.Name) is in promiscuous mode."
        }
    }
}

# Function to check for unpatched vulnerabilities (requires WSUS or SCCM)
function Check-UnpatchedVulnerabilities {
    Write-Host "Checking for unpatched vulnerabilities..."
    # This function requires enterprise tools and cannot be performed locally
    Write-Host "Unpatched vulnerabilities check requires WSUS or SCCM and cannot be performed locally."
}

# Function to check for enabled remote assistance
function Check-RemoteAssistance {
    Write-Host "Checking if Remote Assistance is enabled..."
    $raStatus = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue
    if ($raStatus.fAllowToGetHelp -eq 1) {
        Write-Host "Remote Assistance is enabled. It should be disabled if not required."
    } else {
        Write-Host "Remote Assistance is disabled."
    }
}

# Function to check for installed browser toolbars or extensions
function Check-BrowserExtensions {
    Write-Host "Checking for installed browser toolbars or extensions..."
    # Checking for Internet Explorer toolbars
    $toolbars = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Internet Explorer\Toolbar" -ErrorAction SilentlyContinue
    if ($toolbars) {
        Write-Host "Browser toolbars detected:"
        $toolbars | ForEach-Object { Write-Host "- $($_.PSChildName)" }
    } else {
        Write-Host "No browser toolbars detected."
    }
}

# Function to check for insecure file shares
function Check-FileShares {
    Write-Host "Checking for insecure file shares..."
    $shares = Get-SmbShare
    foreach ($share in $shares) {
        if ($share.ScopeName -eq '*' -and $share.AccessRight -eq 'Full') {
            Write-Host "Insecure share detected: $($share.Name)"
        }
    }
}

# Function to check for unnecessary scheduled tasks
function Check-UnnecessaryScheduledTasks {
    Write-Host "Checking for unnecessary scheduled tasks..."
    $tasks = Get-ScheduledTask
    foreach ($task in $tasks) {
        if ($task.TaskName -match "Update" -or $task.TaskName -match "Telemetry") {
            Write-Host "Unnecessary scheduled task detected: $($task.TaskName)"
        }
    }
}

# Function to check for insecure environment variables
function Check-EnvironmentVariables {
    Write-Host "Checking for insecure environment variables..."
    $envPaths = $Env:Path.Split(';')
    foreach ($path in $envPaths) {
        if ($path -eq '.' -or $path -eq '') {
            Write-Host "Insecure entry in PATH environment variable: $path"
        }
    }
}

# Function to check for outdated drivers
function Check-OutdatedDrivers {
    Write-Host "Checking for outdated drivers..."
    # Requires external tools or driver databases
    Write-Host "Outdated drivers check requires external tools and cannot be performed locally."
}

# Function to check for enabled telnet server
function Check-TelnetServer {
    Write-Host "Checking if Telnet Server is enabled..."
    $telnetService = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
    if ($telnetService -and $telnetService.Status -eq 'Running') {
        Write-Host "Telnet Server is running. It should be disabled."
    } else {
        Write-Host "Telnet Server is not running."
    }
}

# Function to check for presence of test or sample files
function Check-TestFiles {
    Write-Host "Checking for presence of test or sample files..."
    $sampleFiles = Get-ChildItem -Path "C:\inetpub\wwwroot" -Recurse -Include "sample*", "test*" -ErrorAction SilentlyContinue
    if ($sampleFiles) {
        Write-Host "Test or sample files found in web directory:"
        $sampleFiles | ForEach-Object { Write-Host "- $($_.FullName)" }
    } else {
        Write-Host "No test or sample files found."
    }
}

# Function to check for plaintext passwords in scripts
function Check-PlaintextPasswords {
    Write-Host "Checking for plaintext passwords in scripts..."
    $scriptFiles = Get-ChildItem -Path "C:\Scripts" -Include "*.ps1", "*.bat", "*.cmd" -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $scriptFiles) {
        $content = Get-Content -Path $file.FullName
        if ($content -match "password") {
            Write-Host "Potential plaintext password found in $($file.FullName)"
        }
    }
}

# Function to check for disabled Windows Firewall notifications
function Check-FirewallNotifications {
    Write-Host "Checking if Windows Firewall notifications are disabled..."
    $firewallSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Firewall\PrivateProfile" -Name "DisableNotifications" -ErrorAction SilentlyContinue
    if ($firewallSettings.DisableNotifications -eq 1) {
        Write-Host "Windows Firewall notifications are disabled. They should be enabled."
    } else {
        Write-Host "Windows Firewall notifications are enabled."
    }
}

# Function to check for insecure WMI namespace permissions
function Check-WMIPermissions {
    Write-Host "Checking for insecure WMI namespace permissions..."
    $namespace = Get-WmiObject -Namespace "root" -Class "__namespace" -ErrorAction SilentlyContinue
    if ($namespace) {
        Write-Host "WMI namespaces are accessible."
    } else {
        Write-Host "WMI namespaces are not accessible."
    }
}

# Function to check for outdated Group Policy settings
function Check-GroupPolicy {
    Write-Host "Checking for outdated Group Policy settings..."
    # Requires domain controller access
    Write-Host "Group Policy check requires domain controller access and cannot be performed locally."
}

# Function to check for unsecure SNMP configurations
function Check-SNMPConfig {
    Write-Host "Checking for unsecure SNMP configurations..."
    $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
    if ($snmpService -and $snmpService.Status -eq 'Running') {
        $community = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -ErrorAction SilentlyContinue
        if ($community) {
            Write-Host "SNMP is running with community strings:"
            $community | ForEach-Object { Write-Host "- $($_.PSChildName)" }
        } else {
            Write-Host "SNMP is running but no community strings found."
        }
    } else {
        Write-Host "SNMP service is not running."
    }
}

# Function to check for insecure WinRM configuration
function Check-WinRMConfig {
    Write-Host "Checking WinRM configuration..."
    $winRMService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($winRMService -and $winRMService.Status -eq 'Running') {
        $winRMConfig = winrm get winrm/config/service/auth
        if ($winRMConfig -match "Basic = true") {
            Write-Host "WinRM is configured to allow basic authentication. This should be disabled."
        } else {
            Write-Host "WinRM authentication settings are secure."
        }
    } else {
        Write-Host "WinRM service is not running."
    }
}

# Function to check for outdated PowerShell versions
function Check-PowerShellVersion {
    Write-Host "Checking PowerShell version..."
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-Host "PowerShell version is $($psVersion). It is recommended to update to the latest version."
    } else {
        Write-Host "PowerShell version is up to date."
    }
}

# Function to check for installed IIS server
function Check-IISInstallation {
    Write-Host "Checking for IIS server installation..."
    $iisFeature = Get-WindowsFeature -Name "Web-Server" -ErrorAction SilentlyContinue
    if ($iisFeature -and $iisFeature.Installed -eq $true) {
        Write-Host "IIS server is installed."
    } else {
        Write-Host "IIS server is not installed."
    }
}

# Function to check for allowed applications through firewall
function Check-FirewallAllowedApps {
    Write-Host "Checking for applications allowed through the firewall..."
    $allowedApps = Get-NetFirewallApplicationFilter -PolicyStore ActiveStore
    foreach ($app in $allowedApps) {
        Write-Host "Application allowed: $($app.DisplayName)"
    }
}

# Main function to run all checks
function Run-SecurityAudit {
    Write-Host "Starting security audit..."
    # Existing checks
    Check-WeakPasswords
    Check-MediaFiles
    Check-HackingTools
    Check-IPv6
    Check-RDPConfig
    Check-EmptyPasswords
    Check-PasswordPolicy
    Check-Firewall
    Check-Services
    Check-WorldWritableFiles
    Check-Updates
    Check-GuestAccount
    Check-ScheduledTasks
    Check-AnonymousShares
    Check-RemoteRegistry
    Check-AutoLogon
    Check-OpenPorts
    # New additional functions
    Check-DefaultPasswords
    Check-Antivirus
    Check-OutdatedSoftware
    Check-UnauthorizedUsers
    Check-ImportantServices
    Check-SystemRestore
    Check-AuditPolicy
    Check-BitLockerStatus
    Check-WindowsDefender
    Check-PasswordExpirationPolicy
    Check-SecurityUpdates
    Check-InstalledFeatures
    Check-NTFSPermissions
    Check-IISConfiguration
    Check-UACStatus
    Check-RDPSettings
    Check-SMBv1
    Check-DotNetUpdates
    Check-StartupPrograms
    Check-RegistryPermissions
    Check-LMHashes
    Check-GuestInAdmins
    Check-TimeSync
    Check-PromiscuousMode
    Check-RemoteAssistance
    Check-BrowserExtensions
    Check-FileShares
    Check-UnnecessaryScheduledTasks
    Check-EnvironmentVariables
    Check-TelnetServer
    Check-TestFiles
    Check-PlaintextPasswords
    Check-FirewallNotifications
    Check-WMIPermissions
    Check-SNMPConfig
    Check-WinRMConfig
    Check-PowerShellVersion
    Check-IISInstallation
    Check-FirewallAllowedApps
    Write-Host "Security audit completed."
}

# Run the security audit
Run-SecurityAudit
