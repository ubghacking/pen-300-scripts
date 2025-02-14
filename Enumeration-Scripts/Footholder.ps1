$whoibe = $env:UserName

Write-Host "`n========== [ Checking current domain ] ================================================================================================================`n"

Write-Host "Domain: " $env:USERDNSDOMAIN

Write-Host "`n========== [ Checking deomain logon servers ] =========================================================================================================`n"

$dc = $env:LOGONSERVER -replace "\\", ""
Write-Host "Domain Controller for Logon: " $dc

Write-Host "`n========== [ Checking Antivirus Products ] ============================================================================================================`n"

$antivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState, timestamp
$antivirusProducts | Format-Table -AutoSize

Write-Host "`n========== [ Checking who you are ] ===================================================================================================================`n"

whoami /all

Write-Host "`n========== [ Checking if you're a local admin ] =======================================================================================================`n"

$currentUser = whoami
$adminGroupMembers = net localgroup administrators
if ($adminGroupMembers -contains $currentUser) {
    Write-Output "[!] $whoibe is a Local Administrator!"
    Write-Output "[!] Check for UAC bypass, such as with FodHelper?"
} else {
    Write-Output "[-] $whoibe is not a Local Administrator"
}

Write-Host "`n========== [ Checking Local Admins ] ==================================================================================================================`n"

Get-LocalGroupMember -Group "Administrators" | ft

Write-Host "`n========== [ Checking Network Adapters ] ==============================================================================================================`n"

$hostname = $env:COMPUTERNAME
Write-Host "Hostname: $hostname"

$excludeList = "::1", "127.0.0.1"
Get-NetIPAddress | Where-Object { $_.IpAddress -notmatch ($excludeList -join "|") } | Format-Table InterfaceAlias, IPAddress -AutoSize

# Because of ipv4 and ipv6 loopbacks, it's greater then 3!
if ($ipAddresses.Count -gt 3) {
    Write-Host "[!] Multiple IP addresses detected. This might be interesting to pivot to another network."
}

Write-Host "`n========== [ Checking PowerShell history ] ============================================================================================================`n"

$history = (Get-PSReadlineOption).HistorySavePath

if (Test-Path -Path $history -PathType Leaf) {
  Get-Content -Path $history
}

Write-Host "`n========== [ Checking for shared drives ] =============================================================================================================`n"

Get-CimInstance -ClassName Win32_MappedLogicalDisk | Select SystemName, DeviceID, ProviderName | ft

Write-Host "`n========== [ Checking for Applocker Policies ] ========================================================================================================`n"

Get-AppLockerPolicy -Effective | Format-List

# Display header for installed software
Write-Host "`n========== [ Installed Software Gathered from Windows Registry ] ======================================================================================`n"

# For 64-bit applications
$programs64 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
               Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

Write-Host "`n[64 BIT APPLICATIONS]`n"
$programs64 | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object {
    Write-Host "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher) - Install Date: $($_.InstallDate)"
}

# For 32-bit applications on a 64-bit OS
$programs32 = Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
               Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

Write-Host "`n[32 BIT APPLICATIONS]`n"
$programs32 | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object {
    Write-Host "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher) - Install Date: $($_.InstallDate)"
}

# Display header for subfolders
Write-Host "`n========== [ List of Subfolders in Program Files ] ====================================================================================================`n"

# List subfolders in C:\Program Files
Write-Host "`n[64 BIT PROGRAM FILES]`n"
$programFiles64 = Get-ChildItem "C:\Program Files" -Directory -ErrorAction SilentlyContinue

if ($programFiles64) {
    $programFiles64 | ForEach-Object {
        Write-Host "$($_.FullName)"
    }
} else {
    Write-Host "No subfolders found in C:\Program Files."
}

# List subfolders in C:\Program Files (x86)
Write-Host "`n[32 BIT PROGRAM FILES]`n"
$programFiles32 = Get-ChildItem "C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue

if ($programFiles32) {
    $programFiles32 | ForEach-Object {
        Write-Host "$($_.FullName)"
    }
} else {
    Write-Host "No subfolders found in C:\Program Files (x86)."
}

Write-Host "`n========== [ Checking for Unquoted Service Paths ] ====================================================================================================`n"

$unquotedServices = Get-WmiObject -Class Win32_Service -Property Name, DisplayName, PathName, StartMode | 
Where-Object { 
    $_.StartMode -eq "Auto" -and 
    $_.PathName -notlike "C:\Windows*" -and 
    $_.PathName -notlike '"*' -and 
    $_.PathName -match '\s' -and 
    $_.PathName -notlike '*"*"'
} | 
Select-Object PathName, DisplayName, Name

if ($unquotedServices) {
    Write-Host "`n[!] Unquoted service paths found:`n"
    foreach ($service in $unquotedServices) {
        Write-Host "Service Name: $($service.Name)"
        Write-Host "Display Name: $($service.DisplayName)"
        Write-Host "Path Name: $($service.PathName)"
        Write-Host "---------------------------------------------"
    }
} else {
    Write-Host "`n[!] No unquoted service paths found."
    Write-Host "`n[!] DO NOT rely soley on this script, do your due diligence with another Privilege Escalation check!"
}

# AlwaysInstallElevated registry keys
Write-Host "`n========== [ Checking for AlwaysInstallElevated Vulnerability ] =======================================================================================`n"

# Initialize a variable to track vulnerability status
$vulnerable = $false

# Check HKCU
$hkcuValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
if ($hkcuValue) {
    if ($hkcuValue.AlwaysInstallElevated -eq 1) {
        Write-Host "Current User (HKCU): AlwaysInstallElevated is set to 1 (Vulnerable)"
        $vulnerable = $true
    } else {
        Write-Host "Current User (HKCU): AlwaysInstallElevated is set to 0 (Not Vulnerable)"
    }
} else {
    Write-Host "Current User (HKCU): AlwaysInstallElevated key does not exist."
}

# Check HKLM
$hklmValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
if ($hklmValue) {
    if ($hklmValue.AlwaysInstallElevated -eq 1) {
        Write-Host "Local Machine (HKLM): AlwaysInstallElevated is set to 1 (Vulnerable)"
        $vulnerable = $true
    } else {
        Write-Host "Local Machine (HKLM): AlwaysInstallElevated is set to 0 (Not Vulnerable)"
    }
} else {
    Write-Host "Local Machine (HKLM): AlwaysInstallElevated key does not exist."
}

# Final vulnerability status
if ($vulnerable) {
    Write-Host "`n[!] The system is vulnerable due to AlwaysInstallElevated being set to 1."
} else {
    Write-Host "`n[-] The system is not vulnerable."
    Write-Host "`n[!] DO NOT rely soley on this script, do your due diligence with another Privilege Escalation check!"
}


################################################ C:\Users Intersting Files #################################################
# Added section to search for specific files in C:\Users
$foundFiles = Get-ChildItem -Path "C:\Users" -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log,*.ps1,*.bat,*.conf -File -Recurse -ErrorAction SilentlyContinue

if ($foundFiles) {
    Write-Host "`n========== [ Found Interesting Files in C:\Users ] ===================================================================================================`n"
    foreach ($file in $foundFiles) {
        Write-Host "Found: $($file.FullName)"
    }
}

Write-Host "`n========== [ Checking for .ssh directories ] ==========================================================================================================`n"

$users = Get-ChildItem -Path "C:\Users" -Directory
foreach ($user in $users) {
    $sshPath = Join-Path -Path $user.FullName -ChildPath ".ssh"
    if (Test-Path -Path $sshPath -ErrorAction SilentlyContinue) {
        Write-Host "[!] $($user.Name) has an .ssh directory, with current users read permissions!"
        Write-Host "[!] Potential SSH keys found. We can try to crack the key, use it for lateral movement, and it could belong to someone else who we currently are"
    } else {
    Write-Host "[-] No .ssh found in $($User.Name)"
    }
}

# Added section to search for specific files
Write-Host "`n========== [ Checking for flags ] =====================================================================================================================`n"

$flagFiles = Get-ChildItem -Path "C:\Users\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in "proof.txt", "local.txt", "secret.txt" }

if ($flagFiles) {
    Write-Host "[!] Found Flag File!`n"
    foreach ($file in $flagFiles) {
        Write-Host "Found: $($file.FullName)"
    }

    # Commands to run based on the number of files found
    Write-Host "`n[!] Run the following commands to capture the flag and make a screenshot:`n"
    Write-Host "whoami"
    Write-Host "hostname"
    Write-Host "ipconfig"
    
    # Indicate the location of each flag file
    foreach ($file in $flagFiles) {
        Write-Host "Type $($file.FullName)"
    }
}

Write-Host "`n========== [ Checking for other interesting files in disk ] ===========================================================================================`n"

Write-Host "`n[*] This takes a while, pleasse be pateient...`n"

$dirs = Get-ChildItem -Path "C:\" -Directory | Select-Object -ExpandProperty Name
$excludedDirs = "Windows", "PerfLogs, Users"
$includedDirs = $dirs | Where-Object { $excludedDirs -notcontains $_}

foreach ($dir in $includedDirs) {
    Get-ChildItem -Recurse -File -Path "C:\$dir" -ErrorAction SilentlyContinue -Exclude "*Windows*", "*PerfLogs*" | Select-String -Pattern $whoibe | ForEach-Object { "$($_.Path)"}
}

Write-Host "`n[!] This might still require some manual enumeration, this was iffy in testing...`n`n"
