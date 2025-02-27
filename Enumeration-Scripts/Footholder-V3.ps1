function Check-Domain {
    Write-Host "`n========== [ Checking current domain ] ================================================================================================================`n"
    Write-Host "Domain: " $env:USERDNSDOMAIN
}

function Check-DomainLogonServers {
    Write-Host "`n========== [ Checking domain logon servers ] =========================================================================================================`n"
    $dc = $env:LOGONSERVER -replace "\\", ""
    Write-Host "Domain Controller for Logon: " $dc
}

function Check-OS-Information {
    Write-Host "`n========== [ System Information Overview ] ============================================================================================================`n"
    # Get Operating System Information
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osDetails = "Operating System: $($osInfo.Caption) $($osInfo.Version) (Architecture: $($osInfo.OSArchitecture))"

    # Get Installed Security Patches
    $installedPatches = Get-HotFix | Select-Object Description, HotFixID, InstalledOn

    # Get Memory Information
    $memoryInfo = Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum
    $totalMemory = [math]::round($memoryInfo.Sum / 1GB, 2)

    # Get Drive Information
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{Name='Used(GB)';Expression={[math]::round($_.Used/1GB, 2)}}, @{Name='Free(GB)';Expression={[math]::round($_.Free/1GB, 2)}}, @{Name='Total(GB)';Expression={[math]::round($_.Used/1GB + $_.Free/1GB, 2)}}

    # Output the information
    Write-Host $osDetails
    Write-Host "Total Physical Memory: $totalMemory GB`n"

    if ($null -eq $installedPatches -or $installedPatches.Count -eq 0) {
        Write-Host "No security patches found."
    } else {
        Write-Host "Installed Security Patches:`n"
        $installedPatches | Format-Table -AutoSize
    }

    Write-Host "`nDrive Information:`n"
    $drives | Format-Table -AutoSize
}

function Check-AntivirusStatus {
    Write-Host "`n========== [ Checking Antivirus Status ] ============================================================================================================`n"

    # Get Windows Defender status
    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if ($defenderStatus) {
        # Display Windows Defender information
        $signatureDate = $defenderStatus.AntispywareSignatureLastUpdated
        $antivirusEnabled = $defenderStatus.AntivirusEnabled

        Write-Host "Windows Defender is installed."
        Write-Host "Antivirus Enabled: $antivirusEnabled"
        Write-Host "Antispyware Signature Last Updated: $signatureDate"
    } else {
        Write-Host "Windows Defender is not installed or not available."
    }

    # Get all antivirus products
    $antivirusProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | 
                         Select-Object displayName, productState, timestamp

    if ($null -eq $antivirusProducts -or $antivirusProducts.Count -eq 0) {
        Write-Host "Failed to retrieve antivirus products or no antivirus products found."
    } else {
        Write-Host "`nOther Antivirus Products:`n"
        $antivirusProducts | Format-Table -AutoSize
    }
}

function Check-WhoAmI {
    Write-Host "`n========== [ Checking who you are ] ===================================================================================================================`n"
    whoami /all
}

function check-UAV-bypass {
    # Check if the user is a member of the local Administrators group
    $adminGroup = "Administrators"
    $localAdminCheck = net localgroup $adminGroup | Select-String -Pattern $env:USERNAME

    if (-not $localAdminCheck) {
        Write-Host "You are not an administrator and we cannot use UAC bypass."
        exit
    }

    # Check the UAC settings in the registry
    $uacKeyPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $enableLUA = (Get-ItemProperty -Path $uacKeyPath -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
    $promptSecureDesktop = (Get-ItemProperty -Path $uacKeyPath -Name "PromptSecureDesktop" -ErrorAction SilentlyContinue).PromptSecureDesktop

    if ($enableLUA -eq 0) {
        Write-Host "UAC is disabled (EnableLUA = 0). You can use PsExec to run commands as SYSTEM."
    } elseif ($enableLUA -eq 1) {
        Write-Host "UAC is enabled (EnableLUA = 1)."

        if ($promptSecureDesktop -eq 1) {
            Write-Host "PromptSecureDesktop is enabled. You may need to look for eventvwr or fodhelper bypass."
            
            # Check for the presence of eventvwr.exe and fodhelper.exe
            $eventvwrPath = "C:\Windows\System32\eventvwr.exe"
            $fodhelperPath = "C:\Windows\System32\fodhelper.exe"

            $eventvwrExists = Test-Path $eventvwrPath
            $fodhelperExists = Test-Path $fodhelperPath

            if ($eventvwrExists -and $fodhelperExists) {
                Write-Host "Both eventvwr.exe and fodhelper.exe are present."
                Write-Host "Locations:"
                Write-Host " - eventvwr.exe: $eventvwrPath"
                Write-Host " - fodhelper.exe: $fodhelperPath"
            } elseif ($eventvwrExists) {
                Write-Host "Only eventvwr.exe is present."
                Write-Host "Location: $eventvwrPath"
            } elseif ($fodhelperExists) {
                Write-Host "Only fodhelper.exe is present."
                Write-Host "Location: $fodhelperPath"
            } else {
                Write-Host "Neither eventvwr.exe nor fodhelper.exe is present."
            }
        } else {
            Write-Host "PromptSecureDesktop is disabled. You may not need to look for bypass methods."
        }
    } else {
        Write-Host "Unexpected value for EnableLUA: $enableLUA"
    }
}


function Check-LocalAdmin {
    Write-Host "`n========== [ Checking if you're a local admin ] =======================================================================================================`n"
    $whoibe = $env:Username
    $currentUser  = whoami
    $adminGroupMembers = net localgroup administrators
    if ($adminGroupMembers -contains $currentUser ) {
        Write-Output "[!] $whoibe is a Local Administrator!"
        Write-Output "[!] Check for UAC bypass, such as with FodHelper?"
        check-UAV-bypass 
    } else {
        Write-Output "[-] $whoibe is not a Local Administrator"
    }
}

function Check-LocalAdmins {
    Write-Host "`n========== [ Checking Local Admins ] ==================================================================================================================`n"
    
    if (!(Get-Command -Name "Get-LocalGroupMember" -ErrorAction SilentlyContinue)) {

        net localgroup administrators

        } else {

        Get-LocalGroupMember -Group "Administrators" | ft
    }
}

function Check-NetworkAdapters {
    Write-Host "`n========== [ Checking Network Adapters ] ==============================================================================================================`n"
    $hostname = $env:COMPUTERNAME
    Write-Host "Hostname: $hostname"
    $excludeList = "::1", "127.0.0.1"
    
    # Get the IP addresses excluding the ones in the exclude list
    $ipAddresses = Get-NetIPAddress | Where-Object { $_.IpAddress -notmatch ($excludeList -join "|") }
    
    # Get the default gateway
    $defaultGateway = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 -ExpandProperty NextHop

    # Print header
    Write-Host "`n========== [ Network Configuration ] ===================================================================================================================`n"
    
    # Check if there are any valid IP addresses
    if ($ipAddresses) {
        Write-Host "Detected IP Addresses:"
        foreach ($ip in $ipAddresses) {
            Write-Host " - IP Address: $($ip.IPAddress)"
        }
    } else {
        Write-Host "No valid IP addresses found."
    }

    # Print the default gateway
    if ($defaultGateway) {
        Write-Host "Default Gateway: $defaultGateway"
    } else {
        Write-Host "No default gateway found."
    }

    # Check the count of IP addresses
    if ($ipAddresses.Count -gt 3) {
        Write-Host "[!] DON'T MISS THIS!"
        Write-Host "[!] Multiple IP addresses detected. This might be interesting to pivot to another network."
    }
}

function Check-OpenPorts_Services {
    Write-Host "`n========== [ Enumerating Open Ports and Services ] ====================================================================================================`n"
    # Attempt to enumerate open TCP ports and their associated services
    $openPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object LocalAddress, LocalPort, OwningProcess

    if ($null -eq $openPorts -or $openPorts.Count -eq 0) {
        # If no open ports were retrieved, output a message
        Write-Host "No open ports found or failed to retrieve open ports."
    } else {
        # If open ports were retrieved, display them along with the owning process names
        $openPorts | ForEach-Object {
            $processName = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName
            Write-Host "$($_.LocalAddress):$($_.LocalPort) is being listened on by $processName"
        }
    }
}

function Check-PowerShellHistory {
    Write-Host "`n========== [ Checking PowerShell history ] ============================================================================================================`n"
    $history = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path -Path $history -PathType Leaf) {
        Get-Content -Path $history
    }
}

function Check-C-Drive {
    Write-Host "`n========== [ Listing All Folders in C:\ ] ============================================================================================================`n"
    # Attempt to list all directories in C:\
    $folders = Get-ChildItem -Path "C:\" -Directory -ErrorAction SilentlyContinue

    if ($null -eq $folders -or $folders.Count -eq 0) {
        # If no folders were retrieved, output a message
        Write-Host "Failed to retrieve folders or no folders found in C:\."
    } else {
        # If folders were retrieved, display them
        $folders | Format-Table -AutoSize
    }
}

function Check-SharedDrives {
    Write-Host "`n========== [ Checking for shared drives ] =============================================================================================================`n"
    Get-CimInstance -ClassName Win32_MappedLogicalDisk | Select SystemName, DeviceID, ProviderName | ft
}

function Check-AppLockerPolicies {
    Write-Host "`n========== [ Checking for Applocker Policies ] ========================================================================================================`n"
    Get-AppLockerPolicy -Effective | Format-List
}

function Check-InstalledSoftware {
    Write-Host "`n========== [ Installed Software Gathered from Windows Registry ] ======================================================================================`n"
    $programs64 = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                   Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    Write-Host "`n[64 BIT APPLICATIONS]`n"
    $programs64 | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object {
        Write-Host "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher) - Install Date: $($_.InstallDate)"
    }

    $programs32 = Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
                   Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

    Write-Host "`n[32 BIT APPLICATIONS]`n"
    $programs32 | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object {
        Write-Host "$($_.DisplayName) - Version: $($_.DisplayVersion) - Publisher: $($_.Publisher) - Install Date: $($_.InstallDate)"
    }
}

function Check-ProgramFiles {
    Write-Host "`n========== [ List of Subfolders in Program Files ] ====================================================================================================`n"
    Write-Host "`n[64 BIT PROGRAM FILES]`n"
    $programFiles64 = Get-ChildItem "C:\Program Files" -Directory -ErrorAction SilentlyContinue
    if ($programFiles64) {
        $programFiles64 | ForEach-Object {
            Write-Host "$($_.FullName)"
        }
    } else {
        Write-Host "No subfolders found in C:\Program Files."
    }

    Write-Host "`n[32 BIT PROGRAM FILES]`n"
    $programFiles32 = Get-ChildItem "C:\Program Files (x86)" -Directory -ErrorAction SilentlyContinue
    if ($programFiles32) {
        $programFiles32 | ForEach-Object {
            Write-Host "$($_.FullName)"
        }
    } else {
        Write-Host "No subfolders found in C:\Program Files (x86)."
    }
}

function Check-UnquotedServicePaths {
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
        Write-Host "`n[-] No unquoted service paths found."
        Write-Host "`n[!] DO NOT rely solely on this script, do your due diligence with another Privilege Escalation check!"
    }
}

function Check-AlwaysInstallElevated {
    Write-Host "`n========== [ Checking for AlwaysInstallElevated Vulnerability ] =======================================================================================`n"
    $vulnerable = $false

    $hkcuValue = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($hkcuValue) {
        if ($hkcuValue.AlwaysInstallElevated -eq 1) {
            Write-Host "Current User (HKCU): AlwaysInstallElevated is set to 1 (VULNERABLE!)"
            $vulnerable = $true
        } else {
            Write-Host "Current User (HKCU): AlwaysInstallElevated is set to 0 (Not Vulnerable)"
        }
    } else {
        Write-Host "Current User (HKCU): AlwaysInstallElevated key does not exist."
    }

    $hklmValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
    if ($hklmValue) {
        if ($hklmValue.AlwaysInstallElevated -eq 1) {
            Write-Host "Local Machine (HKLM): AlwaysInstallElevated is set to 1 (VULNERABLE!)"
            $vulnerable = $true
        } else {
            Write-Host "Local Machine (HKLM): AlwaysInstallElevated is set to 0 (Not Vulnerable)"
        }
    } else {
        Write-Host "Local Machine (HKLM): AlwaysInstallElevated key does not exist."
    }

    if ($vulnerable) {
        Write-Host "`n[!] Possible PrivEsc DISCOVERED!"
        Write-Host "[!] The system IS vulnerable due to AlwaysInstallElevated being set to 1."
    } else {
        Write-Host "`n[-] The system is not vulnerable."
        Write-Host "`n[!] DO NOT rely solely on this script, do your due diligence with another Privilege Escalation check!"
    }
}

function Check-InterestingFiles {
    Write-Host "`n========== [ Checking for interesting files in C:\Users ] =============================================================================================`n"
    $foundFiles = Get-ChildItem -Path "C:\Users" -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log,*.ps1,*.bat,*.conf -File -Recurse -ErrorAction SilentlyContinue

    if ($foundFiles) {
        foreach ($file in $foundFiles) {
            Write-Host "Found: $($file.FullName)"
        }
    }
}

function Check-SSHDirectories {
    Write-Host "`n========== [ Checking for .ssh directories ] ==========================================================================================================`n"
    $users = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($user in $users) {
        $sshPath = Join-Path -Path $user.FullName -ChildPath ".ssh"
        if (Test-Path -Path $sshPath -ErrorAction SilentlyContinue) {
            Write-Host "`n`n[!] $($user.Name) has an .ssh directory, with current users read permissions!"
            Write-Host "[!] Potential SSH keys found. We can try to crack the key, use it for lateral movement, and it could belong to someone else who we currently are"
            Write-Host "[!] Going to try to print to console... Should check the directory anyways!`n`n"

        Get-ChildItem -Path $sshPath -File | ForEach-Object {
            Write-Host "FILENAME: " $sshPath\$_.Name
            Write-Host ""
            Get-Content -Path $sshPath\$_
            Write-Host ""
        }      
            
        } else {
        Write-Host "[-] No .ssh found in $($User.Name), WITH CURRENT USER PERMISSIONS!"
        }
    }
}

function Check-Flags {
    Write-Host "`n========== [ Checking for flags ] =====================================================================================================================`n"
    $flagFiles = Get-ChildItem -Path "C:\Users\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in "proof.txt", "local.txt", "secret.txt" }

    if ($flagFiles) {
        Write-Host "[!] Found Flag File!`n"
        foreach ($file in $flagFiles) {
            Write-Host "Found: $($file.FullName)"
        }

        Write-Host "`n[!] Run the following commands to capture the flag and make a screenshot:`n"
        Write-Host "whoami"
        Write-Host "hostname"
        Write-Host "ipconfig"
        
        foreach ($file in $flagFiles) {
            Write-Host "Type $($file.FullName)"
        }
    }
}

function Check-OtherInterestingFiles {
    Write-Host "`n========== [ Checking for other interesting files in disk ] ===========================================================================================`n"
    Write-Host "`n[*] This takes a while, pleasse be pateient...`n"

    $whoibe = $env:Username
    $dirs = Get-ChildItem -Path "C:\" -Directory | Select-Object -ExpandProperty Name
    $excludedDirs = "Windows", "PerfLogs, Users"
    $includedDirs = $dirs | Where-Object { $excludedDirs -notcontains $_}

    foreach ($dir in $includedDirs) {
        Get-ChildItem -Recurse -File -Path "C:\$dir" -ErrorAction SilentlyContinue -Exclude "*Windows*", "*PerfLogs*" | Select-String -Pattern $whoibe | ForEach-Object { "$($_.Path)"}
    }
}

function Get-DomainGroups {
    Write-Host "`n========== [ Listing Domain Groups ] =================================================================================================================`n"

    # Get the list of all domain groups
    $groups = net group /domain | Where-Object { 
        $_ -notmatch "The command completed successfully" -and 
        $_ -notmatch "There are no entries" -and 
        $_ -notmatch "Group" -and 
        $_ -notmatch "----" -and 
        $_ -notmatch "Aliases for" -and
        $_ -notmatch "\\\\"
    }

    if ($groups.Count -eq 0) {
        Write-Host "No domain groups found."
    } else {
        foreach ($group in $groups) {
            # Trim whitespace
            $group = $group.Trim()

            if (-not [string]::IsNullOrWhiteSpace($group)) {
                Write-Host $group
            }
        }
    }
}

function Get-DomainUsers {
    Write-Host "`n========== [ Listing Domain Users ] =================================================================================================================`n"

    # Get the list of all domain users
    $users = net user /domain | Where-Object { 
        $_ -notmatch "The command completed successfully" -and 
        $_ -notmatch "There are no entries" -and 
        $_ -notmatch "User  accounts for" -and 
        $_ -notmatch "----" -and 
        $_ -notmatch "The request will be processed at a domain controller for domain" -and
        $_ -notmatch "\\\\"
    }

    if ($users.Count -eq 0) {
        Write-Host "No domain users found."
    } else {
        foreach ($user in $users) {
            # Trim whitespace
            $user = $user.Trim()

            if (-not [string]::IsNullOrWhiteSpace($user)) {
                Write-Host $user
            }
        }
    }
}

function Get-DomainEmailAddresses {
    Write-Host "`n========== [ Generating Domain Email Addresses ] =================================================================================================================`n"

    # Retrieve the domain name from the environment variable
    $domain = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

    # Capture the output of the net user command
    $userOutput = net user /domain

    # Initialize an array to hold the email addresses
    $emailAddresses = @()

    # Process the output to extract usernames
    $userLines = $userOutput -split "`n" | Where-Object { 
        $_ -notmatch "The command completed successfully" -and 
        $_ -notmatch "User   accounts for" -and 
        $_ -notmatch "----" -and 
        $_ -notmatch "The request will be processed at a domain controller for domain" -and 
        $_ -notmatch "\\\\"
    }

    foreach ($line in $userLines) {
        # Split the line into individual usernames
        $usernames = $line -split "\s+"  # Split by whitespace

        foreach ($username in $usernames) {
            # Trim whitespace and check if the username is not empty
            $username = $username.Trim()
            if (-not [string]::IsNullOrWhiteSpace($username)) {
                # Generate email address
                $emailAddress = "$username@$domain"
                
                # Add email address to the array
                $emailAddresses += $emailAddress
            }
        }
    }

    # Define the file path for the output
    $emailFilePath = "C:\Users\Public\Downloads\potential-emailaddresses.txt"

    # Write the email addresses to the file
    $emailAddresses | Out-File -FilePath $emailFilePath -Encoding UTF8

    # Print the email addresses to the console
    Write-Host "`nGenerated Email Addresses:`n"
    $emailAddresses | ForEach-Object { Write-Host $_ }

    Write-Host "`nEmail addresses have been written to $emailFilePath"
}

function Get-DomainGroupMembers {
    Write-Host "`n========== [ Retrieving Domain Group Members ] =====================================================================================================`n"

    # Run the net group command and capture the output
    $output = net group /domain

    # Initialize an array to hold the group names
    $domainGroups = @()

    # Loop through each line of the output to gather group names
    foreach ($line in $output) {
        # Check if the line starts with an asterisk and is not empty
        if ($line -match '^\*') {
            # Trim the asterisk and any leading/trailing whitespace, then add to the array
            $groupName = $line.Trim().TrimStart('*').Trim()
            $domainGroups += $groupName
        }
    }

    # Iterate through each domain group and get its members
    foreach ($group in $domainGroups) {
        # Print the header for the group
        Write-Host "==== [ Domain: $group ] ====="

        # Run the net group command for the specific group and capture the output
        $groupMembersOutput = net group $group /domain

        # Loop through the output to find and print the usernames
        foreach ($memberLine in $groupMembersOutput) {
            # Check if the line contains a username (not empty and not a header line)
            if ($memberLine -and $memberLine -notmatch 'Group Accounts|The command completed successfully|^$') {
                # Print the username
                Write-Host $memberLine.Trim()
            }
        }

        # Print a separator for clarity
        Write-Host "====================================`n"
    }
}



# Call all functions to execute the script
Check-Domain
Check-DomainLogonServers
Check-OS-Information
Check-AntivirusStatus
Check-WhoAmI
Check-LocalAdmin
Check-LocalAdmins
Check-NetworkAdapters
Check-OpenPorts_Services
Check-PowerShellHistory
Check-C-Drive
Check-SharedDrives
Check-AppLockerPolicies
Check-InstalledSoftware
Check-ProgramFiles
Check-UnquotedServicePaths
Check-AlwaysInstallElevated
Check-InterestingFiles
Check-SSHDirectories
Check-Flags
Check-OtherInterestingFiles
Get-DomainGroups
Get-DomainUsers
Get-DomainEmailAddresses
Get-DomainGroupMembers

Write-Host "`n[!] This might still require some manual enumeration! This was not fool-proofed...`n`n"
