A collection of simple scripts written through the OffSec's PEN300 course for public consumption.

# Footholder - Basic Windows Enum Script

This script performs the basic situational awareness checks for Windows machines:

1. Print to console the current domain
2. Print to console the current domain logon servers
3. Check for any Antivirus Products
4. Check who you are, with `whoami /all`
5. Check if you are a local administrator on the box
6. Print to console the local administrator groups
7. Print to console the attached network adapters, to find if you are dual homed
8. Print to console any PowerShell history
9. Check for any connected shared drives
10. Check for AppLocker Policies
11. Print to console installed software (32 bit and 64 bit, categorized)
12. Print to console "Program Files" and "Program Files (x86)" to check for anything interesting within those directories.
13. PrivEsc - Check for any unquoted service paths
14. PrivEsc - Check for AlwaysInstalledElevated
15. Check for interesting files in `C:\Users`
16. Check for any .ssh directories in `C:\Users\<USERNAME>\.ssh`
    a. If the directory exists, print to console SSH Keys, RSA Leys, Public Keys, authorized_keys
17. Check for flags (local.txt, proof.txt, ssecret.txt)
    a. If found, prints to console, with a reminder for commands:
    <br />whoami
    <br />hostname
    <br />ipconfig
    <br />Type `C:\Users\Path\To\Flag.txt`
18. Checks for other intersting files on disk
    a. Excludes `C:\Users`, `C:\Windows`, `C:\PerfLogs`

# Bssic OSEP Linux Enum

This script performs (you guessed it) basic enumeration tasks on a Linux machine:

1. Checks for ansible
2. Checks for ansible hosts
3. Locates ansible playbooks
4. Checks for passwords in various log file locations
5. Checks if jfrog is installed
6. Checks for jfrog artifactory and console logs
7. Checks for access.backup
8. Checks for ssh key files
9. Checks for ssh_config files that contain ControlMaster or ControlPath
10. Checks for any socket files
11. Checks for running processes with SSH_AUTH_SOCK
12. Checks for .ssh files in `/home` directories

# Venom-Generator

[!] THese are not going to bypass defender as is! This just jumpstarts your exam, with vanilla shellcode you must take and encode/encrypt/whatever to bypass defender. [!]

This script will create all your payloads that you used in the course.

[!] Warning!
<br />These were all tested in a homelab, and not inside the course labs! If you're not getting a callback, not my fault.

1. 32-bit reverse_https and reverse_tcp vbapplication, csharp payloads
2. 64 bit reverse_https and reverse_https raw, csharp, powershell, vbapplication, exe, dll, elf (no reverse_https, as that payload doesn't exist for ELF) and msi payloads
3. A lonely, single reverse_tcp_ssl python payload (That I can't recall where it was used in the course, but it's in my notes, so it's in the script)

```
├── csharp
│   ├── reverse_https-x32-csharp.txt
│   ├── reverse_https-x64-csharp.txt
│   ├── reverse_tcp-x32-csharp.txt
│   └── reverse_tcp-x64-csharp.txt
├── dll
│   ├── reverse_https-x64-dll.dll
│   └── reverse_tcp-x64-dll.dll
├── elf
│   └── reverse_tcp-x64-elf
├── exe
│   ├── reverse_https-x64-exe.exe
│   └── reverse_tcp-x64.exe
├── msi
│   ├── reverse_https-x64-msi.msi
│   └── reverse_tcp-x64-msi.msi
├── powershell
│   ├── reverse_https-x64-ps1.ps1
│   └── reverse_tcp-x64-ps1.ps1
├── python
│   └── reverse_tcp_ssl.py
├── raw
│   ├── reverse_https-x64-raw.bin
│   └── reverse_tcp-x64-raw.bin
├── vbapplication
│   ├── reverse_https-x32-vpapplication.txt
│   ├── reverse_https-x64-vbapplication.txt
│   ├── reverse_tcp-x32-vpapplication.txt
│   └── reverse_tcp-x64-vbapplication.txt
└── venom-generator.sh
```