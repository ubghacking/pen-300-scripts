A collection of simple scripts written through the course.

# Footholder

This script performs the basic situational awareness checks, so I do not forget to perform them. It will:

1. Print to console tje current domain
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
    whoami
    hostname
    ipconfig
    Type `C:\Users\Path\To\Flag.txt`
18. Checks for other intersting files on disk
    a. Excludes `C:\Users`, `C:\Windows`, `C:\PerfLogs`