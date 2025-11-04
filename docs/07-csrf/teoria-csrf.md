# Teoria Fundamental de CSRF (Cross-Site Request Forgery)

**Criticidade**: 🟡 Média a 🟠 Alta (CVSS 4.0-8.0)
**Dificuldade**: 🟢 Básica a 🟡 Intermediária
**Bounty Médio**: $500 - $7,500 USD

---

## 📚 Índice

1. [Fundamentos de State Management](#fundamentos-de-state-management)
2. [HTTP e Statelessness](#http-e-statelessness)
3. [Cookie-Based Authentication](#cookie-based-authentication)
4. [Teoria de Ambient Authority](#teoria-de-ambient-authority)
5. [SameSite Cookie Internals](#samesite-cookie-internals)
6. [Token-Based Defenses](#token-based-defenses)

---

## 🔬 Fundamentos de State Management

### O Que É CSRF em Essência?

**CSRF (Cross-Site Request Forgery)** é fundamentalmente um problema de **autenticação automática** que ocorre quando:

1. **Browser envia credenciais automaticamente** (cookies, headers)
2. **Servidor confia apenas em credenciais automáticas**
3. **Atacante induz vítima a fazer request malicioso**

### Por Que CSRF É Diferente de XSS

**Comparação:**

```
XSS (Cross-Site Scripting):
  Objetivo: Executar JavaScript no contexto da vítima
  Método: Injetar script malicioso
  Resultado: Atacante CONTROLA página da vítima
  Escopo: Same-origin (após XSS)

CSRF (Cross-Site Request Forgery):
  Objetivo: Fazer request em nome da vítima
  Método: Induzir browser a enviar request
  Resultado: Atacante FAZ AÇÕES como vítima
  Escopo: Cross-origin
```

**Modelo Formal:**

```
XSS:
  attacker.com → injeta script → victim.com
                                      ↓
                                JavaScript executa
                                      ↓
                                Controle total

CSRF:
  attacker.com → induz request → victim.com
       ↓                              ↑
  Vítima visita          Request vem do browser da vítima
  página maliciosa       com cookies/credenciais válidos
```

---

## 🌐 HTTP e Statelessness

### HTTP Protocol é Stateless

**Definição:** Cada request HTTP é **independente** e **sem contexto** de requests anteriores

**Problema:**

```http
Request 1:
GET /login HTTP/1.1
Host: bank.com
```

```http
Request 2:
GET /transfer?to=attacker&amount=1000 HTTP/1.1
Host: bank.com

Como servidor sabe que Request 2 vem do mesmo usuário logado de Request 1?
→ NÃO SABE! HTTP não mantém estado.
```

### Soluções para State Management

**Solução 1: Cookies**

```http
Response to Request 1 (login):
HTTP/1.1 200 OK
Set-Cookie: session_id=abc123; HttpOnly; Secure

Request 2 (transfer):
GET /transfer?to=attacker&amount=1000 HTTP/1.1
Cookie: session_id=abc123  ← Browser envia automaticamente!
```

**Problema:** Browser envia cookie **AUTOMATICAMENTE** em TODA request para domain

```javascript
// Página do atacante em attacker.com
<img src="https://bank.com/transfer?to=attacker&amount=1000">

// Browser vê: request para bank.com
// Browser envia: Cookie: session_id=abc123 (se vítima estiver logada!)
// Server vê: request autenticado válido
// Server executa: transferência!
```

**Solução 2: Token no URL**

```
GET /transfer?to=attacker&amount=1000&token=xyz789
```

**Problema:** Token pode vazar (referer, logs, browser history)

**Solução 3: Token no Header (Custom)**

```http
POST /transfer HTTP/1.1
X-CSRF-Token: xyz789
```

**Por que é mais seguro:** Browser NÃO adiciona headers customizados automaticamente

---

## 🍪 Cookie-Based Authentication

### Anatomia de um Cookie

**Set-Cookie Header:**

```http
Set-Cookie: session=abc123; Domain=bank.com; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600
```

**Atributos:**

```
session=abc123       → Nome e valor do cookie
Domain=bank.com      → Cookie enviado para *.bank.com
Path=/               → Cookie enviado para todos paths em bank.com
Secure               → Cookie só enviado via HTTPS
HttpOnly             → JavaScript não pode acessar (document.cookie)
SameSite=Strict      → Cookie não enviado em cross-site requests
Max-Age=3600         → Cookie expira em 1 hora
```

### Browser Cookie Storage

**Estrutura Interna:**

```
Browser mantém Cookie Jar:

Map<Domain, Map<Path, Map<Name, Cookie>>>

Exemplo:
  bank.com
    /
      session → {value: "abc123", secure: true, httpOnly: true, sameSite: "Strict"}
      prefs → {value: "dark_mode", secure: false, httpOnly: false}
    /admin
      admin_token → {value: "xyz789", secure: true}
```

**Quando Browser Envia Cookie:**

```
Request: GET https://bank.com/account

Browser checks:
  1. Domain matches? bank.com ✓
  2. Path matches? /account starts with / ✓
  3. Secure? HTTPS ✓
  4. Not expired? Check Max-Age ✓
  5. SameSite? Check request context

If all ✓ → Send: Cookie: session=abc123; prefs=dark_mode
```

### CSRF via Automatic Cookie Sending

**Scenario:**

```html
<!-- attacker.com page -->
<form id="csrf" action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000">
</form>
<script>
    document.getElementById('csrf').submit();
</script>
```

**O que acontece:**

```
1. Vítima acessa attacker.com (while logged into bank.com)

2. JavaScript submits form

3. Browser makes POST request:
   POST https://bank.com/transfer
   Cookie: session=abc123  ← Enviado AUTOMATICAMENTE!
   Content-Type: application/x-www-form-urlencoded

   to=attacker&amount=1000

4. bank.com server receives:
   - Valid session cookie ✓
   - Valid parameters ✓
   - Executes transfer → CSRF!
```

---

## 🔑 Teoria de Ambient Authority

### O Que É Ambient Authority?

**Definição:** Autorização que é **automaticamente concedida** baseada em **contexto ambiental** ao invés de intenção explícita

**Exemplo:**

```
Physical world:
  Porta com biometria
  ↓
  Você encosta a mão → Porta abre
  ↓
  Ambient authority: Sua mão (biometria) é suficiente

  Problema: Se alguém empurra você contra a porta
          → Porta abre mesmo sem sua intenção!

Digital world (Cookies):
  Browser envia cookie automaticamente
  ↓
  Server vê cookie → Autentica request
  ↓
  Ambient authority: Cookie é suficiente

  Problema: CSRF - atacante induz request
          → Server aceita mesmo sem intenção do usuário!
```

### Capability-Based Security

**Modelo Alternativo:**

```
Ambient Authority (Cookie):
  Authorization = Function(Environmental_Context)
  Context = Cookie presente no browser

  Problem: Context pode ser explorado

Capability (Token):
  Authorization = Function(Explicit_Token)
  Token = Gerado por servidor, incluído explicitamente em request

  Advantage: Token deve ser obtido e incluído intencionalmente
```

**Comparação:**

```python
# Ambient Authority (vulnerable)
@app.route('/transfer', methods=['POST'])
def transfer():
    # Cookie enviado automaticamente pelo browser
    user_id = session.get('user_id')  # From cookie
    to = request.form['to']
    amount = request.form['amount']

    # Executa - sem verificar INTENÇÃO
    execute_transfer(user_id, to, amount)

# Capability (secure)
@app.route('/transfer', methods=['POST'])
def transfer():
    user_id = session.get('user_id')
    to = request.form['to']
    amount = request.form['amount']
    csrf_token = request.form['csrf_token']  # Explicit capability!

    # Verifica token (intenção)
    if not verify_csrf_token(csrf_token, user_id):
        abort(403)

    execute_transfer(user_id, to, amount)
```

---

## 🔒 SameSite Cookie Internals

### Como SameSite Funciona

**Três Modos:**

```
SameSite=Strict:
  Cookie enviado APENAS em same-site requests

SameSite=Lax:
  Cookie enviado em:
    - Same-site requests (all)
    - Top-level navigation (GET only)

SameSite=None:
  Cookie enviado em all requests (cross-site também)
  Requer: Secure attribute
```

### Definição de "Same-Site"

**Site vs Origin:**

```
Origin = (Scheme, Host, Port)
  https://example.com:443
  https://sub.example.com:443  ← Different origin

Site = Registerable Domain (eTLD+1)
  example.com
  sub.example.com  ← SAME site (both *.example.com)

Examples:
  bank.com → site: bank.com
  api.bank.com → site: bank.com (same site!)
  bank.org → site: bank.org (different site)
```

**Public Suffix List (PSL):**

```
Defines eTLD (effective Top-Level Domains):
  .com, .org, .co.uk, .github.io, etc.

Examples:
  example.com → eTLD: .com, registerable: example.com
  example.co.uk → eTLD: .co.uk, registerable: example.co.uk
  user.github.io → eTLD: .github.io, registerable: user.github.io
```

### Browser Implementation

**Chromium Source (simplified):**

```cpp
// net/cookies/cookie_util.cc

bool IsSameSiteByDefaultCookiesEnabled() {
    return base::FeatureList::IsEnabled(features::kSameSiteByDefaultCookies);
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContext(
    const GURL& url,
    const GURL& site_for_cookies,
    const url::Origin& initiator) {

    // Check if request is same-site
    if (registry_controlled_domains::SameDomainOrHost(
            url, site_for_cookies,
            registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES)) {
        return CookieOptions::SameSiteCookieContext::SAME_SITE_STRICT;
    }

    // Check for top-level navigation (Lax)
    if (IsTopLevelNavigation(url, site_for_cookies)) {
        return CookieOptions::SameSiteCookieContext::SAME_SITE_LAX;
    }

    return CookieOptions::SameSiteCookieContext::CROSS_SITE;
}

bool ShouldIncludeCookie(const Cookie& cookie, const CookieOptions& options) {
    switch (cookie.SameSite()) {
        case CookieSameSite::STRICT_MODE:
            return options.same_site_cookie_context() == SAME_SITE_STRICT;

        case CookieSameSite::LAX_MODE:
            return options.same_site_cookie_context() != CROSS_SITE;

        case CookieSameSite::NO_RESTRICTION:
            return cookie.IsSecure();  // Must be Secure

        default:
            return false;
    }
}
```

### CSRF Prevention via SameSite

**How it works:**

```html
<!-- attacker.com page -->
<form action="https://bank.com/transfer" method="POST">
    <input name="to" value="attacker">
    <input name="amount" value="1000">
</form>
<script>document.forms[0].submit()</script>
```

**Request Context:**

```
URL: https://bank.com/transfer
Site for cookies: attacker.com  ← Top-level page site
Initiator: attacker.com

SameSite check:
  bank.com ≠ attacker.com → CROSS-SITE

Cookie behavior:
  SameSite=Strict → NOT sent ✓
  SameSite=Lax → NOT sent (POST request) ✓
  SameSite=None → Sent (if Secure) ✗
```

**Result:** Bank doesn't receive session cookie → Request not authenticated → CSRF prevented!

---

## 🎫 Token-Based Defenses

### Synchronizer Token Pattern

**Teoria:**

```
Ideia: Servidor gera token único por sessão/formulário
      Cliente deve incluir token em request

Properties:
  1. Unpredictable (cryptographically random)
  2. Tied to user session
  3. Single-use or time-limited
```

**Implementação:**

```python
import secrets
import hmac
import hashlib

# Server-side
class CSRFProtection:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.tokens = {}  # session_id → token

    def generate_token(self, session_id):
        """Generate CSRF token for session."""
        # Cryptographically secure random token
        token = secrets.token_urlsafe(32)

        # Store: session → token mapping
        self.tokens[session_id] = token

        return token

    def validate_token(self, session_id, provided_token):
        """Validate CSRF token."""
        expected_token = self.tokens.get(session_id)

        if not expected_token:
            return False

        # Constant-time comparison (prevent timing attacks)
        return hmac.compare_digest(expected_token, provided_token)

# Usage
csrf = CSRFProtection(secret_key=b'secret')

# When rendering form:
@app.route('/transfer_form')
def transfer_form():
    session_id = session['id']
    token = csrf.generate_token(session_id)

    return f'''
    <form method="POST" action="/transfer">
        <input type="hidden" name="csrf_token" value="{token}">
        <input name="to" placeholder="Recipient">
        <input name="amount" placeholder="Amount">
        <button>Transfer</button>
    </form>
    '''

# When processing request:
@app.route('/transfer', methods=['POST'])
def transfer():
    session_id = session['id']
    provided_token = request.form.get('csrf_token')

    if not csrf.validate_token(session_id, provided_token):
        abort(403, "CSRF token validation failed")

    # Process transfer
    to = request.form['to']
    amount = request.form['amount']
    execute_transfer(session_id, to, amount)
```

### Double Submit Cookie Pattern

**Teoria:**

```
Ideia: Token armazenado em cookie AND em form
      Servidor compara: cookie value == form value

Advantage: Stateless (não precisa armazenar tokens no servidor)
```

**Implementação:**

```python
# Server-side
@app.route('/transfer_form')
def transfer_form():
    # Generate token
    token = secrets.token_urlsafe(32)

    # Set in cookie
    response = make_response(render_template('form.html', token=token))
    response.set_cookie('csrf_token', token, httponly=False, samesite='Strict')
    # httponly=False: JavaScript precisa acessar para incluir em requests

    return response

@app.route('/transfer', methods=['POST'])
def transfer():
    # Compare cookie vs form value
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')

    if not cookie_token or cookie_token != form_token:
        abort(403)

    # Process transfer
```

**Por que funciona:**

```
Attacker page (attacker.com):
  <form action="https://bank.com/transfer" method="POST">
      <input name="csrf_token" value="???">  ← Attacker doesn't know!
  </form>

  Problem for attacker:
    - Cannot read victim's cookie (Same-Origin Policy)
    - Cannot set cookie for bank.com (cross-domain)
    - Cannot guess token (cryptographically random)

  Result: Attack fails ✓
```

### Encrypted Token Pattern

**Teoria:**

```
Token = Encrypt(session_id || timestamp || nonce, server_secret)

Advantages:
  - Stateless
  - Self-contained
  - Time-limited (timestamp check)
```

**Implementação:**

```python
from cryptography.fernet import Fernet
import time
import json

class EncryptedCSRFToken:
    def __init__(self, secret_key):
        self.cipher = Fernet(secret_key)

    def generate(self, session_id):
        """Generate encrypted token."""
        payload = {
            'session_id': session_id,
            'timestamp': time.time(),
            'nonce': secrets.token_hex(16)
        }

        # Encrypt
        token = self.cipher.encrypt(json.dumps(payload).encode())
        return token.decode()

    def validate(self, token, session_id, max_age=3600):
        """Validate encrypted token."""
        try:
            # Decrypt
            decrypted = self.cipher.decrypt(token.encode())
            payload = json.loads(decrypted)

            # Check session ID
            if payload['session_id'] != session_id:
                return False

            # Check age
            age = time.time() - payload['timestamp']
            if age > max_age:
                return False  # Token expired

            return True

        except Exception:
            return False
```

---

## 📊 Análise de Segurança Formal

### Modelo de Ameaça

**Capacidades do Atacante:**

```
Pode:
  ✓ Fazer vítima visitar página maliciosa
  ✓ Executar JavaScript em attacker.com
  ✓ Fazer requests cross-origin
  ✓ Ver responses de requests same-origin

Não pode:
  ✗ Ler cookies de outro domínio (SOP)
  ✗ Modificar headers do browser (CORS)
  ✗ Ler responses cross-origin (SOP)
  ✗ Executar JavaScript em victim.com (sem XSS)
```

### Definição Formal de CSRF Vulnerability

**Sistema é vulnerável a CSRF se:**

```
∃ state-changing_action A,
∃ forged_request R,
  Server_executes(A, R) = TRUE
  ∧ User_intended(R) = FALSE

Onde:
  A = ação que modifica estado (transfer, delete, etc.)
  R = request forjado por atacante
  Server_executes = servidor aceita e executa R
  User_intended = usuário intencionalmente fez R
```

**CSRF Token quebra a vulnerabilidade:**

```
Com token:
  Server_executes(A, R) = Valid_token(R) ∧ Valid_session(R)

  Forged_request sem token:
    Valid_token(R) = FALSE
    → Server_executes = FALSE ✓

  Forged_request com token errado:
    Valid_token(R) = FALSE
    → Server_executes = FALSE ✓

  Legitimate_request com token correto:
    Valid_token(R) = TRUE ∧ Valid_session(R) = TRUE
    → Server_executes = TRUE ✓
```

---

## 🎯 Comparação de Defesas

| Defense | Complexity | Effectiveness | Stateless | Browser Support |
|---------|-----------|---------------|-----------|-----------------|
| **Synchronizer Token** | Médio | 🟢 Alto | ❌ No | 🟢 Universal |
| **Double Submit** | Baixo | 🟡 Médio* | ✅ Yes | 🟢 Universal |
| **SameSite=Strict** | Baixo | 🟢 Alto | ✅ Yes | 🟡 Modern browsers |
| **SameSite=Lax** | Baixo | 🟡 Médio** | ✅ Yes | 🟡 Modern browsers |
| **Custom Header** | Médio | 🟢 Alto | ✅ Yes | 🟢 Universal (Ajax) |

**Notas:**
- *Vulnerável se atacante controla subdomain
- **Não protege GET requests

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
