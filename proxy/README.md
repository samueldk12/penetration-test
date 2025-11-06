# Pentest Proxy

Proxy HTTP/HTTPS nativo para interceptação e análise automática de tráfego.

## Recursos

✅ HTTP e HTTPS support
✅ Interceptação de requests e responses
✅ Análise automática de vulnerabilidades
✅ Logging em JSON
✅ Estatísticas detalhadas
✅ Detecção de padrões de ataque
✅ Identificação de dados sensíveis

## Instalação

```bash
pip install requests
```

## Uso Básico

```bash
# Porta padrão (8888)
python3 pentest_proxy.py

# Porta customizada
python3 pentest_proxy.py 9999

# Com opções
python3 pentest_proxy.py 8888 '{
    "verbose": true,
    "analyze": true,
    "save": true,
    "log_file": "my_proxy_log.json"
}'
```

## Configuração do Browser

### Chrome
1. Settings → Advanced → System
2. Open proxy settings
3. HTTP Proxy: `127.0.0.1:8888`
4. HTTPS Proxy: `127.0.0.1:8888`

### Firefox
1. Settings → Network Settings
2. Manual proxy configuration
3. HTTP Proxy: `127.0.0.1` Port: `8888`
4. ☑ Also use this proxy for HTTPS

### Command Line
```bash
# curl
curl -x 127.0.0.1:8888 http://example.com

# wget
wget -e use_proxy=yes -e http_proxy=127.0.0.1:8888 http://example.com
```

## Análise Automática

### Detecção em Requests

**SQL Injection:**
```
' OR '1'='1
UNION SELECT
DROP TABLE
```

**XSS:**
```
<script>
javascript:
onerror=
onload=
```

**Dados Sensíveis em URL:**
```
?password=secret
?token=abc123
?api_key=xyz789
```

### Detecção em Responses

**Dados Expostos:**
- Private keys (-----BEGIN RSA KEY-----)
- Passwords em texto
- Tokens longos (32+ chars)

**Headers de Segurança Faltando:**
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Content-Security-Policy

**Mensagens de Erro:**
- SQL errors (mysql, postgresql, etc.)
- Stack traces
- Exceptions

## Output

### Durante Execução

```
[→] GET https://example.com/login
    Body: username=admin&password=test

[←] 200 (1523 bytes)

[!] missing_security_header: X-Frame-Options
```

### Log JSON

```json
{
  "statistics": {
    "total_requests": 250,
    "total_responses": 245,
    "methods": {
      "GET": 200,
      "POST": 50
    },
    "hosts": {
      "example.com": 150,
      "api.example.com": 100
    },
    "vulnerabilities_found": 8
  },
  "vulnerabilities": [
    {
      "type": "sqli_attempt",
      "severity": "high",
      "pattern": "'\\s*OR\\s*'1'\\s*=\\s*'1",
      "location": "request_body",
      "timestamp": "2024-01-01T12:00:00"
    },
    {
      "type": "missing_security_header",
      "severity": "low",
      "header": "X-Frame-Options",
      "description": "Clickjacking protection missing"
    }
  ],
  "requests": [...]
}
```

## Análise de Logs

```bash
# Ver estatísticas
cat proxy_log.json | jq '.statistics'

# Vulnerabilidades
cat proxy_log.json | jq '.vulnerabilities'

# Por tipo
cat proxy_log.json | jq '.vulnerabilities[] | select(.type == "sqli_attempt")'

# Top 10 hosts
cat proxy_log.json | jq '.statistics.hosts | to_entries | sort_by(.value) | reverse | .[0:10]'

# Filtrar por severidade
cat proxy_log.json | jq '.vulnerabilities[] | select(.severity == "high")'
```

## Integração

### Com Selenium

```python
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Iniciar proxy (terminal separado)
# python3 pentest_proxy.py 8888

# Configurar Selenium
options = Options()
options.add_argument('--proxy-server=127.0.0.1:8888')
driver = webdriver.Chrome(options=options)

# Navegar - todo tráfego passará pelo proxy
driver.get('https://example.com')
```

### Com Requests

```python
import requests

proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888',
}

response = requests.get('https://example.com', proxies=proxies, verify=False)
```

### Com Ferramentas CLI

```bash
# Burp Suite
# Configure upstream proxy: 127.0.0.1:8888

# ZAP
# Options → Local Proxies → Add: 127.0.0.1:8888

# sqlmap
sqlmap -u "http://example.com?id=1" --proxy="http://127.0.0.1:8888"
```

## Casos de Uso

### 1. Bug Bounty
```bash
# Iniciar proxy
python3 pentest_proxy.py 8888 > /dev/null 2>&1 &

# Configurar browser para usar proxy
# Navegar normalmente pelo site alvo

# Analisar tráfego
cat proxy_log.json | jq '.vulnerabilities'
```

### 2. API Testing
```bash
# Proxy + Postman
# Configure Postman proxy settings: 127.0.0.1:8888

# Todas as requests da collection passarão pelo proxy
# Análise automática de vulnerabilidades
```

### 3. Mobile App Testing
```bash
# Configure device proxy: IP_DO_SEU_PC:8888
# Instale certificado SSL se necessário

# Todo tráfego do app será analisado
```

### 4. Automation Testing
```python
# CI/CD pipeline
proxy = subprocess.Popen(['python3', 'pentest_proxy.py', '8888'])
time.sleep(2)

# Run tests with proxy
run_selenium_tests(proxy_port=8888)

# Analyze results
with open('proxy_log.json') as f:
    vulns = json.load(f)['vulnerabilities']
    if len(vulns) > 0:
        raise Exception(f"Vulnerabilities found: {len(vulns)}")
```

## Opções Avançadas

```python
options = {
    "verbose": True,          # Logs detalhados
    "analyze": True,          # Análise automática
    "save": True,             # Salvar log
    "log_file": "custom.json" # Nome do arquivo
}
```

## Performance

### Otimizações

- Requests são processadas em threads
- Análise é assíncrona
- Cache automático de respostas
- Buffering de logs

### Limitações

- Máximo 8192 bytes por chunk
- Timeout padrão: 60 segundos
- Último 1000 requests salvos

## Troubleshooting

### Porta em uso
```bash
# Verificar processo
lsof -i :8888

# Matar processo
kill -9 <PID>

# Ou usar porta diferente
python3 pentest_proxy.py 9999
```

### SSL/HTTPS não funciona
```bash
# O proxy aceita conexões HTTPS via CONNECT method
# Mas não decodifica SSL por padrão

# Para full SSL interception, use mitmproxy ou Burp
```

### Lentidão
```bash
# Desabilitar análise automática
python3 pentest_proxy.py 8888 '{"analyze": false}'

# Ou desabilitar logs verbosos
python3 pentest_proxy.py 8888 '{"verbose": false}'
```

## Comparação

| Feature | Pentest Proxy | Burp Suite | mitmproxy |
|---------|---------------|------------|-----------|
| HTTP/HTTPS | ✅ | ✅ | ✅ |
| Análise Auto | ✅ | ❌ | ❌ |
| Lightweight | ✅ | ❌ | ✅ |
| GUI | ❌ | ✅ | ✅ |
| Free | ✅ | Parcial | ✅ |
| Custom Rules | ✅ | ✅ | ✅ |

## Aviso

⚠️ Use apenas para testes autorizados. Interceptação não autorizada de tráfego é ilegal.

## Próximos Passos

- SSL interception completo
- WebSocket support
- Request replay
- Custom rules engine
- Web UI
