# 🚀 Funcionalidades Avançadas - Pentest Suite v2.0

## Índice

- [Novidades da v2.0](#novidades-da-v20)
- [Scanner de Vulnerabilidades LLM](#scanner-de-vulnerabilidades-llm)
- [Payloads Customizados](#payloads-customizados)
- [Múltiplas URLs](#múltiplas-urls)
- [Proxies](#proxies)
- [Autenticação](#autenticação)
- [SSL/TLS](#ssltls)
- [Testes Seletivos](#testes-seletivos)
- [Testes Automatizados](#testes-automatizados)
- [Exemplos Práticos](#exemplos-práticos)

---

## Novidades da v2.0

### ✨ Principais Adições

1. **Scanner de Vulnerabilidades para LLMs** - Teste completo de Large Language Models
2. **Payloads Customizados** - Carregue seus próprios payloads de arquivos
3. **Múltiplas URLs** - Teste vários targets de uma vez
4. **Configuração de Proxies** - Suporte a proxy único ou rotação de proxies
5. **Autenticação Avançada** - Basic Auth, Bearer Token, API Keys
6. **SSL/TLS Customizado** - Certificados do cliente
7. **Testes Seletivos** - Execute apenas testes específicos
8. **Testes Automatizados** - Suite completa de unit tests

---

## Scanner de Vulnerabilidades LLM

### Testes Implementados

#### OWASP Top 10 for LLM Applications

1. **LLM01: Prompt Injection**
   - Direct injection
   - Delimiter injection
   - Encoding bypass

2. **LLM01: Jailbreak Attempts**
   - DAN (Do Anything Now)
   - Role-playing
   - Developer mode
   - Hypothetical scenarios

3. **LLM06: Sensitive Information Disclosure**
   - System prompt extraction
   - PII leakage
   - Training data extraction

4. **LLM02: Insecure Output Handling**
   - XSS in outputs
   - SQL injection in outputs

5. **LLM04: Model Denial of Service**
   - Token exhaustion
   - Computational complexity attacks

6. **LLM08: Excessive Agency**
   - Command execution attempts
   - Function calling abuse

#### Testes Adicionais

- **Token Smuggling** - Unicode, Base64, encoding bypass
- **Memory Poisoning** - Context manipulation
- **Function Calling Abuse** - Abuso de function calling
- **Retrieval Poisoning** - RAG poisoning
- **Indirect Injection** - Via external sources
- **Model Extraction** - Information disclosure

### Como Usar

```bash
# Teste básico de LLM
python3 pentest_advanced.py https://api.openai.com/v1/chat/completions \
    -m llm \
    --api-key YOUR_API_KEY

# Teste com payloads customizados
python3 pentest_advanced.py https://api.example.com/chat \
    -m llm \
    --api-key YOUR_API_KEY \
    --payload-file examples/payloads/prompt_injection.txt

# Testes seletivos
python3 pentest_advanced.py https://api.example.com/chat \
    -m llm \
    --api-key YOUR_API_KEY \
    --tests prompt_injection,jailbreak,system_prompt_leak
```

---

## Payloads Customizados

### Estrutura de Arquivos

```
examples/payloads/
├── sqli.txt              # SQL Injection payloads
├── xss.txt               # XSS payloads
├── prompt_injection.txt  # LLM prompt injection
└── custom.txt            # Seus payloads customizados
```

### Formato dos Arquivos

```txt
# Comentários começam com #
payload1
payload2
# Outro comentário
payload3
```

### Uso

```bash
# Carrega payloads de um arquivo específico
python3 pentest_advanced.py https://example.com \
    --payload-file meus_payloads.txt \
    --payload-category sqli

# Carrega todos os payloads de um diretório
python3 pentest_advanced.py https://example.com \
    --payload-dir examples/payloads/
```

### Criando Seus Próprios Payloads

```bash
# Crie um arquivo com seus payloads
cat > custom_sqli.txt << EOF
# Meus SQL Injection payloads customizados
' OR '1'='1' -- custom1
admin'-- custom2
' UNION SELECT password FROM users--
EOF

# Use no scan
python3 pentest_advanced.py https://target.com \
    --payload-file custom_sqli.txt \
    --payload-category sqli
```

---

## Múltiplas URLs

### Arquivo de URLs Simples

```txt
# examples/urls/targets.txt
https://site1.com
https://site2.com
http://192.168.1.100
https://api.example.com
```

### Arquivo de URLs Detalhado (JSON)

```json
[
  {
    "url": "https://site1.com",
    "name": "Production Site",
    "priority": "high",
    "tests": ["sqli", "xss", "crawl"]
  },
  {
    "url": "https://api.example.com",
    "name": "API Server",
    "priority": "critical",
    "tests": ["api_discovery", "ssrf"]
  }
]
```

### Uso

```bash
# URLs simples
python3 pentest_advanced.py --target-file examples/urls/targets.txt

# URLs detalhadas (JSON)
python3 pentest_advanced.py --target-file examples/urls/targets_detailed.json

# Com testes específicos
python3 pentest_advanced.py --target-file targets.txt \
    --tests sqli,xss,csrf
```

---

## Proxies

### Proxy Único

```bash
# HTTP Proxy
python3 pentest_advanced.py https://example.com \
    --proxy http://proxy.example.com:8080

# Proxy autenticado
python3 pentest_advanced.py https://example.com \
    --proxy http://user:pass@proxy.example.com:8080

# SOCKS5 (Tor)
python3 pentest_advanced.py https://example.com \
    --proxy socks5://127.0.0.1:9050

# Burp Suite
python3 pentest_advanced.py https://example.com \
    --proxy http://127.0.0.1:8080
```

### Lista de Proxies com Rotação

```txt
# examples/configs/proxy_list.txt
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:8080
socks5://proxy3.example.com:1080
```

```bash
# Usa e rotaciona proxies
python3 pentest_advanced.py https://example.com \
    --proxy-list examples/configs/proxy_list.txt
```

---

## Autenticação

### Basic Authentication

```bash
python3 pentest_advanced.py https://example.com \
    --basic-auth admin:password123
```

### Bearer Token

```bash
python3 pentest_advanced.py https://api.example.com \
    --bearer-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### API Key (para LLMs)

```bash
python3 pentest_advanced.py https://api.openai.com/v1/chat \
    -m llm \
    --api-key sk-proj-xxx...
```

### Arquivo de Autenticação

```json
{
  "type": "basic",
  "username": "admin",
  "password": "secret123",
  "token": null
}
```

```bash
python3 pentest_advanced.py https://example.com \
    --auth-file examples/configs/auth_config.json
```

---

## SSL/TLS

### Desabilitar Verificação SSL (Padrão)

```bash
# Por padrão, SSL verification está desabilitado
python3 pentest_advanced.py https://self-signed.example.com
```

### Habilitar Verificação SSL

```bash
python3 pentest_advanced.py https://example.com \
    --verify-ssl
```

### Certificado do Cliente

```bash
python3 pentest_advanced.py https://secure.example.com \
    --ssl-cert /path/to/client.crt \
    --ssl-key /path/to/client.key
```

---

## Testes Seletivos

### Listar Testes Disponíveis

```bash
python3 pentest_advanced.py --list-tests
```

### Selecionar Testes via CLI

```bash
# Testes específicos
python3 pentest_advanced.py https://example.com \
    --tests sqli,xss,csrf

# Testes de LLM
python3 pentest_advanced.py https://api.example.com \
    -m llm \
    --tests prompt_injection,jailbreak,pii_leak
```

### Selecionar Testes via Arquivo

```txt
# examples/configs/tests_to_run.txt
sqli
xss
command_injection
path_traversal
csrf
```

```bash
python3 pentest_advanced.py https://example.com \
    --tests-file examples/configs/tests_to_run.txt
```

---

## Testes Automatizados

### Executar Todos os Testes

```bash
cd tests
python3 run_tests.py
```

### Executar Testes Específicos

```bash
# Teste de configuração
python3 -m unittest tests.test_config

# Teste de file loader
python3 -m unittest tests.test_file_loader

# Teste de LLM scanner
python3 -m unittest tests.test_llm_scanner
```

### Integração Contínua

```bash
# Use em CI/CD
pytest tests/ -v
```

---

## Exemplos Práticos

### 1. Pentest Completo com Todas as Features

```bash
python3 pentest_advanced.py https://example.com \
    --subdomain-enum \
    --port-scan \
    --tech-detect \
    --crawl \
    --bruteforce \
    --proxy-list proxies.txt \
    --basic-auth admin:pass \
    --payload-dir my_payloads/ \
    --tests-file critical_tests.txt \
    -t 15 \
    -f json,html
```

### 2. Teste Múltiplas URLs com Proxies

```bash
python3 pentest_advanced.py \
    --target-file targets.txt \
    --proxy-list proxies.txt \
    --crawl \
    --tests sqli,xss,csrf \
    -o results/
```

### 3. Scan de LLM com Payloads Customizados

```bash
python3 pentest_advanced.py https://api.openai.com/v1/chat/completions \
    -m llm \
    --api-key $OPENAI_API_KEY \
    --payload-file prompt_injection_advanced.txt \
    --tests prompt_injection,jailbreak,token_smuggling \
    -t 30
```

### 4. Teste via Tor com Autenticação

```bash
python3 pentest_advanced.py https://example.onion \
    --proxy socks5://127.0.0.1:9050 \
    --bearer-token $AUTH_TOKEN \
    --crawl \
    --tests sqli,xss
```

### 5. Certificado do Cliente + Basic Auth

```bash
python3 pentest_advanced.py https://secure-api.example.com \
    --ssl-cert client.crt \
    --ssl-key client.key \
    --basic-auth api_user:api_pass \
    --tests api_discovery,ssrf
```

---

## Configuração Avançada via JSON

### Arquivo de Configuração Completo

```json
{
  "proxies": null,
  "proxy_list": ["http://proxy1:8080", "http://proxy2:8080"],
  "rotate_proxy": true,
  "verify_ssl": false,
  "ssl_cert": "/path/to/cert.pem",
  "ssl_key": "/path/to/key.pem",
  "auth_type": "bearer",
  "bearer_token": "your_token_here",
  "custom_headers": {
    "X-Custom-Header": "value",
    "X-API-Version": "2.0"
  },
  "timeout": 15,
  "max_retries": 3,
  "retry_delay": 2,
  "user_agent": "CustomPentestBot/2.0",
  "requests_per_second": 5,
  "delay_between_requests": 0.2
}
```

```bash
python3 pentest_advanced.py https://example.com \
    --config-file my_config.json
```

---

## Performance e Otimização

### Rate Limiting

```json
{
  "requests_per_second": 10,
  "delay_between_requests": 0.1
}
```

### Timeouts Ajustáveis

```bash
# Timeout de 30 segundos
python3 pentest_advanced.py https://slow-site.com -t 30
```

### Retry Logic

```json
{
  "max_retries": 5,
  "retry_delay": 3
}
```

---

## Troubleshooting

### Erro de Importação

```bash
# Verifique que todos os módulos estão instalados
pip install -r requirements.txt
```

### Proxy Não Funciona

```bash
# Teste o proxy separadamente
curl -x http://proxy:8080 https://example.com

# Use verbose mode
python3 pentest_advanced.py https://example.com \
    --proxy http://proxy:8080 \
    --verbose
```

### SSL Certificate Error

```bash
# Desabilite verificação SSL (padrão)
python3 pentest_advanced.py https://self-signed.com

# Ou use --verify-ssl apenas para sites confiáveis
```

---

## Contribuindo

Contribuições são bem-vindas! Áreas para melhoria:

- Novos payloads
- Novos testes para LLMs
- Otimizações de performance
- Novos formatos de relatório
- Integrações (Slack, Discord, etc.)

---

**Desenvolvido com ❤️ para a comunidade de segurança**

*Use com responsabilidade e ética!* 🛡️
