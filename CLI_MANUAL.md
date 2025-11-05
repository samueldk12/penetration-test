# Penetration Test Suite - CLI Manual

**Version**: 2.0.0
**18+ Plugins Integrados | Python + JavaScript | Sistema Modular**

---

## 📑 Índice

- [Instalação](#instalação)
- [Configuração](#configuração)
- [Comandos](#comandos)
  - [scan](#comando-scan)
  - [osint](#comando-osint)
  - [report](#comando-report)
  - [plugins](#comando-plugins)
  - [config](#comando-config)
  - [stats](#comando-stats)
- [Plugins Disponíveis](#plugins-disponíveis)
- [Exemplos de Uso](#exemplos-de-uso)
- [Arquivo de Configuração](#arquivo-de-configuração)
- [Plugins JavaScript](#plugins-javascript)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Instalação

### 1. Requisitos

**Python 3.8+**
```bash
python3 --version
```

**Dependências Python:**
```bash
cd penetration-test
pip install -r requirements.txt
```

**Node.js (Opcional - para plugins JS):**
```bash
# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verificar instalação
node --version
```

### 2. Ferramentas Externas (Opcionais)

Para habilitar todos os plugins:

```bash
# Nikto
sudo apt-get install nikto

# Nmap
sudo apt-get install nmap

# Nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# FFUF
go install github.com/ffuf/ffuf@latest

# Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Dalfox
go install github.com/hahwul/dalfox/v2@latest
```

### 3. Instalação do CLI

```bash
# Tornar executável
chmod +x penetration-test.py

# Criar link simbólico (opcional)
sudo ln -s $(pwd)/penetration-test.py /usr/local/bin/pentest

# Agora pode usar:
pentest --help
```

---

## ⚙️ Configuração

### Inicializar Configuração

```bash
./penetration-test.py config --init
```

Isso cria `config.yaml` com configurações padrão.

### Visualizar Configuração Atual

```bash
./penetration-test.py config --show
```

### Validar Configuração

```bash
./penetration-test.py config --validate
```

---

## 🎯 Comandos

### Comando: `scan`

Executa scan de penetração no alvo.

**Sintaxe:**
```bash
./penetration-test.py scan <TARGET> [OPTIONS]
```

**Opções:**

| Opção | Descrição | Exemplo |
|-------|-----------|---------|
| `--all-plugins` | Executa TODOS os plugins disponíveis | `--all-plugins` |
| `--plugin` | Executa plugin específico | `--plugin nuclei_scanner` |
| `--categories` | Categorias de plugins para executar | `--categories recon vuln_scan` |
| `--exclude` | Plugins para excluir | `--exclude nikto_scanner` |
| `--complete` | Scan completo com todos os relatórios | `--complete` |
| `--parallel N` | Número de plugins em paralelo (padrão: 3) | `--parallel 5` |
| `--timeout N` | Timeout por plugin em segundos (padrão: 300) | `--timeout 600` |
| `--report` | Gerar relatório após scan | `--report` |
| `--report-format` | Formato do relatório (json/html/markdown) | `--report-format html` |
| `--output` | Arquivo/diretório de saída | `--output results/` |
| `--config` | Arquivo de configuração | `--config custom.yaml` |
| `--verbose, -v` | Saída verbosa | `-v` |
| `--debug` | Saída de debug | `--debug` |

**Exemplos:**

```bash
# Scan completo com TODOS os plugins
./penetration-test.py scan example.com --all-plugins --complete --verbose

# Scan apenas com plugins de recon
./penetration-test.py scan example.com --categories recon -v

# Plugin específico com relatório
./penetration-test.py scan example.com --plugin nuclei_scanner --report

# Scan rápido excluindo plugins lentos
./penetration-test.py scan example.com --all-plugins --exclude nikto_scanner nmap_scanner

# Scan agressivo com muitos workers
./penetration-test.py scan example.com --all-plugins --parallel 10 --timeout 600
```

---

### Comando: `osint`

Executa investigação OSINT (Open Source Intelligence).

**Sintaxe:**
```bash
./penetration-test.py osint <TARGET> [OPTIONS]
```

**Suporta:**
- Domínios (example.com)
- Emails (user@example.com)
- Nomes de pessoas ("John Doe")

**Opções:**

| Opção | Descrição |
|-------|-----------|
| `--deep` | Scan OSINT profundo (SSL, histórico, etc) |
| `--no-breaches` | Não verificar data breaches |
| `--no-social` | Não buscar redes sociais |
| `--no-documents` | Não buscar documentos públicos |
| `--output` | Arquivo de saída |
| `-v` | Saída verbosa |

**Exemplos:**

```bash
# OSINT básico em domínio
./penetration-test.py osint example.com

# OSINT profundo com todas as funcionalidades
./penetration-test.py osint example.com --deep -v

# Investigar email
./penetration-test.py osint user@example.com --output email_report.json

# Investigar pessoa
./penetration-test.py osint "John Doe" --no-breaches
```

**Dados Coletados:**

- **Domínios**: WHOIS, DNS records, subdomínios (CT logs), tecnologias, SSL/TLS
- **Emails**: Validação, domínio, breaches (HIBP), redes sociais
- **Pessoas**: Perfis sociais (Twitter, GitHub, LinkedIn, Instagram, Facebook)

---

### Comando: `report`

Gera relatórios de segurança a partir dos dados coletados.

**Sintaxe:**
```bash
./penetration-test.py report [OPTIONS]
```

**Opções:**

| Opção | Descrição | Valores |
|-------|-----------|---------|
| `--type` | Tipo de relatório | `comprehensive`, `vulnerabilities`, `secrets`, `osint`, `recon`, `critical` |
| `--format` | Formato(s) de saída | `json`, `html`, `markdown` (múltiplos suportados) |
| `--domain` | Filtrar por domínio | `example.com` |
| `--severity` | Filtrar por severidade | `critical`, `high`, `medium`, `low`, `info` |
| `--vuln-type` | Filtrar por tipo de vulnerabilidade | `xss`, `sqli`, `ssrf`, etc |
| `--output` | Nome do arquivo de saída | `security_report` |

**Tipos de Relatório:**

- **comprehensive**: Relatório completo com tudo
- **vulnerabilities**: Apenas vulnerabilidades encontradas
- **secrets**: API keys e secrets expostas
- **osint**: Dados de OSINT coletados
- **recon**: URLs, subdomínios, endpoints descobertos
- **critical**: Apenas findings críticos

**Exemplos:**

```bash
# Relatório completo em todos os formatos
./penetration-test.py report --type comprehensive --format json html markdown

# Apenas vulnerabilidades críticas
./penetration-test.py report --type vulnerabilities --severity critical

# Secrets expostas de um domínio específico
./penetration-test.py report --type secrets --domain example.com

# Relatório HTML com saída customizada
./penetration-test.py report --format html --output my_report.html
```

**Estrutura do Relatório Comprehensive:**

```json
{
  "metadata": {
    "generated_at": "2025-01-15T10:30:00",
    "filters_applied": {},
    "report_type": "comprehensive"
  },
  "executive_summary": {
    "total_urls": 150,
    "total_secrets": 5,
    "total_vulnerabilities": 12,
    "severity_distribution": {
      "critical": 2,
      "high": 5,
      "medium": 3,
      "low": 2
    },
    "risk_score": 65
  },
  "osint_findings": { ... },
  "vulnerability_findings": { ... },
  "api_keys_and_secrets": {
    "total_count": 5,
    "api_keys_breakdown": {
      "aws_keys": 2,
      "gcp_keys": 1,
      "github_tokens": 2
    }
  },
  "recon_data": { ... },
  "recommendations": [ ... ]
}
```

---

### Comando: `plugins`

Lista todos os plugins disponíveis.

**Sintaxe:**
```bash
./penetration-test.py plugins [OPTIONS]
```

**Opções:**

| Opção | Descrição |
|-------|-----------|
| `-v, --verbose` | Mostra descrições detalhadas |

**Exemplo:**

```bash
# Lista básica
./penetration-test.py plugins

# Lista com descrições
./penetration-test.py plugins -v
```

**Saída:**
```
==================================================
AVAILABLE PLUGINS
==================================================

📦 RECON
--------------------------------------------------
  Python Plugins:
    • nmap_scanner (v1.0.0)
      Network scanner e service detection usando Nmap
    • ffuf_fuzzer (v1.0.0)
      Fast web fuzzer usando FFUF
    ...

  JavaScript Plugins:
    • xss_detector (v1.0.0)
      Advanced XSS detection using JavaScript

📦 VULN_SCAN
--------------------------------------------------
  ...

==================================================
Total Plugins: 18 (17 Python + 1 JavaScript)
==================================================
```

---

### Comando: `config`

Gerencia arquivo de configuração.

**Sintaxe:**
```bash
./penetration-test.py config [OPTIONS]
```

**Opções:**

| Opção | Descrição |
|-------|-----------|
| `--init` | Cria arquivo de configuração padrão |
| `--show` | Mostra configuração atual |
| `--validate` | Valida configuração |
| `--output FILE` | Arquivo de saída para --init |
| `--config FILE` | Arquivo de configuração customizado |

**Exemplos:**

```bash
# Criar configuração padrão
./penetration-test.py config --init

# Ver configuração
./penetration-test.py config --show

# Validar
./penetration-test.py config --validate

# Criar config customizado
./penetration-test.py config --init --output my_config.yaml
```

---

### Comando: `stats`

Mostra estatísticas do banco de dados.

**Sintaxe:**
```bash
./penetration-test.py stats [OPTIONS]
```

**Exemplo:**

```bash
./penetration-test.py stats
```

**Saída:**
```
============================================================
DATABASE STATISTICS
============================================================
URLs:                 1,245
Endpoints:            532
Subdomains:           87
Secrets/API Keys:     15
Vulnerabilities:      24
Permission Tests:     8

Secrets by Type:
  aws_access_key: 5
  gcp_service_account: 3
  github_token: 7

Vulnerabilities by Severity:
  critical: 2
  high: 8
  medium: 10
  low: 4
============================================================
```

---

## 🔌 Plugins Disponíveis

### Categoria: Recon (8 plugins)

| Plugin | Tipo | Descrição | Ferramenta |
|--------|------|-----------|------------|
| `nmap_scanner` | Python | Network scanner com service detection | Nmap |
| `nuclei_scanner` | Python | Template-based vulnerability scanner | Nuclei |
| `ffuf_fuzzer` | Python | Web fuzzer (dir, vhost, params) | FFUF |
| `katana_crawler` | Python | Web crawler com JS parsing | Katana |
| `subdominator` | Python | Enumeração avançada de subdomínios | Nativo |
| `dnsbruter` | Python | DNS brute force com wildcard detection | Nativo |
| `cert_transparency` | Python | Busca em CT logs | Nativo |
| `search_engine_dorking` | Python | Google/Bing dorking | Nativo |

### Categoria: Vuln Scan (10 plugins)

| Plugin | Tipo | Descrição | Ferramenta |
|--------|------|-----------|------------|
| `nikto_scanner` | Python | Web server vulnerability scanner | Nikto |
| `dalfox_xss` | Python | XSS scanner avançado | Dalfox |
| `xss_scanner` | Python | XSS detection nativo | Nativo |
| `xss_detector` | **JavaScript** | XSS detection com Node.js | Node.js |
| `sqli_scanner` | Python | SQL injection scanner | Nativo |
| `ssrf_scanner` | Python | SSRF com cloud metadata | Nativo |
| `lfi_scanner` | Python | Local file inclusion | Nativo |
| `open_redirect_scanner` | Python | Open redirect detection | Nativo |
| `sensitive_files` | Python | 70+ arquivos sensíveis | Nativo |
| `cloud_vuln_tester` | Python | AWS/GCP/Azure misconfigurations | Nativo |

---

## 📚 Exemplos de Uso

### Exemplo 1: Scan Completo Automatizado

```bash
# Executa TUDO: todos plugins + relatórios completos
./penetration-test.py scan example.com \
  --all-plugins \
  --complete \
  --verbose \
  --parallel 5 \
  --timeout 600 \
  --output results/example-com/
```

**O que isso faz:**
1. Executa todos os 18+ plugins disponíveis
2. 5 plugins rodando em paralelo
3. Timeout de 10 minutos por plugin
4. Salva resultados no banco de dados
5. Gera relatórios em JSON, HTML e Markdown
6. Output verboso mostrando progresso

### Exemplo 2: Recon Profundo

```bash
# Fase 1: OSINT
./penetration-test.py osint example.com --deep -v

# Fase 2: Recon técnico
./penetration-test.py scan example.com \
  --categories recon \
  --verbose \
  --report

# Fase 3: Ver resultados
./penetration-test.py stats
./penetration-test.py report --type recon --format html
```

### Exemplo 3: Vulnerability Assessment

```bash
# Scan focado em vulnerabilidades
./penetration-test.py scan example.com \
  --categories vuln_scan \
  --exclude nikto_scanner \
  --parallel 3 \
  --verbose

# Relatório de vulnerabilidades críticas
./penetration-test.py report \
  --type vulnerabilities \
  --severity critical \
  --format html markdown

# Relatório de secrets expostas
./penetration-test.py report \
  --type secrets \
  --format json
```

### Exemplo 4: Plugin Específico

```bash
# Apenas Nuclei scan
./penetration-test.py scan example.com \
  --plugin nuclei_scanner \
  --verbose

# Apenas Nmap scan com portas customizadas
./penetration-test.py scan 192.168.1.0/24 \
  --plugin nmap_scanner \
  --verbose
```

### Exemplo 5: Workflow Completo

```bash
#!/bin/bash
TARGET="example.com"
OUTPUT_DIR="results/${TARGET}"

mkdir -p "$OUTPUT_DIR"

echo "[1/4] Iniciando OSINT..."
./penetration-test.py osint "$TARGET" --deep \
  --output "$OUTPUT_DIR/osint.json"

echo "[2/4] Executando Recon..."
./penetration-test.py scan "$TARGET" \
  --categories recon \
  --verbose \
  --output "$OUTPUT_DIR"

echo "[3/4] Executando Vulnerability Scan..."
./penetration-test.py scan "$TARGET" \
  --categories vuln_scan \
  --verbose

echo "[4/4] Gerando Relatórios..."
./penetration-test.py report \
  --type comprehensive \
  --format json html markdown \
  --output "$OUTPUT_DIR/report"

echo "✅ Scan completo! Resultados em: $OUTPUT_DIR"
```

---

## 🗂️ Arquivo de Configuração

### Estrutura do `config.yaml`

```yaml
general:
  output_dir: ./output
  database: recon_discoveries.db
  log_level: INFO
  max_threads: 50
  timeout: 300

plugins:
  enabled_categories:
    - recon
    - vuln_scan
  disabled_plugins: []
  python_plugins_dir: ./plugins
  js_plugins_dir: ./js_plugins

scanning:
  max_depth: 3
  follow_redirects: true
  verify_ssl: false
  user_agent: Mozilla/5.0 (Pentest Suite)
  rate_limit: 10  # requests per second
  blacklist_file: blacklist.json

reporting:
  format: json
  include_screenshots: false
  severity_filter: []  # Empty = all
  auto_export: true
  export_formats:
    - json
    - html
    - markdown

osint:
  enable_whois: true
  enable_dns: true
  enable_ct_logs: true
  enable_social_media: false
  enable_breach_check: false
  hibp_api_key: ''
  google_api_key: ''
  shodan_api_key: ''

notifications:
  enabled: false
  webhook_url: ''
  notify_on_critical: true
  notify_on_complete: true

advanced:
  concurrent_scans: 3
  retry_failed: true
  retry_count: 3
  save_raw_responses: false
  debug_mode: false
```

### Configurações Importantes

**general.max_threads**: Número máximo de threads para operações paralelas
**scanning.rate_limit**: Requisições por segundo (evita rate limiting)
**advanced.concurrent_scans**: Plugins executando simultaneamente
**osint.*_api_key**: API keys para funcionalidades avançadas

---

## 🟨 Plugins JavaScript

### Como Funcionam

Plugins JavaScript são executados via Node.js e seguem o mesmo padrão dos plugins Python.

### Estrutura de um Plugin JS

```javascript
#!/usr/bin/env node
/**
 * @name plugin_name
 * @description Plugin description
 * @category recon|vuln_scan
 * @version 1.0.0
 */

const args = JSON.parse(process.argv[2] || '{}');
const target = args.target;
const verbose = args.verbose || false;

// Plugin logic here

// Output results as JSON
console.log(JSON.stringify({
    success: true,
    target: target,
    findings: []
}));
```

### Criar Novo Plugin JS

1. **Criar arquivo** em `tools/js_plugins/my_plugin.js`
2. **Adicionar metadados** no comentário de cabeçalho
3. **Implementar lógica** do plugin
4. **Retornar JSON** com resultados
5. **Tornar executável**: `chmod +x my_plugin.js`

**Exemplo de criação:**

```bash
cd tools/js_plugins/

cat > sql_injector.js << 'EOF'
#!/usr/bin/env node
/**
 * @name sql_injector
 * @description SQL injection scanner in JavaScript
 * @category vuln_scan
 * @version 1.0.0
 */

const args = JSON.parse(process.argv[2] || '{}');

console.log(JSON.stringify({
    success: true,
    target: args.target,
    vulnerabilities: []
}));
EOF

chmod +x sql_injector.js
```

### Listar Plugins JS

```bash
node tools/js_plugin_runner.py
```

---

## 🔧 Troubleshooting

### Problema: "Node.js not installed"

**Solução:**
```bash
# Instalar Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verificar
node --version
```

### Problema: "Plugin not found"

**Solução:**
```bash
# Listar plugins disponíveis
./penetration-test.py plugins -v

# Verificar se plugin existe no diretório
ls tools/plugins/
ls tools/js_plugins/
```

### Problema: "Configuration validation failed"

**Solução:**
```bash
# Ver erros
./penetration-test.py config --validate

# Recriar config padrão
./penetration-test.py config --init --output config_new.yaml
```

### Problema: "No nameservers" (DNS plugins)

**Causa:** Sistema não tem DNS configurado (comum em containers)

**Solução:** Os plugins agora usam DNS público (8.8.8.8, 1.1.1.1) automaticamente como fallback.

### Problema: Plugin externo não funciona

**Verificar instalação:**
```bash
which nikto
which nuclei
which nmap
which ffuf
which katana
which dalfox
```

**Instalar ferramenta faltando** (ver seção Instalação)

### Problema: "Permission denied" no banco de dados

**Solução:**
```bash
chmod 666 recon_discoveries.db
# ou
sudo chown $USER:$USER recon_discoveries.db
```

### Debug Avançado

```bash
# Modo debug completo
./penetration-test.py scan example.com \
  --all-plugins \
  --debug

# Ver logs do banco de dados
sqlite3 recon_discoveries.db "SELECT * FROM vulnerabilities;"

# Testar plugin individualmente
python tools/plugins/nuclei_scanner.py https://example.com
```

---

## 📖 Documentação Adicional

- **Plugin Development**: `tools/PLUGIN_SYSTEM.md`
- **Workflow Examples**: `tools/EXAMPLE_WORKFLOW.md`
- **Recon Guide**: `tools/README_RECON.md`
- **Architecture**: Ver código-fonte com docstrings

---

## 🤝 Contribuindo

Para adicionar novos plugins ou funcionalidades:

1. Fork o repositório
2. Crie plugin seguindo padrão da `PluginInterface`
3. Adicione testes em `test_plugins.py`
4. Envie Pull Request

---

## 📝 Licença

Este projeto é para fins educacionais e testes autorizados apenas.

**⚠️ AVISO LEGAL**: Apenas use em sistemas que você possui ou tem permissão explícita para testar. Uso não autorizado pode ser ilegal.

---

## 🆘 Suporte

Para questões e bugs:
- GitHub Issues: https://github.com/samueldk12/penetration-test/issues
- Documentação: Ver arquivos `.md` no diretório `tools/`

---

**Version**: 2.0.0
**Last Updated**: 2025-01-15
**Maintained by**: Penetration Test Suite Team
