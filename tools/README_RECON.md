# 🔍 Reconnaissance & Secret Detection Tools

Sistema completo de reconnaissance que **detecta secrets, testa permissões e armazena resultados**.

---

## 🚀 Quick Start

**Novo no sistema?** Veja [EXAMPLE_WORKFLOW.md](EXAMPLE_WORKFLOW.md) para exemplos práticos completos!

### Opção 1: Auto Recon (Mais Simples)
```bash
# Reconnaissance completo automatizado
python auto_recon.py example.com
```

### Opção 2: Recon Wrapper (Com ferramentas externas)
```bash
# Usa subfinder, httpx, ffuf
python recon_wrapper.py example.com --full
```

### Opção 3: Manual (Controle total)
```bash
# Passo a passo com componentes individuais
python secret_scanner.py /path/to/code
python permission_tester.py aws --access-key ... --secret-key ...
```

---

## 📦 Componentes

### Componentes Core (Biblioteca)

**Estes são os building blocks do sistema:**

### 1. **discovery_storage.py** - Banco de Dados de Descobertas

Armazena URLs, endpoints, secrets e resultados de testes de permissões em SQLite.

**Tabelas:**
- `urls` - URLs descobertas com metadados (status code, headers, etc.)
- `endpoints` - Endpoints de API com métodos e parâmetros
- `secrets` - API keys e credentials com hash para deduplicação
- `subdomains` - Subdomínios descobertos com IPs e DNS records
- `permission_tests` - Resultados de testes de permissões

**Uso básico:**
```python
from discovery_storage import DiscoveryDatabase

db = DiscoveryDatabase("recon.db")

# Adiciona URL descoberta
url_id = db.add_url(
    "https://api.example.com/v1/users",
    "example.com",
    status_code=200,
    discovered_by="subdomain_scanner"
)

# Adiciona secret
secret_id = db.add_secret(
    "AKIA1234567890ABCDEF",
    "aws_access_key",
    service="aws",
    risk_level="critical"
)

# Adiciona teste de permissões
db.add_permission_test(
    secret_id=secret_id,
    test_type="aws_iam",
    test_result="success",
    permissions_found=["s3:ListBuckets", "iam:ListUsers"],
    risk_assessment="high"
)

# Estatísticas
print(db.get_statistics())

db.close()
```

---

### 2. **secret_scanner.py** - Detector de Secrets

Scanner com **50+ padrões regex** para detectar API keys, cloud credentials e private keys.

**Detecta:**
- ✅ **AWS**: Access Keys, Secret Keys, Session Tokens
- ✅ **GCP**: API Keys, Service Account JSON, Private Keys
- ✅ **Azure**: Storage Keys, Connection Strings, Client Secrets
- ✅ **GitHub**: Personal Access Tokens, OAuth Tokens
- ✅ **Stripe**: Secret Keys (LIVE e TEST)
- ✅ **SendGrid, Twilio, Mailgun, Heroku**
- ✅ **SSH Keys**: RSA, DSA, EC, OpenSSH
- ✅ **JWT Tokens**
- ✅ **Database Connection Strings**

**Uso CLI:**
```bash
# Escaneia arquivo
python secret_scanner.py config.json

# Escaneia diretório
python secret_scanner.py /var/www/html -v

# Filtro por extensões
python secret_scanner.py /project -e .py .js .env

# Salva em JSON
python secret_scanner.py /app -o findings.json
```

**Uso como biblioteca:**
```python
from secret_scanner import SecretScanner

scanner = SecretScanner()

# Escaneia texto
findings = scanner.scan_text("""
API_KEY = "sk_live_[REDACTED_EXAMPLE_KEY]"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
""", source="config.py")

# Escaneia arquivo
findings = scanner.scan_file("config.json")

# Escaneia diretório
findings = scanner.scan_directory("/var/www/html")

# Escaneia resposta HTTP
findings = scanner.scan_url_response(
    url="https://api.example.com/config",
    response_text=response.text,
    response_headers=response.headers
)

# Mostra findings
scanner.print_findings(findings, verbose=True)

# Gera relatório
report = scanner.generate_report(findings)
print(f"Total: {report['total_secrets']}")
print(f"Por risco: {report['by_risk_level']}")
```

**Output exemplo:**
```
[+] 3 secrets encontradas!

🔴 Finding #1
   Tipo: AWS Access Key ID
   Serviço: aws
   Risco: CRITICAL
   Valor: AKIAIOSFODNN7EXAMPLE
   Hash: a1b2c3d4e5f6...
   Fonte: file:///var/www/config.php

🟠 Finding #2
   Tipo: Stripe Secret Key
   Serviço: stripe
   Risco: HIGH
   Valor: sk_live_[REDACTED_EXAMPLE_KEY]
   Hash: x7y8z9a0b1c2...
   Fonte: file:///app/settings.py

=== RESUMO ===
Total de secrets: 3
Por nível de risco:
  CRITICAL: 1
  HIGH: 2
Por serviço:
  aws: 1
  stripe: 1
  github: 1
```

---

### 3. **permission_tester.py** - Testes de Permissões Cloud

Testa permissões de credentials descobertas para **AWS, GCP e Azure**.

#### AWS Permission Tester

Testa **12 permissões** (do mais básico ao mais crítico):

1. ✅ `sts:GetCallerIdentity` (sempre funciona se key válida)
2. 📦 `s3:ListBuckets`
3. 👤 `iam:ListUsers`
4. 🔐 `iam:ListRoles`
5. 💻 `ec2:DescribeInstances`
6. 🗄️ `rds:DescribeDBInstances`
7. ⚡ `lambda:ListFunctions`
8. 📊 `dynamodb:ListTables`
9. 🔑 `secretsmanager:ListSecrets`
10. 🚨 `iam:CreateUser` (simulated - CRÍTICO)
11. 🚨 `s3:PutObject` (CRÍTICO)
12. 🚨 `ec2:RunInstances` (CRÍTICO)

**Uso CLI:**
```bash
python permission_tester.py aws \
    --access-key AKIAIOSFODNN7EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    -o aws_permissions.json
```

**Output:**
```
[+] Credenciais válidas!
    Account: 123456789012
    ARN: arn:aws:iam::123456789012:user/developer

[+] s3:ListBuckets: 15 buckets encontrados
[+] iam:ListUsers: 8 usuários
[+] iam:ListRoles: 12 roles
[+] ec2:DescribeInstances: 3 instâncias
[+] rds:DescribeDBInstances: 2 databases
[+] lambda:ListFunctions: 7 funções
[!!!] AVISO: Credenciais com amplas permissões (possível Admin)

[*] Risk Assessment: HIGH
[*] Total permissions: 7
```

#### GCP Permission Tester

Testa **5 permissões**:

1. ✅ `cloudresourcemanager.projects.get`
2. 📦 `storage.buckets.list`
3. 💻 `compute.instances.list`
4. 👤 `iam.serviceAccounts.list`
5. 🔑 `secretmanager.secrets.list`

**Uso CLI:**
```bash
python permission_tester.py gcp \
    --credentials service-account.json \
    -o gcp_permissions.json
```

#### Azure Permission Tester

Testa **3 permissões**:

1. 📦 `storage.containers.list`
2. 📄 `storage.blobs.list`
3. ℹ️ `storage.account.getProperties`

**Uso CLI:**
```bash
# Com connection string
python permission_tester.py azure \
    --connection-string "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=..." \
    -o azure_permissions.json

# Com account name e key
python permission_tester.py azure \
    --account-name myaccount \
    --account-key "abcdefg1234567890==" \
    -o azure_permissions.json
```

**Uso como biblioteca:**
```python
from permission_tester import AWSPermissionTester

tester = AWSPermissionTester(
    access_key_id="AKIA...",
    secret_access_key="wJal..."
)

result = tester.test_permissions()

print(f"Success: {result.success}")
print(f"Permissions: {result.permissions_found}")
print(f"Risk: {result.risk_assessment}")
print(f"Details: {result.details}")
```

---

### 4. **recon_integration.py** - Integração Completa

**Combina** scanner + tester + storage em uma ferramenta unificada.

#### Funcionalidades:

1. **Escaneia diretório** → Detecta secrets → Testa permissões → Armazena no banco
2. **Escaneia URLs** → Detecta secrets em respostas HTTP → Testa → Armazena
3. **Testa manualmente** → AWS/GCP/Azure keys fornecidas → Armazena resultados
4. **Gera relatórios** → JSON com todas as descobertas e testes

**Uso CLI:**

```bash
# 1. Escaneia diretório (auto-testa permissões)
python recon_integration.py scan /var/www/html

# 2. Escaneia apenas (sem testar)
python recon_integration.py scan /project --no-test

# 3. Testa AWS keys manualmente
python recon_integration.py test-aws \
    --access-key AKIA... \
    --secret-key wJal...

# 4. Testa GCP Service Account
python recon_integration.py test-gcp \
    --credentials service-account.json

# 5. Testa Azure Storage
python recon_integration.py test-azure \
    --connection-string "DefaultEndpointsProtocol=..."

# 6. Gera relatório
python recon_integration.py report -o final_report.json

# Especifica banco customizado
python recon_integration.py --db custom.db report
```

**Workflow completo:**
```bash
# Passo 1: Escaneia codebase
python recon_integration.py scan /var/www/html -e .py .js .php .env

# Passo 2: Testa keys encontradas (automático durante scan)
# ou testa manualmente:
python recon_integration.py test-aws --access-key AKIA... --secret-key wJal...

# Passo 3: Gera relatório
python recon_integration.py report -o final_report.json
```

**Uso como biblioteca:**
```python
from recon_integration import ReconIntegration

recon = ReconIntegration(db_path="recon.db")

# Escaneia e armazena
results = recon.scan_and_store_directory("/var/www/html")
print(f"Secrets: {results['secrets_found']}")
print(f"Testadas: {results['permissions_tested']}")
print(f"Alto risco: {results['high_risk_keys']}")

# Escaneia URL
results = recon.scan_and_store_url(
    url="https://api.example.com/config",
    response_text=response.text,
    response_headers=dict(response.headers),
    status_code=response.status_code
)

# Busca secrets de alto risco
high_risk = recon.get_high_risk_secrets()
for secret in high_risk:
    print(f"[!] {secret['secret_type']}: {secret['risk_level']}")

# Gera relatório
recon.generate_report("report.json")

recon.close()
```

**Output do relatório:**
```json
{
  "statistics": {
    "total_urls": 45,
    "total_secrets": 12,
    "secrets_tested": 8,
    "total_subdomains": 23,
    "secrets_by_type": {
      "AWS Access Key ID": 2,
      "Stripe Secret Key": 1,
      "GitHub PAT (classic)": 3
    },
    "by_risk_level": {
      "critical": 3,
      "high": 5,
      "medium": 4
    }
  },
  "high_risk_secrets": [
    {
      "id": 1,
      "secret_type": "AWS Access Key ID",
      "risk_level": "critical",
      "permissions_tested": 1,
      "permissions_result": "success",
      "discovered_at": "2024-01-15T10:30:00"
    }
  ]
}
```

---

### Componentes Automatizados (End-to-End)

**Estes automatizam o workflow completo:**

### 5. **auto_recon.py** - Reconnaissance Automatizado

**Automatiza todo o processo** sem precisar de ferramentas externas.

**O que faz:**
1. ✅ Subdomain discovery (passivo via crt.sh + DNS brute force)
2. ✅ URL probing (HTTP/HTTPS assíncrono)
3. ✅ Secret scanning em respostas HTTP
4. ✅ Endpoint discovery
5. ✅ Storage automático no banco
6. ✅ Testes de permissões
7. ✅ Relatório JSON

**Uso CLI:**
```bash
# Reconnaissance completo
python auto_recon.py example.com

# Com output customizado
python auto_recon.py example.com -o report.json --db custom.db
```

**Output:**
```
==========================================================
AUTO RECONNAISSANCE - example.com
==========================================================

[FASE 1] SUBDOMAIN DISCOVERY
[+] crt.sh: 45 subdomínios encontrados
[+] DNS brute force: 52 total de subdomínios

[FASE 2] URL PROBING
[+] 38 URLs acessíveis encontradas

[FASE 3] SECRET SCANNING & STORAGE
[!] 3 secrets encontradas em https://api.example.com/config
[*] Testando permissões para AWS Access Key ID...

[FASE 4] ENDPOINT DISCOVERY
[+] Endpoint encontrado: https://api.example.com/admin [403]

[FASE 5] REPORT GENERATION

==========================================================
RECONNAISSANCE COMPLETO!
==========================================================
Tempo total: 245.32s

Subdomínios: 52
URLs: 38
Endpoints: 15
Secrets: 4
  └─ Alto risco: 2
Permissões testadas: 2

Relatório salvo em: auto_recon_example_com.json
Banco de dados: auto_recon.db
==========================================================
```

**Vantagens:**
- 🚀 **Rápido**: Assíncrono, múltiplas requisições paralelas
- 🔋 **Self-contained**: Não precisa de ferramentas externas
- 📊 **Completo**: Tudo em um único comando
- 💾 **Storage integrado**: Tudo salvo automaticamente

**Desvantagens:**
- Wordlist limitada (50 subdomínios comuns)
- Menos subdomínios que ferramentas especializadas

---

### 6. **recon_wrapper.py** - Integração com Ferramentas Externas

**Integra ferramentas populares** (subfinder, httpx, ffuf, nuclei) com o sistema de storage.

**Ferramentas suportadas:**
- 🔍 **Subdomain**: subfinder, amass, assetfinder
- 🌐 **URL Probing**: httpx
- 📁 **Endpoints**: ffuf, gobuster
- 🔒 **Vulnerabilities**: nuclei

**Uso CLI:**
```bash
# Workflow completo (subdomain + URLs + endpoints)
python recon_wrapper.py example.com --full

# Apenas subdomain enumeration
python recon_wrapper.py example.com --subdomain

# Subdomain + URL probing
python recon_wrapper.py example.com --subdomain --url-probing

# Tudo + vulnerability scanning
python recon_wrapper.py example.com --full --vuln-scan
```

**Output:**
```
==========================================================
RECON WRAPPER - example.com
==========================================================

[FASE 1] SUBDOMAIN ENUMERATION
[*] Executando subfinder em example.com...
[+] subfinder: 67 subdomínios encontrados
[*] Executando assetfinder em example.com...
[+] assetfinder: 43 subdomínios encontrados
[+] Total de subdomínios únicos: 89

[FASE 2] URL PROBING
[*] Executando httpx em 89 subdomínios...
[+] httpx: 52 URLs acessíveis

[FASE 3] ENDPOINT DISCOVERY
[*] Executando ffuf em https://api.example.com...
[+] ffuf: 23 endpoints encontrados

Subdomínios: 89
URLs: 52
Endpoints: 31

Relatório salvo em: recon_wrapper_example_com.json
Banco de dados: example_wrapper.db
```

**Vantagens:**
- 🎯 **Melhores resultados**: Usa ferramentas especializadas da indústria
- 🔧 **Flexível**: Escolhe quais ferramentas executar
- 📊 **Storage automático**: Tudo integrado com o banco
- 🚀 **Paralelização**: Ferramentas Go são muito rápidas

**Desvantagens:**
- Requer instalação de ferramentas externas (Go tools)
- Depende de ferramentas de terceiros

**Instalação de ferramentas:**
```bash
# Subdomain
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest

# URL Probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Endpoints
go install github.com/ffuf/ffuf/v2@latest
sudo apt install gobuster

# Vulnerabilities
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Adiciona ao PATH
export PATH=$PATH:~/go/bin
```

---

## 🚀 Quick Start

### 1. Instalação de Dependências

```bash
# Básico (scanner funciona sem dependências externas)
pip install -r requirements.txt

# Para testes AWS
pip install boto3

# Para testes GCP
pip install google-cloud-storage google-api-python-client

# Para testes Azure
pip install azure-storage-blob

# Tudo
pip install boto3 google-cloud-storage google-api-python-client azure-storage-blob
```

### 2. Workflow Completo

```bash
# Passo 1: Escaneia diretório
cd tools
python recon_integration.py scan /path/to/project

# Passo 2: Revisa findings
sqlite3 recon_discoveries.db "SELECT secret_type, risk_level, COUNT(*) FROM secrets GROUP BY secret_type, risk_level"

# Passo 3: Testa keys descobertas manualmente (se necessário)
python recon_integration.py test-aws --access-key AKIA... --secret-key wJal...

# Passo 4: Gera relatório final
python recon_integration.py report -o final_report.json

# Passo 5: Revisa secrets de alto risco
python recon_integration.py --db recon_discoveries.db report | grep -A 5 "high_risk_secrets"
```

---

## 📊 Queries Úteis

```bash
# Total de secrets por tipo
sqlite3 recon_discoveries.db "SELECT secret_type, COUNT(*) as count FROM secrets GROUP BY secret_type ORDER BY count DESC"

# Secrets de alto risco não testadas
sqlite3 recon_discoveries.db "SELECT * FROM secrets WHERE risk_level IN ('critical', 'high') AND permissions_tested = 0"

# Resultados de testes de permissões
sqlite3 recon_discoveries.db "SELECT s.secret_type, p.risk_assessment, p.permissions_found FROM secrets s JOIN permission_tests p ON s.id = p.secret_id"

# URLs com secrets
sqlite3 recon_discoveries.db "SELECT u.url, COUNT(s.id) as secret_count FROM urls u LEFT JOIN secrets s ON u.id = s.url_id GROUP BY u.url HAVING secret_count > 0"

# Estatísticas gerais
sqlite3 recon_discoveries.db "SELECT 'URLs' as type, COUNT(*) as count FROM urls UNION SELECT 'Secrets', COUNT(*) FROM secrets UNION SELECT 'Subdomains', COUNT(*) FROM subdomains"
```

---

## ⚠️ Avisos de Segurança

1. **NÃO execute testes de permissões em produção sem autorização**
2. **Credenciais descobertas podem ser honeypots** - tenha cuidado
3. **Armazene o banco de dados com criptografia** - contém secrets
4. **Logs podem conter secrets** - limpe após análise
5. **Alguns testes podem gerar alertas** - coordene com blue team

---

## 🔧 Exemplos Avançados

### Integração com outros scanners

```python
from recon_integration import ReconIntegration
import requests

recon = ReconIntegration()

# Escaneia múltiplas URLs de um sitemap
urls = [
    "https://api.example.com/config",
    "https://api.example.com/env",
    "https://example.com/.git/config"
]

for url in urls:
    response = requests.get(url)
    results = recon.scan_and_store_url(
        url=url,
        response_text=response.text,
        response_headers=dict(response.headers),
        status_code=response.status_code
    )
    print(f"[{url}] {results['secrets_found']} secrets")

recon.generate_report("multi_url_report.json")
recon.close()
```

### Pipeline CI/CD

```bash
#!/bin/bash
# pre-commit hook

echo "[*] Escaneando por secrets..."
python tools/secret_scanner.py . -e .py .js .env -o /tmp/secrets.json

SECRETS_COUNT=$(jq '.[] | select(.risk_level == "critical" or .risk_level == "high") | length' /tmp/secrets.json | wc -l)

if [ $SECRETS_COUNT -gt 0 ]; then
    echo "[!] ERRO: $SECRETS_COUNT secrets de alto risco encontradas!"
    echo "[!] Revise /tmp/secrets.json"
    exit 1
fi

echo "[+] Nenhuma secret de alto risco encontrada"
```

---

## 📚 Referências

- [AWS IAM Permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-resources-contextkeys.html)
- [GCP IAM Permissions](https://cloud.google.com/iam/docs/permissions-reference)
- [Azure RBAC](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)
- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)

---

**Última atualização**: 2024
**Versão**: 1.0
