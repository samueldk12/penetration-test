# 🎯 Exemplo Prático: Workflow Completo de Reconnaissance

Este documento demonstra um **workflow end-to-end** de reconnaissance usando todas as ferramentas integradas.

---

## 📋 Cenário

**Target**: `example.com`
**Objetivo**: Descobrir subdomínios, endpoints, secrets e testar permissões de cloud keys
**Ferramentas**: auto_recon.py, recon_wrapper.py, secret_scanner.py, permission_tester.py

---

## 🚀 Método 1: Auto Recon (Automated)

### Opção mais simples - Tudo automático

```bash
cd tools

# Reconnaissance completo automatizado
python auto_recon.py example.com

# Com output JSON
python auto_recon.py example.com -o report.json --db example_recon.db
```

**O que acontece:**
1. ✅ Descoberta passiva de subdomínios (crt.sh)
2. ✅ DNS brute force (wordlist comum)
3. ✅ URL probing (HTTP/HTTPS)
4. ✅ Secret scanning em todas as respostas HTTP
5. ✅ Endpoint discovery (top 5 URLs)
6. ✅ Storage automático no SQLite
7. ✅ Relatório JSON gerado

**Output esperado:**
```
==========================================================
AUTO RECONNAISSANCE - example.com
==========================================================

[FASE 1] SUBDOMAIN DISCOVERY
------------------------------------------------------------
[*] Consultando Certificate Transparency (crt.sh)...
[+] crt.sh: 45 subdomínios encontrados
[*] Executando DNS brute force (wordlist comum)...
[+] DNS brute force: 52 total de subdomínios

[+] Total de subdomínios únicos: 52

[FASE 2] URL PROBING
------------------------------------------------------------
[*] Provando 104 URLs (HTTP/HTTPS)...
[+] 38 URLs acessíveis encontradas

[FASE 3] SECRET SCANNING & STORAGE
------------------------------------------------------------
[*] Armazenando 38 URLs e escaneando por secrets...
[!] 3 secrets encontradas em https://api.example.com/config
[!] 1 secrets encontradas em https://staging.example.com/.env
[*] Testando permissões para AWS Access Key ID...

[FASE 4] ENDPOINT DISCOVERY
------------------------------------------------------------
[+] Endpoint encontrado: https://api.example.com/admin [403]
[+] Endpoint encontrado: https://api.example.com/debug [200]

[FASE 5] REPORT GENERATION
------------------------------------------------------------

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

---

## 🛠️ Método 2: Recon Wrapper (Com ferramentas externas)

### Usa ferramentas como subfinder, httpx, ffuf

**Pré-requisitos:**
```bash
# Instala ferramentas externas
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest

# Adiciona ao PATH
export PATH=$PATH:~/go/bin
```

**Workflow completo:**
```bash
cd tools

# 1. Workflow completo (subdomain + URLs + endpoints)
python recon_wrapper.py example.com --full --db example_wrapper.db

# 2. Apenas subdomain enumeration
python recon_wrapper.py example.com --subdomain

# 3. Subdomain + URL probing
python recon_wrapper.py example.com --subdomain --url-probing

# 4. Tudo + vulnerability scanning (nuclei)
python recon_wrapper.py example.com --full --vuln-scan
```

**Output esperado:**
```
==========================================================
RECON WRAPPER - example.com
==========================================================

[FASE 1] SUBDOMAIN ENUMERATION
------------------------------------------------------------
[*] Executando subfinder em example.com...
[+] subfinder: 67 subdomínios encontrados
[*] Executando assetfinder em example.com...
[+] assetfinder: 43 subdomínios encontrados

[+] Total de subdomínios únicos: 89

[FASE 2] URL PROBING
------------------------------------------------------------
[*] Executando httpx em 89 subdomínios...
[+] httpx: 52 URLs acessíveis

[FASE 3] ENDPOINT DISCOVERY
------------------------------------------------------------
[*] Executando ffuf em https://api.example.com...
[+] ffuf: 23 endpoints encontrados
[*] Executando ffuf em https://admin.example.com...
[+] ffuf: 8 endpoints encontrados

[FASE 5] STATISTICS
------------------------------------------------------------

Subdomínios: 89
URLs: 52
Endpoints: 31

Relatório salvo em: recon_wrapper_example_com.json
Banco de dados: example_wrapper.db
```

---

## 🔍 Método 3: Manual Step-by-Step (Controle Total)

### Para quem quer controle granular de cada etapa

### **Passo 1: Subdomain Discovery**

```bash
# Opção A: Usa wrapper
python recon_wrapper.py example.com --subdomain --db manual.db

# Opção B: Ferramentas diretas
subfinder -d example.com -all -silent > subdomains.txt
assetfinder --subs-only example.com >> subdomains.txt
sort -u subdomains.txt -o subdomains.txt

# Importa para o banco
python -c "
from discovery_storage import DiscoveryDatabase
db = DiscoveryDatabase('manual.db')
with open('subdomains.txt') as f:
    for line in f:
        sub = line.strip()
        if sub:
            db.add_subdomain(sub, 'example.com', discovered_by='manual')
db.close()
"
```

### **Passo 2: URL Probing**

```bash
# Opção A: httpx
cat subdomains.txt | httpx -silent -json -o urls.json

# Opção B: auto_recon interno
python -c "
import asyncio
from auto_recon import AutoRecon

async def probe():
    recon = AutoRecon('example.com', 'manual.db')
    with open('subdomains.txt') as f:
        subs = [line.strip() for line in f if line.strip()]
    urls = await recon.probe_urls(subs)
    print(f'{len(urls)} URLs acessíveis')
    recon.close()

asyncio.run(probe())
"
```

### **Passo 3: Secret Scanning**

```bash
# Escaneia respostas HTTP salvas
python secret_scanner.py http_responses/ -v -o secrets.json

# Ou escaneia diretório de código-fonte
python secret_scanner.py /path/to/source -e .py .js .php .env

# Integra com banco
python recon_integration.py scan /path/to/source --db manual.db
```

### **Passo 4: Permission Testing**

```bash
# Lista secrets de alto risco não testadas
sqlite3 manual.db "
SELECT id, secret_type, service, risk_level
FROM secrets
WHERE risk_level IN ('critical', 'high')
AND permissions_tested = 0
"

# Testa AWS keys manualmente
python recon_integration.py test-aws \
    --access-key AKIAIOSFODNN7EXAMPLE \
    --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
    --db manual.db

# Testa GCP service account
python recon_integration.py test-gcp \
    --credentials service-account.json \
    --db manual.db

# Testa Azure storage
python recon_integration.py test-azure \
    --connection-string "DefaultEndpointsProtocol=https;AccountName=..." \
    --db manual.db
```

### **Passo 5: Relatório Final**

```bash
# Gera relatório completo
python recon_integration.py report -o final_report.json --db manual.db

# Visualiza estatísticas
python -c "
from discovery_storage import DiscoveryDatabase
db = DiscoveryDatabase('manual.db')
stats = db.get_statistics()
import json
print(json.dumps(stats, indent=2))
db.close()
"
```

---

## 📊 Método 4: Integração com Pipeline Existente

### Para quem já tem scripts de recon e quer adicionar secret detection

**Cenário**: Você já tem um script que descobre subdomínios e URLs

```python
#!/usr/bin/env python3
"""
Pipeline customizado integrando com ferramentas existentes
"""

from recon_integration import ReconIntegration
from secret_scanner import SecretScanner
import requests

# Suas descobertas existentes
discovered_subdomains = [
    "api.example.com",
    "staging.example.com",
    "dev.example.com"
]

discovered_urls = [
    "https://api.example.com/config",
    "https://staging.example.com/.env",
    "https://dev.example.com/debug"
]

# Inicializa sistema de storage e scanning
recon = ReconIntegration("pipeline.db")
scanner = SecretScanner()

# Processa cada URL
for url in discovered_urls:
    print(f"[*] Escaneando {url}...")

    # Faz requisição
    try:
        response = requests.get(url, timeout=10, verify=False)

        # Escaneia e armazena
        results = recon.scan_and_store_url(
            url=url,
            response_text=response.text,
            response_headers=dict(response.headers),
            status_code=response.status_code
        )

        print(f"[+] {results['secrets_found']} secrets encontradas")
        print(f"[+] {results['high_risk_keys']} keys de alto risco")

    except Exception as e:
        print(f"[!] Erro: {e}")

# Gera relatório
recon.generate_report("pipeline_report.json")

# Busca secrets críticas
high_risk = recon.get_high_risk_secrets()
print(f"\n[!] {len(high_risk)} secrets de ALTO RISCO:")
for secret in high_risk:
    print(f"  - {secret['secret_type']}: {secret['risk_level']}")

recon.close()
```

---

## 🎯 Método 5: Bug Bounty Workflow

### Workflow otimizado para bug bounty hunting

```bash
#!/bin/bash
# bug_bounty_recon.sh

TARGET="example.com"
DB="${TARGET}_bounty.db"

echo "[*] Bug Bounty Recon - $TARGET"

# 1. Subdomain enumeration (rápido)
echo "[1/5] Subdomain discovery..."
python recon_wrapper.py $TARGET --subdomain --db $DB

# 2. URL probing
echo "[2/5] URL probing..."
python recon_wrapper.py $TARGET --url-probing --db $DB

# 3. Secret scanning (alto valor!)
echo "[3/5] Secret scanning..."
python secret_scanner.py http_responses/ -o secrets_$TARGET.json

# 4. Endpoint discovery (top 10 URLs)
echo "[4/5] Endpoint discovery..."
sqlite3 $DB "SELECT url FROM urls LIMIT 10" | while read url; do
    python -c "
from recon_wrapper import ReconWrapper
w = ReconWrapper('$DB')
w.run_ffuf('$url')
w.close()
"
done

# 5. Relatório final
echo "[5/5] Generating report..."
python recon_integration.py report -o bounty_report_$TARGET.json --db $DB

# Busca findings de alto valor
echo ""
echo "=== HIGH VALUE FINDINGS ==="
sqlite3 $DB "
SELECT secret_type, COUNT(*) as count
FROM secrets
WHERE risk_level IN ('critical', 'high')
GROUP BY secret_type
ORDER BY count DESC
"

echo ""
echo "[+] Report: bounty_report_$TARGET.json"
echo "[+] Database: $DB"
```

---

## 📈 Queries SQL Úteis

```bash
# 1. Secrets por tipo e risco
sqlite3 manual.db "
SELECT secret_type, risk_level, COUNT(*) as count
FROM secrets
GROUP BY secret_type, risk_level
ORDER BY count DESC
"

# 2. URLs com mais secrets
sqlite3 manual.db "
SELECT u.url, COUNT(s.id) as secret_count
FROM urls u
LEFT JOIN secrets s ON u.id = s.url_id
GROUP BY u.url
HAVING secret_count > 0
ORDER BY secret_count DESC
LIMIT 10
"

# 3. Secrets não testadas de alto risco
sqlite3 manual.db "
SELECT id, secret_type, service, discovered_at
FROM secrets
WHERE permissions_tested = 0
AND risk_level IN ('critical', 'high')
"

# 4. Resultados de testes de permissões
sqlite3 manual.db "
SELECT s.secret_type, p.risk_assessment, p.permissions_found
FROM secrets s
JOIN permission_tests p ON s.id = p.secret_id
WHERE p.risk_assessment IN ('critical', 'high')
"

# 5. Timeline de descobertas
sqlite3 manual.db "
SELECT
    DATE(discovered_at) as date,
    COUNT(*) as secrets_found
FROM secrets
GROUP BY DATE(discovered_at)
ORDER BY date DESC
"

# 6. Export para CSV
sqlite3 -header -csv manual.db "
SELECT
    secret_type,
    service,
    risk_level,
    permissions_tested,
    discovered_at
FROM secrets
" > secrets_export.csv
```

---

## 🔧 Troubleshooting

### Problema 1: Ferramentas não encontradas

```bash
# Verifica instalação
which subfinder httpx ffuf nuclei

# Instala ferramentas Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ffuf/ffuf/v2@latest

# Adiciona ao PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Problema 2: Dependências Python

```bash
# Instala todas as dependências
pip install aiohttp dnspython requests boto3 google-cloud-storage azure-storage-blob

# Ou usa requirements
pip install -r requirements.txt
```

### Problema 3: Timeout em ferramentas

```python
# Aumenta timeout no código
# Em auto_recon.py linha ~200:
timeout=aiohttp.ClientTimeout(total=30)  # Era 10, agora 30

# Em recon_wrapper.py:
subprocess.run(cmd, timeout=600)  # Era 300, agora 600
```

### Problema 4: Banco de dados corrompido

```bash
# Backup
cp manual.db manual.db.backup

# Verifica integridade
sqlite3 manual.db "PRAGMA integrity_check"

# Re-cria (CUIDADO: perde dados)
rm manual.db
python -c "from discovery_storage import DiscoveryDatabase; DiscoveryDatabase('manual.db').close()"
```

---

## 📚 Próximos Passos

Após o reconnaissance:

1. **Análise Manual**: Revise secrets de alto risco manualmente
2. **Teste de Permissões**: Execute permission_tester.py em keys descobertas
3. **Exploração**: Use endpoints descobertos para fuzzing adicional
4. **Documentação**: Salve findings para relatório final
5. **Cleanup**: Remova dados sensíveis do banco após análise

---

## ⚠️ Avisos Importantes

1. **Autorização**: SEMPRE tenha autorização por escrito
2. **Rate Limiting**: Respeite rate limits do target
3. **Secrets**: Nunca faça commit do banco .db
4. **Testes**: Coordene com blue team antes de testar permissões
5. **Compliance**: Siga políticas de responsible disclosure

---

## 🎓 Resumo

**Para iniciantes**: Use `auto_recon.py` (tudo automático)

**Para intermediários**: Use `recon_wrapper.py --full` (com ferramentas externas)

**Para avançados**: Combine ferramentas manualmente com controle granular

**Para bug bounty**: Script `bug_bounty_recon.sh` otimizado

**Para red team**: Pipeline customizado integrando com suas ferramentas

---

**Última atualização**: 2024-11-05
**Versão**: 1.0
