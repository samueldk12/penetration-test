# Exemplos de Uso - Pentest Suite

Este documento contém exemplos práticos de uso da Pentest Suite.

## ⚠️ IMPORTANTE
**Todos os exemplos abaixo devem ser executados APENAS em sistemas onde você tem autorização explícita!**

## Exemplos Básicos

### 1. Scan Completo de um Domínio

```bash
# Scan completo com todas as funcionalidades
python3 pentest.py example.com -m full \
    --subdomain-enum \
    --port-scan \
    --tech-detect \
    --crawl \
    --bruteforce
```

**O que faz:**
- Enumera subdomínios
- Escaneia portas abertas
- Detecta tecnologias web
- Faz crawling do site
- Bruteforce de diretórios
- Escaneia vulnerabilidades OWASP

### 2. Reconhecimento Rápido

```bash
# Apenas reconhecimento básico
python3 pentest.py target.com -m recon \
    --subdomain-enum \
    --port-scan
```

**O que faz:**
- Encontra subdomínios ativos
- Lista portas abertas e serviços

### 3. Teste de Vulnerabilidades em Aplicação Web

```bash
# Foco em vulnerabilidades web
python3 pentest.py https://webapp.example.com -m full \
    --skip-recon \
    --crawl \
    --crawl-depth 5 \
    -t 10
```

**O que faz:**
- Pula reconhecimento (já conhece o target)
- Crawl profundo (depth 5)
- Testa vulnerabilidades OWASP
- Timeout de 10 segundos

### 4. API Security Testing

```bash
# Teste focado em APIs
python3 pentest.py https://api.example.com -m discovery \
    --crawl \
    --bruteforce
```

**O que faz:**
- Descobre endpoints de API
- Testa caminhos comuns de API
- Verifica configurações de segurança

### 5. Scan Discreto (Stealth)

```bash
# Scan mais lento para evitar detecção
python3 pentest.py example.com \
    --skip-recon \
    --crawl \
    -t 15 \
    -f json
```

**O que faz:**
- Timeout maior (15s) = mais lento
- Apenas relatório JSON (mais discreto)
- Sem port scanning agressivo

## Exemplos Avançados

### 6. Scan Multi-Target de Subdomínios

```bash
# Primeiro, encontra subdomínios
python3 pentest.py company.com -m recon --subdomain-enum

# Depois, escaneia cada subdomínio encontrado
python3 pentest.py sub1.company.com -m vulnscan
python3 pentest.py sub2.company.com -m vulnscan
```

### 7. Scan com Relatório Customizado

```bash
# Gera apenas relatório HTML estilizado
python3 pentest.py https://example.com \
    -m full \
    --crawl \
    -f html \
    -o /path/to/reports
```

### 8. Teste de Aplicação Interna

```bash
# Para aplicações em rede interna
python3 pentest.py http://192.168.1.100:8080 \
    -m full \
    --crawl \
    --bruteforce \
    -t 5
```

### 9. Scan de Vulnerabilidades Específicas

```bash
# Apenas vulnerabilidades, sem discovery extensivo
python3 pentest.py https://example.com \
    --skip-recon \
    --skip-discovery \
    -m vulnscan
```

### 10. Reconhecimento Profundo

```bash
# Máximo reconhecimento possível
python3 pentest.py target.com -m recon \
    --subdomain-enum \
    --port-scan \
    --tech-detect \
    -t 10
```

## Uso em Diferentes Cenários

### Programa Bug Bounty

```bash
# Scan completo respeitando escopo
python3 pentest.py *.bugcrowd-target.com -m full \
    --subdomain-enum \
    --port-scan \
    --crawl \
    --bruteforce \
    -f json,html
```

### Pentest Contratado

```bash
# Scan agressivo com todas as técnicas
python3 pentest.py client-app.com -m full \
    --subdomain-enum \
    --port-scan \
    --tech-detect \
    --crawl \
    --crawl-depth 5 \
    --bruteforce \
    -t 15 \
    -o ./client_reports
```

### Teste de Aplicação Própria

```bash
# Desenvolvimento/QA
python3 pentest.py http://localhost:3000 -m vulnscan
```

### Red Team Exercise

```bash
# Reconhecimento silencioso
python3 pentest.py target.com -m recon \
    --subdomain-enum \
    -t 20 \
    -f json
```

## Interpretando Resultados

### Severidades de Vulnerabilidades

- **CRITICAL**: Exploração direta, RCE, SQL Injection
- **HIGH**: XSS, Path Traversal, autenticação fraca
- **MEDIUM**: CORS, IDOR, falta de rate limiting
- **LOW**: Headers ausentes, directory listing
- **INFO**: Informações sobre tecnologias

### Próximos Passos após Scan

1. **Analise o relatório HTML** - mais fácil de ler
2. **Priorize vulnerabilidades CRITICAL/HIGH**
3. **Valide manualmente** - nem tudo é falso positivo
4. **Teste exploração** - confirme a vulnerabilidade
5. **Documente** - prepare relatório para o cliente
6. **Remedie** - corrija as vulnerabilidades

## Dicas de Performance

### Para sites grandes
```bash
# Limite o crawl depth
python3 pentest.py large-site.com --crawl --crawl-depth 2
```

### Para sites lentos
```bash
# Aumente o timeout
python3 pentest.py slow-site.com -t 30
```

### Para economizar recursos
```bash
# Pule fases desnecessárias
python3 pentest.py site.com --skip-recon --skip-discovery
```

## Automação

### Script Bash para múltiplos targets

```bash
#!/bin/bash
# scan_multiple.sh

TARGETS=(
    "site1.com"
    "site2.com"
    "site3.com"
)

for target in "${TARGETS[@]}"; do
    echo "Scanning $target..."
    python3 pentest.py "$target" -m full --crawl -f json,html
    sleep 60  # Pausa entre scans
done
```

### Agendamento com Cron

```bash
# Escaneia todo dia às 2 AM
0 2 * * * cd /path/to/pentest && python3 pentest.py target.com -m full
```

## Troubleshooting

### Erro: Connection timeout
```bash
# Aumente o timeout
python3 pentest.py target.com -t 30
```

### Erro: Rate limited
```bash
# Adicione delays (modificar código) ou use proxy
```

### Erro: SSL certificate verification
```bash
# Já desabilitado por padrão na ferramenta
```

## Combinações Úteis

### Scan Rápido
```bash
python3 pentest.py target.com --skip-recon --crawl -t 3
```

### Scan Completo
```bash
python3 pentest.py target.com -m full --subdomain-enum --port-scan --tech-detect --crawl --bruteforce -t 10
```

### Scan Furtivo
```bash
python3 pentest.py target.com --crawl -t 20 -f json
```

### Scan Agressivo
```bash
python3 pentest.py target.com -m full --subdomain-enum --port-scan --crawl --crawl-depth 10 --bruteforce -t 5
```

---

## Recursos Adicionais

- Consulte o [README.md](README.md) para documentação completa
- Veja os relatórios em `reports/` após cada scan
- Contribua com novos módulos no GitHub

**Lembre-se: Sempre obtenha autorização antes de realizar qualquer teste!** 🛡️
