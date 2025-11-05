# 🔐 Pentest Suite - Ferramenta Automatizada de Teste de Penetração

Uma suite completa de ferramentas automatizadas em Python para reconhecimento e testes de penetração baseados no **OWASP Top 10**.

## ⚠️ AVISO LEGAL

**USO ÉTICO E LEGAL OBRIGATÓRIO**

Esta ferramenta foi desenvolvida EXCLUSIVAMENTE para fins educacionais e testes de segurança autorizados. Você deve ter **AUTORIZAÇÃO EXPLÍCITA E POR ESCRITO** do proprietário do sistema antes de realizar qualquer teste.

- ❌ O uso não autorizado é **ILEGAL**
- ❌ Você pode enfrentar **consequências criminais**
- ❌ A responsabilidade pelo uso é **100% sua**

**Use apenas em:**
- Sistemas próprios
- Ambientes de teste autorizados
- Programas de Bug Bounty
- Pentests contratados legalmente

## 🚀 Funcionalidades

### 1. Reconhecimento (Recon)
- ✅ Enumeração de subdomínios (DNS bruteforce + Certificate Transparency)
- ✅ Port scanning avançado
- ✅ Banner grabbing
- ✅ Detecção de tecnologias web (CMS, frameworks, bibliotecas JS)
- ✅ Identificação de serviços

### 2. Descoberta de Endpoints
- ✅ Web crawling recursivo
- ✅ Directory/file bruteforce
- ✅ Descoberta de API endpoints
- ✅ Parsing de robots.txt e sitemap.xml
- ✅ Extração de formulários
- ✅ Análise de JavaScript para endpoints

### 3. Scanner de Vulnerabilidades OWASP Top 10

#### A03: Injection
- ✅ SQL Injection (error-based e time-based)
- ✅ Cross-Site Scripting (XSS) - Reflected e Stored
- ✅ Command Injection (OS)
- ✅ LDAP Injection

#### A01: Broken Access Control
- ✅ Path Traversal / Directory Traversal
- ✅ IDOR (Insecure Direct Object Reference)
- ✅ Unrestricted File Upload

#### A02: Cryptographic Failures
- ✅ Sensitive Data Exposure
- ✅ Weak Cryptography Detection
- ✅ Insecure Protocol (HTTP vs HTTPS)

#### A05: Security Misconfiguration
- ✅ Missing Security Headers
- ✅ Directory Listing
- ✅ Default Credentials
- ✅ Verbose Error Messages
- ✅ Information Disclosure

#### A07: Authentication Failures
- ✅ Weak Authentication
- ✅ No Rate Limiting (Brute Force)
- ✅ Session Fixation

#### A08: Software and Data Integrity Failures
- ✅ Insecure Deserialization

#### A10: SSRF
- ✅ Server-Side Request Forgery

#### Testes Adicionais
- ✅ CORS Misconfiguration
- ✅ Open Redirect
- ✅ CSRF (Cross-Site Request Forgery)

### 4. Geração de Relatórios
- 📄 **JSON** - Para processamento automatizado
- 🌐 **HTML** - Relatório visual profissional
- 📝 **TXT** - Relatório em texto simples

## 📦 Instalação

### Pré-requisitos
- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)

### Passos de Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/your-repo/pentest-suite.git
cd penetration-test

# 2. Crie um ambiente virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Torne o script executável (Linux/Mac)
chmod +x pentest.py
```

## 🎯 Uso

### Sintaxe Básica

```bash
python3 pentest.py [target] [options]
```

### Exemplos de Uso

#### 1. Scan Completo (Recomendado)
```bash
python3 pentest.py example.com -m full --subdomain-enum --port-scan --tech-detect --crawl --bruteforce
```

#### 2. Apenas Reconhecimento
```bash
python3 pentest.py example.com -m recon --subdomain-enum --port-scan --tech-detect
```

#### 3. Apenas Descoberta de Endpoints
```bash
python3 pentest.py https://example.com -m discovery --crawl --bruteforce
```

#### 4. Apenas Scan de Vulnerabilidades
```bash
python3 pentest.py https://example.com -m vulnscan
```

#### 5. Scan Customizado
```bash
# Scan completo sem reconhecimento, com timeout maior
python3 pentest.py https://example.com --skip-recon --crawl --bruteforce -t 10

# Scan com profundidade de crawl maior
python3 pentest.py https://example.com --crawl --crawl-depth 5

# Gerar apenas relatório HTML
python3 pentest.py https://example.com -f html
```

### Opções da CLI

```
Argumentos Principais:
  target                Target URL, IP ou domínio

  -m, --mode           Modo de execução: full, recon, discovery, vulnscan
                       (default: full)

Reconhecimento:
  --subdomain-enum     Enumeração de subdomínios
  --port-scan          Scan de portas
  --tech-detect        Detecção de tecnologias

Descoberta de Endpoints:
  --crawl              Web crawling
  --bruteforce         Directory bruteforce
  --crawl-depth N      Profundidade máxima do crawl (default: 3)

Skip Options:
  --skip-recon         Pula fase de reconhecimento
  --skip-discovery     Pula fase de descoberta
  --skip-vulnscan      Pula fase de vulnerabilidades

Opções Gerais:
  -t, --timeout N      Timeout em segundos (default: 5)
  -o, --output DIR     Diretório de saída (default: reports)
  -f, --format         Formatos: json,html,txt (default: json,html,txt)
  --verbose            Modo verbose
```

## 📊 Relatórios

Os relatórios são salvos no diretório `reports/` (ou customizado com `-o`).

### Estrutura do Relatório

```
reports/
├── pentest_report_example.com_20240101_120000.json
├── pentest_report_example.com_20240101_120000.html
└── pentest_report_example.com_20240101_120000.txt
```

### Relatório HTML
O relatório HTML inclui:
- ✨ Design profissional e responsivo
- 📈 Resumo executivo com métricas
- 🎨 Visualização por severidade (cores)
- 📋 Detalhes completos de cada vulnerabilidade
- 🔍 Informações de reconhecimento e descoberta

## 🏗️ Arquitetura

```
penetration-test/
├── pentest.py                          # CLI principal
├── pentest_suite/
│   ├── __init__.py
│   └── modules/
│       ├── __init__.py
│       ├── recon.py                    # Módulo de reconhecimento
│       ├── endpoint_discovery.py       # Descoberta de endpoints
│       ├── vuln_scanner.py            # Scanner de vulnerabilidades
│       └── reporter.py                 # Geração de relatórios
├── requirements.txt
└── README.md
```

## 🔧 Desenvolvimento

### Adicionar Novos Módulos

1. Crie um novo arquivo em `pentest_suite/modules/`
2. Implemente sua classe de scanner
3. Integre no `pentest.py`

### Adicionar Novos Payloads

Os payloads estão definidos nos métodos de teste em `vuln_scanner.py`. Para adicionar novos:

```python
def test_new_vulnerability(self, endpoints: List[str]):
    """Testa nova vulnerabilidade"""
    payloads = [
        'payload1',
        'payload2',
    ]

    # Lógica de teste...
```

## 🐛 Troubleshooting

### Erro: "ModuleNotFoundError"
```bash
pip install -r requirements.txt
```

### Timeout muito curto
```bash
python3 pentest.py target.com -t 15  # Aumenta para 15 segundos
```

### SSL Certificate Verification Failed
A ferramenta desabilita verificação SSL por padrão para testes. Se precisar habilitar:
```python
# Em vuln_scanner.py, linha ~25
self.session.verify = True
```

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto é distribuído sob a licença MIT. Veja `LICENSE` para mais informações.

## ⚡ Performance

### Otimizações Implementadas
- ✅ Threading para scans paralelos
- ✅ Connection pooling (requests.Session)
- ✅ Timeouts configuráveis
- ✅ Rate limiting inteligente

### Benchmarks Típicos
- Reconhecimento: 2-5 minutos
- Descoberta: 5-15 minutos (depende do site)
- Vulnerabilidades: 10-30 minutos

## 🎓 Recursos de Aprendizado

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

## 📞 Suporte

Para questões, bugs ou sugestões:
- Abra uma [Issue](https://github.com/your-repo/issues)
- Email: security@example.com

## 🙏 Agradecimentos

- OWASP Foundation
- Comunidade de segurança open source
- Todos os contribuidores

---

**Desenvolvido com ❤️ para a comunidade de segurança**

*Lembre-se: Com grande poder vem grande responsabilidade. Hack ethically!* 🛡️
