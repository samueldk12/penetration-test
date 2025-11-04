# 🎓 Laboratórios Guiados - Vulnerabilidades OWASP

## 📋 Sobre Este Laboratório

Este é um **laboratório progressivo e guiado** onde você aprenderá cada vulnerabilidade do zero ao avançado, com exemplos práticos e exercícios reais.

### 🎯 Metodologia

Para cada vulnerabilidade, você encontrará:

1. **📖 Teoria Completa** - Entenda o conceito profundamente
2. **🔰 Exemplo Básico** - Vulnerabilidade simples e clara
3. **⚙️ Exemplo Intermediário** - Cenário mais realista
4. **🚀 Exemplo Avançado** - Aplicação real-world com múltiplas camadas
5. **🛠️ Guia de Exploração** - Como explorar passo a passo
6. **📝 Exercícios Práticos** - Desafios para fixar o conhecimento

### 🗺️ Mapa de Aprendizado

```
Iniciante (1-2 semanas)
├── 01. SQL Injection
├── 02. XSS (Cross-Site Scripting)
└── 03. Broken Access Control

Intermediário (2-3 semanas)
├── 04. SSRF (Server-Side Request Forgery)
├── 05. Command Injection
├── 06. Path Traversal
└── 07. CSRF (Cross-Site Request Forgery)

Avançado (3-4 semanas)
├── 08. Insecure Deserialization
├── 09. SSTI (Server-Side Template Injection)
├── 10. XXE (XML External Entity)
└── 11. Race Conditions
```

---

## 📚 Laboratórios Disponíveis

### 1️⃣ [SQL Injection](01-sql-injection/README.md)

**O que você aprenderá:**
- ✅ Injeção SQL básica (authentication bypass)
- ✅ UNION-based SQLi (extração de dados)
- ✅ Blind SQLi (boolean e time-based)
- ✅ Second-order SQLi
- ✅ Bypass de WAF e filtros
- ✅ Exploração em contextos reais (login, search, comentários)

**Aplicações:**
- `basic_app.py` - Login vulnerável clássico
- `intermediate_app.py` - E-commerce com search e filtros
- `advanced_app.py` - Sistema bancário com múltiplos endpoints

**Tempo estimado:** 4-6 horas

---

### 2️⃣ [Cross-Site Scripting (XSS)](02-xss/README.md)

**O que você aprenderá:**
- ✅ Reflected XSS (parâmetros URL)
- ✅ Stored XSS (banco de dados)
- ✅ DOM-based XSS (JavaScript)
- ✅ Bypass de sanitização (nested tags, encoding)
- ✅ XSS em diferentes contextos (HTML, JavaScript, CSS)
- ✅ Exploits reais (cookie stealing, keylogging, phishing)

**Aplicações:**
- `basic_app.py` - Search com reflected XSS
- `intermediate_app.py` - Blog com stored XSS
- `advanced_app.py` - Rede social completa

**Tempo estimado:** 4-6 horas

---

### 3️⃣ [Broken Access Control](03-access-control/README.md)

**O que você aprenderá:**
- ✅ IDOR (Insecure Direct Object Reference)
- ✅ Privilege Escalation (vertical e horizontal)
- ✅ Missing Function Level Access Control
- ✅ Path-based access control bypass
- ✅ Parameter tampering
- ✅ JWT manipulation

**Aplicações:**
- `basic_app.py` - API REST com IDOR simples
- `intermediate_app.py` - Sistema de arquivos com path traversal
- `advanced_app.py` - Plataforma multi-tenant

**Tempo estimado:** 3-5 horas

---

### 4️⃣ [Server-Side Request Forgery (SSRF)](04-ssrf/README.md)

**O que você aprenderá:**
- ✅ SSRF básico (acesso localhost)
- ✅ Bypass de blacklist (IP encoding)
- ✅ SSRF para cloud metadata (AWS, GCP, Azure)
- ✅ DNS rebinding
- ✅ SSRF blind (out-of-band)
- ✅ SSRF em diferentes protocolos (file://, gopher://)

**Aplicações:**
- `basic_app.py` - URL fetcher simples
- `intermediate_app.py` - Webhook system
- `advanced_app.py` - Microservices architecture

**Tempo estimado:** 4-6 horas

---

### 5️⃣ [Command Injection](05-command-injection/README.md)

**O que você aprenderá:**
- ✅ OS Command Injection básico
- ✅ Bypass de filtros (separadores alternativos)
- ✅ Blind command injection (out-of-band)
- ✅ Time-based detection
- ✅ Reverse shells
- ✅ Data exfiltration

**Aplicações:**
- `basic_app.py` - Ping utility
- `intermediate_app.py` - File converter
- `advanced_app.py` - CI/CD pipeline

**Tempo estimado:** 3-5 horas

---

### 6️⃣ [Path Traversal](06-path-traversal/README.md)

**O que você aprenderá:**
- ✅ Directory traversal básico (../)
- ✅ Bypass de filtros (encoding, null bytes)
- ✅ File inclusion (LFI/RFI)
- ✅ Path traversal para RCE
- ✅ Zip slip
- ✅ Template path traversal

**Aplicações:**
- `basic_app.py` - File download
- `intermediate_app.py` - Image gallery
- `advanced_app.py` - CMS com upload

**Tempo estimado:** 3-4 horas

---

### 7️⃣ [CSRF (Cross-Site Request Forgery)](07-csrf/README.md)

**O que você aprenderá:**
- ✅ CSRF básico (GET requests)
- ✅ CSRF em POST requests
- ✅ CSRF com JSON
- ✅ Bypass de referrer check
- ✅ Bypass de CORS
- ✅ Login CSRF

**Aplicações:**
- `basic_app.py` - Profile update
- `intermediate_app.py` - Banking transfer
- `advanced_app.py` - OAuth flow

**Tempo estimado:** 2-4 horas

---

### 8️⃣ [Insecure Deserialization](08-deserialization/README.md)

**O que você aprenderá:**
- ✅ Python Pickle RCE
- ✅ PHP unserialize()
- ✅ Java deserialization
- ✅ Node.js node-serialize
- ✅ Magic methods exploitation
- ✅ Gadget chains

**Aplicações:**
- `basic_app.py` - Session com pickle
- `intermediate_app.py` - Cache system
- `advanced_app.py` - Job queue

**Tempo estimado:** 5-7 horas

---

### 9️⃣ [Server-Side Template Injection (SSTI)](09-ssti/README.md)

**O que você aprenderá:**
- ✅ Detecção de SSTI
- ✅ Jinja2 exploitation
- ✅ Template sandbox escape
- ✅ RCE via SSTI
- ✅ Bypass de filtros
- ✅ SSTI em diferentes engines

**Aplicações:**
- `basic_app.py` - Email template
- `intermediate_app.py` - Report generator
- `advanced_app.py` - Dynamic website builder

**Tempo estimado:** 4-6 horas

---

### 🔟 [XXE (XML External Entity)](10-xxe/README.md)

**O que você aprenderá:**
- ✅ XXE básico (file read)
- ✅ XXE para SSRF
- ✅ Blind XXE (out-of-band)
- ✅ XXE em diferentes parsers
- ✅ Billion Laughs (DoS)
- ✅ XXE em formatos diversos (SVG, DOCX, XLSX)

**Aplicações:**
- `basic_app.py` - XML parser
- `intermediate_app.py` - SOAP API
- `advanced_app.py` - Document processing system

**Tempo estimado:** 4-5 horas

---

### 1️⃣1️⃣ [Race Conditions](11-race-conditions/README.md)

**O que você aprenderá:**
- ✅ TOCTOU (Time-of-Check Time-of-Use)
- ✅ Race condition em transferências
- ✅ Race condition em vouchers
- ✅ Limite rate limiting bypass
- ✅ HTTP/2 multiplexing
- ✅ Concurrency exploitation

**Aplicações:**
- `basic_app.py` - Wallet system
- `intermediate_app.py` - E-commerce vouchers
- `advanced_app.py` - Ticket booking system

**Tempo estimado:** 4-6 horas

---

## 🚀 Como Começar

### Pré-requisitos

```bash
# Python 3.8+
python3 --version

# Dependências
pip install flask requests pyjwt beautifulsoup4 lxml

# Ferramentas úteis
pip install burpsuite-cli sqlmap
```

### Passo a Passo

#### 1. Escolha uma Vulnerabilidade

Comece pela **SQL Injection** se for iniciante:
```bash
cd learn/labs/guided/01-sql-injection
cat README.md
```

#### 2. Leia a Teoria

Entenda o conceito antes de praticar.

#### 3. Execute o Exemplo Básico

```bash
# Terminal 1: Inicia aplicação
python3 basic_app.py

# Terminal 2: Teste manualmente
curl http://localhost:5010
```

#### 4. Siga o Guia de Exploração

```bash
cat exploits.md
```

#### 5. Tente os Exercícios

```bash
cat exercises.md
```

#### 6. Avance para Próximo Nível

- Básico → Intermediário → Avançado
- Mesma vulnerabilidade em diferentes contextos

---

## 📊 Sistema de Pontuação

### Níveis de Dificuldade

| Nível | Pontos | Descrição |
|-------|--------|-----------|
| 🟢 Básico | 10 pts | Vulnerabilidade direta, sem proteções |
| 🟡 Intermediário | 25 pts | Alguns filtros, requer bypass |
| 🔴 Avançado | 50 pts | Múltiplas camadas, cenário real |
| 💀 Expert | 100 pts | Chain de vulnerabilidades |

### Tracking de Progresso

Crie seu arquivo de progresso:
```bash
cp progress_template.md my_progress.md
```

Marque à medida que completa:
- [ ] SQL Injection - Básico (10 pts)
- [ ] SQL Injection - Intermediário (25 pts)
- [ ] SQL Injection - Avançado (50 pts)
- ... (total 1000+ pontos possíveis)

---

## 🛠️ Ferramentas Recomendadas

### Essenciais

1. **Burp Suite Community** - Proxy HTTP
   ```bash
   # Download: https://portswigger.net/burp/communitydownload
   ```

2. **curl** - Testes rápidos
   ```bash
   curl -v http://localhost:5010/endpoint
   ```

3. **Python requests** - Automação
   ```python
   import requests
   r = requests.get('http://localhost:5010')
   ```

### Avançadas

1. **SQLMap** - SQL Injection automatizado
   ```bash
   sqlmap -u "http://localhost:5010/search?q=test"
   ```

2. **XSSer** - XSS automatizado
   ```bash
   xsser --url "http://localhost:5010/search?q=XSS"
   ```

3. **Nuclei** - Scanner de vulnerabilidades
   ```bash
   nuclei -u http://localhost:5010
   ```

---

## 📖 Metodologia de Estudo

### Ciclo de Aprendizado (por vulnerabilidade)

```
1. 📚 TEORIA (30 min)
   └── Leia README.md completamente

2. 🔰 PRÁTICA BÁSICA (1h)
   ├── Execute basic_app.py
   ├── Siga exploits.md
   └── Entenda cada passo

3. ⚙️ PRÁTICA INTERMEDIÁRIA (1-2h)
   ├── Execute intermediate_app.py
   ├── Tente explorar sem olhar soluções
   └── Use exploits.md se travar

4. 🚀 PRÁTICA AVANÇADA (2-3h)
   ├── Execute advanced_app.py
   ├── Explore sozinho primeiro
   └── Compare com soluções

5. 📝 EXERCÍCIOS (1h)
   ├── Complete exercises.md
   └── Documente suas descobertas

6. 🔄 REVISÃO
   ├── Resuma em suas palavras
   ├── Crie seus próprios payloads
   └── Ensine para alguém (método Feynman)
```

### Dicas de Estudo

✅ **Faça:**
- Documente cada descoberta
- Crie seus próprios payloads
- Tente entender o "porquê" de cada exploração
- Pratique em múltiplos contextos
- Automatize exploits com scripts

❌ **Evite:**
- Apenas copiar e colar comandos
- Pular para avançado sem dominar básico
- Decorar payloads sem entender
- Usar ferramentas automatizadas antes de entender manualmente

---

## 🎯 Objetivos de Aprendizado

Ao completar todos os laboratórios, você será capaz de:

### Técnico
✅ Identificar 11 tipos principais de vulnerabilidades web
✅ Explorar vulnerabilidades manualmente
✅ Bypassar proteções e filtros comuns
✅ Criar exploits automatizados
✅ Encadear vulnerabilidades (chaining)
✅ Escrever relatórios técnicos de vulnerabilidades

### Profissional
✅ Conduzir pentest web completo
✅ Validar correções de segurança
✅ Participar de bug bounty programs
✅ Preparar para certificações (OSCP, GWAPT, CEH)

---

## 📈 Próximos Passos

Após completar os laboratórios guiados:

### 1. Labs Integrados
```bash
cd learn/labs/
# Lab 1 (Easy), Lab 2 (Medium), Lab 3 (Hard)
```

### 2. Projetos Reais
- HackTheBox
- TryHackMe
- PortSwigger Academy
- PentesterLab

### 3. Bug Bounty
- HackerOne
- Bugcrowd
- YesWeHack
- Intigriti

### 4. Certificações
- **OSCP** - Offensive Security Certified Professional
- **GWAPT** - GIAC Web Application Penetration Tester
- **CEH** - Certified Ethical Hacker
- **BSCP** - Burp Suite Certified Practitioner

---

## 🤝 Suporte e Comunidade

### Dúvidas

1. Revise README.md da vulnerabilidade
2. Consulte exploits.md
3. Verifique exercises.md para exemplos
4. Busque em learn/basics/ para teoria adicional

### Contribuindo

Encontrou um bug? Tem sugestão de melhoria?
- Abra uma issue no GitHub
- Envie um pull request
- Compartilhe seus payloads customizados

---

## 📝 Licença e Uso Ético

⚠️ **IMPORTANTE**:

Este material é apenas para fins educacionais. **NUNCA** teste vulnerabilidades em sistemas sem autorização explícita.

✅ **Uso Permitido:**
- Laboratórios deste projeto
- Plataformas de treinamento (HTB, THM, etc.)
- Pentests contratados
- Bug bounty programs
- Seu próprio ambiente de teste

❌ **Uso Proibido:**
- Sistemas de terceiros sem autorização
- Websites públicos sem permissão
- Infraestrutura corporativa sem contrato
- Qualquer uso malicioso

**Violações podem resultar em processos criminais!**

---

## 🏆 Certificado de Conclusão

Ao completar todos os 11 laboratórios (1000+ pontos), você pode:

1. Documentar suas conquistas em `my_progress.md`
2. Criar um portfolio no GitHub com seus exploits
3. Adicionar ao LinkedIn: "Completed OWASP Guided Labs"
4. Usar como preparação para certificações

---

**Bons estudos e happy hacking! 🛡️**

**Comece agora**: [01 - SQL Injection →](01-sql-injection/README.md)
