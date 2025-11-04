# 🧪 Laboratórios Práticos de Segurança Web

## 📚 Visão Geral

Três laboratórios hands-on com aplicações web vulneráveis para prática de penetration testing.

---

## 🎯 Lab 1: Nível Fácil

**Localização**: `../../tests/vulnerable_apps/easy/`

**Porta**: 5000

**Dificuldade**: ⭐ Iniciante

### Vulnerabilidades

- SQL Injection básica
- XSS Reflected simples
- XSS Stored
- Information Disclosure
- Broken Access Control
- Directory Listing
- Path Traversal básico
- Credenciais padrão

### Como Executar

```bash
cd ../../tests/vulnerable_apps/easy
python3 app.py
```

Acesse: http://localhost:5000

### Objetivos

- [ ] Fazer login como admin sem senha
- [ ] Executar JavaScript no browser via XSS
- [ ] Acessar painel admin sem autenticação
- [ ] Ler arquivo /etc/passwd (ou app.py)
- [ ] Encontrar todas as FLAGS escondidas
- [ ] Extrair senhas de todos os usuários

---

## 🎯 Lab 2: Nível Médio

**Localização**: `../../tests/vulnerable_apps/medium/`

**Porta**: 5001

**Dificuldade**: ⭐⭐ Intermediário

### Vulnerabilidades

- SQL Injection com bypass de filtros
- XSS com bypass de sanitização
- SSRF (Server-Side Request Forgery)
- Command Injection com bypass
- Insecure Deserialization (pickle)
- CSRF (Cross-Site Request Forgery)

### Como Executar

```bash
cd ../../tests/vulnerable_apps/medium
python3 app.py
```

Acesse: http://localhost:5001

### Objetivos

- [ ] Bypassar filtro WAF para SQL Injection
- [ ] Bypassar sanitização para XSS
- [ ] Fazer SSRF para acessar localhost
- [ ] Executar comandos do sistema
- [ ] Explorar desserialização insegura
- [ ] Realizar ataque CSRF

---

## 🎯 Lab 3: Nível Difícil

**Localização**: `../../tests/vulnerable_apps/hard/`

**Porta**: 5002

**Dificuldade**: ⭐⭐⭐ Avançado

### Vulnerabilidades

- JWT Algorithm Confusion
- Blind SQL Injection com WAF bypass
- Second-Order SQL Injection
- Race Condition
- SSRF Avançado com múltiplos bypasses
- Server-Side Template Injection (SSTI)
- XML External Entity (XXE)

### Como Executar

```bash
cd ../../tests/vulnerable_apps/hard
python3 app.py
```

Acesse: http://localhost:5002

### Objetivos

- [ ] Forjar JWT token com algorithm='none'
- [ ] Explorar Blind SQLi time-based
- [ ] Explorar Second-Order SQLi
- [ ] Ganhar race condition para duplicar dinheiro
- [ ] Bypassar múltiplas proteções SSRF
- [ ] Explorar SSTI para RCE
- [ ] Ler arquivos via XXE

---

## 🛠️ Ferramentas Recomendadas

### Essenciais

- **Browser DevTools** (F12)
- **curl** - Cliente HTTP
- **Postman** - Teste de APIs

### Intermediárias

- **Burp Suite Community** - Proxy e repeater
- **OWASP ZAP** - Scanner automatizado
- **Python requests** - Scripts customizados

### Avançadas

- **sqlmap** - Exploração automática de SQLi
- **XSStrike** - Scanner de XSS
- **Pentest Suite** - Nossa ferramenta!

---

## 📖 Como Estudar

### Para Cada Lab

1. **Leia a documentação**
   - `learn/basics/` para teoria
   - `learn/vulnerabilities/` para técnicas avançadas

2. **Execute a aplicação**
   - Inicie o servidor
   - Explore manualmente

3. **Identifique vulnerabilidades**
   - Use DevTools
   - Teste inputs
   - Observe respostas

4. **Explore manualmente**
   - Tente payloads básicos
   - Tente bypass de filtros
   - Documente achados

5. **Teste com ferramentas**
   - Burp Suite para interceptar
   - Scripts Python
   - Pentest Suite

6. **Consulte soluções**
   - Depois de tentar!
   - `learn/solutions/`

---

## 🎓 Metodologia de Teste

### Fase 1: Reconhecimento

```bash
# Inspecione a aplicação
curl -I http://localhost:5000

# Veja código fonte (Ctrl+U)
# Use DevTools (F12)
```

### Fase 2: Mapeamento

```bash
# Liste endpoints
curl http://localhost:5000
# Veja links, forms, APIs
```

### Fase 3: Teste de Vulnerabilidades

```bash
# SQL Injection
curl -X POST http://localhost:5000/login \
  -d "username=admin' OR '1'='1'--" \
  -d "password=test"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"
```

### Fase 4: Exploração

```bash
# Use Burp Suite
# Intercept and modify requests
# Try different payloads
```

### Fase 5: Documentação

```markdown
# Vulnerabilidade: SQL Injection
- URL: /login
- Parâmetro: username
- Payload: admin' OR '1'='1'--
- Impacto: Authentication Bypass
- Severidade: CRITICAL
```

---

## 📊 Sistema de Pontuação

### Lab 1 (Fácil)

- [ ] SQL Injection: 10 pontos
- [ ] XSS Reflected: 10 pontos
- [ ] XSS Stored: 10 pontos
- [ ] Info Disclosure: 5 pontos
- [ ] Broken Access: 10 pontos
- [ ] Path Traversal: 10 pontos
- [ ] Todas as FLAGS: 15 pontos

**Total**: 70 pontos

### Lab 2 (Médio)

- [ ] SQLi com bypass: 20 pontos
- [ ] XSS com bypass: 20 pontos
- [ ] SSRF: 15 pontos
- [ ] Command Injection: 20 pontos
- [ ] Deserialization: 25 pontos
- [ ] CSRF: 15 pontos

**Total**: 115 pontos

### Lab 3 (Difícil)

- [ ] JWT Confusion: 30 pontos
- [ ] Blind SQLi: 35 pontos
- [ ] Second-Order SQLi: 40 pontos
- [ ] Race Condition: 30 pontos
- [ ] SSRF Avançado: 35 pontos
- [ ] SSTI: 40 pontos
- [ ] XXE: 30 pontos

**Total**: 240 pontos

---

## 🏆 Certificação

Ao completar todos os labs, você terá:

- ✅ Entendimento profundo de OWASP Top 10
- ✅ Experiência prática em exploração
- ✅ Habilidade de bypass de proteções
- ✅ Conhecimento de remediation
- ✅ Base para certificações profissionais (CEH, OSCP)

---

## ⚠️ Avisos Importantes

1. **USE APENAS EM AMBIENTE LOCAL**
   - Não exponha na internet
   - Use apenas em localhost
   - É para aprendizado

2. **RESPONSABILIDADE**
   - Vulnerabilidades são intencionais
   - NÃO use técnicas em sistemas reais sem autorização
   - Respeite a lei

3. **SEGURANÇA**
   - Não use senhas reais
   - Não teste em rede corporativa
   - Mantenha containers isolados

---

## 🚀 Quick Start

```bash
# Terminal 1 - Inicia Lab 1
cd tests/vulnerable_apps/easy
python3 app.py

# Terminal 2 - Testa
cd learn/solutions
python3 exploit_lab1.py

# Terminal 3 - Scan automático
python3 pentest_advanced.py http://localhost:5000 \
    -m full --crawl --tests sqli,xss
```

---

## 📚 Recursos Adicionais

- [Documentação Completa](../README.md)
- [SQL Injection Guide](../basics/01-sql-injection.md)
- [XSS Guide](../basics/02-xss.md)
- [Soluções Lab 1](../solutions/lab1-solutions.md)
- [Soluções Lab 2](../solutions/lab2-solutions.md)
- [Soluções Lab 3](../solutions/lab3-solutions.md)

---

**Bons estudos e hack ethically!** 🛡️
