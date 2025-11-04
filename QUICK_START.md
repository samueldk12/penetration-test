# 🚀 Quick Start Guide - Pentest Suite

## 📋 O Que Foi Criado

Este projeto agora contém:

✅ **Suite de Pentest Automatizada** - Scanner OWASP Top 10 + LLM
✅ **3 Aplicações Web Vulneráveis** - Para prática hands-on
✅ **Testes de Integração** - Verificam se vulnerabilidades são exploráveis
✅ **Sistema de Aprendizado Completo** - Documentação e tutoriais
✅ **Payloads Extensivos** - 100+ payloads prontos

---

## 🎯 Como Começar

### 1. Instale Dependências

```bash
# Instale requirements
pip install -r requirements.txt

# Instale Flask para os labs
pip install Flask PyJWT
```

### 2. Escolha Seu Caminho

#### 🎓 **Caminho 1: Aprender (Recomendado para Iniciantes)**

```bash
# 1. Leia a documentação
cat learn/README.md

# 2. Estude SQL Injection
cat learn/basics/01-sql-injection.md

# 3. Inicie o Lab 1 (Fácil)
cd tests/vulnerable_apps/easy
python3 app.py
# Acesse: http://localhost:5000

# 4. Pratique manualmente
# - Tente fazer login sem senha
# - Tente XSS nos campos
# - Explore os endpoints

# 5. Veja as soluções
cat learn/solutions/lab1-solutions.md

# 6. Execute o teste automatizado
cd ../../..
python3 tests/test_integration_easy.py
```

#### 🔧 **Caminho 2: Testar Ferramentas (Para Experientes)**

```bash
# 1. Inicie um lab vulnerável
cd tests/vulnerable_apps/easy
python3 app.py &

# 2. Em outro terminal, escaneie
cd ../../..
python3 pentest_advanced.py http://localhost:5000 \
    -m full \
    --crawl \
    --tests sqli,xss,path_traversal

# 3. Veja relatórios
ls -la reports/
```

#### 🧪 **Caminho 3: Desenvolver (Para Contribuidores)**

```bash
# 1. Execute testes unitários
cd tests
python3 run_tests.py

# 2. Execute testes de integração
python3 test_integration_easy.py

# 3. Desenvolva novos módulos
# Edite pentest_suite/modules/
```

---

## 📚 Estrutura do Projeto

```
penetration-test/
├── pentest.py                      # CLI básico
├── pentest_advanced.py             # CLI completo (v2.0)
│
├── pentest_suite/                  # Módulos principais
│   ├── modules/
│   │   ├── recon.py               # Reconhecimento
│   │   ├── endpoint_discovery.py  # Descoberta
│   │   ├── vuln_scanner.py        # Scanner OWASP
│   │   ├── llm_scanner.py         # Scanner LLM
│   │   └── reporter.py            # Relatórios
│   ├── config.py                  # Configurações avançadas
│   └── file_loader.py             # Carregamento de arquivos
│
├── tests/                          # Testes
│   ├── test_*.py                  # Unit tests
│   ├── test_integration_*.py      # Integration tests
│   └── vulnerable_apps/           # Apps de teste
│       ├── easy/app.py           # Lab 1 - Fácil
│       ├── medium/app.py         # Lab 2 - Médio
│       └── hard/app.py           # Lab 3 - Difícil
│
├── learn/                          # Sistema de aprendizado
│   ├── README.md                  # Guia principal
│   ├── basics/                    # Fundamentos
│   │   └── 01-sql-injection.md   # SQL Injection completo
│   ├── labs/                      # Labs práticos
│   │   └── README.md             # Guia dos labs
│   └── solutions/                 # Soluções
│       └── lab1-solutions.md     # Soluções Lab 1
│
└── examples/                       # Exemplos
    ├── payloads/                  # Payloads prontos
    ├── urls/                      # Listas de targets
    └── configs/                   # Configurações
```

---

## 🎯 Cenários de Uso

### Cenário 1: Estudante Aprendendo Segurança

```bash
# Dia 1: SQL Injection
1. Leia learn/basics/01-sql-injection.md
2. Inicie tests/vulnerable_apps/easy/app.py
3. Pratique SQL injection manualmente
4. Veja learn/solutions/lab1-solutions.md

# Dia 2: XSS
1. Continue no Lab 1
2. Pratique XSS Reflected e Stored
3. Use diferentes payloads

# Dia 3: Scan Automatizado
1. Use pentest_advanced.py no Lab 1
2. Compare com seus achados manuais
3. Analise relatórios
```

### Cenário 2: Profissional Testando API

```bash
# 1. Configure autenticação
cat > auth.json << EOF
{
  "type": "bearer",
  "token": "seu_token_aqui"
}
EOF

# 2. Escaneie API
python3 pentest_advanced.py https://api.example.com \
    --auth-file auth.json \
    --tests api_discovery,ssrf,command_injection

# 3. Analise relatórios
firefox reports/pentest_report_*.html
```

### Cenário 3: Bug Bounty Hunter

```bash
# 1. Crie lista de targets
cat > targets.txt << EOF
https://site1.example.com
https://site2.example.com
https://api.example.com
EOF

# 2. Configure proxy (Burp Suite)
python3 pentest_advanced.py \
    --target-file targets.txt \
    --proxy http://127.0.0.1:8080 \
    --crawl --bruteforce

# 3. Use payloads customizados
python3 pentest_advanced.py https://target.com \
    --payload-file my_custom_sqli.txt \
    --tests sqli
```

### Cenário 4: Red Team

```bash
# 1. Reconhecimento
python3 pentest_advanced.py target.com \
    -m recon \
    --subdomain-enum \
    --port-scan \
    --tech-detect

# 2. Descoberta
python3 pentest_advanced.py https://target.com \
    -m discovery \
    --crawl --crawl-depth 5 \
    --bruteforce

# 3. Exploração
python3 pentest_advanced.py https://target.com \
    -m vulnscan \
    --tests sqli,xss,ssrf,command_injection
```

---

## 🧪 Testando as Aplicações Vulneráveis

### Lab 1 - Fácil (Porta 5000)

```bash
# Terminal 1: Inicia app
cd tests/vulnerable_apps/easy
python3 app.py

# Terminal 2: Testa
# SQL Injection
curl -X POST http://localhost:5000/login \
  -d "username=admin' OR '1'='1'--" \
  -d "password=test"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# Info Disclosure
curl http://localhost:5000/debug

# Terminal 3: Scan automático
python3 pentest_advanced.py http://localhost:5000 \
    -m full --crawl
```

### Lab 2 - Médio (Porta 5001)

```bash
cd tests/vulnerable_apps/medium
python3 app.py

# SQL Injection com bypass
curl -X POST http://localhost:5001/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' oR(1=1)--" \
  -d "password=test"

# SSRF
curl -X POST http://localhost:5001/api/fetch \
  -d "url=http://127.1/"
```

### Lab 3 - Difícil (Porta 5002)

```bash
cd tests/vulnerable_apps/hard
python3 app.py

# Login para pegar JWT
curl -X POST http://localhost:5002/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"administrator","password":"C0mpl3x_P@ssw0rd!2024"}'

# Blind SQLi
curl "http://localhost:5002/api/users/search?q=test" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🧪 Executando Testes

### Testes Unitários

```bash
# Todos os testes
cd tests
python3 run_tests.py

# Teste específico
python3 -m unittest test_config
python3 -m unittest test_file_loader
python3 -m unittest test_llm_scanner
```

### Testes de Integração

```bash
# Lab 1 (Fácil)
python3 tests/test_integration_easy.py

# Resultado esperado:
# - 11 testes devem passar
# - Todas as vulnerabilidades devem ser confirmadas
```

---

## 📊 Relatórios

### Localização

```bash
ls -la reports/
```

### Formatos Disponíveis

```bash
# JSON (máquina)
cat reports/pentest_report_*.json | jq

# HTML (visual)
firefox reports/pentest_report_*.html

# TXT (legível)
cat reports/pentest_report_*.txt
```

---

## 🎓 Ordem de Estudo Recomendada

### Semana 1: Fundamentos

- [ ] Leia `learn/README.md`
- [ ] Estude `learn/basics/01-sql-injection.md`
- [ ] Complete Lab 1 manualmente
- [ ] Execute testes automatizados no Lab 1

### Semana 2: Intermediário

- [ ] Estude técnicas de bypass
- [ ] Complete Lab 2
- [ ] Use Burp Suite
- [ ] Desenvolva scripts Python customizados

### Semana 3: Avançado

- [ ] Complete Lab 3
- [ ] Explore payloads complexos
- [ ] Teste em ambiente real (autorizado!)
- [ ] Contribua com novos payloads

---

## 🔧 Troubleshooting

### Erro: "Address already in use"

```bash
# Encontre processo usando a porta
lsof -i :5000

# Mate o processo
kill -9 PID

# Ou use outra porta
python3 app.py  # Edite app.run(port=XXXX)
```

### Erro: "Module not found"

```bash
pip install -r requirements.txt
pip install Flask PyJWT
```

### Banco de dados corrompido

```bash
# Remova e reinicie app
rm vulnerable_*.db
python3 app.py  # Recria automaticamente
```

---

## 🎯 Metas de Aprendizado

### Iniciante (1-2 meses)

- [ ] Entender todas as vulnerabilidades do OWASP Top 10
- [ ] Completar Lab 1 (70 pontos)
- [ ] Usar Burp Suite básico
- [ ] Escrever scripts Python simples

### Intermediário (3-4 meses)

- [ ] Dominar técnicas de bypass
- [ ] Completar Lab 2 (115 pontos)
- [ ] Usar Burp Suite avançado
- [ ] Desenvolver payloads customizados

### Avançado (6+ meses)

- [ ] Completar Lab 3 (240 pontos)
- [ ] Blind exploitation
- [ ] Chains de vulnerabilidades
- [ ] Contribuir para o projeto

**Total**: 425 pontos possíveis!

---

## 📚 Próximos Passos

### Depois de Dominar os Labs

1. **Pratique em Plataformas**
   - HackTheBox
   - TryHackMe
   - PortSwigger Academy

2. **Participe de Bug Bounty**
   - HackerOne
   - Bugcrowd
   - Intigriti

3. **Busque Certificações**
   - CEH (Certified Ethical Hacker)
   - OSCP (Offensive Security Certified Professional)
   - GWAPT (GIAC Web Application Penetration Tester)

4. **Contribua**
   - Adicione novos payloads
   - Crie novos módulos
   - Melhore documentação

---

## 🤝 Comunidade

- GitHub: [Link do Repo]
- Discord: [Link do Discord]
- Twitter: @pentestsuite

---

## ⚠️ Lembrete Final

**NUNCA use estas técnicas em sistemas sem autorização explícita!**

- É ILEGAL
- Pode resultar em prisão
- Viola a ética hacker
- Use apenas em:
  - Seus próprios sistemas
  - Labs locais (fornecidos)
  - Bug bounty autorizado
  - Pentests contratados

---

**Bons estudos e hack ethically!** 🛡️

*"Segurança não é um produto, é um processo."*
