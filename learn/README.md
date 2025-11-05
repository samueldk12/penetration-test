# 🎓 Learn - Centro de Aprendizado em Segurança Web

Bem-vindo ao centro de aprendizado completo sobre vulnerabilidades web e técnicas de penetration testing!

## 📚 Estrutura

```
learn/
├── README.md                    # Este arquivo
├── basics/                      # Fundamentos
│   ├── 01-sql-injection.md
│   ├── 02-xss.md
│   ├── 03-csrf.md
│   └── ...
├── vulnerabilities/             # Análise detalhada de vulnerabilidades
│   ├── owasp-top-10-2025.md
│   ├── advanced-payloads.md
│   └── bypass-techniques.md
├── labs/                        # Laboratórios práticos
│   ├── lab1/                    # Nível Fácil
│   ├── lab2/                    # Nível Médio
│   └── lab3/                    # Nível Difícil
└── solutions/                   # Soluções detalhadas
    ├── lab1-solutions.md
    ├── lab2-solutions.md
    └── lab3-solutions.md
```

## 🎯 Como Usar Este Material

### 1. Comece pelos Fundamentos

Leia os arquivos em `basics/` para entender cada tipo de vulnerabilidade:
- O que é
- Como funciona
- Por que é perigoso
- Como explorar
- Como prevenir

### 2. Pratique nos Labs

Cada lab contém uma aplicação web vulnerável que você pode executar localmente:

```bash
# Lab 1 - Fácil
cd learn/labs/lab1
python3 app.py

# Lab 2 - Médio
cd learn/labs/lab2
python3 app.py

# Lab 3 - Difícil
cd learn/labs/lab3
python3 app.py
```

### 3. Teste Manualmente

Explore as vulnerabilidades usando:
- Browser (inspeção manual)
- Burp Suite / OWASP ZAP
- curl
- Python requests

### 4. Teste com Ferramentas Automatizadas

Use a Pentest Suite para escanear:

```bash
# Scan automático
python3 pentest_advanced.py http://localhost:5000 \
    -m full \
    --crawl \
    --subdomain-enum \
    --port-scan
```

### 5. Consulte as Soluções

Depois de tentar, veja as soluções em `solutions/` com:
- Passo a passo detalhado
- Payloads utilizados
- Explicação técnica
- Como remediar

## 📖 Ordem de Estudo Recomendada

### Iniciante

1. `basics/01-sql-injection.md`
2. `basics/02-xss.md`
3. Lab 1 (Fácil)
4. `solutions/lab1-solutions.md`

### Intermediário

1. `basics/03-csrf.md`
2. `basics/04-ssrf.md`
3. `vulnerabilities/bypass-techniques.md`
4. Lab 2 (Médio)
5. `solutions/lab2-solutions.md`

### Avançado

1. `vulnerabilities/advanced-payloads.md`
2. `vulnerabilities/owasp-top-10-2025.md`
3. Lab 3 (Difícil)
4. `solutions/lab3-solutions.md`

## 🔐 Segurança e Ética

### ⚠️ AVISOS IMPORTANTES

1. **Use apenas em ambientes autorizados**
   - Seus próprios sistemas
   - Labs locais
   - Programas de bug bounty autorizados
   - Ambientes de teste com permissão

2. **NUNCA use contra sistemas reais sem autorização**
   - É ILEGAL
   - Pode resultar em processos criminais
   - Viola a ética hacker

3. **Responsabilidade**
   - Você é 100% responsável pelo uso destas técnicas
   - Este material é APENAS educacional
   - Use com sabedoria e ética

## 🎓 Conceitos Fundamentais

### O que é Penetration Testing?

Penetration testing (pentest) é o processo de testar sistemas de computador, redes ou aplicações web para encontrar vulnerabilidades de segurança que um atacante poderia explorar.

### Metodologia de Pentest

1. **Reconhecimento** - Coleta de informações
2. **Escaneamento** - Identificação de alvos e portas
3. **Enumeração** - Coleta de informações detalhadas
4. **Exploração** - Tentativa de explorar vulnerabilidades
5. **Pós-Exploração** - Manutenção de acesso
6. **Relatório** - Documentação de achados

### OWASP Top 10

A OWASP (Open Web Application Security Project) mantém uma lista das 10 vulnerabilidades web mais críticas:

1. **A01:2021 - Broken Access Control**
2. **A02:2021 - Cryptographic Failures**
3. **A03:2021 - Injection**
4. **A04:2021 - Insecure Design**
5. **A05:2021 - Security Misconfiguration**
6. **A06:2021 - Vulnerable and Outdated Components**
7. **A07:2021 - Identification and Authentication Failures**
8. **A08:2021 - Software and Data Integrity Failures**
9. **A09:2021 - Security Logging and Monitoring Failures**
10. **A10:2021 - Server-Side Request Forgery (SSRF)**

## 📊 Progressão de Aprendizado

### Nível 1: Iniciante

- [ ] Entender SQL Injection básica
- [ ] Entender XSS Reflected
- [ ] Completar Lab 1
- [ ] Identificar 5+ vulnerabilidades manualmente

### Nível 2: Intermediário

- [ ] Bypass de filtros SQL
- [ ] Bypass de sanitização XSS
- [ ] Entender CSRF
- [ ] Entender SSRF
- [ ] Completar Lab 2
- [ ] Usar Burp Suite efetivamente

### Nível 3: Avançado

- [ ] Blind SQL Injection
- [ ] Second-Order SQL Injection
- [ ] SSTI (Server-Side Template Injection)
- [ ] Race Conditions
- [ ] Completar Lab 3
- [ ] Desenvolver payloads customizados

## 🛠️ Ferramentas Recomendadas

### Essenciais

- **Burp Suite Community** - Proxy e scanner
- **OWASP ZAP** - Scanner automatizado
- **curl** - Cliente HTTP linha de comando
- **Postman** - Testes de API

### Avançadas

- **sqlmap** - Exploração automática de SQL Injection
- **XSStrike** - Scanner de XSS
- **Metasploit** - Framework de exploração
- **Nmap** - Scanner de portas

### Nossa Suite

- **Pentest Suite** - Scanner automatizado completo
  - Reconhecimento
  - Descoberta de endpoints
  - Teste de vulnerabilidades OWASP
  - Teste de vulnerabilidades LLM
  - Relatórios detalhados

## 📚 Recursos Adicionais

### Sites de Aprendizado

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

### Livros Recomendados

- "The Web Application Hacker's Handbook"
- "OWASP Testing Guide"
- "Real-World Bug Hunting"

### Certificações

- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- GWAPT (GIAC Web Application Penetration Tester)

## 🤝 Contribuindo

Encontrou um erro? Tem uma sugestão de melhoria?

1. Abra uma issue no GitHub
2. Envie um pull request
3. Compartilhe seu conhecimento!

## 📞 Suporte

- GitHub Issues: [link]
- Email: security@example.com
- Discord: [link]

---

**Bons estudos e hack ethically!** 🛡️

*"Com grande poder vem grande responsabilidade"*
