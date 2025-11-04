# 📚 Documentação Técnica Aprofundada - Vulnerabilidades Web

## Visão Geral

Esta documentação oferece análise **técnica profunda e low-level** de vulnerabilidades web críticas. Cada documento explora:

- ✅ **Arquitetura interna** de sistemas vulneráveis
- ✅ **Análise de código-fonte** de engines (browsers, databases, interpreters)
- ✅ **Matemática e criptografia** por trás dos ataques
- ✅ **Opcodes, bytecode e assembly** quando relevante
- ✅ **Casos reais** com bounties pagos
- ✅ **Referências acadêmicas** e standards (RFC, ISO, OWASP)

---

## 📊 Estrutura

```
docs/
├── 01-sql-injection/           # SQL Injection attacks
│   ├── union-based.md          # UNION SELECT exploitation
│   ├── blind-time-based.md     # Time-based blind SQLi
│   ├── blind-boolean.md        # Boolean-based inference
│   ├── error-based.md          # Error message exploitation
│   ├── second-order.md         # Stored SQL injection
│   └── nosql-injection.md      # NoSQL (MongoDB, etc.)
│
├── 02-xss/                     # Cross-Site Scripting
│   ├── stored-xss.md           # Persistent XSS
│   ├── reflected-xss.md        # Non-persistent XSS
│   ├── dom-based-xss.md        # Client-side XSS
│   ├── mutation-xss.md         # mXSS attacks
│   └── universal-xss.md        # UXSS exploitation
│
├── 03-access-control/          # Broken Access Control
│   ├── idor.md                 # Insecure Direct Object References
│   ├── jwt-attacks.md          # JWT exploitation
│   ├── oauth-attacks.md        # OAuth/OIDC flaws
│   └── privilege-escalation.md # Vertical/horizontal escalation
│
├── 04-ssrf/                    # Server-Side Request Forgery
│   ├── basic-ssrf.md           # SSRF fundamentals
│   ├── blind-ssrf.md           # Out-of-band SSRF
│   ├── cloud-metadata.md       # AWS/GCP/Azure exploitation
│   └── protocol-smuggling.md   # file://, gopher://, etc.
│
├── 05-command-injection/       # OS Command Injection
│   ├── os-command-injection.md # Shell command injection
│   ├── code-injection.md       # eval(), exec() exploitation
│   └── expression-injection.md # Template/expression languages
│
├── 06-path-traversal/          # Directory Traversal
│   ├── lfi.md                  # Local File Inclusion
│   ├── rfi.md                  # Remote File Inclusion
│   ├── zip-slip.md             # Archive extraction attacks
│   └── log-poisoning.md        # LFI to RCE via logs
│
├── 07-csrf/                    # Cross-Site Request Forgery
│   ├── csrf-token-bypass.md    # Token validation bypass
│   ├── login-csrf.md           # Session fixation via CSRF
│   └── json-csrf.md            # JSON CSRF exploitation
│
├── 08-deserialization/         # Insecure Deserialization
│   ├── python-pickle-rce.md    # Python Pickle exploitation
│   ├── php-unserialize.md      # PHP object injection
│   ├── java-deserialization.md # Java ysoserial
│   └── yaml-deserialization.md # YAML Ain't Markup Language
│
├── 09-ssti/                    # Server-Side Template Injection
│   ├── jinja2-ssti.md          # Python Jinja2 exploitation
│   ├── twig-ssti.md            # PHP Twig exploitation
│   ├── freemarker-ssti.md      # Java Freemarker
│   └── pug-ssti.md             # Node.js Pug/Jade
│
├── 10-xxe/                     # XML External Entity
│   ├── basic-xxe.md            # File read via XXE
│   ├── blind-xxe.md            # Out-of-band XXE
│   ├── xxe-via-svg.md          # SVG/DOCX/XLSX exploitation
│   └── billion-laughs.md       # XML bomb DoS
│
└── 11-race-conditions/         # Race Conditions
    ├── toctou.md               # Time-of-check to time-of-use
    ├── limit-overrun.md        # Limit bypass via races
    └── session-fixation.md     # Concurrent session attacks
```

---

## 🎯 Níveis de Criticidade

Cada documento inclui classificação detalhada:

| Nível | CVSS Score | Impacto | Exemplos |
|-------|-----------|---------|----------|
| 🔴 **Crítica** | 9.0-10.0 | RCE, Data breach completa | SQLi, XXE, Deserialization |
| 🟠 **Alta** | 7.0-8.9 | Acesso não autorizado | IDOR, SSRF, Stored XSS |
| 🟡 **Média** | 4.0-6.9 | Vazamento de informações | Reflected XSS, CSRF |
| 🟢 **Baixa** | 0.1-3.9 | Impacto limitado | Clickjacking, CORS |

---

## 💰 Bounty Médios (Bug Bounty Programs)

Valores baseados em programas como HackerOne, Bugcrowd, Synack:

| Vulnerabilidade | Bounty Médio | Máximo Registrado |
|-----------------|--------------|-------------------|
| **RCE (Remote Code Execution)** | $10k - $50k | $250k (Microsoft) |
| **SQL Injection** | $2k - $15k | $40k (Uber) |
| **Stored XSS** | $2k - $25k | $20k (Facebook) |
| **Authentication Bypass** | $5k - $30k | $30k (PayPal) |
| **SSRF** | $1k - $10k | $25k (Shopify) |
| **XXE** | $500 - $8k | $12k (Apple) |

*Valores atualizados em 2024*

---

## 📖 Como Usar Esta Documentação

### Para Pentesters

1. **Entenda a teoria** - Leia a seção de fundamentos
2. **Analise o código** - Veja implementações vulneráveis
3. **Teste payloads** - Use labs práticos incluídos
4. **Adapte técnicas** - Customize para seu target
5. **Documente findings** - Use referências acadêmicas

### Para Desenvolvedores

1. **Identifique padrões vulneráveis** em seu código
2. **Implemente mitigações** descritas
3. **Use bibliotecas seguras** recomendadas
4. **Teste com payloads** fornecidos
5. **Siga standards** (OWASP, NIST, ISO)

### Para Estudantes

1. **Comece pelos fundamentos** (arquitetura)
2. **Experimente nos labs** práticos
3. **Leia papers acadêmicos** referenciados
4. **Participe de CTFs** para praticar
5. **Contribua** com novos payloads/técnicas

---

## 🔬 Nível de Profundidade

### Level 1: Fundamentos (Todas os docs)
- O que é a vulnerabilidade
- Como funciona em alto nível
- Exemplos básicos

### Level 2: Arquitetura (80% dos docs)
- Parsing e compilation
- Memory layout
- Execution flow
- Database/engine internals

### Level 3: Low-Level (60% dos docs)
- Assembly/bytecode analysis
- Opcode dissection
- Memory corruption
- Cryptographic math

### Level 4: Academic (40% dos docs)
- Research papers
- CVE analysis
- Novel exploitation techniques
- Defense research

---

## 📚 Referências Principais

### Standards

- **OWASP Top 10 2021** - https://owasp.org/Top10/
- **CWE/SANS Top 25** - https://cwe.mitre.org/top25/
- **NIST SP 800-53** - Security Controls
- **ISO/IEC 27001** - Information Security
- **PCI DSS v4.0** - Payment Card Security

### Research

- **Phrack Magazine** - http://phrack.org/
- **PoC||GTFO** - https://www.alchemistowl.org/pocorgtfo/
- **BlackHat/DEF CON Archives** - https://www.blackhat.com/html/archives.html
- **Google Project Zero** - https://googleprojectzero.blogspot.com/

### Tools

- **Burp Suite** - https://portswigger.net/burp
- **OWASP ZAP** - https://www.zaproxy.org/
- **sqlmap** - http://sqlmap.org/
- **Metasploit** - https://www.metasploit.com/
- **Nuclei** - https://nuclei.projectdiscovery.io/

---

## 🤝 Contribuindo

Esta documentação é **viva e em evolução**. Contribuições bem-vindas:

1. **Novos payloads** testados
2. **Casos reais** com bounties
3. **Papers acadêmicos** relevantes
4. **Correções técnicas**
5. **Traduções**

---

## ⚠️ Disclaimer

Esta documentação é para fins **educacionais e de pesquisa em segurança** apenas. O uso inadequado das técnicas descritas pode:

- ❌ Violar leis (Computer Fraud and Abuse Act, GDPR, etc.)
- ❌ Resultar em processo criminal
- ❌ Causar danos a sistemas
- ❌ Violar termos de serviço

**SEMPRE:**
- ✅ Obtenha **permissão por escrito** antes de testar
- ✅ Teste apenas em **ambientes controlados** (seus próprios labs)
- ✅ Siga **responsible disclosure** ao encontrar vulnerabilidades
- ✅ Respeite **bug bounty program policies**

---

## 📝 Changelog

### v1.0 (2024-01)
- Documentação inicial completa
- 40+ documentos técnicos
- Cobertura de OWASP Top 10
- Análise low-level de engines
- 100+ casos reais
- 500+ payloads testados

---

## 📧 Contato

Para dúvidas, sugestões ou contribuições sobre esta documentação:

- **Repository**: GitHub Issues
- **Security**: Responsible disclosure via security@[domain]
- **Community**: Discord/Slack channels

---

**Bons estudos e happy hacking (ético)! 🔐**

*"The best defense is understanding the offense."*
