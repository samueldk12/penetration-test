# Teoria Fundamental de Controle de Acesso

**Criticidade**: 🟠 Alta a 🔴 Crítica (CVSS 6.5-9.5)
**Dificuldade**: 🟢 Básica a 🟡 Intermediária
**Bounty Médio**: $500 - $20,000 USD

---

## 📚 Índice

1. [Fundamentos de Controle de Acesso](#fundamentos-de-controle-de-acesso)
2. [Modelos Teóricos de Segurança](#modelos-teóricos-de-segurança)
3. [Matriz de Controle de Acesso](#matriz-de-controle-de-acesso)
4. [Teoria de Referências Diretas](#teoria-de-referências-diretas)
5. [Autenticação vs Autorização](#autenticação-vs-autorização)
6. [Privilégio e Propagação de Confiança](#privilégio-e-propagação-de-confiança)

---

## 🔬 Fundamentos de Controle de Acesso

### O Que É Controle de Acesso?

**Controle de acesso** é o mecanismo que determina:
- **Quem** (sujeito) pode fazer **o quê** (operação) em **qual** recurso (objeto)

**Definição Formal:**

```
Access Control System = (S, O, A, P)

Onde:
  S = Conjunto de sujeitos (users, processes, services)
  O = Conjunto de objetos (files, records, resources)
  A = Conjunto de ações (read, write, execute, delete)
  P = Política de acesso: S × O × A → {allow, deny}

Exemplo:
  P(user_alice, file_123, read) = allow
  P(user_bob, file_123, write) = deny
```

### Por Que Controle de Acesso Falha?

**Root Causes:**

1. **Ausência de Verificação**
   ```python
   # ❌ Nenhuma verificação
   def get_document(doc_id):
       return database.query(f"SELECT * FROM docs WHERE id={doc_id}")

   # Qualquer usuário pode acessar qualquer documento!
   ```

2. **Verificação Incompleta**
   ```python
   # ❌ Verifica autenticação, mas não autorização
   @login_required  # Só verifica: usuário está logado?
   def get_document(doc_id):
       return database.query(f"SELECT * FROM docs WHERE id={doc_id}")

   # Usuários logados podem acessar TODOS os documentos!
   ```

3. **Verificação no Cliente**
   ```javascript
   // ❌ Verificação apenas no frontend
   if (currentUser.role === 'admin') {
       // Mostra botão "Delete"
   }

   // Atacante bypassa fazendo request direto à API!
   ```

4. **Confiança em Dados do Cliente**
   ```python
   # ❌ Confia no user_id do cookie
   def get_profile():
       user_id = request.cookies.get('user_id')  # Controlado pelo cliente!
       return database.query(f"SELECT * FROM users WHERE id={user_id}")

   # Atacante modifica cookie para acessar outros perfis!
   ```

### Broken Access Control como Problema Sistêmico

**Arquitetura Típica (3 Camadas):**

```
┌─────────────────────┐
│   Presentation      │  Frontend (HTML/JS)
│      Layer          │  ❌ Verificação aqui: bypassável
└─────────────────────┘
         ↓
┌─────────────────────┐
│   Application       │  Backend (API/Logic)
│      Layer          │  ✅ Verificação aqui: necessária
└─────────────────────┘
         ↓
┌─────────────────────┐
│   Data Layer        │  Database
│                     │  ✅ Row-Level Security: defesa adicional
└─────────────────────┘
```

**Falhas Comuns por Camada:**

| Camada | Verificação | Bypassável? | Exemplo de Falha |
|--------|-------------|-------------|------------------|
| **Frontend** | Esconde botões | ✅ Sim | Atacante usa API diretamente |
| **Backend** | Verifica permissões | ❌ Não* | *Se implementado corretamente |
| **Database** | Row-Level Security | ❌ Não | Requer suporte DB específico |

---

## 📐 Modelos Teóricos de Segurança

### Modelo DAC (Discretionary Access Control)

**Definição:** O **dono** do recurso controla quem pode acessá-lo

**Características:**
```
- Flexível: Usuário pode compartilhar recursos
- Descentralizado: Cada dono define políticas
- Vulnerável: Dono pode conceder acesso inadequado
```

**Implementação:**

```
File System Unix:
  owner: alice
  group: developers
  permissions: rwxr-x---
               ↑   ↑  ↑
             owner group others

alice decide quem pode acessar (DAC)
```

**Exemplo em Aplicação Web:**

```python
class Document:
    owner_id = ...
    shared_with = [...]  # Lista de user_ids

def can_access(user, doc):
    return user.id == doc.owner_id or user.id in doc.shared_with

# Dono (user) controla acesso (Discretionary)
```

**Vulnerabilidade:**

```
Problema: Propagação descontrolada de acesso

User A → compartilha com User B
User B → compartilha com User C (malicioso!)
User C não deveria ter acesso!

Solução: Mandatory Access Control (MAC)
```

### Modelo MAC (Mandatory Access Control)

**Definição:** O **sistema** controla acesso baseado em **classificações de segurança**

**Características:**
```
- Rígido: Usuários NÃO podem mudar políticas
- Centralizado: Administrador define regras
- Seguro: Previne vazamento não autorizado
```

**Bell-LaPadula Model (Confidencialidade):**

```
Classificações (hierárquicas):
  Top Secret > Secret > Confidential > Unclassified

Regras:
1. No Read Up: Sujeito não pode ler objeto de nível superior
   User (Secret) ❌ Read Document (Top Secret)

2. No Write Down: Sujeito não pode escrever em objeto de nível inferior
   User (Secret) ❌ Write Document (Unclassified)
   (previne vazamento)

Propriedades:
- Simple Security Property: s pode ler o sse level(s) ≥ level(o)
- *-Property (Star): s pode escrever o sse level(s) ≤ level(o)
```

**Exemplo Militar:**

```
Coronel (Top Secret):
  ✅ Pode ler: Docs Top Secret, Secret, Confidential
  ❌ Pode escrever: Apenas Top Secret docs

Soldado (Confidential):
  ✅ Pode ler: Docs Confidential, Unclassified
  ❌ Não pode ler: Secret, Top Secret
  ✅ Pode escrever: Confidential e acima
```

### Modelo RBAC (Role-Based Access Control)

**Definição:** Acesso baseado em **funções** (roles) atribuídas a usuários

**Componentes:**

```
RBAC = (U, R, P, S, UA, PA)

U = Usuários (users)
R = Funções (roles)
P = Permissões (permissions)
S = Sessões (sessions)
UA = User-Role Assignment
PA = Permission-Role Assignment

Exemplo:
  user_alice ∈ U
  role_admin ∈ R
  permission_delete_user ∈ P

  UA(user_alice) = {role_admin}
  PA(role_admin) = {permission_delete_user, permission_create_user, ...}

  Inferência:
    user_alice tem permission_delete_user
```

**Hierarquia de Roles:**

```
        [Super Admin]
              |
         [Administrator]
         /           \
    [Manager]     [Auditor]
        |
    [Employee]
        |
     [Guest]

Regra: Role superior herda permissões dos inferiores

Super Admin ⊃ Administrator ⊃ Manager ⊃ Employee ⊃ Guest
```

**Implementação:**

```python
class User:
    roles = []  # List of Role objects

class Role:
    permissions = []  # List of Permission objects
    parent_role = None  # Role hierarchy

def has_permission(user, permission):
    for role in user.roles:
        # Direct permission
        if permission in role.permissions:
            return True

        # Inherited permission (DFS in role hierarchy)
        current_role = role
        while current_role.parent_role:
            current_role = current_role.parent_role
            if permission in current_role.permissions:
                return True

    return False
```

**Vulnerabilidades RBAC:**

1. **Role Creep**
   ```
   User acumula roles ao longo do tempo
   Violates Principle of Least Privilege

   Exemplo:
     user_bob: [employee, manager, admin]
                ↑ deveria ter apenas um!
   ```

2. **Overprivileged Roles**
   ```
   Role tem mais permissões que necessário

   role_customer_support: [
       read_customer_data,  ✅ Necessário
       write_customer_data,  ✅ Necessário
       delete_account  ❌ Desnecessário!
   ]
   ```

### Modelo ABAC (Attribute-Based Access Control)

**Definição:** Acesso baseado em **atributos** de sujeito, objeto, ambiente

**Componentes:**

```
ABAC Decision:
  P(subject_attrs, object_attrs, action, environment_attrs) → {allow, deny}

Attributes:
  Subject: {role, department, clearance_level, seniority}
  Object: {classification, owner, sensitivity, created_date}
  Environment: {time, location, network, device}
  Action: {read, write, delete, share}
```

**Exemplo de Política:**

```
Policy: "Acesso a Documentos Financeiros"

Regra:
  ALLOW read IF:
    subject.department = "Finance" AND
    object.classification ≤ subject.clearance_level AND
    environment.time BETWEEN 08:00 AND 18:00 AND
    environment.location = "Office"

DENY otherwise

Exemplo Concreto:
  Subject: {department: "Finance", clearance: 3}
  Object: {classification: 2, type: "Financial Report"}
  Environment: {time: "14:30", location: "Office"}
  Action: read

  Evaluation:
    "Finance" = "Finance" ✅
    2 ≤ 3 ✅
    14:30 BETWEEN 08:00 AND 18:00 ✅
    "Office" = "Office" ✅

  Result: ALLOW
```

**Implementação (XACML-like):**

```xml
<Policy>
    <Rule Effect="Permit">
        <Condition>
            <Apply FunctionId="and">
                <Apply FunctionId="string-equal">
                    <SubjectAttributeDesignator AttributeId="department"/>
                    <AttributeValue>Finance</AttributeValue>
                </Apply>
                <Apply FunctionId="integer-less-than-or-equal">
                    <ResourceAttributeDesignator AttributeId="classification"/>
                    <SubjectAttributeDesignator AttributeId="clearance"/>
                </Apply>
            </Apply>
        </Condition>
    </Rule>
</Policy>
```

---

## 🗂️ Matriz de Controle de Acesso

### Representação Matemática

**Access Control Matrix (ACM):**

```
       | obj₁  | obj₂  | obj₃  | obj₄
-------+-------+-------+-------+------
subj₁  |  r,w  |   r   |       |  x
subj₂  |   r   |  r,w  |   w   |
subj₃  |       |       | r,w,x | r,w

Onde:
  r = read, w = write, x = execute
```

**Interpretação:**

```
ACM[subj₁][obj₂] = {read}
→ subj₁ pode ler obj₂

ACM[subj₃][obj₃] = {read, write, execute}
→ subj₃ pode ler, escrever e executar obj₃

ACM[subj₂][obj₁] = {read}
→ subj₂ pode apenas ler obj₁ (não write)
```

### Implementações de ACM

**Implementação 1: ACL (Access Control Lists)**

```
Armazenamento: Por objeto (coluna da matriz)

obj₁:
  - subj₁: {read, write}
  - subj₂: {read}

obj₂:
  - subj₁: {read}
  - subj₂: {read, write}

Vantagens:
  ✅ Fácil revogar acesso a um objeto
  ✅ Fácil ver quem tem acesso a um objeto

Desvantagens:
  ❌ Difícil ver todos objetos que um sujeito pode acessar
  ❌ Revogação de acesso de um sujeito é custosa
```

**Código:**

```python
class Object:
    acl = []  # [(subject, permissions)]

def can_access(subject, obj, action):
    for (s, perms) in obj.acl:
        if s == subject and action in perms:
            return True
    return False

# Uso:
obj1.acl = [
    (user_alice, ['read', 'write']),
    (user_bob, ['read'])
]

can_access(user_alice, obj1, 'write')  # True
can_access(user_bob, obj1, 'write')    # False
```

**Implementação 2: Capability Lists**

```
Armazenamento: Por sujeito (linha da matriz)

subj₁:
  - obj₁: {read, write}
  - obj₂: {read}

subj₂:
  - obj₁: {read}
  - obj₂: {read, write}
  - obj₃: {write}

Vantagens:
  ✅ Fácil ver todos recursos que um sujeito pode acessar
  ✅ Transfer de acesso é simples (passa capability)

Desvantagens:
  ❌ Difícil revogar acesso a um objeto
  ❌ Capabilities podem ser forjadas se não protegidas
```

**Código:**

```python
class Subject:
    capabilities = []  # [(object, permissions)]

def grant_capability(subject, obj, permissions):
    subject.capabilities.append((obj, permissions))

def can_access(subject, obj, action):
    for (o, perms) in subject.capabilities:
        if o == obj and action in perms:
            return True
    return False

# Uso:
grant_capability(user_alice, obj1, ['read', 'write'])
grant_capability(user_alice, obj2, ['read'])

can_access(user_alice, obj1, 'write')  # True
```

### Sparse vs Dense Matrices

**Problema de Esparsidade:**

```
Realidade: ACM é extremamente esparsa

Exemplo: Facebook
  Usuários: 2 bilhões (S)
  Objetos (posts, fotos, etc.): 100 bilhões (O)

  ACM: 2B × 100B = 200 quintilhões de células!
  Mas: maioria das células é VAZIA (usuário não tem acesso)
  Esparsidade: ~99.99999%
```

**Solução: Armazenar apenas células não-vazias**

```python
# ❌ Dense storage (impraticável)
acm = [[set() for _ in range(num_objects)] for _ in range(num_subjects)]

# ✅ Sparse storage
acm = {}  # {(subject, object): permissions}

acm[(user1, obj1)] = {'read', 'write'}
acm[(user1, obj2)] = {'read'}
# Células não presentes = sem acesso
```

---

## 🔑 Teoria de Referências Diretas

### O Problema de Identificadores Expostos

**Definição:** Aplicação usa identificadores **internos** (IDs de banco) diretamente na **interface externa** (URLs, APIs)

**Por que isso é problemático:**

```
Princípio violado: Information Hiding

Internal: ID do banco de dados (implementação)
External: Identificador opaco (interface)

Quando ID interno é exposto:
  1. Atacante conhece estrutura interna
  2. Pode inferir outros IDs válidos
  3. Pode enumerar todos os recursos
```

**Exemplo:**

```
URL: https://bank.com/account?id=123456

Inferências:
  - IDs são sequenciais
  - Existem ~123,456 contas
  - Próxima conta: id=123457
  - Enumerar todas: for id in range(1, 200000)
```

### Referências Diretas vs Indiretas

**Referência Direta (Insegura):**

```python
# URL: /api/invoice?id=456

@app.route('/api/invoice')
def get_invoice():
    invoice_id = request.args.get('id')  # Direto do DB
    invoice = db.query(f"SELECT * FROM invoices WHERE id={invoice_id}")
    return jsonify(invoice)

# ❌ Qualquer usuário pode acessar qualquer invoice!
```

**Referência Indireta (Segura):**

```python
# URL: /api/invoice?token=xK9mQ2pL4wN3vB5zR8fY7cH6

@app.route('/api/invoice')
def get_invoice():
    token = request.args.get('token')  # Token opaco

    # Mapeamento interno token → ID
    invoice_mapping = session.get('invoice_tokens', {})
    invoice_id = invoice_mapping.get(token)

    if not invoice_id:
        return jsonify({"error": "Invalid token"}), 403

    # Verifica ownership
    if not user_owns_invoice(current_user.id, invoice_id):
        return jsonify({"error": "Unauthorized"}), 403

    invoice = db.query(f"SELECT * FROM invoices WHERE id={invoice_id}")
    return jsonify(invoice)

# ✅ Token não revela ID interno
# ✅ Verificação de autorização
```

### Teoria de Enumeration

**Enumeration Attack:**

```
Goal: Descobrir todos os recursos válidos

Method: Testar sistematicamente todos IDs possíveis

Complexity:
  Range: [id_min, id_max]
  Attempts: id_max - id_min + 1
  Time: (id_max - id_min + 1) × request_time

Exemplo:
  Range: [1, 100000]
  Request time: 0.1s
  Total time: 10,000s ≈ 2.8 horas
```

**Defesas:**

1. **Rate Limiting**
   ```python
   @rate_limit(max_requests=100, window=60)  # 100 req/min
   def get_resource(id):
       ...

   # Enumeration agora leva: 100,000 / 100 = 1,000 minutos ≈ 17 horas
   ```

2. **UUIDs (Universally Unique Identifiers)**
   ```python
   import uuid

   # UUID v4: 128 bits random
   resource_id = uuid.uuid4()  # "550e8400-e29b-41d4-a716-446655440000"

   # Espaço de busca: 2^128 ≈ 10^38
   # Impossível enumerar!
   ```

3. **Cryptographic Tokens**
   ```python
   import secrets

   # 256-bit random token
   token = secrets.token_urlsafe(32)  # "xK9mQ2pL4wN3vB5zR8fY7cH6jG1dS0aT"

   # Armazena mapeamento: token → resource_id
   token_mapping[token] = resource_id
   ```

---

## 🔐 Autenticação vs Autorização

### Distinção Fundamental

**Autenticação (Authentication):**
```
Pergunta: "Quem é você?"
Resposta: Credenciais (senha, token, biometria)
Verifica: Identidade

Exemplo:
  Login com username + password
  → Sistema verifica se credenciais estão corretas
  → Se sim: Identidade confirmada
```

**Autorização (Authorization):**
```
Pergunta: "O que você pode fazer?"
Resposta: Permissões, roles, políticas
Verifica: Acesso

Exemplo:
  Usuário autenticado tenta acessar documento X
  → Sistema verifica se usuário tem permissão
  → Se sim: Acesso concedido
```

**Relação:**

```
Autenticação PRECEDE Autorização

Fluxo:
  1. User submits credentials
  2. Authentication: Verify identity  ← "Você é quem diz ser?"
  3. Create session
  4. User requests resource
  5. Authorization: Check permissions  ← "Pode acessar isso?"
  6. Grant/Deny access

Analogia:
  Autenticação = Mostrar ID no aeroporto
  Autorização = Verificar se tem ticket para o voo específico
```

### Broken Access Control: Confusão entre Auth e Authz

**Anti-Pattern Comum:**

```python
# ❌ VULNERÁVEL
@app.route('/api/document/<doc_id>')
@login_required  # Apenas autenticação!
def get_document(doc_id):
    # Falta: autorização (usuário pode acessar ESTE documento?)
    doc = database.get(doc_id)
    return jsonify(doc)

# Problema:
#   - Qualquer usuário autenticado pode acessar qualquer documento
#   - Autenticação ≠ Autorização!
```

**Pattern Correto:**

```python
# ✅ SEGURO
@app.route('/api/document/<doc_id>')
@login_required  # Autenticação
@authorize('read', 'document')  # Autorização
def get_document(doc_id):
    # Verifica se ESTE usuário pode acessar ESTE documento
    if not user_can_access_document(current_user.id, doc_id):
        abort(403)

    doc = database.get(doc_id)
    return jsonify(doc)
```

---

## 👑 Privilégio e Propagação de Confiança

### Princípio do Menor Privilégio (Least Privilege)

**Definição:** Todo sujeito deve ter apenas as permissões **mínimas necessárias** para cumprir sua função

**Matemática:**

```
Seja F = função/tarefa do sujeito
Seja P_required = permissões necessárias para F
Seja P_granted = permissões concedidas

Princípio: P_granted = P_required (exato)
Violação: P_granted > P_required (excesso)
Inseguro: P_granted < P_required (insuficiente)
```

**Exemplo:**

```
Tarefa: Backup de dados
P_required: {read_database}
P_granted_wrong: {read_database, write_database, delete_database}  ❌ Excesso!
P_granted_correct: {read_database}  ✅ Mínimo necessário
```

### Privilege Escalation

**Vertical Escalation:**
```
Usuário comum → Consegue privilégios de admin

Exemplo:
  Normal user → Admin
  Employee → Manager
  Guest → Authenticated User
```

**Horizontal Escalation:**
```
Usuário A → Acessa recursos de usuário B (mesmo nível)

Exemplo:
  User alice → Acessa dados de user bob
  Customer 1 → Acessa pedidos de customer 2
```

**Causa Raiz:**

```
Insuficiente verificação de privilégio em pontos de decisão

Decision Points:
  - API endpoints
  - Function calls
  - Database queries
  - File access

Para CADA decision point:
  Verify: Current user has privilege to perform action on resource
```

---

**Última atualização**: 2024
**Versão**: 1.0 - Documento Teórico Fundamental
