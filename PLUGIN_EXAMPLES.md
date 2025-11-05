# Plugin Usage Examples

Practical examples for using security testing plugins.

## 🎯 Quick Start

### Test a Single Plugin

```bash
# Test web application scanner
cd plugins/server-testing/webapp_scanner
python3 webapp_scanner.py https://example.com

# Test API exploiter
cd plugins/api-testing/api_exploiter
python3 api_exploiter.py https://api.example.com
```

---

## 📋 Real-World Scenarios

### Scenario 1: E-commerce Security Audit

**Objective:** Test an e-commerce website for common vulnerabilities

```bash
# 1. Web application scan
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    https://shop.example.com

# 2. API testing (checkout API)
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://shop.example.com/api/v1 \
    YOUR_JWT_TOKEN

# 3. Nuclei comprehensive scan
python3 plugins/server-testing/nuclei_integration/nuclei_integration.py \
    https://shop.example.com
```

**Expected Findings:**
- Missing security headers
- Exposed API endpoints
- BOLA vulnerabilities in order endpoints
- Weak JWT implementation

---

### Scenario 2: SaaS Application Testing

**Objective:** Security assessment of a SaaS platform

```bash
# 1. Discover API endpoints
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://app.saas-platform.com

# 2. Test authentication
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://api.saas-platform.com \
    --options '{"test_jwt": true, "test_rate_limit": true}'

# 3. Server configuration check
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    https://app.saas-platform.com \
    --options '{"check_ssl": true, "timeout": 20}'
```

---

### Scenario 3: GraphQL API Assessment

**Objective:** Test GraphQL API security

```bash
# Run API exploiter with GraphQL options
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://api.example.com/graphql

# Check for:
# - Introspection enabled
# - Batch query support
# - Query depth limits
# - BOLA in nested queries
```

**Example Output:**
```json
{
  "vulnerabilities": [
    {
      "type": "graphql_introspection_enabled",
      "severity": "medium",
      "description": "GraphQL introspection is enabled"
    },
    {
      "type": "graphql_batching_enabled",
      "description": "Batch queries supported - rate limit bypass possible"
    }
  ]
}
```

---

### Scenario 4: Bug Bounty Recon

**Objective:** Initial reconnaissance for bug bounty

```bash
#!/bin/bash
# bug_bounty_scan.sh

TARGET="example.com"
OUTPUT_DIR="bounty_results/$TARGET"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting bug bounty reconnaissance for $TARGET"

# 1. Web app scan
echo "[*] Running web application scan..."
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    "https://$TARGET" > "$OUTPUT_DIR/webapp_scan.json"

# 2. API discovery and testing
echo "[*] Testing API security..."
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    "https://api.$TARGET" > "$OUTPUT_DIR/api_scan.json"

# 3. Nuclei scan (high/critical only)
echo "[*] Running Nuclei scan..."
python3 plugins/server-testing/nuclei_integration/nuclei_integration.py \
    "https://$TARGET" \
    --options '{"severity": "critical,high"}' > "$OUTPUT_DIR/nuclei_scan.json"

echo "[*] Scans complete! Results in $OUTPUT_DIR/"

# Extract critical findings
echo "[*] Critical findings:"
cat "$OUTPUT_DIR"/*.json | jq -r '.vulnerabilities[] | select(.severity == "critical" or .severity == "high") | "\(.type): \(.description)"'
```

---

### Scenario 5: CI/CD Integration

**Objective:** Automated security testing in pipeline

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install Dependencies
        run: |
          pip install requests beautifulsoup4 PyJWT

      - name: Run WebApp Scanner
        run: |
          python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
            ${{ secrets.STAGING_URL }} \
            > results/webapp_scan.json

      - name: Run API Exploiter
        run: |
          python3 plugins/api-testing/api_exploiter/api_exploiter.py \
            ${{ secrets.API_URL }} \
            > results/api_scan.json

      - name: Check for Critical Issues
        run: |
          CRITICAL=$(cat results/*.json | jq -r '.vulnerabilities[] | select(.severity == "critical")' | wc -l)
          if [ $CRITICAL -gt 0 ]; then
            echo "❌ Found $CRITICAL critical vulnerabilities!"
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: results/
```

---

## 🔧 Advanced Usage

### Custom Options

```bash
# WebApp Scanner with custom options
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    https://example.com \
    --options '{
        "threads": 10,
        "timeout": 15,
        "check_ssl": true,
        "user_agent": "Custom-Scanner/1.0"
    }'

# API Exploiter with full options
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://api.example.com \
    --options '{
        "api_type": "rest",
        "auth_token": "eyJhbGc...",
        "test_bola": true,
        "test_jwt": true,
        "test_rate_limit": true,
        "id_range": "1-1000"
    }'
```

### Chaining Plugins

```bash
#!/bin/bash
# comprehensive_scan.sh

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Run all plugins sequentially
for plugin in plugins/*/*.py; do
    echo "[*] Running $plugin..."
    python3 "$plugin" "$TARGET" 2>/dev/null | \
        jq -r '.vulnerabilities[] | select(.severity == "critical" or .severity == "high")'
done
```

### Parallel Execution

```bash
#!/bin/bash
# parallel_scan.sh

TARGET=$1

# Run plugins in parallel
(python3 plugins/server-testing/webapp_scanner/webapp_scanner.py "$TARGET" > webapp.json) &
(python3 plugins/api-testing/api_exploiter/api_exploiter.py "$TARGET" > api.json) &
(python3 plugins/server-testing/nuclei_integration/nuclei_integration.py "$TARGET" > nuclei.json) &

# Wait for all to complete
wait

echo "[*] All scans complete!"

# Combine results
jq -s 'add' webapp.json api.json nuclei.json > combined_results.json
```

---

## 📊 Interpreting Results

### WebApp Scanner Output

```json
{
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "critical",
      "url": "https://example.com/search",
      "parameter": "q",
      "payload": "' OR '1'='1",
      "description": "Potential SQL injection vulnerability"
    }
  ],
  "server_info": {
    "server": "Apache/2.4.41",
    "powered_by": "PHP/7.4.3"
  },
  "technologies": [
    {"name": "WordPress", "source": "HTML content analysis"}
  ]
}
```

### API Exploiter Output

```json
{
  "target": "https://api.example.com",
  "vulnerabilities": [
    {
      "type": "jwt_weak_secret",
      "severity": "critical",
      "secret": "secret123",
      "description": "JWT uses weak secret: secret123"
    },
    {
      "type": "bola_idor",
      "severity": "high",
      "endpoint": "/api/users/{id}",
      "accessible_count": 47,
      "description": "BOLA/IDOR vulnerability - 47 IDs accessible"
    }
  ]
}
```

---

## 🎓 Best Practices

### 1. Always Start with Discovery

```bash
# First, understand the target
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py \
    https://target.com \
    --options '{"threads": 1}'  # Gentle scan

# Then, focused testing based on findings
```

### 2. Use Appropriate Rate Limiting

```bash
# For production systems
--options '{"threads": 3, "rate_limit": 50}'

# For testing environments
--options '{"threads": 10, "rate_limit": 200}'
```

### 3. Document Findings

```bash
# Save results with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://api.example.com \
    > results/api_scan_$TIMESTAMP.json
```

### 4. Verify Critical Findings Manually

Don't rely solely on automated tools - manually verify critical findings!

---

## ⚠️ Important Notes

1. **Authorization Required:** Always get written permission before testing
2. **Rate Limiting:** Respect rate limits to avoid DoS
3. **Data Handling:** Don't exfiltrate real data during testing
4. **Responsible Disclosure:** Report findings responsibly
5. **Legal Compliance:** Follow all applicable laws and regulations

---

## 🆘 Troubleshooting

### Plugin Not Found

```bash
# Check plugin exists
ls -la plugins/server-testing/webapp_scanner/

# Verify permissions
chmod +x plugins/server-testing/webapp_scanner/webapp_scanner.py
```

### Dependency Issues

```bash
# Install missing dependencies
pip install requests beautifulsoup4 PyJWT urllib3

# Or from requirements.txt
pip install -r requirements.txt
```

### Timeout Errors

```bash
# Increase timeout
--options '{"timeout": 30}'

# Reduce threads
--options '{"threads": 2}'
```

---

## 📚 Additional Resources

- [Plugin Development Guide](plugins/README.md)
- [API Exploitation Guide](docs/api-exploitation.html)
- [Security Best Practices](docs/best-practices.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
