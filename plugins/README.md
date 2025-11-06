# Security Testing Plugins

Professional plugins for comprehensive security testing of web applications, servers, and APIs.

## 📦 Plugin Categories

### 1. Server Testing
- **webapp_scanner** - Comprehensive web application scanner (proprietary)
- **nuclei_integration** - Nuclei vulnerability scanner integration (third-party)

### 2. API Testing
- **api_exploiter** - Complete API security testing (proprietary)

---

## 🔧 Proprietary Plugins

### WebApp Scanner

Comprehensive web application and server security scanner.

**Features:**
✅ Server information gathering
✅ Technology stack detection
✅ Security headers analysis
✅ Common vulnerability checks
✅ SQL injection testing
✅ Directory/file discovery
✅ HTTP methods testing
✅ SSL/TLS configuration check

**Usage:**
```bash
# Via main tool
python3 penetration-test.py scan example.com --plugin webapp_scanner

# Direct usage
python3 plugins/server-testing/webapp_scanner/webapp_scanner.py https://example.com

# With options
python3 penetration-test.py scan example.com \
    --plugin webapp_scanner \
    --options '{"threads": 10, "timeout": 15, "check_ssl": true}'
```

**Options:**
```json
{
  "threads": 5,           # Concurrent threads
  "timeout": 10,          # Request timeout (seconds)
  "check_ssl": false,     # Verify SSL certificates
  "user_agent": "PenTest-Suite/1.0"  # Custom User-Agent
}
```

**Output:**
```json
{
  "target": "https://example.com",
  "vulnerabilities": [
    {
      "type": "missing_security_header",
      "severity": "low",
      "header": "X-Frame-Options",
      "description": "X-Frame-Options not set - clickjacking possible"
    },
    {
      "type": "directory_listing",
      "severity": "medium",
      "url": "https://example.com/uploads/",
      "description": "Directory listing enabled"
    }
  ],
  "findings": [...],
  "server_info": {
    "server": "nginx/1.18.0",
    "powered_by": "PHP/7.4.3"
  },
  "technologies": [...]
}
```

---

### API Exploiter

Complete API security testing and exploitation plugin.

**Features:**
✅ REST, GraphQL, SOAP API support
✅ API endpoint discovery
✅ JWT security testing (none algorithm, weak secrets)
✅ BOLA/IDOR vulnerability testing
✅ Rate limiting testing
✅ GraphQL introspection & batching
✅ Authentication testing
✅ HTTP methods testing

**Usage:**
```bash
# Basic API test
python3 penetration-test.py scan https://api.example.com \
    --plugin api_exploiter

# With authentication
python3 penetration-test.py scan https://api.example.com \
    --plugin api_exploiter \
    --options '{"auth_token": "eyJhbGc...", "api_type": "rest"}'

# GraphQL testing
python3 penetration-test.py scan https://api.example.com/graphql \
    --plugin api_exploiter \
    --options '{"api_type": "graphql", "test_bola": true}'

# Direct usage
python3 plugins/api-testing/api_exploiter/api_exploiter.py \
    https://api.example.com YOUR_JWT_TOKEN
```

**Options:**
```json
{
  "api_type": "rest",           # rest, graphql, soap
  "auth_token": "",             # Bearer token
  "test_bola": true,            # Test BOLA/IDOR
  "test_jwt": true,             # Test JWT security
  "test_rate_limit": true,      # Test rate limiting
  "id_range": "1-100"          # ID range for BOLA testing
}
```

**Example Output:**
```json
{
  "vulnerabilities": [
    {
      "type": "jwt_none_algorithm",
      "severity": "critical",
      "description": "Server accepts JWT with 'none' algorithm"
    },
    {
      "type": "bola_idor",
      "severity": "high",
      "endpoint": "/api/users/{id}",
      "accessible_count": 15,
      "description": "BOLA/IDOR vulnerability - 15 IDs accessible"
    },
    {
      "type": "no_rate_limiting",
      "severity": "medium",
      "requests_made": 50,
      "description": "No rate limiting detected"
    }
  ]
}
```

---

## 🔗 Third-Party Tool Integration

### Nuclei Integration

Integrate with Projectdiscovery's Nuclei scanner for comprehensive vulnerability scanning.

**Installation:**
```bash
# Install Nuclei (if not already installed)
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or the plugin will attempt to install automatically
```

**Usage:**
```bash
# Basic scan
python3 penetration-test.py scan example.com --plugin nuclei_integration

# Custom severity
python3 penetration-test.py scan example.com \
    --plugin nuclei_integration \
    --options '{"severity": "critical,high"}'

# With custom templates
python3 penetration-test.py scan example.com \
    --plugin nuclei_integration \
    --options '{"templates": "/path/to/custom/templates"}'

# High rate limit
python3 penetration-test.py scan example.com \
    --plugin nuclei_integration \
    --options '{"rate_limit": 300, "update": true}'
```

**Options:**
```json
{
  "severity": "critical,high,medium",  # Severity levels
  "templates": "",                      # Custom templates path
  "rate_limit": 150,                    # Max requests/second
  "update": true                        # Update templates before scan
}
```

**Features:**
- 1000+ vulnerability templates
- CVE detection
- Misconfiguration checks
- Exposed panel detection
- Technology-specific tests

---

## 📝 Creating Custom Plugins

### Plugin Structure

```
plugins/
└── category/
    └── plugin_name/
        ├── plugin.json          # Plugin metadata
        ├── plugin_name.py       # Main code (Python)
        ├── plugin_name.js       # Main code (JavaScript)
        ├── plugin_name.go       # Main code (Go)
        └── README.md           # Documentation (optional)
```

### plugin.json Schema

```json
{
  "name": "my_plugin",
  "version": "1.0.0",
  "description": "Plugin description",
  "type": "python",                    # python, javascript, go
  "category": "server_testing",        # server_testing, api_testing, recon, etc.
  "author": "Your Name",
  "entrypoint": "my_plugin.py",
  "dependencies": ["requests"],        # Python packages
  "external_tools": ["tool"],          # External tools required
  "options": {
    "option_name": {
      "type": "string",                # string, integer, boolean
      "default": "value",
      "description": "Option description"
    }
  }
}
```

### Python Plugin Template

```python
#!/usr/bin/env python3
"""
My Custom Plugin
Description of what it does
"""

import sys
import json

class MyPlugin:
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

        self.results = {
            'target': self.target,
            'vulnerabilities': [],
            'findings': []
        }

    def run(self):
        """Main plugin logic"""
        print(f"[*] Running my plugin on {self.target}")

        # Your testing logic here
        self.test_something()

        return self.results

    def test_something(self):
        """Test for something"""
        # Test logic
        pass


def main(target, options=None):
    """Plugin entry point"""
    plugin = MyPlugin(target, options)
    results = plugin.run()

    # Print summary
    print(f"\nVulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Findings: {len(results['findings'])}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)

    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2))
```

---

## 🎯 Usage Examples

### Scenario 1: Full Web Application Test

```bash
# Run all server testing plugins
python3 penetration-test.py scan https://example.com \
    --category server_testing \
    --output results/webapp-scan

# Or specific plugins
python3 penetration-test.py scan https://example.com \
    --plugins webapp_scanner,nuclei_integration \
    --output results/webapp-scan
```

### Scenario 2: API Security Assessment

```bash
# Complete API testing
python3 penetration-test.py scan https://api.example.com \
    --plugin api_exploiter \
    --options '{"auth_token": "YOUR_TOKEN", "api_type": "rest", "id_range": "1-1000"}' \
    --output results/api-scan

# Generate report
python3 penetration-test.py report \
    --scan results/api-scan \
    --format html,json \
    --severity critical,high
```

### Scenario 3: GraphQL API Testing

```bash
# GraphQL specific tests
python3 penetration-test.py scan https://api.example.com/graphql \
    --plugin api_exploiter \
    --options '{
        "api_type": "graphql",
        "auth_token": "YOUR_TOKEN",
        "test_bola": true,
        "test_jwt": true
    }'
```

### Scenario 4: Combined Testing

```bash
# Run multiple plugins in parallel
python3 penetration-test.py scan https://example.com \
    --plugins webapp_scanner,nuclei_integration,api_exploiter \
    --threads 3 \
    --output results/full-scan

# With notification
python3 penetration-test.py scan https://example.com \
    --plugins webapp_scanner,nuclei_integration \
    --notify telegram \
    --severity critical,high
```

---

## 🔄 Plugin Management

### List Available Plugins

```bash
python3 penetration-test.py plugin list

# Filter by category
python3 penetration-test.py plugin list --category server_testing
```

### Install Plugin from GitHub

```bash
python3 penetration-test.py plugin install https://github.com/user/plugin-repo
```

### Update Plugins

```bash
# Update all
python3 penetration-test.py plugin update --all

# Update specific
python3 penetration-test.py plugin update api_exploiter
```

### Remove Plugin

```bash
python3 penetration-test.py plugin remove old_plugin
```

---

## 📊 Understanding Results

### Vulnerability Severity Levels

| Severity | CVSS Score | Description |
|----------|------------|-------------|
| **Critical** | 9.0 - 10.0 | Immediate action required |
| **High** | 7.0 - 8.9 | Fix as soon as possible |
| **Medium** | 4.0 - 6.9 | Plan to fix soon |
| **Low** | 0.1 - 3.9 | Minimal risk |
| **Info** | 0.0 | Information only |

### Common Vulnerability Types

- **BOLA/IDOR** - Broken Object Level Authorization
- **SQL Injection** - Database injection attacks
- **XSS** - Cross-Site Scripting
- **Directory Listing** - Exposed directories
- **Information Disclosure** - Sensitive data exposed
- **Missing Security Headers** - Security headers not set
- **Weak JWT** - JWT implementation flaws

---

## ⚠️ Legal & Ethical Use

**WARNING:** Only test systems you own or have explicit permission to test!

✅ **Legal:**
- Your own applications
- Authorized penetration tests
- Bug bounty programs (within scope)
- Security research with permission

❌ **Illegal:**
- Unauthorized testing
- Testing without permission
- Malicious use

---

## 🤝 Contributing Plugins

Want to contribute a plugin?

1. Follow the plugin structure above
2. Include comprehensive documentation
3. Add tests
4. Submit pull request

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

---

## 📚 Resources

### Documentation
- [Plugin Development Guide](../docs/plugin-development.md)
- [API Documentation](../docs/api-documentation.md)

### Tools
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Burp Suite](https://portswigger.net/burp)

### Learning
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security](https://owasp.org/API-Security/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
