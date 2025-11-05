# 🔒 Advanced Penetration Testing Scanner v2.0

Professional automated security testing tool for bug bounty programs and authorized penetration testing engagements.

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing only**. Only use this tool on systems you have explicit permission to test. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse or damage caused by this tool.

## ✨ Features

### Comprehensive Vulnerability Detection
- **Cross-Site Scripting (XSS)** - Reflected, Stored, and DOM-based
- **SQL Injection** - Error-based, Union-based, Boolean-based, and Time-based blind
- **Command Injection** - OS command execution and blind command injection
- **Server-Side Request Forgery (SSRF)** - Internal network access and cloud metadata exploitation
- **XML External Entity (XXE)** - File disclosure and SSRF via XML
- **Path Traversal** - Directory traversal and file inclusion
- **LDAP Injection** - Authentication bypass and data extraction
- **NoSQL Injection** - MongoDB and other NoSQL database attacks
- **Open Redirect** - URL redirection vulnerabilities
- **CRLF Injection** - HTTP response splitting and header injection
- **Server-Side Template Injection (SSTI)** - Template engine exploitation
- **Insecure Direct Object Reference (IDOR)** - Broken access control
- **Insecure Deserialization** - Object injection attacks
- **CORS Misconfiguration** - Cross-origin resource sharing issues
- **Clickjacking** - UI redressing vulnerabilities

### Advanced Reconnaissance
- **Subdomain Enumeration** - DNS brute-force and certificate transparency logs
- **DNS Record Collection** - A, AAAA, MX, NS, TXT, CNAME, SOA records
- **Port Scanning** - Common port detection with service identification
- **Technology Detection** - Web frameworks, CMS, and technology stack fingerprinting
- **Security Headers Analysis** - HSTS, CSP, X-Frame-Options, etc.
- **SSL/TLS Information** - Certificate details and cipher analysis
- **Endpoint Discovery** - API endpoints, admin panels, and hidden paths
- **JavaScript File Enumeration** - JS file discovery and analysis
- **Form Detection** - HTML form discovery and parameter extraction
- **Comment Extraction** - HTML and JavaScript comment harvesting
- **API Endpoint Discovery** - REST, GraphQL, and Swagger documentation
- **Email Harvesting** - Email address extraction

### Professional Reporting
- **Bug Bounty Ready** - Reports formatted for bug bounty submissions
- **Multiple Formats** - HTML, TXT, and JSON reports
- **CVSS Scoring** - Industry-standard vulnerability severity ratings
- **CWE Classification** - Common Weakness Enumeration mappings
- **Detailed PoC** - Proof of Concept with request/response evidence
- **Color-Coded Output** - Easy-to-read console output with severity indicators

### Extensive Payload Database
- **500+ Payloads** - Comprehensive payload collection for all vulnerability types
- **Bypass Techniques** - Filter evasion and WAF bypass payloads
- **Encoding Variants** - URL, HTML, Unicode, and Base64 encoded payloads
- **Polyglot Payloads** - Multi-context exploitation vectors

## 📋 Requirements

- Python 3.7+
- Internet connection for reconnaissance modules
- Authorized target for testing

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/penetration-test.git
cd penetration-test
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Make Executable (Optional)
```bash
chmod +x pentest_scanner.py
```

## 📖 Usage

### Basic Scan
```bash
python pentest_scanner.py -t https://example.com
```

### Reconnaissance Only
```bash
python pentest_scanner.py -t https://example.com -m recon
```

### Vulnerability Scan Only
```bash
python pentest_scanner.py -t https://example.com -m scan
```

### Full Scan with Custom Output
```bash
python pentest_scanner.py -t https://example.com -m full -o my_report
```

### Advanced Options
```bash
python pentest_scanner.py -t https://example.com \
    --threads 20 \
    --timeout 15 \
    --proxy http://127.0.0.1:8080 \
    --skip-ssl \
    -v
```

## 🎯 Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--target` | `-t` | Target URL or domain (required) | - |
| `--mode` | `-m` | Scan mode: recon, scan, or full | full |
| `--output` | `-o` | Output report filename | pentest_report |
| `--verbose` | `-v` | Verbose output | False |
| `--threads` | - | Number of concurrent threads | 10 |
| `--timeout` | - | Request timeout in seconds | 10 |
| `--proxy` | - | Proxy URL (e.g., http://127.0.0.1:8080) | None |
| `--skip-ssl` | - | Skip SSL certificate verification | False |

## 📊 Output Files

After scanning, the tool generates three types of reports:

1. **HTML Report** (`<output>.html`) - Professional, color-coded report suitable for bug bounty submissions
2. **Text Report** (`<output>.txt`) - Detailed text-based report with all findings
3. **JSON Report** (`findings_<timestamp>.json`) - Machine-readable format for integration

## 🎨 Report Features

### HTML Report Includes:
- Executive summary with severity breakdown
- Color-coded vulnerability cards (Critical, High, Medium, Low, Info)
- Detailed vulnerability descriptions
- CVSS scores and CWE classifications
- Proof of Concept with payloads
- HTTP request/response evidence
- Remediation recommendations
- Professional styling suitable for presentations

## 🔍 Vulnerability Detection Examples

### XSS Detection
```bash
# The scanner tests 30+ XSS payloads per parameter including:
- Basic: <script>alert('XSS')</script>
- Event handlers: <img src=x onerror=alert('XSS')>
- Encoded: %3Cscript%3Ealert('XSS')%3C/script%3E
- Polyglot: Complex multi-context payloads
```

### SQL Injection Detection
```bash
# Tests 25+ SQLi payloads including:
- Error-based: ' OR '1'='1
- Union-based: ' UNION SELECT NULL--
- Time-based: ' AND SLEEP(5)--
- Boolean-based: ' AND 1=1--
```

### Command Injection Detection
```bash
# Tests 20+ command injection payloads:
- Basic: ; ls
- Piped: | whoami
- Blind: ; sleep 5
- Windows: & dir
```

## 🛡️ Security Best Practices

1. **Always obtain written authorization** before testing any target
2. **Use a proxy** (e.g., Burp Suite) to review all requests
3. **Respect rate limits** to avoid overwhelming target systems
4. **Test in staging environments** when possible
5. **Follow responsible disclosure** for any vulnerabilities found
6. **Keep logs** of all testing activities
7. **Use VPN** to protect your identity during authorized testing

## 🔧 Integration with Bug Bounty Tools

### Using with Burp Suite
```bash
python pentest_scanner.py -t https://example.com --proxy http://127.0.0.1:8080
```

### Using with OWASP ZAP
```bash
python pentest_scanner.py -t https://example.com --proxy http://127.0.0.1:8081
```

## 📚 Reconnaissance Modules

### Subdomain Enumeration
- DNS brute-force with 100+ common subdomains
- Certificate Transparency log queries (crt.sh)
- Discovers dev, staging, admin, and API subdomains

### Port Scanning
- Scans 40+ common ports
- Service identification
- Banner grabbing for version detection

### Technology Detection
- WordPress, Joomla, Drupal
- Django, Flask, Laravel
- React, Angular, Vue.js
- PHP, ASP.NET, Node.js
- And many more...

## 🎓 Educational Use

This tool is designed for:
- **Security training** and education
- **CTF competitions** and challenges
- **Bug bounty programs** (with proper authorization)
- **Professional penetration testing** engagements
- **Security research** and vulnerability analysis
- **Academic research** in cybersecurity

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests with:
- New vulnerability detection modules
- Additional payload variations
- Improved reconnaissance techniques
- Bug fixes and optimizations
- Documentation improvements

## 📝 Changelog

### Version 2.0 (Current)
- ✅ Added 15 vulnerability scanning modules
- ✅ Implemented comprehensive reconnaissance suite
- ✅ Created professional bug bounty logging system
- ✅ Added 500+ payloads across all vulnerability types
- ✅ Implemented HTML/TXT/JSON report generation
- ✅ Added CVSS scoring and CWE classification
- ✅ Multi-threaded scanning for performance
- ✅ Proxy support for integration with security tools
- ✅ Color-coded terminal output

## 🔗 Resources

### Bug Bounty Platforms
- [HackerOne](https://www.hackerone.com/)
- [Bugcrowd](https://www.bugcrowd.com/)
- [Intigriti](https://www.intigriti.com/)
- [YesWeHack](https://www.yeswehack.com/)
- [Synack](https://www.synack.com/)

### Security References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## 📧 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Submit a pull request
- Contact the maintainers

## ⚖️ License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- OWASP for security testing methodology
- Bug bounty community for payload inspiration
- Security researchers worldwide for their contributions

---

**Remember: With great power comes great responsibility. Always test ethically and legally.**

Made with ❤️ for the security community