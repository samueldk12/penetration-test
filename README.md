# Cloud API Key Vulnerability Scanner - Penetration Testing Framework

🔒 **Automated penetration testing framework for discovering and testing vulnerable cloud API keys**

## 🎯 Overview

This is a comprehensive penetration testing framework designed to:
- **Scan for exposed API keys** across AWS, Azure, GCP, and 20+ cloud services
- **Test API key validity** and permissions automatically
- **Discover web vulnerabilities** using integrated security scanners
- **Run automated pentest tools** (Nmap, Nikto, Nuclei, SQLmap, etc.)
- **Generate detailed reports** in HTML and JSON formats

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR AUTHORIZED SECURITY TESTING ONLY**

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors assume no liability for misuse of this tool
- Always comply with applicable laws and regulations
- Get written authorization before testing any system

## 🚀 Features

### 🔑 Cloud API Key Testing
- **AWS**: Tests access keys, enumerates S3, EC2, IAM, Lambda, RDS, DynamoDB, Secrets Manager, and more
- **Azure**: Tests service principals, enumerates subscriptions, resource groups, storage, VMs, Key Vaults
- **GCP**: Tests service accounts and API keys, enumerates Compute Engine, Cloud Storage, IAM, Cloud SQL, Secret Manager
- **Generic Services**: GitHub, GitLab, Slack, Heroku, DigitalOcean, Stripe, SendGrid, Telegram, Discord, NPM, Docker Hub, and 10+ more

### 🕷️ Web Vulnerability Scanning
- Security headers analysis
- XSS reflection detection
- SQL injection hints
- Open redirect vulnerabilities
- Sensitive information disclosure
- Exposed files detection (.env, .git, config files)
- Technology stack detection
- SSL/TLS configuration testing

### 🛠️ Integrated Pentest Tools
- **Nmap**: Network and port scanning
- **Nikto**: Web server vulnerability scanning
- **Nuclei**: Template-based vulnerability scanning
- **SQLmap**: SQL injection testing (requires authorization)
- **Gobuster/DIRB**: Directory brute forcing
- **WPScan**: WordPress security scanning
- **WhatWeb**: Web technology fingerprinting
- **Wafw00f**: WAF detection
- **testssl.sh/SSLyze**: SSL/TLS testing
- **Subfinder/Amass**: Subdomain enumeration

### 📊 Reporting
- **HTML Reports**: Beautiful, interactive HTML reports with charts and color-coded severity levels
- **JSON Reports**: Machine-readable JSON output for automation
- **Detailed Findings**: Comprehensive vulnerability descriptions with remediation guidance

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- (Optional) Kali Linux or similar for pre-installed pentest tools

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/penetration-test.git
cd penetration-test
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

Or use a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Install External Tools (Optional)
For full functionality, install these tools:

**On Kali Linux / Debian / Ubuntu:**
```bash
sudo apt update
sudo apt install -y nmap nikto sqlmap dirb gobuster wpscan whatweb \
  subfinder nuclei testssl.sh python3-pip
```

**On macOS (using Homebrew):**
```bash
brew install nmap nikto sqlmap dirb gobuster wpscan whatweb nuclei
```

**On other systems:**
Check each tool's documentation for installation instructions.

## 📖 Usage

### Basic Usage

#### 1. Scan a URL for Vulnerabilities
```bash
python3 main.py -t https://example.com
```

#### 2. Comprehensive Scan (All Tools)
```bash
python3 main.py -t https://example.com --comprehensive
```

#### 3. Scan Multiple URLs
```bash
python3 main.py -u urls.txt
```

#### 4. Scan for Exposed API Keys in Current Directory
```bash
python3 main.py --scan-keys
```

#### 5. Test Specific API Keys
```bash
python3 main.py -k api_keys.txt
```

### Advanced Usage

#### Scan with Custom Config
```bash
python3 main.py -t https://example.com -c config/custom_config.yaml
```

#### Specify Output File
```bash
python3 main.py -t https://example.com -o my_scan_results.json
```

#### Test Specific Cloud Providers
```bash
python3 main.py --scan-keys --providers aws azure
```

### Command-Line Options

```
usage: main.py [-h] [-t TARGET] [-u URLS_FILE] [-k KEYS_FILE]
               [-c CONFIG] [-o OUTPUT] [--comprehensive] [--scan-keys]
               [--providers {aws,azure,gcp,all}]

options:
  -h, --help            Show help message
  -t, --target          Target URL or domain to scan
  -u, --urls-file       File containing list of URLs to scan
  -k, --keys-file       File containing API keys to test
  -c, --config          Configuration file path (default: config/config.yaml)
  -o, --output          Output file for results
  --comprehensive       Run comprehensive scan (all modules)
  --scan-keys          Scan for exposed API keys in current directory
  --providers          Cloud providers to test (aws, azure, gcp, all)
```

## 📁 Project Structure

```
penetration-test/
├── main.py                      # Main entry point
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── .gitignore                   # Git ignore rules
│
├── config/                      # Configuration files
│   ├── __init__.py
│   ├── settings.py             # Settings manager
│   └── config.yaml             # Default configuration
│
├── modules/                     # Cloud provider testing modules
│   ├── __init__.py
│   ├── aws_tester.py           # AWS API key testing
│   ├── azure_tester.py         # Azure credential testing
│   ├── gcp_tester.py           # GCP service account testing
│   └── generic_cloud_tester.py # Generic cloud services (GitHub, Slack, etc.)
│
├── scanners/                    # Vulnerability scanners
│   ├── __init__.py
│   ├── url_scanner.py          # Web vulnerability scanner
│   └── api_key_scanner.py      # API key discovery scanner
│
├── tools/                       # Pentest tool integrations
│   ├── __init__.py
│   └── pentest_manager.py      # Manages external pentest tools
│
├── utils/                       # Utility modules
│   ├── __init__.py
│   ├── logger.py               # Logging utility
│   └── reporter.py             # Report generation
│
└── reports/                     # Generated reports (created automatically)
    ├── scan_results_*.json
    └── scan_results_*.html
```

## 🔧 Configuration

Edit `config/config.yaml` to customize:
- Logging level and output
- Tool enablement (enable/disable specific tools)
- Scanning depth and limits
- Rate limiting
- AWS regions to test
- Wordlist paths
- Excluded directories and files

Example configuration:
```yaml
log_level: INFO
report_dir: reports
max_threads: 5
timeout: 30

enable_nmap: true
enable_sqlmap: false  # Disabled by default
enable_nikto: true
enable_nuclei: true

test_aws_keys: true
test_azure_keys: true
test_gcp_keys: true
```

## 🎨 Example Output

### Terminal Output
```
2024-11-05 10:30:15 - INFO - Starting comprehensive scan on: https://example.com
2024-11-05 10:30:16 - INFO - Running URL scan for 1 targets
2024-11-05 10:30:16 - INFO - Scanning URL: https://example.com
2024-11-05 10:30:17 - INFO - Available tools: nmap, nikto, whatweb, nuclei
2024-11-05 10:30:17 - INFO - Running Nmap on example.com
2024-11-05 10:30:25 - INFO - Running Nikto on https://example.com
2024-11-05 10:30:45 - WARNING - VALID AWS KEY FOUND: AKIAIOSFODNN7EXAMPLE
2024-11-05 10:31:00 - INFO - Results saved to: scan_results_20241105_103100.json
2024-11-05 10:31:01 - INFO - HTML report generated: scan_results_20241105_103100.html

============================================================
SCAN COMPLETED
============================================================

Found 5 security issues
  [CRITICAL] Immediately revoke and rotate aws API key
  [HIGH] Key has access to 8 AWS services
  [MEDIUM] X-Frame-Options header missing
  [MEDIUM] Content-Security-Policy header missing
  [LOW] Server version disclosed
```

### HTML Report
The HTML report includes:
- Executive summary with severity breakdown
- Detailed vulnerability listings
- API key findings with permissions
- Security recommendations
- Pentest tool outputs
- Color-coded severity levels
- Interactive collapsible sections

## 🔐 Security Best Practices

### For Users of This Tool:
1. **Get authorization** before scanning any system
2. **Store scan results securely** - they may contain sensitive information
3. **Never commit API keys** or credentials to version control
4. **Use virtual environments** to isolate dependencies
5. **Keep the tool updated** with `git pull`

### For Defenders:
1. **Rotate exposed keys immediately**
2. **Enable MFA** on all cloud accounts
3. **Use least privilege** access policies
4. **Implement key rotation** policies
5. **Monitor for unusual API activity**
6. **Use secret management** tools (AWS Secrets Manager, Azure Key Vault, etc.)
7. **Scan your repositories** regularly for exposed secrets
8. **Never hardcode credentials** in source code

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Roadmap

- [ ] Add support for more cloud providers (Alibaba Cloud, Oracle Cloud)
- [ ] Implement passive reconnaissance mode
- [ ] Add machine learning for vulnerability prioritization
- [ ] Create Metasploit module integration
- [ ] Add support for authenticated scanning
- [ ] Implement distributed scanning across multiple hosts
- [ ] Add REST API for remote scanning
- [ ] Create web UI dashboard
- [ ] Add Slack/Discord notifications
- [ ] Implement CI/CD integration (GitHub Actions, GitLab CI)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OWASP for security testing methodologies
- The creators of all integrated tools (Nmap, Nikto, Nuclei, etc.)
- The infosec community for sharing knowledge
- Bug bounty hunters for inspiration

## ⚡ Quick Start Guide

### Scenario 1: Test if Your AWS Keys Are Exposed
```bash
# Scan your codebase
python3 main.py --scan-keys --providers aws

# Review the report
open reports/scan_results_*.html
```

### Scenario 2: Security Audit of Your Website
```bash
# Run comprehensive scan
python3 main.py -t https://yourwebsite.com --comprehensive

# Check the HTML report
open scan_results_*.html
```

### Scenario 3: Bug Bounty Hunting
```bash
# Create a file with target URLs
echo "https://target1.example.com" > targets.txt
echo "https://target2.example.com" >> targets.txt

# Scan all targets
python3 main.py -u targets.txt --comprehensive

# Review findings
cat scan_results_*.json
```

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError"
**Solution**: Install dependencies with `pip install -r requirements.txt`

### Issue: "Permission denied" when running tools
**Solution**: Run with sudo or install tools in user space

### Issue: "Tool not found"
**Solution**: The tool will skip unavailable tools. Install them or disable in config

### Issue: AWS/Azure/GCP SDK errors
**Solution**: Check that you have the latest SDK versions installed

## 📚 Additional Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [AWS Security Best Practices](https://aws.amazon.com/security/best-practices/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [Bug Bounty Guide](https://www.bugbountyhunter.com/)

---

⭐ **If you find this tool useful, please star the repository!** ⭐
