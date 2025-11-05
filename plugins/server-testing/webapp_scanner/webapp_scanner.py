#!/usr/bin/env python3
"""
Web Application Security Scanner Plugin
Comprehensive testing for web applications and servers
"""

import requests
import json
import sys
import urllib3
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Disable SSL warnings if check_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebAppScanner:
    def __init__(self, target, options=None):
        self.target = target if target.startswith('http') else f'http://{target}'
        self.options = options or {}
        self.threads = self.options.get('threads', 5)
        self.timeout = self.options.get('timeout', 10)
        self.verify_ssl = self.options.get('check_ssl', False)
        self.user_agent = self.options.get('user_agent', 'PenTest-Suite/1.0')

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})

        self.results = {
            'target': self.target,
            'vulnerabilities': [],
            'findings': [],
            'server_info': {},
            'technologies': []
        }

    def run(self):
        """Main scan execution"""
        print(f"[*] Starting web application scan: {self.target}")

        # Server Information
        self.gather_server_info()

        # Technology Detection
        self.detect_technologies()

        # Security Headers
        self.check_security_headers()

        # Common Vulnerabilities
        self.check_common_vulns()

        # Directory/File Discovery
        self.discover_endpoints()

        # HTTP Methods
        self.check_http_methods()

        # SSL/TLS Configuration
        if self.target.startswith('https'):
            self.check_ssl_config()

        return self.results

    def gather_server_info(self):
        """Gather basic server information"""
        print("[*] Gathering server information...")

        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )

            # Server header
            server = response.headers.get('Server', 'Unknown')
            self.results['server_info']['server'] = server

            # Powered by
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            self.results['server_info']['powered_by'] = powered_by

            # Status code
            self.results['server_info']['status_code'] = response.status_code

            # Content type
            self.results['server_info']['content_type'] = response.headers.get('Content-Type', 'Unknown')

            print(f"[+] Server: {server}")
            print(f"[+] Powered-By: {powered_by}")

        except Exception as e:
            self.results['findings'].append({
                'type': 'error',
                'message': f'Failed to connect: {str(e)}'
            })

    def detect_technologies(self):
        """Detect web technologies in use"""
        print("[*] Detecting technologies...")

        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            # Check headers for technology indicators
            headers_to_check = {
                'X-Powered-By': ['PHP', 'ASP.NET', 'Express', 'Django'],
                'Server': ['Apache', 'nginx', 'IIS', 'LiteSpeed'],
                'X-AspNet-Version': ['ASP.NET'],
                'X-AspNetMvc-Version': ['ASP.NET MVC']
            }

            for header, techs in headers_to_check.items():
                if header in response.headers:
                    for tech in techs:
                        if tech.lower() in response.headers[header].lower():
                            self.results['technologies'].append({
                                'name': tech,
                                'source': f'Header: {header}'
                            })

            # Check HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Meta generators
            meta_gen = soup.find('meta', attrs={'name': 'generator'})
            if meta_gen and meta_gen.get('content'):
                self.results['technologies'].append({
                    'name': meta_gen['content'],
                    'source': 'Meta generator tag'
                })

            # Common frameworks in HTML
            html_content = response.text
            framework_patterns = {
                'WordPress': r'wp-content|wp-includes',
                'Drupal': r'drupal\.js|sites/default',
                'Joomla': r'joomla',
                'Laravel': r'laravel_session',
                'React': r'react|__REACT',
                'Angular': r'ng-app|angular',
                'Vue.js': r'vue\.js|__vue__'
            }

            for framework, pattern in framework_patterns.items():
                if re.search(pattern, html_content, re.I):
                    self.results['technologies'].append({
                        'name': framework,
                        'source': 'HTML content analysis'
                    })

            print(f"[+] Detected {len(self.results['technologies'])} technologies")

        except Exception as e:
            pass

    def check_security_headers(self):
        """Check for missing or weak security headers"""
        print("[*] Checking security headers...")

        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            security_headers = {
                'Strict-Transport-Security': 'HSTS not set - site vulnerable to downgrade attacks',
                'X-Frame-Options': 'X-Frame-Options not set - clickjacking possible',
                'X-Content-Type-Options': 'X-Content-Type-Options not set - MIME sniffing possible',
                'Content-Security-Policy': 'CSP not set - XSS attacks easier',
                'X-XSS-Protection': 'X-XSS-Protection not set',
                'Referrer-Policy': 'Referrer-Policy not set - information leakage possible'
            }

            for header, message in security_headers.items():
                if header not in response.headers:
                    self.results['vulnerabilities'].append({
                        'type': 'missing_security_header',
                        'severity': 'low',
                        'header': header,
                        'description': message
                    })
                    print(f"[-] Missing: {header}")
                else:
                    print(f"[+] Found: {header}")

            # Check for information disclosure headers
            disclosure_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version',
                'X-AspNetMvc-Version', 'X-Runtime'
            ]

            for header in disclosure_headers:
                if header in response.headers:
                    self.results['findings'].append({
                        'type': 'information_disclosure',
                        'severity': 'info',
                        'header': header,
                        'value': response.headers[header],
                        'description': f'Server exposes {header} header'
                    })

        except Exception as e:
            pass

    def check_common_vulns(self):
        """Check for common vulnerabilities"""
        print("[*] Checking for common vulnerabilities...")

        # Directory Listing
        self.check_directory_listing()

        # Backup Files
        self.check_backup_files()

        # Default Files
        self.check_default_files()

        # SQL Injection (basic)
        self.check_sql_injection()

    def check_directory_listing(self):
        """Check for directory listing"""
        test_paths = [
            '/images/', '/img/', '/css/', '/js/',
            '/assets/', '/uploads/', '/files/'
        ]

        for path in test_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if response.status_code == 200:
                    # Check for directory listing indicators
                    if 'Index of' in response.text or '<title>Directory' in response.text:
                        self.results['vulnerabilities'].append({
                            'type': 'directory_listing',
                            'severity': 'medium',
                            'url': url,
                            'description': 'Directory listing enabled'
                        })
                        print(f"[!] Directory listing found: {url}")

            except:
                pass

    def check_backup_files(self):
        """Check for common backup files"""
        backup_files = [
            'backup.zip', 'backup.tar.gz', 'backup.sql',
            'database.sql', 'db.sql', 'dump.sql',
            'backup.bak', 'web.config.bak', '.git/config',
            '.env', '.env.backup', 'config.php.bak'
        ]

        for filename in backup_files:
            try:
                url = urljoin(self.target, filename)
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'type': 'exposed_backup',
                        'severity': 'high',
                        'url': url,
                        'description': f'Backup file accessible: {filename}'
                    })
                    print(f"[!] Backup file found: {url}")

            except:
                pass

    def check_default_files(self):
        """Check for default/common files"""
        default_files = [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'phpinfo.php', 'info.php', 'test.php',
            'readme.html', 'license.txt', 'changelog.txt'
        ]

        for filename in default_files:
            try:
                url = urljoin(self.target, filename)
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )

                if response.status_code == 200:
                    self.results['findings'].append({
                        'type': 'default_file',
                        'severity': 'info',
                        'url': url,
                        'description': f'Default file found: {filename}'
                    })

            except:
                pass

    def check_sql_injection(self):
        """Basic SQL injection test"""
        sql_payloads = ["'", "1' OR '1'='1", "admin'--", "' OR 1=1--"]

        try:
            # Get a page to test
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if forms:
                print(f"[*] Testing {len(forms)} forms for SQL injection...")

                for form in forms[:3]:  # Test first 3 forms
                    action = form.get('action', '')
                    method = form.get('method', 'get').lower()

                    inputs = form.find_all('input')
                    for inp in inputs:
                        name = inp.get('name')
                        if name:
                            for payload in sql_payloads[:2]:  # Test 2 payloads
                                try:
                                    url = urljoin(self.target, action)
                                    data = {name: payload}

                                    if method == 'post':
                                        test_response = self.session.post(
                                            url, data=data,
                                            timeout=5,
                                            verify=self.verify_ssl
                                        )
                                    else:
                                        test_response = self.session.get(
                                            url, params=data,
                                            timeout=5,
                                            verify=self.verify_ssl
                                        )

                                    # Check for SQL error messages
                                    sql_errors = [
                                        'sql syntax', 'mysql_fetch', 'mysqli',
                                        'ORA-', 'PostgreSQL', 'SQLite',
                                        'Unclosed quotation', 'syntax error'
                                    ]

                                    for error in sql_errors:
                                        if error.lower() in test_response.text.lower():
                                            self.results['vulnerabilities'].append({
                                                'type': 'sql_injection',
                                                'severity': 'critical',
                                                'url': url,
                                                'parameter': name,
                                                'payload': payload,
                                                'description': 'Potential SQL injection vulnerability'
                                            })
                                            print(f"[!] Potential SQLi found: {url}?{name}={payload}")
                                            break

                                except:
                                    pass

        except Exception as e:
            pass

    def discover_endpoints(self):
        """Discover common endpoints"""
        print("[*] Discovering common endpoints...")

        common_paths = [
            '/admin', '/admin/', '/administrator', '/login',
            '/wp-admin', '/phpmyadmin', '/admin.php',
            '/api', '/api/v1', '/api/v2',
            '/uploads', '/upload', '/files',
            '/backup', '/temp', '/test'
        ]

        found = 0
        for path in common_paths:
            try:
                url = urljoin(self.target, path)
                response = self.session.get(
                    url,
                    timeout=5,
                    verify=self.verify_ssl,
                    allow_redirects=False
                )

                if response.status_code in [200, 301, 302, 401, 403]:
                    self.results['findings'].append({
                        'type': 'endpoint_discovery',
                        'url': url,
                        'status_code': response.status_code
                    })
                    found += 1

            except:
                pass

        print(f"[+] Found {found} endpoints")

    def check_http_methods(self):
        """Check allowed HTTP methods"""
        print("[*] Checking HTTP methods...")

        try:
            response = self.session.options(
                self.target,
                timeout=self.timeout,
                verify=self.verify_ssl
            )

            allowed = response.headers.get('Allow', '')
            if allowed:
                methods = [m.strip() for m in allowed.split(',')]

                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in methods if m in dangerous_methods]

                if found_dangerous:
                    self.results['vulnerabilities'].append({
                        'type': 'dangerous_http_methods',
                        'severity': 'medium',
                        'methods': found_dangerous,
                        'description': f'Dangerous HTTP methods enabled: {", ".join(found_dangerous)}'
                    })
                    print(f"[!] Dangerous methods: {', '.join(found_dangerous)}")

        except:
            pass

    def check_ssl_config(self):
        """Check SSL/TLS configuration"""
        print("[*] Checking SSL/TLS configuration...")

        try:
            import ssl
            import socket

            hostname = urlparse(self.target).hostname
            port = urlparse(self.target).port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()

                    self.results['findings'].append({
                        'type': 'ssl_info',
                        'protocol': protocol,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject'])
                    })

                    # Check for weak protocols
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.results['vulnerabilities'].append({
                            'type': 'weak_ssl_protocol',
                            'severity': 'high',
                            'protocol': protocol,
                            'description': f'Weak SSL/TLS protocol in use: {protocol}'
                        })

        except Exception as e:
            pass


def main(target, options=None):
    """Plugin entry point"""
    scanner = WebAppScanner(target, options)
    results = scanner.run()

    # Print summary
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Findings: {len(results['findings'])}")
    print(f"Technologies: {len(results['technologies'])}")

    # Print critical/high severity vulns
    critical = [v for v in results['vulnerabilities'] if v.get('severity') in ['critical', 'high']]
    if critical:
        print(f"\nCritical/High Severity Issues: {len(critical)}")
        for vuln in critical:
            print(f"  - {vuln['type']}: {vuln.get('description', 'N/A')}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2))
