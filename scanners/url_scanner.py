#!/usr/bin/env python3
"""
URL Vulnerability Scanner
Comprehensive web application vulnerability scanner
"""

import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from utils.logger import get_logger


class URLScanner:
    """Scan URLs for various web vulnerabilities"""

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def scan(self, url):
        """Perform comprehensive URL scan"""
        self.logger.info(f"Starting vulnerability scan for: {url}")

        result = {
            'url': url,
            'vulnerabilities': [],
            'ssl_issues': [],
            'headers': {},
            'forms': [],
            'endpoints': [],
            'sensitive_info': [],
            'technologies': []
        }

        try:
            # Basic request
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)

            # SSL/TLS checks
            result['ssl_issues'] = self._check_ssl_issues(url)

            # Security headers
            result['vulnerabilities'].extend(self._check_security_headers(response.headers))

            # Technology detection
            result['technologies'] = self._detect_technologies(response)

            # Parse HTML if present
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')

                # Find forms
                result['forms'] = self._extract_forms(soup, url)

                # Find endpoints
                result['endpoints'] = self._extract_endpoints(soup, url)

                # Check for sensitive information
                result['sensitive_info'] = self._find_sensitive_info(response.text)

                # Check for common vulnerabilities
                result['vulnerabilities'].extend(self._check_xss_reflection(url, soup))
                result['vulnerabilities'].extend(self._check_sql_injection_hints(response.text))
                result['vulnerabilities'].extend(self._check_open_redirect(url))

            # Check for common files
            result['exposed_files'] = self._check_exposed_files(url)

            # Rate vulnerabilities
            result['risk_summary'] = self._calculate_risk_summary(result)

        except requests.exceptions.SSLError:
            result['ssl_issues'].append({
                'type': 'SSL_ERROR',
                'severity': 'HIGH',
                'description': 'SSL certificate validation failed'
            })
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection failed'
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Error scanning URL: {str(e)}")

        return result

    def _check_ssl_issues(self, url):
        """Check for SSL/TLS issues"""
        issues = []

        if url.startswith('http://'):
            issues.append({
                'type': 'NO_SSL',
                'severity': 'MEDIUM',
                'description': 'Website not using HTTPS',
                'fix': 'Implement HTTPS with valid SSL certificate'
            })

        return issues

    def _check_security_headers(self, headers):
        """Check for missing security headers"""
        vulnerabilities = []

        security_headers = {
            'Strict-Transport-Security': {
                'severity': 'MEDIUM',
                'description': 'HSTS header missing',
                'fix': 'Add Strict-Transport-Security header'
            },
            'X-Frame-Options': {
                'severity': 'MEDIUM',
                'description': 'X-Frame-Options header missing - vulnerable to clickjacking',
                'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'severity': 'LOW',
                'description': 'X-Content-Type-Options header missing',
                'fix': 'Add X-Content-Type-Options: nosniff'
            },
            'Content-Security-Policy': {
                'severity': 'MEDIUM',
                'description': 'Content-Security-Policy header missing - vulnerable to XSS',
                'fix': 'Implement Content-Security-Policy header'
            },
            'X-XSS-Protection': {
                'severity': 'LOW',
                'description': 'X-XSS-Protection header missing',
                'fix': 'Add X-XSS-Protection: 1; mode=block'
            }
        }

        for header, info in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'MISSING_SECURITY_HEADER',
                    'header': header,
                    'severity': info['severity'],
                    'description': info['description'],
                    'fix': info['fix']
                })

        # Check for sensitive information in headers
        if 'Server' in headers:
            vulnerabilities.append({
                'type': 'INFO_DISCLOSURE',
                'severity': 'LOW',
                'description': f'Server version disclosed: {headers["Server"]}',
                'fix': 'Remove or obfuscate Server header'
            })

        if 'X-Powered-By' in headers:
            vulnerabilities.append({
                'type': 'INFO_DISCLOSURE',
                'severity': 'LOW',
                'description': f'Technology disclosed: {headers["X-Powered-By"]}',
                'fix': 'Remove X-Powered-By header'
            })

        return vulnerabilities

    def _detect_technologies(self, response):
        """Detect technologies used by the website"""
        technologies = []

        # Check headers
        if 'X-Powered-By' in response.headers:
            technologies.append(response.headers['X-Powered-By'])

        if 'Server' in response.headers:
            technologies.append(response.headers['Server'])

        # Check HTML patterns
        html = response.text.lower()

        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', 'sites/default'],
            'Joomla': ['joomla', 'com_content'],
            'Laravel': ['laravel', '_token'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'React': ['react', '_reactroot'],
            'Angular': ['ng-app', 'angular'],
            'Vue.js': ['vue', 'v-app'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }

        for tech, patterns in tech_patterns.items():
            if any(pattern in html for pattern in patterns):
                technologies.append(tech)

        return list(set(technologies))

    def _extract_forms(self, soup, base_url):
        """Extract all forms from HTML"""
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms

    def _extract_endpoints(self, soup, base_url):
        """Extract endpoints from HTML"""
        endpoints = set()

        # Extract from links
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:
                endpoints.add(full_url)

        # Extract from forms
        for form in soup.find_all('form', action=True):
            action = form['action']
            full_url = urljoin(base_url, action)
            endpoints.add(full_url)

        # Extract from scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            endpoints.add(full_url)

        return list(endpoints)[:50]  # Limit to 50

    def _find_sensitive_info(self, text):
        """Find sensitive information in response"""
        sensitive = []

        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\+?1?\d{9,15}',
            'credit_card': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'private_key': r'-----BEGIN (RSA |)PRIVATE KEY-----',
            'jwt': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        }

        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                sensitive.append({
                    'type': info_type,
                    'count': len(matches),
                    'samples': matches[:3]  # Only show first 3
                })

        return sensitive

    def _check_xss_reflection(self, url, soup):
        """Check for potential XSS vulnerabilities"""
        vulnerabilities = []

        # Check if URL parameters are reflected in page
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            vulnerabilities.append({
                'type': 'POTENTIAL_XSS',
                'severity': 'MEDIUM',
                'description': 'URL parameters detected - test for XSS reflection',
                'fix': 'Implement proper input validation and output encoding'
            })

        return vulnerabilities

    def _check_sql_injection_hints(self, text):
        """Check for SQL error messages"""
        vulnerabilities = []

        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'ORA-',
            'PostgreSQL',
            'SQLite',
            'SQLSTATE',
            'Unclosed quotation',
        ]

        for error in sql_errors:
            if error.lower() in text.lower():
                vulnerabilities.append({
                    'type': 'SQL_INJECTION_HINT',
                    'severity': 'HIGH',
                    'description': f'SQL error message detected: {error}',
                    'fix': 'Implement proper error handling and use parameterized queries'
                })
                break

        return vulnerabilities

    def _check_open_redirect(self, url):
        """Check for open redirect parameters"""
        vulnerabilities = []

        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'rurl', 'dest']
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param in redirect_params:
            if param in params:
                vulnerabilities.append({
                    'type': 'OPEN_REDIRECT',
                    'severity': 'MEDIUM',
                    'description': f'Potential open redirect parameter: {param}',
                    'fix': 'Validate redirect URLs against whitelist'
                })

        return vulnerabilities

    def _check_exposed_files(self, base_url):
        """Check for commonly exposed sensitive files"""
        exposed = []

        sensitive_files = [
            '.git/config',
            '.env',
            '.htaccess',
            'web.config',
            'wp-config.php',
            'config.php',
            'phpinfo.php',
            'robots.txt',
            'sitemap.xml',
            'backup.zip',
            'backup.sql',
            '.DS_Store',
            'composer.json',
            'package.json',
            '.gitlab-ci.yml',
            '.travis.yml',
            'Dockerfile',
            'docker-compose.yml',
        ]

        for file in sensitive_files:
            url = urljoin(base_url, file)
            try:
                response = self.session.head(url, timeout=5, verify=False)
                if response.status_code == 200:
                    exposed.append({
                        'file': file,
                        'url': url,
                        'severity': 'HIGH' if file in ['.env', '.git/config', 'backup.sql'] else 'MEDIUM'
                    })
            except:
                pass

        return exposed

    def _calculate_risk_summary(self, result):
        """Calculate overall risk summary"""
        risk_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }

        for vuln in result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'UNKNOWN')
            if severity in risk_counts:
                risk_counts[severity] += 1

        for issue in result.get('ssl_issues', []):
            severity = issue.get('severity', 'UNKNOWN')
            if severity in risk_counts:
                risk_counts[severity] += 1

        for exposed in result.get('exposed_files', []):
            severity = exposed.get('severity', 'UNKNOWN')
            if severity in risk_counts:
                risk_counts[severity] += 1

        total = sum(risk_counts.values())

        return {
            'total_issues': total,
            'by_severity': risk_counts,
            'overall_risk': self._calculate_overall_risk(risk_counts)
        }

    def _calculate_overall_risk(self, risk_counts):
        """Calculate overall risk level"""
        if risk_counts['CRITICAL'] > 0:
            return 'CRITICAL'
        elif risk_counts['HIGH'] > 2:
            return 'HIGH'
        elif risk_counts['HIGH'] > 0 or risk_counts['MEDIUM'] > 5:
            return 'HIGH'
        elif risk_counts['MEDIUM'] > 0:
            return 'MEDIUM'
        elif risk_counts['LOW'] > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
