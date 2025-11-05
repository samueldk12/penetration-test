"""
Advanced Reconnaissance Module
Comprehensive information gathering for penetration testing
"""

import requests
import socket
import dns.resolver
import re
import ssl
import OpenSSL
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Any
import subprocess
import json
import time

class ReconModule:
    """Advanced reconnaissance module for information gathering"""

    def __init__(self, target, logger, threads=10, timeout=10, proxy=None):
        self.target = target
        self.logger = logger
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.parsed_target = urlparse(target if '://' in target else f'http://{target}')
        self.domain = self.parsed_target.netloc or self.parsed_target.path
        self.session = self._init_session()

        self.results = {
            'subdomains': set(),
            'dns_records': {},
            'open_ports': [],
            'technologies': set(),
            'endpoints': set(),
            'security_headers': {},
            'ssl_info': {},
            'whois_info': {},
            'emails': set(),
            'js_files': set(),
            'forms': [],
            'comments': [],
            'apis': set(),
        }

    def _init_session(self):
        """Initialize HTTP session with headers"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        if self.proxy:
            session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

    def run_full_recon(self) -> Dict[str, Any]:
        """Execute full reconnaissance suite"""
        self.logger.log_info("Starting full reconnaissance...")

        # Execute recon modules
        recon_tasks = [
            ("Subdomain enumeration", self.enumerate_subdomains),
            ("DNS record collection", self.collect_dns_records),
            ("Port scanning", self.scan_ports),
            ("Technology detection", self.detect_technologies),
            ("Security headers analysis", self.analyze_security_headers),
            ("SSL/TLS information", self.gather_ssl_info),
            ("Endpoint discovery", self.discover_endpoints),
            ("JavaScript file enumeration", self.enumerate_js_files),
            ("Form detection", self.detect_forms),
            ("Comment extraction", self.extract_comments),
            ("API endpoint discovery", self.discover_api_endpoints),
            ("Email harvesting", self.harvest_emails),
        ]

        for task_name, task_func in recon_tasks:
            try:
                self.logger.log_info(f"Executing: {task_name}")
                task_func()
            except Exception as e:
                self.logger.log_error(f"Error in {task_name}: {str(e)}")

        # Convert sets to lists for JSON serialization
        return {
            'target': self.target,
            'domain': self.domain,
            'subdomains': list(self.results['subdomains']),
            'dns_records': self.results['dns_records'],
            'open_ports': self.results['open_ports'],
            'technologies': list(self.results['technologies']),
            'endpoints': list(self.results['endpoints']),
            'security_headers': self.results['security_headers'],
            'ssl_info': self.results['ssl_info'],
            'emails': list(self.results['emails']),
            'js_files': list(self.results['js_files']),
            'forms': self.results['forms'],
            'comments': self.results['comments'],
            'apis': list(self.results['apis']),
        }

    def enumerate_subdomains(self):
        """Enumerate subdomains using multiple techniques"""
        subdomains = set()

        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start',
            'sms', 'office', 'exchange', 'ipv4', 'help', 'home', 'library', 'ftp2',
            'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it',
            'gateway', 'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web1', 'dashboard',
            'api-dev', 'api-prod', 'api-staging', 'dev-api', 'prod-api', 'staging-api',
            'v1', 'v2', 'graphql', 'rest', 'internal', 'external', 'admin-api'
        ]

        def check_subdomain(subdomain):
            try:
                hostname = f"{subdomain}.{self.domain}"
                socket.gethostbyname(hostname)
                return hostname
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
                    self.logger.log_success(f"Subdomain found: {result}")

        # DNS enumeration via certificate transparency logs (simulated)
        try:
            # Try to get subdomains from certificate transparency
            ct_subdomains = self._check_certificate_transparency()
            subdomains.update(ct_subdomains)
        except Exception as e:
            self.logger.log_warning(f"Certificate transparency check failed: {str(e)}")

        self.results['subdomains'] = subdomains

    def _check_certificate_transparency(self) -> Set[str]:
        """Check certificate transparency logs for subdomains"""
        subdomains = set()
        try:
            # Using crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # Parse multiple names (can be newline separated)
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and self.domain in subdomain:
                            subdomains.add(subdomain)
        except Exception as e:
            self.logger.log_warning(f"CT log enumeration error: {str(e)}")

        return subdomains

    def collect_dns_records(self):
        """Collect DNS records (A, AAAA, MX, NS, TXT, CNAME)"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        dns_records = {}

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                records = [str(rdata) for rdata in answers]
                dns_records[record_type] = records
                self.logger.log_success(f"DNS {record_type} records found: {len(records)}")
            except Exception as e:
                dns_records[record_type] = []

        self.results['dns_records'] = dns_records

    def scan_ports(self):
        """Scan common ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 6379, 5432, 1433,
            9200, 9300, 11211, 6379, 7001, 8000, 8001, 8008, 8888, 9090, 10000
        ]

        open_ports = []

        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                if result == 0:
                    # Try to get service banner
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return {'port': port, 'service': service, 'state': 'open'}
                return None
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self.logger.log_success(f"Open port found: {result['port']} ({result['service']})")

        self.results['open_ports'] = sorted(open_ports, key=lambda x: x['port'])

    def detect_technologies(self):
        """Detect web technologies using headers, HTML content, and patterns"""
        technologies = set()

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)

            # Check headers
            headers = response.headers
            if 'X-Powered-By' in headers:
                technologies.add(f"X-Powered-By: {headers['X-Powered-By']}")
            if 'Server' in headers:
                technologies.add(f"Server: {headers['Server']}")

            content = response.text

            # Technology signatures
            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-json'],
                'Joomla': ['Joomla', '/components/com_'],
                'Drupal': ['Drupal', '/sites/default/', '/sites/all/'],
                'Django': ['csrfmiddlewaretoken', '__admin'],
                'Flask': ['werkzeug'],
                'Laravel': ['laravel_session', 'XSRF-TOKEN'],
                'React': ['react', 'react-dom', '__REACT'],
                'Angular': ['ng-', 'angular'],
                'Vue.js': ['vue', 'v-if', 'v-for'],
                'jQuery': ['jquery', 'jQuery'],
                'Bootstrap': ['bootstrap'],
                'PHP': ['.php', 'PHPSESSID'],
                'ASP.NET': ['__VIEWSTATE', '__EVENTVALIDATION', 'asp.net'],
                'Node.js': ['express'],
            }

            for tech, signatures in tech_signatures.items():
                if any(sig.lower() in content.lower() for sig in signatures):
                    technologies.add(tech)
                    self.logger.log_success(f"Technology detected: {tech}")

            # Check cookies
            for cookie in response.cookies:
                technologies.add(f"Cookie: {cookie.name}")

        except Exception as e:
            self.logger.log_warning(f"Technology detection error: {str(e)}")

        self.results['technologies'] = technologies

    def analyze_security_headers(self):
        """Analyze security headers"""
        security_headers = {
            'Strict-Transport-Security': False,
            'X-Frame-Options': False,
            'X-Content-Type-Options': False,
            'Content-Security-Policy': False,
            'X-XSS-Protection': False,
            'Referrer-Policy': False,
            'Permissions-Policy': False,
        }

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            headers = response.headers

            for header in security_headers.keys():
                if header in headers:
                    security_headers[header] = headers[header]
                    self.logger.log_success(f"Security header present: {header}")
                else:
                    self.logger.log_warning(f"Security header missing: {header}")

        except Exception as e:
            self.logger.log_warning(f"Security header analysis error: {str(e)}")

        self.results['security_headers'] = security_headers

    def gather_ssl_info(self):
        """Gather SSL/TLS certificate information"""
        ssl_info = {}

        try:
            hostname = self.domain
            port = 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)

                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()
                    ssl_info['subject'] = dict(x[0] for x in cert.get_subject().get_components())
                    ssl_info['issuer'] = dict(x[0] for x in cert.get_issuer().get_components())
                    ssl_info['serial_number'] = cert.get_serial_number()
                    ssl_info['not_before'] = cert.get_notBefore().decode('utf-8')
                    ssl_info['not_after'] = cert.get_notAfter().decode('utf-8')

                    self.logger.log_success("SSL/TLS information collected")

        except Exception as e:
            self.logger.log_warning(f"SSL info gathering error: {str(e)}")

        self.results['ssl_info'] = ssl_info

    def discover_endpoints(self):
        """Discover endpoints through crawling and common paths"""
        endpoints = set()

        # Common endpoint wordlist
        common_paths = [
            '/admin', '/login', '/api', '/api/v1', '/api/v2', '/dashboard',
            '/user', '/users', '/upload', '/download', '/search', '/config',
            '/backup', '/test', '/dev', '/debug', '/console', '/phpinfo.php',
            '/info.php', '/.git', '/.env', '/swagger', '/graphql', '/health',
            '/status', '/metrics', '/docs', '/api-docs', '/.well-known',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/wp-admin', '/wp-login.php', '/administrator', '/phpmyadmin',
            '/adminer', '/portal', '/api/swagger', '/api/docs', '/actuator',
        ]

        def check_endpoint(path):
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
                if response.status_code not in [404, 502, 503, 504]:
                    return {'url': url, 'status_code': response.status_code, 'size': len(response.content)}
                return None
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_endpoint, path) for path in common_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    endpoints.add(result['url'])
                    self.logger.log_success(f"Endpoint found: {result['url']} (Status: {result['status_code']})")

        self.results['endpoints'] = endpoints

    def enumerate_js_files(self):
        """Enumerate JavaScript files"""
        js_files = set()

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            content = response.text

            # Find JS file references
            js_pattern = r'<script[^>]+src=["\'](.*?\.js)["\']'
            matches = re.findall(js_pattern, content, re.IGNORECASE)

            for match in matches:
                js_url = urljoin(self.target, match)
                js_files.add(js_url)
                self.logger.log_success(f"JavaScript file found: {js_url}")

        except Exception as e:
            self.logger.log_warning(f"JS enumeration error: {str(e)}")

        self.results['js_files'] = js_files

    def detect_forms(self):
        """Detect HTML forms"""
        forms = []

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            content = response.text

            # Basic form detection
            form_pattern = r'<form[^>]*>(.*?)</form>'
            matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)

            for i, match in enumerate(matches):
                form_data = {
                    'id': i,
                    'action': '',
                    'method': 'GET',
                    'inputs': []
                }

                # Extract form action
                action_match = re.search(r'action=["\'](.*?)["\']', match, re.IGNORECASE)
                if action_match:
                    form_data['action'] = action_match.group(1)

                # Extract form method
                method_match = re.search(r'method=["\'](.*?)["\']', match, re.IGNORECASE)
                if method_match:
                    form_data['method'] = method_match.group(1).upper()

                # Extract inputs
                input_pattern = r'<input[^>]+>'
                inputs = re.findall(input_pattern, match, re.IGNORECASE)
                for inp in inputs:
                    name_match = re.search(r'name=["\'](.*?)["\']', inp, re.IGNORECASE)
                    type_match = re.search(r'type=["\'](.*?)["\']', inp, re.IGNORECASE)
                    if name_match:
                        form_data['inputs'].append({
                            'name': name_match.group(1),
                            'type': type_match.group(1) if type_match else 'text'
                        })

                forms.append(form_data)
                self.logger.log_success(f"Form detected: {form_data['action']} ({form_data['method']})")

        except Exception as e:
            self.logger.log_warning(f"Form detection error: {str(e)}")

        self.results['forms'] = forms

    def extract_comments(self):
        """Extract HTML and JavaScript comments"""
        comments = []

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            content = response.text

            # HTML comments
            html_comment_pattern = r'<!--(.*?)-->'
            html_comments = re.findall(html_comment_pattern, content, re.DOTALL)
            for comment in html_comments:
                comments.append({'type': 'HTML', 'content': comment.strip()})

            # JavaScript comments
            js_comment_pattern = r'//(.*?)$'
            js_comments = re.findall(js_comment_pattern, content, re.MULTILINE)
            for comment in js_comments:
                if comment.strip():
                    comments.append({'type': 'JavaScript', 'content': comment.strip()})

            if comments:
                self.logger.log_success(f"Comments extracted: {len(comments)}")

        except Exception as e:
            self.logger.log_warning(f"Comment extraction error: {str(e)}")

        self.results['comments'] = comments[:50]  # Limit to 50

    def discover_api_endpoints(self):
        """Discover API endpoints"""
        api_endpoints = set()

        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/api', '/rest/v1', '/rest/v2',
            '/graphql', '/gql',
            '/swagger', '/swagger.json', '/swagger/v1/swagger.json',
            '/api/swagger.json', '/api/swagger.yaml',
            '/openapi.json', '/openapi.yaml',
            '/api-docs', '/api/docs', '/docs',
            '/v1', '/v2', '/v3',
        ]

        def check_api(path):
            try:
                url = urljoin(self.target, path)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    return url
                return None
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_api, path) for path in api_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    api_endpoints.add(result)
                    self.logger.log_success(f"API endpoint found: {result}")

        self.results['apis'] = api_endpoints

    def harvest_emails(self):
        """Harvest email addresses"""
        emails = set()

        try:
            response = self.session.get(self.target, timeout=self.timeout, verify=False)
            content = response.text

            # Email pattern
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            matches = re.findall(email_pattern, content)

            for email in matches:
                emails.add(email)
                self.logger.log_success(f"Email found: {email}")

        except Exception as e:
            self.logger.log_warning(f"Email harvesting error: {str(e)}")

        self.results['emails'] = emails
