#!/usr/bin/env python3
"""
OSINT Module
Módulo completo de OSINT (Open Source Intelligence)
"""

import requests
import json
import re
import socket
import whois
import dns.resolver
from typing import Dict, List, Optional, Set
from datetime import datetime
from pathlib import Path
import concurrent.futures
from urllib.parse import urlparse
import hashlib


class OSINTModule:
    """Módulo principal de OSINT."""

    def __init__(self):
        self.results = {
            'target': '',
            'scan_date': datetime.now().isoformat(),
            'domain_info': {},
            'email_addresses': [],
            'social_media': [],
            'leaked_credentials': [],
            'dns_records': {},
            'subdomains': [],
            'ip_addresses': [],
            'technologies': [],
            'data_breaches': [],
            'public_documents': [],
            'metadata': {}
        }

    def investigate(self, target: str, **kwargs) -> Dict:
        """
        Realiza investigação OSINT completa no alvo.

        Args:
            target: Domínio, email ou nome para investigar
            **kwargs: Opções adicionais
                - deep_scan: Escaneia mais profundamente (default: False)
                - include_breaches: Verifica data breaches (default: True)
                - include_social: Busca redes sociais (default: True)
                - include_documents: Busca documentos públicos (default: True)

        Returns:
            Dict com resultados OSINT
        """
        self.results['target'] = target

        deep_scan = kwargs.get('deep_scan', False)
        include_breaches = kwargs.get('include_breaches', True)
        include_social = kwargs.get('include_social', True)
        include_documents = kwargs.get('include_documents', True)

        target_type = self._detect_target_type(target)

        if target_type == 'domain':
            self._investigate_domain(target, deep_scan)
        elif target_type == 'email':
            self._investigate_email(target, include_breaches)
        elif target_type == 'person':
            self._investigate_person(target, include_social)

        if include_documents:
            self._search_public_documents(target)

        return self.results

    def _detect_target_type(self, target: str) -> str:
        """Detecta tipo do alvo."""
        if '@' in target:
            return 'email'
        elif '.' in target and not ' ' in target:
            return 'domain'
        else:
            return 'person'

    def _investigate_domain(self, domain: str, deep_scan: bool):
        """Investiga domínio."""
        print(f"[*] Investigating domain: {domain}")

        # WHOIS
        self.results['domain_info'] = self._whois_lookup(domain)

        # DNS Records
        self.results['dns_records'] = self._dns_enumeration(domain)

        # Subdomains
        self.results['subdomains'] = self._find_subdomains(domain)

        # IP Addresses
        self.results['ip_addresses'] = self._resolve_ips(domain)

        # Technologies
        self.results['technologies'] = self._detect_technologies(domain)

        # Email harvesting
        self.results['email_addresses'] = self._harvest_emails(domain)

        if deep_scan:
            # SSL/TLS info
            self.results['ssl_info'] = self._get_ssl_info(domain)

            # Historical data
            self.results['historical_data'] = self._get_historical_data(domain)

    def _investigate_email(self, email: str, include_breaches: bool):
        """Investiga email."""
        print(f"[*] Investigating email: {email}")

        # Validação
        self.results['email_validation'] = self._validate_email(email)

        # Data breaches
        if include_breaches:
            self.results['data_breaches'] = self._check_breaches(email)

        # Social media
        self.results['social_media'] = self._find_social_media_by_email(email)

        # Domain do email
        domain = email.split('@')[1]
        self.results['email_domain_info'] = self._whois_lookup(domain)

    def _investigate_person(self, name: str, include_social: bool):
        """Investiga pessoa."""
        print(f"[*] Investigating person: {name}")

        # Social media
        if include_social:
            self.results['social_media'] = self._find_social_media_by_name(name)

        # Public records
        self.results['public_records'] = self._search_public_records(name)

    def _whois_lookup(self, domain: str) -> Dict:
        """Realiza lookup WHOIS."""
        try:
            # Set default timeout for socket operations
            socket.setdefaulttimeout(10)

            w = whois.whois(domain)

            return {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None
            }
        except socket.timeout:
            return {'error': 'WHOIS lookup timeout'}
        except Exception as e:
            return {'error': str(e)}

    def _dns_enumeration(self, domain: str) -> Dict:
        """Enumera registros DNS."""
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        resolver = dns.resolver.Resolver()

        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                dns_records[record_type] = []

        return dns_records

    def _find_subdomains(self, domain: str) -> List[str]:
        """Encontra subdomínios via Certificate Transparency."""
        subdomains = set()

        try:
            # crt.sh
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower().replace('*.', '')
                        if name and name.endswith(domain):
                            subdomains.add(name)

        except Exception as e:
            print(f"Error finding subdomains: {e}")

        return sorted(list(subdomains))

    def _resolve_ips(self, domain: str) -> List[Dict]:
        """Resolve IPs do domínio."""
        ips = []

        try:
            # Set timeout for DNS resolution
            socket.setdefaulttimeout(10)

            # IPv4
            ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
            for addr in ipv4_addresses:
                ip = addr[4][0]
                ips.append({
                    'ip': ip,
                    'type': 'IPv4',
                    'reverse_dns': self._reverse_dns(ip)
                })

            # IPv6
            try:
                ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
                for addr in ipv6_addresses:
                    ip = addr[4][0]
                    ips.append({
                        'ip': ip,
                        'type': 'IPv6',
                        'reverse_dns': self._reverse_dns(ip)
                    })
            except:
                pass

        except socket.timeout:
            print(f"Timeout resolving IPs for {domain}")
        except Exception as e:
            print(f"Error resolving IPs: {e}")

        return ips

    def _reverse_dns(self, ip: str) -> Optional[str]:
        """Realiza reverse DNS."""
        try:
            socket.setdefaulttimeout(5)  # Shorter timeout for reverse DNS
            return socket.gethostbyaddr(ip)[0]
        except socket.timeout:
            return None
        except:
            return None

    def _detect_technologies(self, domain: str) -> List[Dict]:
        """Detecta tecnologias usadas no site."""
        technologies = []

        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, verify=False)

            # Server header
            if 'Server' in response.headers:
                technologies.append({
                    'name': response.headers['Server'],
                    'type': 'Web Server',
                    'confidence': 'high'
                })

            # X-Powered-By
            if 'X-Powered-By' in response.headers:
                technologies.append({
                    'name': response.headers['X-Powered-By'],
                    'type': 'Backend',
                    'confidence': 'high'
                })

            # Content analysis
            content = response.text.lower()

            # WordPress
            if 'wp-content' in content or 'wordpress' in content:
                technologies.append({
                    'name': 'WordPress',
                    'type': 'CMS',
                    'confidence': 'high'
                })

            # React
            if 'react' in content:
                technologies.append({
                    'name': 'React',
                    'type': 'JavaScript Framework',
                    'confidence': 'medium'
                })

            # jQuery
            if 'jquery' in content:
                technologies.append({
                    'name': 'jQuery',
                    'type': 'JavaScript Library',
                    'confidence': 'high'
                })

        except Exception as e:
            print(f"Error detecting technologies: {e}")

        return technologies

    def _harvest_emails(self, domain: str) -> List[Dict]:
        """Coleta emails relacionados ao domínio."""
        emails = set()

        # Padrões comuns
        common_prefixes = [
            'info', 'contact', 'admin', 'support', 'sales', 'hello',
            'noreply', 'no-reply', 'webmaster', 'postmaster', 'help'
        ]

        for prefix in common_prefixes:
            email = f"{prefix}@{domain}"
            emails.add(email)

        # Busca em Google (simulado - em produção, usar API)
        # Este é um placeholder para integração futura

        return [{'email': email, 'source': 'common_patterns'} for email in sorted(emails)]

    def _validate_email(self, email: str) -> Dict:
        """Valida email."""
        validation = {
            'email': email,
            'format_valid': False,
            'domain_exists': False,
            'mx_records': False
        }

        # Valida formato
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        validation['format_valid'] = bool(re.match(pattern, email))

        if not validation['format_valid']:
            return validation

        # Extrai domínio
        domain = email.split('@')[1]

        # Verifica se domínio existe
        try:
            socket.gethostbyname(domain)
            validation['domain_exists'] = True
        except:
            return validation

        # Verifica MX records
        try:
            resolver = dns.resolver.Resolver()
            resolver.resolve(domain, 'MX')
            validation['mx_records'] = True
        except:
            pass

        return validation

    def _check_breaches(self, email: str) -> List[Dict]:
        """Verifica data breaches (integração com HaveIBeenPwned seria ideal)."""
        # Placeholder - requer API key do HIBP
        return [{
            'note': 'Breach checking requires HIBP API key',
            'recommendation': 'Configure HIBP_API_KEY environment variable'
        }]

    def _find_social_media_by_email(self, email: str) -> List[Dict]:
        """Busca perfis de redes sociais por email."""
        # Placeholder para integração futura com APIs de redes sociais
        return []

    def _find_social_media_by_name(self, name: str) -> List[Dict]:
        """Busca perfis de redes sociais por nome."""
        social_media = []

        # Lista de plataformas comuns
        platforms = {
            'Twitter': f'https://twitter.com/{name}',
            'GitHub': f'https://github.com/{name}',
            'LinkedIn': f'https://linkedin.com/in/{name}',
            'Instagram': f'https://instagram.com/{name}',
            'Facebook': f'https://facebook.com/{name}'
        }

        # Verifica se perfis existem (checagem básica)
        for platform, url in platforms.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    social_media.append({
                        'platform': platform,
                        'url': url,
                        'status': 'found'
                    })
            except:
                pass

        return social_media

    def _search_public_records(self, name: str) -> Dict:
        """Busca registros públicos."""
        # Placeholder para integração com bases de dados públicas
        return {
            'note': 'Public records search requires integration with specific databases'
        }

    def _search_public_documents(self, target: str) -> List[Dict]:
        """Busca documentos públicos."""
        documents = []

        # Google Dorks para documentos
        dorks = [
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:doc',
            f'site:{target} filetype:xls',
            f'site:{target} filetype:ppt'
        ]

        # Placeholder - requer integração com Google Custom Search API

        return documents

    def _get_ssl_info(self, domain: str) -> Dict:
        """Obtém informações SSL/TLS."""
        import ssl
        import socket

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {'error': str(e)}

    def _get_historical_data(self, domain: str) -> Dict:
        """Obtém dados históricos do Wayback Machine."""
        try:
            url = f"http://archive.org/wayback/available?url={domain}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                return data.get('archived_snapshots', {})

        except Exception as e:
            return {'error': str(e)}

        return {}

    def export_report(self, output_file: str = 'osint_report.json'):
        """Exporta relatório OSINT."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        return output_file


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python osint_module.py <target> [--deep]")
        print("\nExamples:")
        print("  python osint_module.py example.com")
        print("  python osint_module.py user@example.com")
        print("  python osint_module.py 'John Doe'")
        sys.exit(1)

    osint = OSINTModule()
    target = sys.argv[1]
    deep_scan = '--deep' in sys.argv

    print(f"[*] Starting OSINT investigation on: {target}")
    results = osint.investigate(target, deep_scan=deep_scan)

    # Exporta relatório
    report_file = osint.export_report()
    print(f"\n[+] Report saved to: {report_file}")

    # Resumo
    print("\n" + "="*60)
    print("OSINT INVESTIGATION SUMMARY")
    print("="*60)
    print(f"Target: {results['target']}")
    print(f"Scan Date: {results['scan_date']}")

    if results.get('subdomains'):
        print(f"\nSubdomains found: {len(results['subdomains'])}")

    if results.get('email_addresses'):
        print(f"Emails found: {len(results['email_addresses'])}")

    if results.get('ip_addresses'):
        print(f"IP addresses: {len(results['ip_addresses'])}")

    if results.get('technologies'):
        print(f"Technologies detected: {len(results['technologies'])}")

    print("\n" + "="*60)
