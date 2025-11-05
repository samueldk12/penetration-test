#!/usr/bin/env python3
"""
Subdominator Plugin
Ferramenta Python nativa para enumeração avançada de subdomínios
"""

import dns.resolver
import dns.zone
import dns.query
import requests
import concurrent.futures
from typing import Dict, List, Set, Optional
from pathlib import Path
import json

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class SubdominatorPlugin(PluginInterface):
    """Plugin para enumeração avançada de subdomínios."""

    name = "subdominator"
    version = "1.0.0"
    category = "recon"
    description = "Advanced subdomain enumeration"

    def __init__(self):
        super().__init__()
        # Cria resolver com DNS públicos
        try:
            self.resolver = dns.resolver.Resolver()
        except:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        self.resolver.timeout = 2
        self.resolver.lifetime = 2

        # Garante que há nameservers configurados
        if not self.resolver.nameservers:
            self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def run(self, domain: str, **kwargs) -> Dict:
        """
        Enumera subdomínios de múltiplas fontes.

        Args:
            domain: Domínio alvo
            **kwargs: Opções adicionais
                - wordlist: Path para wordlist de subdomínios
                - bruteforce: Habilita brute force (default: True)
                - dns_records: Tipos de DNS records para consultar
                - threads: Número de threads (default: 50)
                - verify_alive: Verifica se subdomínios estão ativos

        Returns:
            Dict com subdomínios encontrados
        """
        wordlist = kwargs.get('wordlist')
        bruteforce = kwargs.get('bruteforce', True)
        dns_records = kwargs.get('dns_records', ['A', 'AAAA', 'CNAME'])
        threads = kwargs.get('threads', 50)
        verify_alive = kwargs.get('verify_alive', True)

        subdomains = set()

        # 1. Certificate Transparency
        print("[*] Querying Certificate Transparency logs...")
        ct_subs = self._query_crtsh(domain)
        subdomains.update(ct_subs)
        print(f"[+] Found {len(ct_subs)} subdomains from CT logs")

        # 2. DNS Brute Force
        if bruteforce and wordlist:
            print("[*] Starting DNS brute force...")
            brute_subs = self._dns_bruteforce(domain, wordlist, threads)
            subdomains.update(brute_subs)
            print(f"[+] Found {len(brute_subs)} subdomains from brute force")

        # 3. Zone Transfer Attempt
        print("[*] Attempting zone transfer...")
        zone_subs = self._zone_transfer(domain)
        if zone_subs:
            subdomains.update(zone_subs)
            print(f"[+] Found {len(zone_subs)} subdomains from zone transfer")
        else:
            print("[-] Zone transfer not allowed")

        # 4. DNS Records Enumeration
        print("[*] Enumerating DNS records...")
        dns_subs = self._enumerate_dns_records(domain, dns_records)
        subdomains.update(dns_subs)
        print(f"[+] Found {len(dns_subs)} subdomains from DNS records")

        # Verifica quais estão ativos
        alive_subdomains = []
        if verify_alive and subdomains:
            print(f"[*] Verifying {len(subdomains)} subdomains...")
            alive_subdomains = self._verify_alive(list(subdomains), threads)
            print(f"[+] {len(alive_subdomains)} subdomains are alive")

        return {
            'success': True,
            'domain': domain,
            'total_subdomains': len(subdomains),
            'subdomains': sorted(list(subdomains)),
            'alive_subdomains': alive_subdomains,
            'sources': {
                'certificate_transparency': len(ct_subs),
                'dns_bruteforce': len(brute_subs) if bruteforce and wordlist else 0,
                'zone_transfer': len(zone_subs) if zone_subs else 0,
                'dns_records': len(dns_subs)
            }
        }

    def _query_crtsh(self, domain: str) -> Set[str]:
        """Consulta Certificate Transparency via crt.sh."""
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name and name.endswith(domain):
                            # Remove wildcards
                            name = name.replace('*.', '')
                            if name:
                                subdomains.add(name)

        except Exception as e:
            print(f"Error querying crt.sh: {e}")

        return subdomains

    def _dns_bruteforce(self, domain: str, wordlist: str, threads: int) -> Set[str]:
        """Realiza brute force de subdomínios."""
        subdomains = set()

        try:
            # Lê wordlist
            with open(wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]

            # Brute force paralelo
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(self._check_subdomain, word, domain): word
                    for word in words
                }

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.add(result)

        except FileNotFoundError:
            print(f"Wordlist not found: {wordlist}")
        except Exception as e:
            print(f"Error in DNS brute force: {e}")

        return subdomains

    def _check_subdomain(self, word: str, domain: str) -> Optional[str]:
        """Verifica se subdomínio existe via DNS."""
        subdomain = f"{word}.{domain}"

        try:
            self.resolver.resolve(subdomain, 'A')
            return subdomain
        except:
            pass

        return None

    def _zone_transfer(self, domain: str) -> Set[str]:
        """Tenta zone transfer DNS."""
        subdomains = set()

        try:
            # Obtém nameservers
            ns_records = self.resolver.resolve(domain, 'NS')

            for ns in ns_records:
                ns_addr = str(ns.target).rstrip('.')

                try:
                    # Tenta zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_addr, domain))

                    for name in zone.nodes.keys():
                        subdomain = f"{name}.{domain}".lower()
                        if subdomain.endswith(domain):
                            subdomains.add(subdomain)

                except Exception:
                    continue

        except Exception:
            pass

        return subdomains

    def _enumerate_dns_records(self, domain: str, record_types: List[str]) -> Set[str]:
        """Enumera subdomínios através de DNS records."""
        subdomains = set()

        for record_type in record_types:
            try:
                records = self.resolver.resolve(domain, record_type)

                for record in records:
                    value = str(record).lower()
                    if value.endswith(domain):
                        subdomains.add(value)

            except Exception:
                continue

        return subdomains

    def _verify_alive(self, subdomains: List[str], threads: int) -> List[Dict]:
        """Verifica quais subdomínios estão ativos."""
        alive = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._probe_subdomain, sub): sub
                for sub in subdomains
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    alive.append(result)

        return alive

    def _probe_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Verifica se subdomínio está ativo."""
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.head(
                    url,
                    timeout=5,
                    allow_redirects=True,
                    verify=False
                )

                return {
                    'subdomain': subdomain,
                    'url': url,
                    'status_code': response.status_code,
                    'protocol': protocol
                }

            except:
                continue

        return None


# Wordlist padrão de subdomínios comuns
DEFAULT_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'staging',
    'test', 'admin', 'portal', 'blog', 'shop', 'forum', 'store', 'vpn', 'mysql',
    'db', 'database', 'cdn', 'mobile', 'm', 'app', 'beta', 'demo', 'support',
    'secure', 'payment', 'checkout', 'billing', 'dashboard', 'panel', 'crm',
    'login', 'sso', 'auth', 'oauth', 'api2', 'v1', 'v2', 'v3', 'static', 'media',
    'assets', 'images', 'img', 'css', 'js', 'files', 'download', 'downloads'
]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdominator.py <domain> [wordlist]")
        sys.exit(1)

    plugin = SubdominatorPlugin()
    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None

    # Se não tiver wordlist, cria uma temporária
    if not wordlist:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for word in DEFAULT_SUBDOMAINS:
                f.write(f"{word}\n")
            wordlist = f.name

    print(f"Running Subdominator on {domain}...")
    result = plugin.run(domain, wordlist=wordlist, verify_alive=True)

    print(json.dumps(result, indent=2))
