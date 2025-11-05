#!/usr/bin/env python3
"""
DNSBruter Plugin
Ferramenta Python nativa para DNS brute force avançado
"""

import dns.resolver
import dns.reversename
import ipaddress
import concurrent.futures
from typing import Dict, List, Set, Optional
from pathlib import Path
import json
import time

import sys
sys.path.append(str(Path(__file__).parent.parent))
from plugin_system import PluginInterface


class DNSBruterPlugin(PluginInterface):
    """Plugin para DNS brute force avançado."""

    name = "dnsbruter"
    version = "1.0.0"
    category = "recon"
    description = "Advanced DNS brute force"

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
        Realiza DNS brute force avançado.

        Args:
            domain: Domínio alvo
            **kwargs: Opções adicionais
                - wordlist: Path para wordlist
                - record_types: Tipos de DNS records (default: ['A', 'AAAA'])
                - threads: Número de threads (default: 100)
                - wildcard_detection: Detecta wildcards (default: True)
                - reverse_dns: Realiza reverse DNS (default: True)
                - permutations: Gera permutações (default: True)

        Returns:
            Dict com resultados do brute force
        """
        wordlist = kwargs.get('wordlist')
        record_types = kwargs.get('record_types', ['A', 'AAAA'])
        threads = kwargs.get('threads', 100)
        wildcard_detection = kwargs.get('wildcard_detection', True)
        reverse_dns = kwargs.get('reverse_dns', True)
        permutations = kwargs.get('permutations', True)

        if not wordlist:
            return {
                'success': False,
                'error': 'Wordlist required'
            }

        # Detecta wildcards
        wildcard_ips = set()
        if wildcard_detection:
            print("[*] Checking for wildcard DNS...")
            wildcard_ips = self._detect_wildcard(domain)
            if wildcard_ips:
                print(f"[!] Wildcard detected: {wildcard_ips}")
            else:
                print("[+] No wildcard detected")

        # Carrega wordlist
        print(f"[*] Loading wordlist from {wordlist}...")
        words = self._load_wordlist(wordlist)
        print(f"[+] Loaded {len(words)} words")

        # Gera permutações se solicitado
        if permutations:
            print("[*] Generating permutations...")
            words = self._generate_permutations(words, domain)
            print(f"[+] Total words with permutations: {len(words)}")

        # Realiza brute force
        print(f"[*] Starting DNS brute force with {threads} threads...")
        start_time = time.time()

        results = self._brute_force(
            domain,
            words,
            record_types,
            threads,
            wildcard_ips
        )

        elapsed = time.time() - start_time
        print(f"[+] Brute force completed in {elapsed:.2f} seconds")
        print(f"[+] Found {len(results)} valid subdomains")

        # Reverse DNS
        reverse_results = []
        if reverse_dns and results:
            print("[*] Performing reverse DNS lookups...")
            reverse_results = self._reverse_dns_lookups(results, threads)
            print(f"[+] Completed {len(reverse_results)} reverse lookups")

        return {
            'success': True,
            'domain': domain,
            'total_found': len(results),
            'results': results,
            'reverse_dns': reverse_results,
            'wildcard_detected': len(wildcard_ips) > 0,
            'wildcard_ips': list(wildcard_ips),
            'elapsed_time': elapsed,
            'queries_per_second': len(words) / elapsed if elapsed > 0 else 0
        }

    def _detect_wildcard(self, domain: str) -> Set[str]:
        """Detecta se domínio tem wildcard DNS."""
        wildcard_ips = set()

        # Testa alguns subdomínios aleatórios
        random_subs = [
            f"{''.join(__import__('random').choices('abcdefghijklmnopqrstuvwxyz', k=20))}.{domain}"
            for _ in range(5)
        ]

        for sub in random_subs:
            try:
                answers = self.resolver.resolve(sub, 'A')
                for answer in answers:
                    wildcard_ips.add(str(answer))
            except:
                pass

        return wildcard_ips

    def _load_wordlist(self, wordlist: str) -> List[str]:
        """Carrega wordlist de arquivo."""
        words = []

        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
        except Exception as e:
            print(f"Error loading wordlist: {e}")

        return words

    def _generate_permutations(self, words: List[str], domain: str) -> List[str]:
        """Gera permutações de palavras."""
        permutations = set(words)

        # Adiciona permutações comuns
        suffixes = ['dev', 'test', 'staging', 'prod', 'api', 'www', 'admin', 'old', 'new', 'v1', 'v2']
        prefixes = ['www', 'old', 'new', 'test', 'dev']

        for word in words[:100]:  # Limita para evitar explosão combinatória
            # Adiciona sufixos
            for suffix in suffixes:
                permutations.add(f"{word}-{suffix}")
                permutations.add(f"{word}.{suffix}")

            # Adiciona prefixos
            for prefix in prefixes:
                permutations.add(f"{prefix}-{word}")
                permutations.add(f"{prefix}.{word}")

        return list(permutations)

    def _brute_force(
        self,
        domain: str,
        words: List[str],
        record_types: List[str],
        threads: int,
        wildcard_ips: Set[str]
    ) -> List[Dict]:
        """Realiza brute force DNS paralelo."""
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    self._check_dns_record,
                    word,
                    domain,
                    record_types,
                    wildcard_ips
                ): word
                for word in words
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)

        return results

    def _check_dns_record(
        self,
        word: str,
        domain: str,
        record_types: List[str],
        wildcard_ips: Set[str]
    ) -> Optional[Dict]:
        """Verifica registro DNS para um subdomínio."""
        subdomain = f"{word}.{domain}" if not word.endswith(domain) else word

        for record_type in record_types:
            try:
                answers = self.resolver.resolve(subdomain, record_type)

                # Filtra wildcards
                ips = set()
                for answer in answers:
                    ip = str(answer)
                    if ip not in wildcard_ips:
                        ips.add(ip)

                if ips:
                    return {
                        'subdomain': subdomain,
                        'record_type': record_type,
                        'addresses': list(ips),
                        'word': word
                    }

            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.Timeout:
                continue
            except Exception:
                continue

        return None

    def _reverse_dns_lookups(self, results: List[Dict], threads: int) -> List[Dict]:
        """Realiza reverse DNS lookups."""
        reverse_results = []

        # Coleta todos os IPs
        ips = set()
        for result in results:
            for ip in result.get('addresses', []):
                ips.add(ip)

        # Reverse lookup paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._reverse_lookup, ip): ip
                for ip in ips
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    reverse_results.append(result)

        return reverse_results

    def _reverse_lookup(self, ip: str) -> Optional[Dict]:
        """Realiza reverse DNS lookup para um IP."""
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')

            hostnames = [str(answer).rstrip('.') for answer in answers]

            return {
                'ip': ip,
                'hostnames': hostnames
            }

        except Exception:
            return None


# Wordlist padrão compacta
DEFAULT_DNS_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'staging',
    'test', 'admin', 'portal', 'blog', 'shop', 'forum', 'store', 'vpn', 'mysql',
    'db', 'database', 'cdn', 'mobile', 'm', 'app', 'beta', 'demo', 'support'
]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dnsbruter.py <domain> [wordlist]")
        sys.exit(1)

    plugin = DNSBruterPlugin()
    domain = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None

    # Se não tiver wordlist, cria uma temporária
    if not wordlist:
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for word in DEFAULT_DNS_WORDLIST:
                f.write(f"{word}\n")
            wordlist = f.name

    print(f"Running DNSBruter on {domain}...")
    result = plugin.run(domain, wordlist=wordlist)

    print(json.dumps(result, indent=2))
