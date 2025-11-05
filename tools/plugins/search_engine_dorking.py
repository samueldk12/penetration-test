#!/usr/bin/env python3
"""
Search Engine Dorking Plugin - Busca subdomínios e informações usando Google/Bing dorks
"""

import requests
import re
from typing import Dict, Any, List, Set
import time
from urllib.parse import quote_plus, urlparse
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class SearchEngineDorkingPlugin(PluginInterface):
    """Plugin para search engine dorking (Google, Bing)."""

    name = "search_engine_dorking"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Search for subdomains and sensitive information using Google/Bing dorks"
    category = "recon"
    requires = ["requests"]

    # Dorks para subdomain discovery
    SUBDOMAIN_DORKS = [
        'site:{domain}',
        'site:*.{domain}',
        'site:{domain} -www',
    ]

    # Dorks para sensitive files
    SENSITIVE_FILE_DORKS = [
        'site:{domain} filetype:pdf',
        'site:{domain} filetype:xls',
        'site:{domain} filetype:doc',
        'site:{domain} filetype:txt',
        'site:{domain} filetype:sql',
        'site:{domain} filetype:log',
        'site:{domain} filetype:bak',
        'site:{domain} inurl:backup',
        'site:{domain} inurl:admin',
        'site:{domain} inurl:login',
        'site:{domain} inurl:password',
        'site:{domain} inurl:config',
        'site:{domain} intitle:"index of"',
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Executa search engine dorking.

        Args:
            target: Domínio alvo
            **kwargs:
                engines: Lista de engines (google, bing) - default: ['google']
                mode: subdomain|sensitive|all - default: subdomain
                delay: Delay entre queries em segundos - default: 2

        Returns:
            Dicionário com resultados
        """
        engines = kwargs.get('engines', ['google'])
        mode = kwargs.get('mode', 'subdomain')
        delay = kwargs.get('delay', 2)

        print(f"[*] Starting search engine dorking for {target}...")
        print(f"[*] Engines: {', '.join(engines)}")
        print(f"[*] Mode: {mode}")

        all_subdomains: Set[str] = set()
        all_urls: Set[str] = set()

        # Seleciona dorks baseado no modo
        if mode == 'subdomain':
            dorks = [d.format(domain=target) for d in self.SUBDOMAIN_DORKS]
        elif mode == 'sensitive':
            dorks = [d.format(domain=target) for d in self.SENSITIVE_FILE_DORKS]
        elif mode == 'all':
            dorks = [d.format(domain=target) for d in self.SUBDOMAIN_DORKS + self.SENSITIVE_FILE_DORKS]
        else:
            dorks = []

        for dork in dorks:
            print(f"[*] Searching: {dork}")

            for engine in engines:
                if engine == 'google':
                    results = self._search_google(dork, delay)
                elif engine == 'bing':
                    results = self._search_bing(dork, delay)
                else:
                    continue

                # Extrai subdomínios e URLs dos resultados
                for url in results:
                    all_urls.add(url)

                    # Extrai subdomain
                    parsed = urlparse(url)
                    if parsed.netloc and target in parsed.netloc:
                        all_subdomains.add(parsed.netloc)

        print(f"\n[+] Found {len(all_subdomains)} unique subdomains")
        print(f"[+] Found {len(all_urls)} unique URLs")

        self.results = {
            'subdomains': list(all_subdomains),
            'urls': list(all_urls)
        }

        return {
            'subdomains': list(all_subdomains),
            'urls': list(all_urls),
            'subdomain_count': len(all_subdomains),
            'url_count': len(all_urls),
            'target': target
        }

    def _search_google(self, dork: str, delay: int = 2) -> List[str]:
        """
        Busca no Google (scraping).

        Args:
            dork: Dork query
            delay: Delay em segundos

        Returns:
            Lista de URLs encontradas
        """
        urls = []

        try:
            # Google search URL
            search_url = f"https://www.google.com/search?q={quote_plus(dork)}&num=50"

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }

            response = requests.get(search_url, headers=headers, timeout=10)

            if response.status_code == 200:
                # Extrai URLs dos resultados (regex simples)
                # Formato: <a href="/url?q=https://example.com/...
                pattern = r'<a href="/url\?q=(https?://[^&]+)'
                matches = re.findall(pattern, response.text)

                for url in matches:
                    # Limpa URL
                    url = url.split('&')[0]
                    urls.append(url)

                print(f"    [Google] Found {len(urls)} results")

            elif response.status_code == 429:
                self.errors.append("Google rate limit exceeded")
                print(f"    [!] Rate limit exceeded")

            # Delay para evitar rate limiting
            time.sleep(delay)

        except Exception as e:
            self.errors.append(f"Error searching Google: {str(e)}")

        return urls

    def _search_bing(self, dork: str, delay: int = 2) -> List[str]:
        """
        Busca no Bing.

        Args:
            dork: Dork query
            delay: Delay em segundos

        Returns:
            Lista de URLs encontradas
        """
        urls = []

        try:
            # Bing search URL
            search_url = f"https://www.bing.com/search?q={quote_plus(dork)}&count=50"

            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }

            response = requests.get(search_url, headers=headers, timeout=10)

            if response.status_code == 200:
                # Extrai URLs dos resultados
                # Formato Bing: <a href="https://example.com/..."
                pattern = r'<a href="(https?://[^"]+)"'
                matches = re.findall(pattern, response.text)

                for url in matches:
                    # Filtra URLs do Bing (bing.com)
                    if 'bing.com' not in url and 'microsoft.com' not in url:
                        urls.append(url)

                print(f"    [Bing] Found {len(urls)} results")

            # Delay
            time.sleep(delay)

        except Exception as e:
            self.errors.append(f"Error searching Bing: {str(e)}")

        return urls
