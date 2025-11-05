#!/usr/bin/env python3
"""
Wayback URLs Plugin - Descobre URLs históricas do Wayback Machine
"""

import requests
from typing import Dict, Any, List
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class WaybackURLsPlugin(PluginInterface):
    """Plugin para descobrir URLs históricas."""

    name = "wayback_urls"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Discovers historical URLs from Wayback Machine"
    category = "recon"
    requires = ["requests"]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Descobre URLs do Wayback Machine.

        Args:
            target: Domínio alvo
            **kwargs: limit (int) - Limite de URLs

        Returns:
            Dicionário com URLs descobertas
        """
        limit = kwargs.get('limit', 1000)

        print(f"[*] Querying Wayback Machine for {target}...")

        urls = set()

        try:
            # API do Wayback Machine
            api_url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original&collapse=urlkey&limit={limit}"

            response = requests.get(api_url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                # Primeira linha é o header, pula ela
                for item in data[1:]:
                    url = item[0]
                    urls.add(url)

                print(f"[+] Found {len(urls)} unique URLs")

                self.results = list(urls)

                return {
                    'urls': list(urls),
                    'count': len(urls)
                }

            else:
                error = f"API returned status code: {response.status_code}"
                self.errors.append(error)
                return {'error': error}

        except Exception as e:
            error = f"Error querying Wayback Machine: {str(e)}"
            self.errors.append(error)
            return {'error': error}
