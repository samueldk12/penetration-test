#!/usr/bin/env python3
"""
Certificate Transparency Plugin - Busca subdomínios em Certificate Transparency logs
Fontes: crt.sh, censys.io, certspotter
"""

import requests
import json
from typing import Dict, Any, List, Set
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class CertTransparencyPlugin(PluginInterface):
    """Plugin para buscar subdomínios em Certificate Transparency logs."""

    name = "cert_transparency"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Search for subdomains in Certificate Transparency logs (crt.sh, censys)"
    category = "recon"
    requires = ["requests"]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Busca subdomínios em CT logs.

        Args:
            target: Domínio alvo
            **kwargs:
                sources: Lista de fontes (crtsh, censys) - default: all

        Returns:
            Dicionário com subdomínios descobertos
        """
        sources = kwargs.get('sources', ['crtsh'])

        print(f"[*] Searching Certificate Transparency logs for {target}...")

        all_subdomains: Set[str] = set()

        # Source 1: crt.sh
        if 'crtsh' in sources:
            print("[*] Querying crt.sh...")
            subdomains = self._query_crtsh(target)
            all_subdomains.update(subdomains)
            print(f"[+] crt.sh: {len(subdomains)} subdomains")

        # Source 2: Certspotter (alternativa)
        if 'certspotter' in sources:
            print("[*] Querying certspotter...")
            subdomains = self._query_certspotter(target)
            all_subdomains.update(subdomains)
            print(f"[+] certspotter: {len(subdomains)} subdomains")

        # Remove wildcards e limpa
        cleaned = set()
        for subdomain in all_subdomains:
            # Remove wildcard
            if subdomain.startswith('*.'):
                subdomain = subdomain[2:]

            # Valida formato
            if subdomain and '.' in subdomain and subdomain.endswith(target):
                cleaned.add(subdomain.lower())

        print(f"\n[+] Total unique subdomains: {len(cleaned)}")

        self.results = list(cleaned)

        return {
            'subdomains': list(cleaned),
            'count': len(cleaned),
            'target': target
        }

    def _query_crtsh(self, domain: str) -> Set[str]:
        """
        Consulta crt.sh API.

        Args:
            domain: Domínio alvo

        Returns:
            Set de subdomínios
        """
        subdomains = set()

        try:
            # crt.sh JSON API
            url = f"https://crt.sh/?q=%.{domain}&output=json"

            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()

                    for entry in data:
                        # Extrai nome comum
                        name_value = entry.get('name_value', '')

                        # Pode ter múltiplos nomes separados por \n
                        for name in name_value.split('\n'):
                            name = name.strip().lower()
                            if name:
                                subdomains.add(name)

                        # Também pega common_name
                        common_name = entry.get('common_name', '').strip().lower()
                        if common_name:
                            subdomains.add(common_name)

                except json.JSONDecodeError:
                    self.errors.append("Failed to parse crt.sh JSON response")

        except requests.exceptions.Timeout:
            self.errors.append("crt.sh query timed out")
        except Exception as e:
            self.errors.append(f"Error querying crt.sh: {str(e)}")

        return subdomains

    def _query_certspotter(self, domain: str) -> Set[str]:
        """
        Consulta Certspotter API (alternativa ao crt.sh).

        Args:
            domain: Domínio alvo

        Returns:
            Set de subdomínios
        """
        subdomains = set()

        try:
            # Certspotter API (free, sem auth necessária)
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"

            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()

                for entry in data:
                    dns_names = entry.get('dns_names', [])
                    for name in dns_names:
                        name = name.strip().lower()
                        if name:
                            subdomains.add(name)

        except Exception as e:
            self.errors.append(f"Error querying certspotter: {str(e)}")

        return subdomains
