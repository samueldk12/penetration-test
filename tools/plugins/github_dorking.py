#!/usr/bin/env python3
"""
GitHub Dorking Plugin - Busca secrets e informações sensíveis no GitHub
"""

import requests
from typing import Dict, Any, List
import time
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class GitHubDorkingPlugin(PluginInterface):
    """Plugin para GitHub dorking."""

    name = "github_dorking"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Search for secrets and sensitive information on GitHub"
    category = "recon"
    requires = ["requests"]

    # Dorks comuns
    DORKS = [
        '{domain} password',
        '{domain} api_key',
        '{domain} secret',
        '{domain} token',
        '{domain} aws_access_key_id',
        '{domain} credentials',
        '{domain} config',
        '{domain} .env',
        '{domain} private key',
        '{domain} db_password',
        '{domain} extension:json',
        '{domain} extension:xml',
        '{domain} extension:yml',
        '{domain} extension:properties'
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Executa GitHub dorking.

        Args:
            target: Domínio alvo
            **kwargs: github_token (str) - Token GitHub API (opcional)

        Returns:
            Dicionário com resultados
        """
        github_token = kwargs.get('github_token')

        print(f"[*] Starting GitHub dorking for {target}...")

        if not github_token:
            print("[!] WARNING: No GitHub token provided. Rate limit will be very restrictive (60 req/hour)")
            print("[!] Provide token with --config github_token=YOUR_TOKEN for better results")

        findings = []

        headers = {}
        if github_token:
            headers['Authorization'] = f'token {github_token}'

        for dork_template in self.DORKS:
            dork = dork_template.format(domain=target)

            print(f"[*] Searching: {dork}")

            try:
                # GitHub Search API
                api_url = "https://api.github.com/search/code"
                params = {
                    'q': dork,
                    'per_page': 10  # Limita para evitar rate limit
                }

                response = requests.get(api_url, headers=headers, params=params, timeout=10)

                if response.status_code == 200:
                    data = response.json()

                    if data.get('total_count', 0) > 0:
                        print(f"[+] Found {data['total_count']} results for: {dork}")

                        for item in data.get('items', []):
                            finding = {
                                'dork': dork,
                                'file': item.get('name'),
                                'path': item.get('path'),
                                'repo': item.get('repository', {}).get('full_name'),
                                'url': item.get('html_url'),
                                'score': item.get('score', 0)
                            }
                            findings.append(finding)

                elif response.status_code == 403:
                    print("[!] Rate limit exceeded. Waiting 60 seconds...")
                    time.sleep(60)

                elif response.status_code == 422:
                    print(f"[!] Invalid search query: {dork}")

                # Rate limiting (GitHub permite 30 req/min com token, 10 sem)
                time.sleep(2 if github_token else 6)

            except Exception as e:
                error = f"Error searching for '{dork}': {str(e)}"
                self.errors.append(error)
                print(f"[!] {error}")

        print(f"\n[+] Total findings: {len(findings)}")

        self.results = findings

        return {
            'findings': findings,
            'count': len(findings)
        }
