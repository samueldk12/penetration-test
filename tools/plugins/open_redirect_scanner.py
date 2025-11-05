#!/usr/bin/env python3
"""
Open Redirect Scanner Plugin - Detecta vulnerabilidades de Open Redirect
"""

import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class OpenRedirectScannerPlugin(PluginInterface):
    """Plugin para detectar Open Redirect vulnerabilities."""

    name = "open_redirect_scanner"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Automated Open Redirect vulnerability scanner"
    category = "vuln_scan"
    requires = ["requests"]

    # Payloads para Open Redirect
    PAYLOADS = [
        # External domains
        "https://evil.com",
        "http://evil.com",
        "//evil.com",
        "///evil.com",

        # Protocol-relative
        "//google.com",
        "//evil.com",

        # With @ symbol
        "https://legitimate.com@evil.com",
        "http://legitimate.com@evil.com",

        # URL encoded
        "https%3A%2F%2Fevil.com",
        "%2F%2Fevil.com",

        # Double encoded
        "%252f%252fevil.com",

        # Backslashes (Windows)
        "https:\\evil.com",
        "\\\\evil.com",

        # Whitespace bypass
        "https://evil.com ",
        " https://evil.com",

        # Javascript protocol
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ]

    # Parâmetros comuns de redirect
    REDIRECT_PARAMS = [
        'redirect', 'url', 'next', 'redir', 'destination',
        'return', 'returnTo', 'return_to', 'returnUrl', 'return_url',
        'goto', 'target', 'link', 'continue', 'forward',
        'out', 'view', 'to', 'uri', 'path', 'callback'
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia URL para Open Redirect.

        Args:
            target: URL alvo
            **kwargs:
                method: GET|POST (default: GET)
                params: Parâmetros (opcional)
                timeout: Timeout (default: 5)
                follow_redirects: Seguir redirects (default: False)

        Returns:
            Dicionário com vulnerabilidades
        """
        method = kwargs.get('method', 'GET').upper()
        params = kwargs.get('params', {})
        timeout = kwargs.get('timeout', 5)
        follow_redirects = kwargs.get('follow_redirects', False)

        print(f"[*] Scanning {target} for Open Redirect vulnerabilities...")

        vulnerabilities = []

        # Parse URL
        parsed = urlparse(target)

        # Se não tem parâmetros, tenta extrair
        if not params:
            params = parse_qs(parsed.query)
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        # Se ainda não tem parâmetros, tenta parâmetros comuns
        if not params:
            print("[*] No parameters found, testing common redirect parameters...")

            for param_name in self.REDIRECT_PARAMS:
                print(f"[*] Testing parameter: {param_name}")

                vuln = self._test_parameter(
                    target, param_name, {},
                    method, timeout, follow_redirects
                )

                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[!] VULNERABLE! Parameter: {param_name}")
        else:
            # Testa cada parâmetro existente
            for param_name in params.keys():
                print(f"[*] Testing parameter: {param_name}")

                vuln = self._test_parameter(
                    target, param_name, params,
                    method, timeout, follow_redirects
                )

                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[!] VULNERABLE! Parameter: {param_name}")

        print(f"\n[+] Found {len(vulnerabilities)} Open Redirect vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'target': target
        }

    def _test_parameter(self, base_url: str, param_name: str, params: dict,
                       method: str, timeout: int, follow_redirects: bool) -> Dict:
        """Testa um parâmetro específico."""

        for payload in self.PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                # Reconstrói URL
                parsed = urlparse(base_url)
                query_string = urlencode(test_params)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    query_string,
                    parsed.fragment
                ))

                # Faz requisição
                if method == 'GET':
                    response = requests.get(
                        test_url,
                        timeout=timeout,
                        allow_redirects=follow_redirects,
                        verify=False
                    )
                elif method == 'POST':
                    response = requests.post(
                        base_url,
                        data=test_params,
                        timeout=timeout,
                        allow_redirects=follow_redirects,
                        verify=False
                    )
                else:
                    continue

                # Verifica redirect
                is_vulnerable = self._check_redirect(response, payload)

                if is_vulnerable:
                    return {
                        'type': 'open_redirect',
                        'severity': 'medium',
                        'url': base_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'description': f'Open Redirect vulnerability in parameter "{param_name}"',
                        'impact': 'Attacker can redirect users to malicious sites',
                        'remediation': 'Validate redirect URLs against whitelist',
                        'evidence': {
                            'status_code': response.status_code,
                            'location_header': response.headers.get('Location', ''),
                            'final_url': response.url if follow_redirects else ''
                        }
                    }

            except:
                pass

        return None

    def _check_redirect(self, response, payload: str) -> bool:
        """Verifica se houve redirect para payload."""

        # Verifica status code de redirect
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False

        # Verifica Location header
        location = response.headers.get('Location', '')

        if not location:
            return False

        # Verifica se location contém o payload
        # Remove protocol-relative // para comparação
        payload_clean = payload.replace('//', '').replace('https:', '').replace('http:', '')
        location_clean = location.replace('//', '').replace('https:', '').replace('http:', '')

        if payload_clean in location_clean:
            return True

        # Verifica domínios específicos
        dangerous_domains = ['evil.com', 'google.com']
        for domain in dangerous_domains:
            if domain in location.lower():
                return True

        return False
