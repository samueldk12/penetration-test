#!/usr/bin/env python3
"""
Selenium Fuzzer Plugin
Parameter fuzzing and form input testing using Selenium WebDriver
"""

# Add project root to path
from pathlib import Path
import sys
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'tools'))

try:
    from plugin_system import PluginInterface
except ImportError:
    from tools.plugin_system import PluginInterface

import sys
import json
import time
import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available - install with: pip install selenium")


class SeleniumFuzzer(PluginInterface):
    def __init__(self, config=None):
        super().__init__(config)

    name = "selenium_fuzzer"
    version = "1.0.0"
    author = "Penetration Test Suite"
    description = "Selenium-based parameter fuzzing and input testing"
    category = "web_testing"
    requires = ['selenium', 'beautifulsoup4']
    def load_wordlist(self):
        """Load wordlist from file"""
        if not self.wordlist_path:
            # Try to load combined wordlist from default location
            combined_payloads = []

            # Try to load from wordlists directory
            wordlist_dir = self.options.get('wordlist_dir', 'wordlists')
            default_lists = ['sqli.txt', 'xss.txt', 'lfi.txt', 'rce.txt', 'iframe.txt']

            for wordlist_file in default_lists:
                possible_paths = [
                    os.path.join(wordlist_dir, wordlist_file),
                    os.path.join('..', '..', '..', 'wordlists', wordlist_file),
                    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'wordlists', wordlist_file)
                ]

                for filepath in possible_paths:
                    try:
                        if os.path.exists(filepath):
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                            combined_payloads.extend(payloads[:50])  # First 50 from each
                            print(f"[+] Loaded {len(payloads[:50])} payloads from {wordlist_file}")
                            break
                    except:
                        continue

            if combined_payloads:
                self.wordlist = combined_payloads
                print(f"[+] Total payloads loaded: {len(self.wordlist)}")
                return True

            # Fallback to default fuzzing payloads if files not found
            print("[!] Using default fuzzing payloads")
            self.wordlist = [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "<script>alert('XSS')</script>",
                "../../../etc/passwd",
                "'; DROP TABLE users--",
                "%27 OR %271%27=%271",
                "admin' --",
                "1' OR '1' = '1",
                "<img src=x onerror=alert(1)>",
                "${7*7}",
                "{{7*7}}",
                "'; WAITFOR DELAY '00:00:05'--",
                "1 AND 1=1",
                "1 AND 1=2",
                "../",
                "..\\",
                "/etc/passwd",
                "C:\\windows\\system32\\",
                "<iframe src='javascript:alert(1)'>",
                "javascript:alert(1)"
            ]
            print("[*] Using default fuzzing payloads")
        else:
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.wordlist = [line.strip() for line in f if line.strip()]
                print(f"[+] Loaded {len(self.wordlist)} payloads from wordlist")
            except Exception as e:
                print(f"[!] Failed to load wordlist: {e}")
                return False

        return True

    def init_driver(self):
        """Initialize Selenium WebDriver"""
        print(f"[*] Initializing {self.browser_type} browser...")

        try:
            if 'chrome' in self.browser_type:
                chrome_options = ChromeOptions()
                if 'headless' in self.browser_type:
                    chrome_options.add_argument('--headless')
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                chrome_options.add_argument('--disable-gpu')
                chrome_options.add_argument('--window-size=1920,1080')
                self.driver = webdriver.Chrome(options=chrome_options)

            elif 'firefox' in self.browser_type:
                firefox_options = FirefoxOptions()
                if 'headless' in self.browser_type:
                    firefox_options.add_argument('--headless')
                self.driver = webdriver.Firefox(options=firefox_options)

            else:
                print(f"[!] Unsupported browser: {self.browser_type}")
                return False

            self.driver.set_page_load_timeout(self.timeout)
            print("[+] Browser initialized successfully")
            return True

        except Exception as e:
            print(f"[!] Failed to initialize browser: {e}")
            print("[!] Make sure WebDriver is installed:")
            print("    Chrome: https://chromedriver.chromium.org/")
            print("    Firefox: https://github.com/mozilla/geckodriver/releases")
            return False

    def check_page_content(self, payload, url):
        """Check page for errors, SQL errors, and XSS reflection"""
        findings = []

        try:
            page_source = self.driver.page_source.lower()

            # Check for errors
            if self.check_errors:
                for pattern in self.error_patterns:
                    if re.search(pattern, page_source, re.IGNORECASE):
                        findings.append({
                            'type': 'error_message',
                            'severity': 'medium',
                            'pattern': pattern,
                            'payload': payload,
                            'url': url,
                            'description': f'Error pattern detected: {pattern}'
                        })
                        self.results['stats']['errors_found'] += 1
                        break

            # Check for SQL errors
            if self.check_sql:
                for pattern in self.sql_patterns:
                    if re.search(pattern, page_source, re.IGNORECASE):
                        findings.append({
                            'type': 'sql_error',
                            'severity': 'high',
                            'pattern': pattern,
                            'payload': payload,
                            'url': url,
                            'description': f'SQL error detected - possible SQL injection: {pattern}'
                        })
                        self.results['stats']['sql_errors'] += 1
                        break

            # Check for XSS reflection
            if self.check_xss:
                # Look for payload reflection in page
                if payload in self.driver.page_source:
                    # Check if it's in a potentially dangerous context
                    soup = BeautifulSoup(self.driver.page_source, 'html.parser')

                    # Check if payload is in script tags or event handlers
                    scripts = soup.find_all('script')
                    for script in scripts:
                        if payload in str(script):
                            findings.append({
                                'type': 'xss_reflection',
                                'severity': 'high',
                                'payload': payload,
                                'url': url,
                                'context': 'script_tag',
                                'description': 'Payload reflected in script tag - possible XSS'
                            })
                            self.results['stats']['xss_reflected'] += 1
                            break

                    # Check for reflection in HTML attributes
                    all_tags = soup.find_all()
                    for tag in all_tags:
                        for attr, value in tag.attrs.items():
                            if isinstance(value, str) and payload in value:
                                findings.append({
                                    'type': 'xss_reflection',
                                    'severity': 'medium',
                                    'payload': payload,
                                    'url': url,
                                    'context': f'{tag.name}[{attr}]',
                                    'description': f'Payload reflected in {tag.name} {attr} attribute'
                                })
                                break

            # Check for iframe injection
            if self.check_iframe:
                if 'iframe' in payload.lower() or 'frame' in payload.lower():
                    soup = BeautifulSoup(self.driver.page_source, 'html.parser')

                    # Check for injected iframes
                    iframes = soup.find_all('iframe')
                    for iframe in iframes:
                        iframe_str = str(iframe).lower()
                        # Check for dangerous iframe attributes
                        if any(indicator in iframe_str for indicator in ['javascript:', 'data:text/html', 'srcdoc=', 'onload=', 'onerror=']):
                            # Check if this iframe contains our payload
                            if payload.lower() in self.driver.page_source.lower():
                                findings.append({
                                    'type': 'iframe_injection',
                                    'severity': 'high',
                                    'payload': payload,
                                    'url': url,
                                    'iframe_src': iframe.get('src', 'N/A'),
                                    'description': 'Iframe injection detected - potentially dangerous iframe injected'
                                })
                                self.results['stats']['iframe_injected'] += 1
                                break

                    # Check for clickjacking vulnerability (lack of X-Frame-Options)
                    try:
                        script = """
                        return (async () => {
                            const response = await fetch(window.location.href);
                            return {
                                'x-frame-options': response.headers.get('x-frame-options'),
                                'csp': response.headers.get('content-security-policy')
                            };
                        })();
                        """
                        headers = self.driver.execute_script(script)
                        if headers:
                            x_frame = headers.get('x-frame-options')
                            csp = headers.get('csp')

                            if not x_frame and (not csp or 'frame-ancestors' not in str(csp).lower()):
                                findings.append({
                                    'type': 'clickjacking',
                                    'severity': 'medium',
                                    'payload': payload,
                                    'url': url,
                                    'description': 'No X-Frame-Options or CSP frame-ancestors header - clickjacking possible'
                                })
                    except:
                        pass

            # Take screenshot if enabled
            if self.screenshot and findings:
                try:
                    screenshot_dir = 'screenshots'
                    os.makedirs(screenshot_dir, exist_ok=True)
                    filename = f"{screenshot_dir}/finding_{int(time.time())}.png"
                    self.driver.save_screenshot(filename)
                    for finding in findings:
                        finding['screenshot'] = filename
                except:
                    pass

        except Exception as e:
            print(f"[!] Error checking page content: {e}")

        return findings

    def fuzz_url_parameters(self):
        """Fuzz URL parameters"""
        print("[*] Starting URL parameter fuzzing...")

        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)

        if not params:
            print("[!] No URL parameters found to fuzz")
            return

        print(f"[+] Found parameters: {list(params.keys())}")

        for param_name in params.keys():
            print(f"\n[*] Fuzzing parameter: {param_name}")

            for payload in self.wordlist:
                self.results['stats']['tests'] += 1

                # Build URL with payload
                new_params = params.copy()
                new_params[param_name] = [payload]

                new_query = urlencode(new_params, doseq=True)
                new_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                print(f"[*] Testing: {param_name}={payload[:50]}...")

                try:
                    self.driver.get(new_url)
                    time.sleep(0.5)  # Wait for page to render

                    # Check for findings
                    findings = self.check_page_content(payload, new_url)
                    for finding in findings:
                        finding['parameter'] = param_name
                        if finding['severity'] in ['critical', 'high']:
                            self.results['vulnerabilities'].append(finding)
                            print(f"[!] {finding['severity'].upper()}: {finding['description']}")
                        else:
                            self.results['findings'].append(finding)

                except TimeoutException:
                    print(f"[!] Timeout loading page")
                except Exception as e:
                    print(f"[!] Error: {e}")

                time.sleep(self.delay)

    def fuzz_form_inputs(self):
        """Fuzz form input fields"""
        print("[*] Starting form input fuzzing...")

        try:
            # Load target page
            self.driver.get(self.target)
            time.sleep(1)

            # Find all forms
            forms = self.driver.find_elements(By.TAG_NAME, 'form')

            if not forms:
                print("[!] No forms found on page")
                return

            print(f"[+] Found {len(forms)} form(s)")

            for form_idx, form in enumerate(forms):
                print(f"\n[*] Testing form {form_idx + 1}...")

                # Find all input fields in the form
                inputs = form.find_elements(By.TAG_NAME, 'input')
                textareas = form.find_elements(By.TAG_NAME, 'textarea')
                all_inputs = inputs + textareas

                # Filter to text inputs
                text_inputs = []
                for inp in all_inputs:
                    input_type = inp.get_attribute('type')
                    if input_type in ['text', 'search', 'email', 'url', 'tel', None] or inp.tag_name == 'textarea':
                        text_inputs.append(inp)

                if not text_inputs:
                    print(f"[!] No text inputs found in form {form_idx + 1}")
                    continue

                print(f"[+] Found {len(text_inputs)} text input(s)")

                # Fuzz each input
                for input_idx, inp in enumerate(text_inputs):
                    input_name = inp.get_attribute('name') or inp.get_attribute('id') or f'input_{input_idx}'
                    print(f"\n[*] Fuzzing input: {input_name}")

                    for payload in self.wordlist:
                        self.results['stats']['tests'] += 1

                        # Reload page to reset form
                        self.driver.get(self.target)
                        time.sleep(0.5)

                        try:
                            # Re-find the form and input
                            current_form = self.driver.find_elements(By.TAG_NAME, 'form')[form_idx]
                            current_inputs = current_form.find_elements(By.TAG_NAME, 'input') + \
                                           current_form.find_elements(By.TAG_NAME, 'textarea')

                            # Find our input
                            current_input = None
                            for ci in current_inputs:
                                ci_name = ci.get_attribute('name') or ci.get_attribute('id') or ''
                                if ci_name == input_name:
                                    current_input = ci
                                    break

                            if not current_input:
                                continue

                            # Clear and input payload
                            current_input.clear()
                            current_input.send_keys(payload)

                            print(f"[*] Testing: {input_name}={payload[:50]}...")

                            # Submit form (try to find submit button)
                            try:
                                submit_btn = current_form.find_element(By.CSS_SELECTOR, 'button[type="submit"], input[type="submit"]')
                                submit_btn.click()
                            except:
                                # Try Enter key
                                current_input.send_keys(Keys.RETURN)

                            time.sleep(1)  # Wait for response

                            # Check for findings
                            current_url = self.driver.current_url
                            findings = self.check_page_content(payload, current_url)
                            for finding in findings:
                                finding['form_index'] = form_idx
                                finding['input_name'] = input_name
                                if finding['severity'] in ['critical', 'high']:
                                    self.results['vulnerabilities'].append(finding)
                                    print(f"[!] {finding['severity'].upper()}: {finding['description']}")
                                else:
                                    self.results['findings'].append(finding)

                        except Exception as e:
                            print(f"[!] Error testing input: {e}")

                        time.sleep(self.delay)

        except Exception as e:
            print(f"[!] Error in form fuzzing: {e}")

    def run(self, target, **kwargs):
        """Main execution"""
        self.target = target
        self.options = kwargs
        if not SELENIUM_AVAILABLE:
            return {
                'error': 'Selenium not available - install with: pip install selenium',
                'target': self.target
            }

        # Load wordlist
        if not self.load_wordlist():
            return {
                'error': 'Failed to load wordlist',
                'target': self.target
            }

        # Initialize driver
        if not self.init_driver():
            return {
                'error': 'Failed to initialize WebDriver',
                'target': self.target
            }

        try:
            # Run fuzzing based on mode
            if self.mode in ['param', 'both']:
                self.fuzz_url_parameters()

            if self.mode in ['form', 'both']:
                self.fuzz_form_inputs()

        finally:
            # Always close driver
            if self.driver:
                self.driver.quit()
                print("\n[*] Browser closed")

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    fuzzer = SeleniumFuzzer(target, options)
    results = fuzzer.run()

    # Print summary
    print("\n" + "="*60)
    print("SELENIUM FUZZER SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Target: {results['target']}")
    print(f"Mode: {results['mode']}")
    print(f"Total Tests: {results['stats']['tests']}")
    print(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")
    print(f"Findings: {len(results['findings'])}")
    print(f"Errors Detected: {results['stats']['errors_found']}")
    print(f"SQL Errors: {results['stats']['sql_errors']}")
    print(f"XSS Reflections: {results['stats']['xss_reflected']}")

    # Print vulnerabilities
    if results['vulnerabilities']:
        print(f"\n[!] HIGH SEVERITY VULNERABILITIES:")
        for vuln in results['vulnerabilities']:
            print(f"  - [{vuln['severity'].upper()}] {vuln['type']}: {vuln['description']}")
            print(f"    Payload: {vuln['payload']}")
            if 'parameter' in vuln:
                print(f"    Parameter: {vuln['parameter']}")
            if 'input_name' in vuln:
                print(f"    Input: {vuln['input_name']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [options_json]")
        print("\nExamples:")
        print(f"  # Fuzz URL parameters")
        print(f"  {sys.argv[0]} 'http://example.com/search?q=test'")
        print(f"\n  # Fuzz form inputs")
        print(f"  {sys.argv[0]} http://example.com/login '{{\"mode\": \"form\"}}'")
        print(f"\n  # Both with custom wordlist")
        print(f"  {sys.argv[0]} http://example.com/page '{{\"mode\": \"both\", \"wordlist\": \"payloads.txt\"}}'")
        sys.exit(1)

    target = sys.argv[1]
    options = None

    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except:
            print("[!] Invalid JSON options")
            sys.exit(1)

    result = main(target, options)
    print("\n" + json.dumps(result, indent=2))
