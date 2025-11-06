#!/usr/bin/env python3
"""
Interactive Selenium Pentesting Plugin
Real-time interactive pentesting with hotkeys and visual feedback
"""

# Add project root to path
from pathlib import Path
import sys
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'tools'))

try:
    from tools.plugin_system import PluginInterface
except ImportError:
    from plugin_system import PluginInterface

import sys
import json
import time
import threading
from datetime import datetime
from bs4 import BeautifulSoup

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available - install with: pip install selenium")

try:
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False
    print("[!] pynput not available - install with: pip install pynput")


class InteractivePentester(PluginInterface):
    def __init__(self, config=None):
        super().__init__(config)

    name = "selenium_interactive"
    version = "1.0.0"
    author = "Penetration Test Suite"
    description = "Interactive penetration testing with Selenium and hotkeys"
    category = "interactive_testing"
    requires = ['selenium', 'pynput', 'beautifulsoup4']
    def load_wordlist(self, filename):
        """Load wordlist from file"""
        import os

        # Try multiple paths
        possible_paths = [
            os.path.join(self.wordlist_dir, filename),
            os.path.join('..', '..', '..', 'wordlists', filename),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'wordlists', filename)
        ]

        for filepath in possible_paths:
            try:
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        payloads = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                    print(f"[+] Loaded {len(payloads)} payloads from {filename}")
                    return payloads
            except Exception as e:
                continue

        # Fallback to default payloads
        print(f"[!] Could not load {filename}, using default payloads")

        if 'sqli' in filename:
            return [
                "' OR '1'='1", "' OR '1'='1' --", "\" OR \"1\"=\"1",
                "' OR 1=1--", "admin' --", "' UNION SELECT NULL--"
            ]
        elif 'xss' in filename:
            return [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>", "javascript:alert('XSS')"
            ]
        elif 'lfi' in filename:
            return [
                "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd"
            ]
        elif 'iframe' in filename:
            return [
                "<iframe src=\"javascript:alert(1)\"></iframe>",
                "<iframe src=\"https://evil.com\"></iframe>",
                "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
                "<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
                "<iframe src=\"x\" onload=\"alert(1)\"></iframe>",
                "<iframe src=\"https://victim.com\" style=\"opacity:0\"></iframe>"
            ]

        return []

    def init_driver(self):
        """Initialize Selenium WebDriver"""
        print("[*] Initializing browser...")

        try:
            if self.browser_type == 'chrome':
                chrome_options = ChromeOptions()
                chrome_options.add_argument('--disable-blink-features=AutomationControlled')
                chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
                chrome_options.add_experimental_option('useAutomationExtension', False)

                if self.proxy_enabled:
                    chrome_options.add_argument(f'--proxy-server=127.0.0.1:{self.proxy_port}')

                self.driver = webdriver.Chrome(options=chrome_options)

            elif self.browser_type == 'firefox':
                firefox_options = FirefoxOptions()

                if self.proxy_enabled:
                    firefox_options.set_preference("network.proxy.type", 1)
                    firefox_options.set_preference("network.proxy.http", "127.0.0.1")
                    firefox_options.set_preference("network.proxy.http_port", self.proxy_port)

                self.driver = webdriver.Firefox(options=firefox_options)

            # Inject helper script
            self.inject_helper_script()

            print("[+] Browser initialized")
            return True

        except Exception as e:
            print(f"[!] Failed to initialize browser: {e}")
            return False

    def inject_helper_script(self):
        """Inject JavaScript helper for visual feedback"""
        helper_js = """
        window.pentestHelper = {
            highlightElement: function(element) {
                if (element.originalBorder === undefined) {
                    element.originalBorder = element.style.border;
                }
                element.style.border = '3px solid #ff0000';
                element.style.backgroundColor = '#ffff00';
            },

            unhighlightElement: function(element) {
                if (element.originalBorder !== undefined) {
                    element.style.border = element.originalBorder;
                    element.style.backgroundColor = '';
                }
            },

            showNotification: function(message, type) {
                var notification = document.createElement('div');
                notification.id = 'pentest-notification';
                notification.style.position = 'fixed';
                notification.style.top = '20px';
                notification.style.right = '20px';
                notification.style.padding = '15px 25px';
                notification.style.borderRadius = '5px';
                notification.style.zIndex = '999999';
                notification.style.fontSize = '14px';
                notification.style.fontWeight = 'bold';
                notification.style.boxShadow = '0 4px 6px rgba(0,0,0,0.3)';

                if (type === 'testing') {
                    notification.style.backgroundColor = '#ffa500';
                    notification.style.color = 'white';
                } else if (type === 'success') {
                    notification.style.backgroundColor = '#28a745';
                    notification.style.color = 'white';
                } else if (type === 'vulnerability') {
                    notification.style.backgroundColor = '#dc3545';
                    notification.style.color = 'white';
                } else {
                    notification.style.backgroundColor = '#17a2b8';
                    notification.style.color = 'white';
                }

                notification.textContent = message;

                var existing = document.getElementById('pentest-notification');
                if (existing) {
                    existing.remove();
                }

                document.body.appendChild(notification);

                setTimeout(function() {
                    notification.remove();
                }, 3000);
            },

            logTest: function(testType, payload, result) {
                console.log('%c[PENTEST] ' + testType, 'color: red; font-weight: bold;');
                console.log('Payload:', payload);
                console.log('Result:', result);
            }
        };

        console.log('%c[PENTEST HELPER LOADED]', 'color: green; font-size: 16px; font-weight: bold;');
        """

        try:
            self.driver.execute_script(helper_js)
        except:
            pass

    def show_notification(self, message, notification_type='info'):
        """Show notification in browser"""
        try:
            self.driver.execute_script(
                f"window.pentestHelper.showNotification('{message}', '{notification_type}');"
            )
        except:
            pass

    def highlight_element(self, element):
        """Highlight element in browser"""
        try:
            self.driver.execute_script(
                "arguments[0].style.border = '3px solid red'; arguments[0].style.backgroundColor = '#ffff00';",
                element
            )
        except:
            pass

    def test_sql_injection(self, element):
        """Test SQL injection on element"""
        print("\n[*] Testing SQL Injection...")
        self.show_notification("🔍 Testing SQL Injection...", "testing")

        test_results = []
        original_value = element.get_attribute('value') or ''

        for payload in self.sql_payloads:
            try:
                # Clear and input payload
                element.clear()
                element.send_keys(payload)
                time.sleep(0.5)

                # Try to submit
                try:
                    element.send_keys(Keys.RETURN)
                    time.sleep(1)
                except:
                    pass

                # Check for SQL errors
                page_source = self.driver.page_source.lower()
                sql_errors = [
                    'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
                    'syntax error', 'database error', 'db error',
                    'you have an error in your sql', 'warning: mysql',
                    'unclosed quotation mark', 'quoted string not properly terminated'
                ]

                error_found = any(err in page_source for err in sql_errors)

                test_results.append({
                    'payload': payload,
                    'error_found': error_found,
                    'url': self.driver.current_url
                })

                if error_found:
                    vuln = {
                        'type': 'sql_injection',
                        'severity': 'high',
                        'payload': payload,
                        'url': self.driver.current_url,
                        'element': element.get_attribute('name') or element.get_attribute('id') or 'unknown',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results['vulnerabilities'].append(vuln)
                    self.show_notification("⚠️ SQL Injection vulnerability detected!", "vulnerability")
                    print(f"[!] SQL Injection found with payload: {payload}")
                    break

                # Navigate back if needed
                if self.driver.current_url != self.target:
                    self.driver.back()
                    time.sleep(1)
                    # Re-find element
                    return

            except Exception as e:
                print(f"[-] Error testing payload {payload}: {e}")

        self.results['tests_performed'].append({
            'type': 'sql_injection',
            'element': element.get_attribute('name') or element.get_attribute('id'),
            'results': test_results,
            'timestamp': datetime.now().isoformat()
        })

        if not any(r['error_found'] for r in test_results):
            self.show_notification("✓ No SQL Injection detected", "success")
            print("[+] No SQL injection found")

    def test_xss(self, element):
        """Test XSS on element"""
        print("\n[*] Testing XSS...")
        self.show_notification("🔍 Testing XSS...", "testing")

        test_results = []

        for payload in self.xss_payloads:
            try:
                # Clear and input payload
                element.clear()
                element.send_keys(payload)
                time.sleep(0.5)

                # Try to submit
                try:
                    element.send_keys(Keys.RETURN)
                    time.sleep(1)
                except:
                    pass

                # Check if payload is reflected
                page_source = self.driver.page_source

                # Check for unescaped payload
                if payload in page_source:
                    # Check if it's in a dangerous context
                    soup = BeautifulSoup(page_source, 'html.parser')
                    reflected = False

                    # Check script tags
                    for script in soup.find_all('script'):
                        if payload in str(script):
                            reflected = True
                            break

                    # Check event handlers
                    for tag in soup.find_all():
                        for attr in ['onclick', 'onload', 'onerror', 'onmouseover']:
                            if tag.get(attr) and payload in str(tag.get(attr)):
                                reflected = True
                                break

                    if reflected:
                        vuln = {
                            'type': 'xss',
                            'severity': 'high',
                            'payload': payload,
                            'url': self.driver.current_url,
                            'element': element.get_attribute('name') or element.get_attribute('id') or 'unknown',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results['vulnerabilities'].append(vuln)
                        self.show_notification("⚠️ XSS vulnerability detected!", "vulnerability")
                        print(f"[!] XSS found with payload: {payload}")
                        break

                test_results.append({
                    'payload': payload,
                    'reflected': reflected if 'reflected' in locals() else False,
                    'url': self.driver.current_url
                })

                # Navigate back if needed
                if self.driver.current_url != self.target:
                    self.driver.back()
                    time.sleep(1)
                    return

            except Exception as e:
                print(f"[-] Error testing payload {payload}: {e}")

        self.results['tests_performed'].append({
            'type': 'xss',
            'element': element.get_attribute('name') or element.get_attribute('id'),
            'results': test_results,
            'timestamp': datetime.now().isoformat()
        })

        if not any(r.get('reflected', False) for r in test_results):
            self.show_notification("✓ No XSS detected", "success")
            print("[+] No XSS found")

    def test_lfi(self, element):
        """Test Local File Inclusion"""
        print("\n[*] Testing LFI...")
        self.show_notification("🔍 Testing LFI...", "testing")

        test_results = []

        for payload in self.lfi_payloads:
            try:
                element.clear()
                element.send_keys(payload)
                time.sleep(0.5)

                try:
                    element.send_keys(Keys.RETURN)
                    time.sleep(1)
                except:
                    pass

                # Check for file content indicators
                page_source = self.driver.page_source.lower()
                lfi_indicators = [
                    'root:', '/bin/bash', '/bin/sh',  # Linux
                    '[boot loader]', '[operating systems]',  # Windows
                    'unable to open', 'failed to open stream'  # PHP errors
                ]

                lfi_found = any(indicator in page_source for indicator in lfi_indicators)

                if lfi_found:
                    vuln = {
                        'type': 'lfi',
                        'severity': 'critical',
                        'payload': payload,
                        'url': self.driver.current_url,
                        'element': element.get_attribute('name') or element.get_attribute('id') or 'unknown',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results['vulnerabilities'].append(vuln)
                    self.show_notification("⚠️ LFI vulnerability detected!", "vulnerability")
                    print(f"[!] LFI found with payload: {payload}")
                    break

                test_results.append({
                    'payload': payload,
                    'lfi_found': lfi_found,
                    'url': self.driver.current_url
                })

                if self.driver.current_url != self.target:
                    self.driver.back()
                    time.sleep(1)
                    return

            except Exception as e:
                print(f"[-] Error testing payload {payload}: {e}")

        self.results['tests_performed'].append({
            'type': 'lfi',
            'element': element.get_attribute('name') or element.get_attribute('id'),
            'results': test_results,
            'timestamp': datetime.now().isoformat()
        })

        if not any(r['lfi_found'] for r in test_results):
            self.show_notification("✓ No LFI detected", "success")
            print("[+] No LFI found")

    def test_iframe_injection(self, element):
        """Test Iframe Injection and Clickjacking"""
        print("\n[*] Testing Iframe Injection...")
        self.show_notification("🔍 Testing Iframe Injection...", "testing")

        test_results = []

        for payload in self.iframe_payloads:
            try:
                element.clear()
                element.send_keys(payload)
                time.sleep(0.5)

                try:
                    element.send_keys(Keys.RETURN)
                    time.sleep(1)
                except:
                    pass

                # Check for iframe injection indicators
                page_source = self.driver.page_source.lower()
                iframe_indicators = [
                    '<iframe', 'srcdoc=', 'javascript:',
                    'data:text/html', 'onload=', 'onerror='
                ]

                # Check if payload is reflected unescaped
                iframe_found = False
                if payload.lower() in page_source:
                    soup = BeautifulSoup(self.driver.page_source, 'html.parser')

                    # Check for iframe tags
                    iframes = soup.find_all('iframe')
                    for iframe in iframes:
                        if any(indicator in str(iframe).lower() for indicator in ['javascript:', 'data:text/html', 'srcdoc=']):
                            iframe_found = True
                            break

                    # Check for embedded iframes in attributes
                    for tag in soup.find_all():
                        for attr, value in tag.attrs.items():
                            if value and payload in str(value):
                                iframe_found = True
                                break

                # Check for clickjacking protection
                x_frame_options = None
                csp_frame_ancestors = None
                try:
                    # Make a request to check headers
                    current_url = self.driver.current_url
                    script = """
                    return (async () => {
                        const response = await fetch(window.location.href);
                        return {
                            'x-frame-options': response.headers.get('x-frame-options'),
                            'content-security-policy': response.headers.get('content-security-policy')
                        };
                    })();
                    """
                    headers = self.driver.execute_script(script)
                    if headers:
                        x_frame_options = headers.get('x-frame-options')
                        csp = headers.get('content-security-policy')
                        if csp and 'frame-ancestors' in csp.lower():
                            csp_frame_ancestors = True
                except:
                    pass

                # Clickjacking vulnerability if no protection
                clickjacking_vuln = (x_frame_options is None and csp_frame_ancestors is None)

                if iframe_found:
                    vuln = {
                        'type': 'iframe_injection',
                        'severity': 'high',
                        'payload': payload,
                        'url': self.driver.current_url,
                        'element': element.get_attribute('name') or element.get_attribute('id') or 'unknown',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results['vulnerabilities'].append(vuln)
                    self.show_notification("⚠️ Iframe Injection vulnerability detected!", "vulnerability")
                    print(f"[!] Iframe Injection found with payload: {payload}")
                    break

                if clickjacking_vuln and 'clickjacking' in payload.lower():
                    vuln = {
                        'type': 'clickjacking',
                        'severity': 'medium',
                        'payload': payload,
                        'url': self.driver.current_url,
                        'details': 'No X-Frame-Options or CSP frame-ancestors header found',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.results['vulnerabilities'].append(vuln)
                    self.show_notification("⚠️ Clickjacking vulnerability detected!", "vulnerability")
                    print(f"[!] Clickjacking vulnerability - No frame protection headers")

                test_results.append({
                    'payload': payload,
                    'iframe_found': iframe_found,
                    'clickjacking_vulnerable': clickjacking_vuln,
                    'x_frame_options': x_frame_options,
                    'url': self.driver.current_url
                })

                if self.driver.current_url != self.target:
                    self.driver.back()
                    time.sleep(1)
                    return

            except Exception as e:
                print(f"[-] Error testing payload {payload}: {e}")

        self.results['tests_performed'].append({
            'type': 'iframe_injection',
            'element': element.get_attribute('name') or element.get_attribute('id'),
            'results': test_results,
            'timestamp': datetime.now().isoformat()
        })

        if not any(r['iframe_found'] for r in test_results):
            self.show_notification("✓ No Iframe Injection detected", "success")
            print("[+] No Iframe Injection found")

    def execute_console_test(self, script):
        """Execute JavaScript test in console"""
        print(f"\n[*] Executing console test...")

        try:
            result = self.driver.execute_script(f"return {script}")

            test_result = {
                'script': script,
                'result': result,
                'timestamp': datetime.now().isoformat(),
                'url': self.driver.current_url
            }

            self.results['console_tests'].append(test_result)
            self.show_notification(f"✓ Console test executed", "success")
            print(f"[+] Result: {result}")

            return result

        except Exception as e:
            print(f"[!] Console test error: {e}")
            return None

    def on_press(self, key):
        """Handle key press"""
        try:
            # Track Ctrl key
            if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                self.ctrl_pressed = True

            # Hotkeys
            if self.ctrl_pressed and not self.testing_in_progress:
                if hasattr(key, 'char'):
                    # Ctrl + I = SQL Injection
                    if key.char == 'i':
                        self.testing_in_progress = True
                        threading.Thread(target=self.handle_sql_test).start()

                    # Ctrl + X = XSS
                    elif key.char == 'x':
                        self.testing_in_progress = True
                        threading.Thread(target=self.handle_xss_test).start()

                    # Ctrl + L = LFI
                    elif key.char == 'l':
                        self.testing_in_progress = True
                        threading.Thread(target=self.handle_lfi_test).start()

                    # Ctrl + F = Iframe Injection
                    elif key.char == 'f':
                        self.testing_in_progress = True
                        threading.Thread(target=self.handle_iframe_test).start()

                    # Ctrl + C = Console test
                    elif key.char == 'c' and self.console_mode:
                        self.testing_in_progress = True
                        threading.Thread(target=self.handle_console_test).start()

                    # Ctrl + Q = Quit
                    elif key.char == 'q':
                        print("\n[*] Exiting...")
                        self.running = False
                        return False

        except Exception as e:
            pass

    def on_release(self, key):
        """Handle key release"""
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            self.ctrl_pressed = False

    def handle_sql_test(self):
        """Handle SQL injection test"""
        try:
            element = self.driver.switch_to.active_element
            if element and element.tag_name in ['input', 'textarea']:
                self.test_sql_injection(element)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.testing_in_progress = False

    def handle_xss_test(self):
        """Handle XSS test"""
        try:
            element = self.driver.switch_to.active_element
            if element and element.tag_name in ['input', 'textarea']:
                self.test_xss(element)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.testing_in_progress = False

    def handle_lfi_test(self):
        """Handle LFI test"""
        try:
            element = self.driver.switch_to.active_element
            if element and element.tag_name in ['input', 'textarea']:
                self.test_lfi(element)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.testing_in_progress = False

    def handle_iframe_test(self):
        """Handle Iframe Injection test"""
        try:
            element = self.driver.switch_to.active_element
            if element and element.tag_name in ['input', 'textarea']:
                self.test_iframe_injection(element)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.testing_in_progress = False

    def handle_console_test(self):
        """Handle console test"""
        try:
            # Example: Test fetch API
            script = """
            (async () => {
                try {
                    const response = await fetch(window.location.href);
                    return {
                        status: response.status,
                        headers: Object.fromEntries(response.headers.entries())
                    };
                } catch (e) {
                    return {error: e.message};
                }
            })()
            """
            self.execute_console_test(script)
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.testing_in_progress = False

    def start_keyboard_listener(self):
        """Start keyboard listener"""
        if not PYNPUT_AVAILABLE:
            print("[!] Keyboard listener not available")
            return False

        self.hotkey_listener = keyboard.Listener(
            on_press=self.on_press,
            on_release=self.on_release
        )
        self.hotkey_listener.start()
        return True

    def show_help(self):
        """Show help message"""
        help_text = """
╔════════════════════════════════════════════════════════════╗
║           INTERACTIVE PENTEST - HOTKEYS                    ║
╠════════════════════════════════════════════════════════════╣
║  Ctrl + I  →  SQL Injection Test                          ║
║  Ctrl + X  →  XSS Test                                     ║
║  Ctrl + L  →  LFI Test                                     ║
║  Ctrl + F  →  Iframe Injection & Clickjacking Test        ║
║  Ctrl + C  →  Console JavaScript Test                     ║
║  Ctrl + Q  →  Quit                                         ║
╠════════════════════════════════════════════════════════════╣
║  USAGE:                                                    ║
║  1. Click on any input field                               ║
║  2. Press the hotkey combination                           ║
║  3. Wait for tests to complete                             ║
║  4. Check notifications for results                        ║
╚════════════════════════════════════════════════════════════╝
"""
        print(help_text)

    def run(self, target, **kwargs):
        """Main execution"""
        self.target = target
        self.options = kwargs
        if not SELENIUM_AVAILABLE:
            return {'error': 'Selenium not available'}

        if not PYNPUT_AVAILABLE:
            return {'error': 'pynput not available'}

        # Initialize browser
        if not self.init_driver():
            return {'error': 'Failed to initialize browser'}

        # Navigate to target
        print(f"[*] Navigating to {self.target}")
        self.driver.get(self.target)
        time.sleep(2)

        # Start keyboard listener
        self.start_keyboard_listener()

        # Show help
        self.show_help()
        self.show_notification("Interactive Pentest Mode Active! Press Ctrl+I/X/L/F to test", "info")

        print("\n[*] Interactive mode active - Use hotkeys to test")
        print("[*] Press Ctrl+Q to quit")

        # Keep running
        try:
            while self.running:
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")

        # Cleanup
        print("\n[*] Closing browser...")
        if self.hotkey_listener:
            self.hotkey_listener.stop()
        if self.driver:
            self.driver.quit()

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    tester = InteractivePentester(target, options)
    results = tester.run()

    # Print summary
    print("\n" + "="*60)
    print("INTERACTIVE PENTEST SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Tests Performed: {len(results['tests_performed'])}")
    print(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")
    print(f"Console Tests: {len(results['console_tests'])}")

    if results['vulnerabilities']:
        print("\n[!] VULNERABILITIES:")
        for vuln in results['vulnerabilities']:
            print(f"  - [{vuln['severity'].upper()}] {vuln['type']}: {vuln['payload'][:50]}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 selenium_interactive.py <target_url> [options_json]")
        print("\nExample:")
        print("  python3 selenium_interactive.py https://example.com")
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
