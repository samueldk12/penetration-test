#!/usr/bin/env python3
"""
Console Testing Module
Execute JavaScript tests and API pentesting via browser console
"""

import sys
import json
import time
from datetime import datetime

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("[!] Selenium not available")


class ConsoleTester:
    """JavaScript Console Pentesting Module"""

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

        self.browser = self.options.get('browser', 'chrome')
        self.headless = self.options.get('headless', False)

        self.driver = None
        self.results = {
            'target': self.target,
            'tests': [],
            'vulnerabilities': [],
            'api_tests': []
        }

        # Predefined test scripts
        self.test_scripts = {
            'cors': self.get_cors_test_script(),
            'api_enum': self.get_api_enumeration_script(),
            'fetch_test': self.get_fetch_test_script(),
            'xss_dom': self.get_dom_xss_test_script(),
            'local_storage': self.get_storage_test_script(),
            'cookie_test': self.get_cookie_test_script(),
            'csp_test': self.get_csp_test_script(),
            'api_fuzzing': self.get_api_fuzzing_script(),
        }

    def init_driver(self):
        """Initialize WebDriver"""
        print("[*] Initializing browser...")

        try:
            if self.browser == 'chrome':
                options = ChromeOptions()
                if self.headless:
                    options.add_argument('--headless')
                options.add_argument('--disable-web-security')
                options.add_argument('--disable-features=IsolateOrigins,site-per-process')
                self.driver = webdriver.Chrome(options=options)
            else:
                options = FirefoxOptions()
                if self.headless:
                    options.add_argument('--headless')
                self.driver = webdriver.Firefox(options=options)

            print("[+] Browser initialized")
            return True

        except Exception as e:
            print(f"[!] Failed to initialize browser: {e}")
            return False

    def execute_script(self, script, description=""):
        """Execute JavaScript in console"""
        try:
            result = self.driver.execute_script(f"return {script}")

            test_result = {
                'description': description,
                'script': script[:200] + '...' if len(script) > 200 else script,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }

            self.results['tests'].append(test_result)
            return result

        except Exception as e:
            print(f"[!] Script execution error: {e}")
            return {'error': str(e)}

    def get_cors_test_script(self):
        """CORS vulnerability test"""
        return """
(async () => {
    const testOrigins = [
        'https://evil.com',
        'null',
        window.location.protocol + '//' + window.location.host.replace(/^www\./, 'attacker.')
    ];

    const results = [];

    for (const origin of testOrigins) {
        try {
            const response = await fetch(window.location.href, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Origin': origin
                }
            });

            const corsHeader = response.headers.get('Access-Control-Allow-Origin');
            const credsHeader = response.headers.get('Access-Control-Allow-Credentials');

            results.push({
                origin: origin,
                allowed: corsHeader === origin || corsHeader === '*',
                credentials: credsHeader === 'true',
                vulnerable: (corsHeader === origin || corsHeader === '*') && credsHeader === 'true'
            });

        } catch (e) {
            results.push({origin: origin, error: e.message});
        }
    }

    return {
        test: 'CORS',
        vulnerable: results.some(r => r.vulnerable),
        results: results
    };
})()
"""

    def get_api_enumeration_script(self):
        """API endpoint enumeration"""
        return """
(async () => {
    const commonEndpoints = [
        '/api', '/api/v1', '/api/v2',
        '/rest', '/graphql',
        '/users', '/user', '/admin',
        '/config', '/settings', '/status',
        '/health', '/version', '/info'
    ];

    const baseUrl = window.location.protocol + '//' + window.location.host;
    const found = [];

    for (const endpoint of commonEndpoints) {
        try {
            const response = await fetch(baseUrl + endpoint, {
                method: 'GET',
                credentials: 'include'
            });

            if (response.status !== 404) {
                found.push({
                    endpoint: endpoint,
                    status: response.status,
                    contentType: response.headers.get('Content-Type')
                });
            }
        } catch (e) {
            // Ignore errors
        }
    }

    return {
        test: 'API_Enumeration',
        found: found,
        count: found.length
    };
})()
"""

    def get_fetch_test_script(self):
        """Test Fetch API for vulnerabilities"""
        return """
(async () => {
    const tests = [];

    // Test 1: Check if API requires authentication
    try {
        const noAuthResponse = await fetch(window.location.href, {
            method: 'GET',
            credentials: 'omit'
        });
        tests.push({
            name: 'No Authentication',
            status: noAuthResponse.status,
            vulnerable: noAuthResponse.status === 200
        });
    } catch (e) {
        tests.push({name: 'No Authentication', error: e.message});
    }

    // Test 2: Check HTTP methods
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'];
    const allowedMethods = [];

    for (const method of methods) {
        try {
            const response = await fetch(window.location.href, {
                method: method,
                credentials: 'include'
            });

            if (response.status !== 405) {
                allowedMethods.push(method);
            }
        } catch (e) {}
    }

    tests.push({
        name: 'HTTP Methods',
        allowed: allowedMethods,
        dangerous: allowedMethods.some(m => ['DELETE', 'PUT', 'PATCH'].includes(m))
    });

    // Test 3: Check for rate limiting
    let rateLimited = false;
    for (let i = 0; i < 20; i++) {
        try {
            const response = await fetch(window.location.href);
            if (response.status === 429) {
                rateLimited = true;
                break;
            }
        } catch (e) {}
    }

    tests.push({
        name: 'Rate Limiting',
        enabled: rateLimited,
        vulnerable: !rateLimited
    });

    return {
        test: 'Fetch_API_Tests',
        tests: tests
    };
})()
"""

    def get_dom_xss_test_script(self):
        """DOM-based XSS testing"""
        return """
(async () => {
    const sources = [];
    const sinks = [];

    // Check for dangerous sources
    if (window.location.hash) sources.push({type: 'location.hash', value: window.location.hash});
    if (window.location.search) sources.push({type: 'location.search', value: window.location.search});

    // Check for dangerous sinks
    const dangerousSinks = [
        'innerHTML', 'outerHTML', 'document.write',
        'eval', 'setTimeout', 'setInterval'
    ];

    // Scan page scripts for sinks
    const scripts = Array.from(document.getElementsByTagName('script'));
    for (const script of scripts) {
        const content = script.textContent;
        for (const sink of dangerousSinks) {
            if (content.includes(sink)) {
                sinks.push({sink: sink, found: true});
            }
        }
    }

    return {
        test: 'DOM_XSS',
        sources: sources,
        sinks: sinks,
        potentially_vulnerable: sources.length > 0 && sinks.length > 0
    };
})()
"""

    def get_storage_test_script(self):
        """Local/Session storage testing"""
        return """
(async () => {
    const results = {
        localStorage: [],
        sessionStorage: [],
        cookies: []
    };

    // Check localStorage
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        const value = localStorage.getItem(key);

        const sensitive = /token|password|secret|key|auth/i.test(key);

        results.localStorage.push({
            key: key,
            value: value.substring(0, 50),
            sensitive: sensitive
        });
    }

    // Check sessionStorage
    for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        const value = sessionStorage.getItem(key);

        const sensitive = /token|password|secret|key|auth/i.test(key);

        results.sessionStorage.push({
            key: key,
            value: value.substring(0, 50),
            sensitive: sensitive
        });
    }

    // Check cookies
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
        const [key, value] = cookie.split('=').map(s => s.trim());
        const sensitive = /token|session|auth/i.test(key);

        results.cookies.push({
            key: key,
            value: value ? value.substring(0, 50) : '',
            sensitive: sensitive
        });
    }

    return {
        test: 'Storage_Analysis',
        results: results,
        sensitive_data_found: [
            ...results.localStorage.filter(i => i.sensitive),
            ...results.sessionStorage.filter(i => i.sensitive),
            ...results.cookies.filter(i => i.sensitive)
        ].length > 0
    };
})()
"""

    def get_cookie_test_script(self):
        """Cookie security testing"""
        return """
(async () => {
    const cookies = document.cookie.split(';').map(c => {
        const [name, value] = c.trim().split('=');
        return {name, value: value || ''};
    });

    const issues = [];

    // Test if cookies are accessible via JavaScript (no HttpOnly)
    if (cookies.length > 0) {
        issues.push({
            issue: 'Cookies accessible via JavaScript',
            severity: 'medium',
            count: cookies.length,
            description: 'Cookies without HttpOnly flag can be stolen via XSS'
        });
    }

    // Try to set a test cookie
    document.cookie = "pentest=test; path=/";
    const testSet = document.cookie.includes('pentest=test');

    return {
        test: 'Cookie_Security',
        cookies: cookies.map(c => ({name: c.name, length: c.value.length})),
        accessible_via_js: cookies.length > 0,
        can_set_cookies: testSet,
        issues: issues
    };
})()
"""

    def get_csp_test_script(self):
        """Content Security Policy testing"""
        return """
(async () => {
    const csp = {
        present: false,
        policy: null,
        issues: []
    };

    // Check for CSP meta tag
    const metaCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (metaCSP) {
        csp.present = true;
        csp.policy = metaCSP.content;
        csp.source = 'meta';
    }

    // Try to detect CSP from violations
    let cspViolation = false;
    const originalHandler = window.onerror;

    window.addEventListener('securitypolicyviolation', (e) => {
        cspViolation = true;
        csp.present = true;
        csp.violated_directive = e.violatedDirective;
    });

    // Try inline script (should violate CSP if present)
    try {
        eval('1+1');
        csp.issues.push({
            issue: 'eval() allowed',
            severity: 'high'
        });
    } catch (e) {
        if (e.message.includes('Content Security Policy')) {
            csp.present = true;
        }
    }

    if (!csp.present) {
        csp.issues.push({
            issue: 'No CSP configured',
            severity: 'medium',
            description: 'Content Security Policy not configured - XSS attacks easier'
        });
    }

    return {
        test: 'CSP_Analysis',
        csp: csp
    };
})()
"""

    def get_api_fuzzing_script(self):
        """API fuzzing via console"""
        return """
(async () => {
    const currentUrl = new URL(window.location.href);
    const params = new URLSearchParams(currentUrl.search);

    const payloads = [
        "'", '"', '<', '>', '..', '../',
        '1\\'OR\\'1\\'=\\'1', '<script>alert(1)</script>',
        '${7*7}', '{{7*7}}'
    ];

    const results = [];

    // Fuzz each parameter
    for (const [key, value] of params.entries()) {
        for (const payload of payloads) {
            try {
                const testParams = new URLSearchParams(params);
                testParams.set(key, payload);

                const testUrl = currentUrl.origin + currentUrl.pathname + '?' + testParams.toString();

                const response = await fetch(testUrl, {
                    credentials: 'include'
                });

                const text = await response.text();

                // Check for reflections
                const reflected = text.includes(payload);

                // Check for errors
                const hasError = /error|exception|sql|syntax/i.test(text);

                if (reflected || hasError) {
                    results.push({
                        parameter: key,
                        payload: payload,
                        reflected: reflected,
                        error: hasError,
                        status: response.status
                    });
                }

            } catch (e) {
                results.push({
                    parameter: key,
                    payload: payload,
                    error: true,
                    message: e.message
                });
            }
        }
    }

    return {
        test: 'API_Fuzzing',
        results: results,
        vulnerabilities: results.filter(r => r.reflected || r.error).length
    };
})()
"""

    def run_all_tests(self):
        """Run all predefined tests"""
        print(f"\n[*] Running console tests on {self.target}")

        for test_name, script in self.test_scripts.items():
            print(f"\n[*] Running {test_name} test...")

            result = self.execute_script(script, test_name)

            if result:
                print(f"[+] {test_name} completed")

                # Check for vulnerabilities
                if isinstance(result, dict):
                    if result.get('vulnerable'):
                        vuln = {
                            'type': test_name,
                            'severity': 'high',
                            'details': result,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results['vulnerabilities'].append(vuln)
                        print(f"[!] Vulnerability found: {test_name}")

                    if result.get('potentially_vulnerable'):
                        vuln = {
                            'type': test_name,
                            'severity': 'medium',
                            'details': result,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.results['vulnerabilities'].append(vuln)
                        print(f"[!] Potential vulnerability: {test_name}")

            time.sleep(1)

    def run_custom_script(self, script, description="Custom Script"):
        """Run custom JavaScript"""
        print(f"\n[*] Running custom script: {description}")
        return self.execute_script(script, description)

    def interactive_mode(self):
        """Interactive console testing"""
        print("\n[*] Entering interactive mode")
        print("[*] Enter JavaScript code to execute (or 'quit' to exit)")

        while True:
            try:
                code = input("\nJS> ")

                if code.lower() in ['quit', 'exit', 'q']:
                    break

                if code.lower() == 'help':
                    self.print_help()
                    continue

                if code.lower() == 'list':
                    self.list_tests()
                    continue

                if code.lower().startswith('run '):
                    test_name = code[4:].strip()
                    if test_name in self.test_scripts:
                        result = self.execute_script(
                            self.test_scripts[test_name],
                            test_name
                        )
                        print(json.dumps(result, indent=2))
                    else:
                        print(f"[!] Test not found: {test_name}")
                    continue

                result = self.execute_script(code, "Interactive")
                print(json.dumps(result, indent=2))

            except EOFError:
                break
            except Exception as e:
                print(f"[!] Error: {e}")

    def list_tests(self):
        """List available tests"""
        print("\nAvailable Tests:")
        for test_name in self.test_scripts.keys():
            print(f"  - {test_name}")
        print("\nUsage: run <test_name>")

    def print_help(self):
        """Print help"""
        print("""
Interactive Console Testing Commands:
  help                 - Show this help
  list                 - List available tests
  run <test_name>      - Run a specific test
  <javascript_code>    - Execute arbitrary JavaScript
  quit                 - Exit interactive mode

Examples:
  JS> document.title
  JS> fetch('/api/users').then(r => r.json())
  JS> run cors
  JS> run api_enum
""")

    def run(self):
        """Main execution"""
        if not SELENIUM_AVAILABLE:
            return {'error': 'Selenium not available'}

        if not self.init_driver():
            return {'error': 'Failed to initialize browser'}

        try:
            # Navigate to target
            print(f"[*] Navigating to {self.target}")
            self.driver.get(self.target)
            time.sleep(2)

            # Run all tests
            self.run_all_tests()

            # Interactive mode if requested
            if self.options.get('interactive', False):
                self.interactive_mode()

        except KeyboardInterrupt:
            print("\n[*] Interrupted by user")

        finally:
            if self.driver:
                self.driver.quit()

        return self.results


def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python3 console_tester.py <target_url> [options]")
        print("\nOptions (JSON):")
        print('  {"browser": "chrome", "headless": false, "interactive": false}')
        print("\nExamples:")
        print("  python3 console_tester.py https://example.com")
        print("  python3 console_tester.py https://example.com '{\"interactive\": true}'")
        sys.exit(1)

    target = sys.argv[1]
    options = {}

    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except:
            print("[!] Invalid JSON options")

    tester = ConsoleTester(target, options)
    results = tester.run()

    # Print summary
    print("\n" + "="*60)
    print("CONSOLE TESTING SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return

    print(f"Tests Run: {len(results['tests'])}")
    print(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")

    if results['vulnerabilities']:
        print("\n[!] VULNERABILITIES:")
        for vuln in results['vulnerabilities']:
            print(f"  - [{vuln['severity'].upper()}] {vuln['type']}")

    print("\n" + json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
