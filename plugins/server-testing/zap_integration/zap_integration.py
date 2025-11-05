#!/usr/bin/env python3
"""
OWASP ZAP Integration Plugin
Integration with OWASP Zed Attack Proxy (third-party tool)
"""

import subprocess
import requests
import json
import sys
import os
import time
import shutil
from urllib.parse import urljoin, urlparse

class ZAPIntegration:
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

        self.scan_type = self.options.get('scan_type', 'both')
        self.spider = self.options.get('spider', True)
        self.ajax_spider = self.options.get('ajax_spider', False)
        self.api_key = self.options.get('api_key', '')
        self.zap_port = self.options.get('zap_port', 8080)

        self.zap_base = f"http://localhost:{self.zap_port}"
        self.zap_process = None

        self.results = {
            'target': self.target,
            'vulnerabilities': [],
            'info': [],
            'stats': {
                'total_alerts': 0,
                'by_severity': {}
            }
        }

    def check_zap_installed(self):
        """Check if ZAP is installed"""
        # Check for zap.sh (Linux/Mac) or zap.bat (Windows)
        zap_sh = shutil.which('zap.sh')
        zap_bat = shutil.which('zap.bat')

        if not zap_sh and not zap_bat:
            print("[!] OWASP ZAP not found.")
            print("[!] Please install from: https://www.zaproxy.org/download/")
            print("[!] Or use Docker: docker pull owasp/zap2docker-stable")
            return False

        print(f"[+] ZAP found: {zap_sh or zap_bat}")
        return True

    def start_zap_daemon(self):
        """Start ZAP in daemon mode"""
        print(f"[*] Starting ZAP daemon on port {self.zap_port}...")

        # Check if ZAP is already running
        try:
            response = requests.get(f"{self.zap_base}/JSON/core/view/version/", timeout=2)
            if response.status_code == 200:
                print("[+] ZAP already running")
                return True
        except:
            pass

        # Find ZAP executable
        zap_cmd = shutil.which('zap.sh') or shutil.which('zap.bat')

        if not zap_cmd:
            return False

        # Start ZAP in daemon mode
        try:
            cmd = [zap_cmd, '-daemon', '-port', str(self.zap_port), '-config', 'api.disablekey=true']

            self.zap_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Wait for ZAP to start
            print("[*] Waiting for ZAP to start...")
            max_wait = 60
            for i in range(max_wait):
                try:
                    response = requests.get(f"{self.zap_base}/JSON/core/view/version/", timeout=2)
                    if response.status_code == 200:
                        version = response.json()
                        print(f"[+] ZAP started successfully (version: {version.get('version', 'unknown')})")
                        time.sleep(2)  # Give it a bit more time
                        return True
                except:
                    time.sleep(1)

            print("[!] ZAP failed to start within timeout")
            return False

        except Exception as e:
            print(f"[!] Failed to start ZAP: {e}")
            return False

    def stop_zap_daemon(self):
        """Stop ZAP daemon"""
        if self.zap_process:
            print("[*] Stopping ZAP daemon...")
            try:
                # Try graceful shutdown via API
                requests.get(f"{self.zap_base}/JSON/core/action/shutdown/", timeout=5)
                time.sleep(2)
            except:
                pass

            # Force kill if still running
            try:
                self.zap_process.terminate()
                self.zap_process.wait(timeout=10)
            except:
                self.zap_process.kill()

            print("[+] ZAP stopped")

    def api_call(self, endpoint, method='GET', params=None):
        """Make API call to ZAP"""
        url = urljoin(self.zap_base, endpoint)

        if params is None:
            params = {}

        if self.api_key:
            params['apikey'] = self.api_key

        try:
            if method == 'GET':
                response = requests.get(url, params=params, timeout=30)
            else:
                response = requests.post(url, params=params, timeout=30)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[!] API call failed: {response.status_code}")
                return None

        except Exception as e:
            print(f"[!] API call error: {e}")
            return None

    def run_spider(self):
        """Run ZAP spider"""
        print(f"[*] Running spider on {self.target}...")

        # Access the target first
        self.api_call('/JSON/core/action/accessUrl/', 'POST', {'url': self.target})
        time.sleep(2)

        # Start spider
        result = self.api_call('/JSON/spider/action/scan/', 'POST', {'url': self.target})

        if not result:
            print("[!] Failed to start spider")
            return False

        scan_id = result.get('scan')
        print(f"[*] Spider started (ID: {scan_id})")

        # Wait for spider to complete
        while True:
            status = self.api_call('/JSON/spider/view/status/', params={'scanId': scan_id})
            if status:
                progress = status.get('status', 0)
                print(f"[*] Spider progress: {progress}%")

                if int(progress) >= 100:
                    break

            time.sleep(3)

        print("[+] Spider completed")
        return True

    def run_ajax_spider(self):
        """Run AJAX spider"""
        print(f"[*] Running AJAX spider on {self.target}...")

        result = self.api_call('/JSON/ajaxSpider/action/scan/', 'POST', {'url': self.target})

        if not result:
            print("[!] Failed to start AJAX spider")
            return False

        print("[*] AJAX spider started")

        # Wait for AJAX spider to complete
        while True:
            status = self.api_call('/JSON/ajaxSpider/view/status/')
            if status:
                state = status.get('status', '')
                print(f"[*] AJAX spider status: {state}")

                if state == 'stopped':
                    break

            time.sleep(5)

        print("[+] AJAX spider completed")
        return True

    def run_passive_scan(self):
        """Wait for passive scan to complete"""
        print("[*] Running passive scan...")

        # Passive scan runs automatically, just wait for it to finish
        while True:
            records = self.api_call('/JSON/pscan/view/recordsToScan/')
            if records:
                remaining = records.get('recordsToScan', 0)

                if int(remaining) == 0:
                    break

                print(f"[*] Passive scan - records remaining: {remaining}")

            time.sleep(2)

        print("[+] Passive scan completed")
        return True

    def run_active_scan(self):
        """Run active scan"""
        print(f"[*] Running active scan on {self.target}...")

        result = self.api_call('/JSON/ascan/action/scan/', 'POST', {'url': self.target})

        if not result:
            print("[!] Failed to start active scan")
            return False

        scan_id = result.get('scan')
        print(f"[*] Active scan started (ID: {scan_id})")

        # Wait for active scan to complete
        while True:
            status = self.api_call('/JSON/ascan/view/status/', params={'scanId': scan_id})
            if status:
                progress = status.get('status', 0)
                print(f"[*] Active scan progress: {progress}%")

                if int(progress) >= 100:
                    break

            time.sleep(5)

        print("[+] Active scan completed")
        return True

    def get_alerts(self):
        """Retrieve alerts from ZAP"""
        print("[*] Retrieving alerts...")

        alerts = self.api_call('/JSON/core/view/alerts/', params={'baseurl': self.target})

        if not alerts or 'alerts' not in alerts:
            print("[!] No alerts retrieved")
            return

        print(f"[+] Retrieved {len(alerts['alerts'])} alerts")

        # Process alerts
        severity_map = {
            '3': 'high',
            '2': 'medium',
            '1': 'low',
            '0': 'info'
        }

        for alert in alerts['alerts']:
            risk = alert.get('risk', '0')
            severity = severity_map.get(risk, 'info')

            vuln = {
                'type': alert.get('alert', '').lower().replace(' ', '_'),
                'name': alert.get('alert', ''),
                'severity': severity,
                'confidence': alert.get('confidence', '').lower(),
                'description': alert.get('description', ''),
                'solution': alert.get('solution', ''),
                'reference': alert.get('reference', ''),
                'cwe_id': alert.get('cweid', ''),
                'wasc_id': alert.get('wascid', ''),
                'url': alert.get('url', ''),
                'method': alert.get('method', ''),
                'param': alert.get('param', ''),
                'evidence': alert.get('evidence', '')
            }

            # Track by severity
            if severity not in self.results['stats']['by_severity']:
                self.results['stats']['by_severity'][severity] = 0
            self.results['stats']['by_severity'][severity] += 1

            if severity in ['critical', 'high', 'medium']:
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] {severity.upper()}: {vuln['name']} at {vuln['url']}")
            else:
                self.results['info'].append(vuln)

        self.results['stats']['total_alerts'] = len(alerts['alerts'])

    def run(self):
        """Main execution"""
        # Check installation
        if not self.check_zap_installed():
            return {
                'error': 'ZAP not installed',
                'target': self.target
            }

        # Start ZAP
        if not self.start_zap_daemon():
            return {
                'error': 'Failed to start ZAP',
                'target': self.target
            }

        try:
            # Access target
            print(f"[*] Accessing target: {self.target}")
            self.api_call('/JSON/core/action/accessUrl/', 'POST', {'url': self.target})
            time.sleep(2)

            # Run spider if enabled
            if self.spider:
                self.run_spider()

            # Run AJAX spider if enabled
            if self.ajax_spider:
                self.run_ajax_spider()

            # Run scans based on scan_type
            if self.scan_type in ['passive', 'both']:
                self.run_passive_scan()

            if self.scan_type in ['active', 'both']:
                self.run_active_scan()

            # Get results
            self.get_alerts()

        finally:
            # Always stop ZAP
            self.stop_zap_daemon()

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    integration = ZAPIntegration(target, options)
    results = integration.run()

    # Print summary
    print("\n" + "="*60)
    print("ZAP SCAN SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Total Alerts: {results['stats']['total_alerts']}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Info: {len(results['info'])}")

    if results['stats']['by_severity']:
        print("\nBy Severity:")
        for severity, count in results['stats']['by_severity'].items():
            print(f"  {severity.upper()}: {count}")

    # Print high severity issues
    high_severity = [v for v in results['vulnerabilities'] if v['severity'] in ['critical', 'high']]
    if high_severity:
        print(f"\nCritical/High Severity Issues: {len(high_severity)}")
        for vuln in high_severity[:10]:
            print(f"  - [{vuln['severity'].upper()}] {vuln['name']}")
            print(f"    URL: {vuln['url']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url> [options_json]")
        print("\nExample:")
        print(f"  {sys.argv[0]} https://example.com")
        print(f"  {sys.argv[0]} https://example.com '{{\"scan_type\": \"passive\"}}'")
        sys.exit(1)

    target = sys.argv[1]
    options = None

    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except:
            print("[!] Invalid JSON options")

    result = main(target, options)
    print("\n" + json.dumps(result, indent=2))
