#!/usr/bin/env python3
"""
Nikto Integration Plugin
Integration with Nikto web server scanner (third-party tool)
"""

import subprocess
import json
import sys
import os
import shutil
import tempfile
import re
from urllib.parse import urlparse

class NiktoIntegration:
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

        self.tuning = self.options.get('tuning', '')
        self.timeout = self.options.get('timeout', 600)
        self.ssl = self.options.get('ssl', False)
        self.port = self.options.get('port', None)
        self.output_format = self.options.get('output', 'json')

        # Parse target
        parsed = urlparse(self.target)
        self.host = parsed.hostname or self.target
        if not self.port:
            self.port = parsed.port or (443 if parsed.scheme == 'https' or self.ssl else 80)

        self.results = {
            'target': self.target,
            'host': self.host,
            'port': self.port,
            'vulnerabilities': [],
            'info': [],
            'stats': {
                'total_items': 0,
                'osvdb_entries': 0
            }
        }

    def check_nikto_installed(self):
        """Check if Nikto is installed"""
        nikto_path = shutil.which('nikto') or shutil.which('nikto.pl')

        if not nikto_path:
            print("[!] Nikto not found.")
            print("[!] Please install from: https://github.com/sullo/nikto")
            print("[!] On Debian/Ubuntu: apt-get install nikto")
            print("[!] On Kali Linux: nikto is pre-installed")
            return False

        print(f"[+] Nikto found: {nikto_path}")
        return True

    def run_scan(self):
        """Run Nikto scan"""
        print(f"[*] Running Nikto scan on {self.host}:{self.port}")

        # Create temp file for output
        output_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        output_file.close()

        # Build command
        nikto_cmd = shutil.which('nikto') or shutil.which('nikto.pl')

        cmd = [
            nikto_cmd,
            '-h', self.host,
            '-p', str(self.port),
            '-Format', 'json',
            '-output', output_file.name,
            '-nointeractive'
        ]

        # Add SSL if needed
        if self.ssl or self.port == 443:
            cmd.append('-ssl')

        # Add tuning if specified
        if self.tuning:
            cmd.extend(['-Tuning', self.tuning])

        # Add timeout
        cmd.extend(['-timeout', str(self.timeout)])

        print(f"[*] Command: {' '.join(cmd)}")

        try:
            # Run Nikto
            print("[*] Scan started (this may take a while)...")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 60
            )

            # Check for errors in stderr
            if result.stderr:
                print(f"[*] Nikto stderr: {result.stderr[:500]}")

            # Parse output file
            try:
                with open(output_file.name, 'r') as f:
                    content = f.read()

                    # Nikto JSON output can be malformed, try to fix common issues
                    # Sometimes it's not a valid JSON array
                    if content.strip():
                        # Try to parse as is
                        try:
                            data = json.loads(content)
                        except json.JSONDecodeError:
                            # Try to extract JSON objects
                            json_objects = re.findall(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content)
                            if json_objects:
                                # Take the largest JSON object (usually the main one)
                                data = json.loads(max(json_objects, key=len))
                            else:
                                print("[!] Failed to parse Nikto JSON output")
                                return False

                        self.parse_nikto_output(data)
                    else:
                        print("[!] Nikto output file is empty")
                        return False

            except Exception as e:
                print(f"[!] Failed to parse output: {e}")
                # Try to parse raw output from stdout
                if result.stdout:
                    self.parse_text_output(result.stdout)

            finally:
                # Clean up temp file
                try:
                    os.unlink(output_file.name)
                except:
                    pass

            return True

        except subprocess.TimeoutExpired:
            print("[!] Scan timeout")
            return False
        except Exception as e:
            print(f"[!] Scan failed: {e}")
            return False

    def parse_nikto_output(self, data):
        """Parse Nikto JSON output"""
        # Nikto JSON structure can vary, handle different formats
        vulnerabilities = []

        # Try to extract vulnerabilities from different structures
        if isinstance(data, dict):
            # Check for 'vulnerabilities' key
            if 'vulnerabilities' in data:
                vulnerabilities = data['vulnerabilities']
            # Check for host data
            elif 'host' in data or 'ip' in data:
                # Single scan result
                if 'vulnerabilities' in data:
                    vulnerabilities = data['vulnerabilities']
                # Sometimes items are directly in the object
                else:
                    for key, value in data.items():
                        if isinstance(value, list):
                            vulnerabilities.extend(value)
        elif isinstance(data, list):
            # List of vulnerabilities
            vulnerabilities = data

        print(f"[*] Processing {len(vulnerabilities)} items...")

        # Severity mapping based on OSVDB and common patterns
        severity_keywords = {
            'critical': ['remote code execution', 'rce', 'command injection', 'sql injection', 'sqli', 'unrestricted file upload'],
            'high': ['authentication bypass', 'directory traversal', 'path traversal', 'xxe', 'ssrf', 'file inclusion'],
            'medium': ['cross-site scripting', 'xss', 'csrf', 'open redirect', 'information disclosure', 'default credentials'],
            'low': ['missing security header', 'cookie without', 'ssl', 'tls', 'outdated']
        }

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue

            # Extract information
            msg = item.get('msg', item.get('message', item.get('description', '')))
            osvdb = item.get('OSVDB', item.get('osvdb', ''))
            method = item.get('method', 'GET')
            uri = item.get('uri', item.get('url', ''))

            # Determine severity
            severity = 'info'
            msg_lower = msg.lower()
            for sev, keywords in severity_keywords.items():
                if any(keyword in msg_lower for keyword in keywords):
                    severity = sev
                    break

            vuln = {
                'type': 'nikto_finding',
                'method': method,
                'uri': uri,
                'description': msg,
                'severity': severity,
                'osvdb': osvdb
            }

            # Add CVSS if available
            if 'cvss' in item:
                vuln['cvss'] = item['cvss']

            # Count OSVDB entries
            if osvdb:
                self.results['stats']['osvdb_entries'] += 1

            # Categorize
            if severity in ['critical', 'high', 'medium']:
                self.results['vulnerabilities'].append(vuln)
                print(f"[!] {severity.upper()}: {msg[:100]}")
            else:
                self.results['info'].append(vuln)

        self.results['stats']['total_items'] = len(vulnerabilities)

    def parse_text_output(self, text):
        """Parse text output as fallback"""
        print("[*] Parsing text output...")

        lines = text.split('\n')
        for line in lines:
            # Look for lines with findings (usually start with + or -)
            if line.startswith('+') or line.startswith('-'):
                # Extract meaningful part
                content = line[1:].strip()

                if content and len(content) > 10:
                    vuln = {
                        'type': 'nikto_finding',
                        'description': content,
                        'severity': 'info'
                    }
                    self.results['info'].append(vuln)

    def run(self):
        """Main execution"""
        # Check installation
        if not self.check_nikto_installed():
            return {
                'error': 'Nikto not installed',
                'target': self.target
            }

        # Run scan
        self.run_scan()

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    integration = NiktoIntegration(target, options)
    results = integration.run()

    # Print summary
    print("\n" + "="*60)
    print("NIKTO SCAN SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Target: {results['host']}:{results['port']}")
    print(f"Total Items: {results['stats']['total_items']}")
    print(f"OSVDB Entries: {results['stats']['osvdb_entries']}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Info: {len(results['info'])}")

    # Print critical/high findings
    critical_high = [v for v in results['vulnerabilities'] if v['severity'] in ['critical', 'high']]
    if critical_high:
        print(f"\nCritical/High Severity: {len(critical_high)}")
        for vuln in critical_high[:15]:
            print(f"  - [{vuln['severity'].upper()}] {vuln['description'][:80]}")
            if vuln.get('uri'):
                print(f"    URI: {vuln['uri']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [options_json]")
        print("\nExamples:")
        print(f"  {sys.argv[0]} example.com")
        print(f"  {sys.argv[0]} https://example.com")
        print(f"  {sys.argv[0]} example.com '{{\"port\": 443, \"ssl\": true}}'")
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
