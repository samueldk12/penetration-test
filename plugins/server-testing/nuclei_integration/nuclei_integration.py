#!/usr/bin/env python3
"""
Nuclei Integration Plugin
Integrate with Nuclei vulnerability scanner (third-party tool)
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

import subprocess
import json
import sys
import os
import shutil

class NucleiIntegration(PluginInterface):
    def __init__(self, config=None, target, options=None):
        super().__init__(config)

    name = "nuclei_integration"
    version = "1.0.0"
    author = "Penetration Test Suite"
    description = "Integration with Nuclei vulnerability scanner (third-party)"
    category = "server_testing"
    requires = []
        self.target = target
        self.options = options or {}

        self.severity = self.options.get('severity', 'critical,high,medium')
        self.templates = self.options.get('templates', '')
        self.rate_limit = self.options.get('rate_limit', 150)
        self.update = self.options.get('update', True)

        self.results = {
            'target': self.target,
            'vulnerabilities': [],
            'info': [],
            'stats': {}
        }

    def check_nuclei_installed(self):
        """Check if Nuclei is installed"""
        nuclei_path = shutil.which('nuclei')

        if not nuclei_path:
            print("[!] Nuclei not found. Installing...")
            return self.install_nuclei()

        print(f"[+] Nuclei found: {nuclei_path}")
        return True

    def install_nuclei(self):
        """Install Nuclei"""
        print("[*] Installing Nuclei...")

        try:
            # Try to install via go
            if shutil.which('go'):
                subprocess.run(
                    ['go', 'install', '-v', 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
                    check=True,
                    capture_output=True
                )
                print("[+] Nuclei installed successfully")
                return True
            else:
                print("[!] Go not found. Please install Nuclei manually:")
                print("    https://github.com/projectdiscovery/nuclei")
                return False

        except Exception as e:
            print(f"[!] Failed to install Nuclei: {e}")
            print("[!] Please install manually:")
            print("    GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return False

    def update_templates(self):
        """Update Nuclei templates"""
        if not self.update:
            return

        print("[*] Updating Nuclei templates...")

        try:
            result = subprocess.run(
                ['nuclei', '-update-templates'],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                print("[+] Templates updated")
            else:
                print(f"[-] Template update failed: {result.stderr}")

        except Exception as e:
            print(f"[!] Template update error: {e}")

    def run_scan(self):
        """Run Nuclei scan"""
        print(f"[*] Running Nuclei scan on {self.target}")
        print(f"[*] Severity: {self.severity}")

        # Build command
        cmd = [
            'nuclei',
            '-u', self.target,
            '-severity', self.severity,
            '-rate-limit', str(self.rate_limit),
            '-json',
            '-silent'
        ]

        # Add custom templates if specified
        if self.templates and os.path.exists(self.templates):
            cmd.extend(['-t', self.templates])

        print(f"[*] Command: {' '.join(cmd)}")

        try:
            # Run Nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )

            # Parse JSON output
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            finding = json.loads(line)
                            self.process_finding(finding)
                        except json.JSONDecodeError:
                            pass

            # Parse stats from stderr
            if result.stderr:
                self.parse_stats(result.stderr)

            return True

        except subprocess.TimeoutExpired:
            print("[!] Scan timeout (10 minutes)")
            return False
        except Exception as e:
            print(f"[!] Scan failed: {e}")
            return False

    def process_finding(self, finding):
        """Process a Nuclei finding"""
        info = finding.get('info', {})
        severity = info.get('severity', 'info').lower()

        vuln = {
            'template_id': finding.get('template-id'),
            'name': info.get('name'),
            'severity': severity,
            'description': info.get('description', ''),
            'matched_at': finding.get('matched-at'),
            'type': finding.get('type'),
            'tags': info.get('tags', []),
            'reference': info.get('reference', [])
        }

        # Extract additional info
        if 'extracted-results' in finding:
            vuln['extracted'] = finding['extracted-results']

        if 'curl-command' in finding:
            vuln['curl_command'] = finding['curl-command']

        if severity in ['critical', 'high', 'medium']:
            self.results['vulnerabilities'].append(vuln)
            print(f"[!] {severity.upper()}: {info.get('name')}")
        else:
            self.results['info'].append(vuln)

    def parse_stats(self, stderr):
        """Parse scan statistics from stderr"""
        # Look for stats in output
        import re

        templates_match = re.search(r'(\d+) templates', stderr)
        if templates_match:
            self.results['stats']['templates'] = int(templates_match.group(1))

        requests_match = re.search(r'(\d+) requests', stderr)
        if requests_match:
            self.results['stats']['requests'] = int(requests_match.group(1))

    def run(self):
        """Main execution"""
        # Check installation
        if not self.check_nuclei_installed():
            return {
                'error': 'Nuclei not installed',
                'target': self.target
            }

        # Update templates
        self.update_templates()

        # Run scan
        self.run_scan()

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    integration = NucleiIntegration(target, options)
    results = integration.run()

    # Print summary
    print("\n" + "="*60)
    print("NUCLEI SCAN SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Info: {len(results['info'])}")

    if results['stats']:
        print(f"Templates Used: {results['stats'].get('templates', 'N/A')}")
        print(f"Requests Made: {results['stats'].get('requests', 'N/A')}")

    # Print critical/high
    critical = [v for v in results['vulnerabilities'] if v['severity'] in ['critical', 'high']]
    if critical:
        print(f"\nCritical/High Severity: {len(critical)}")
        for vuln in critical[:10]:
            print(f"  - [{vuln['severity'].upper()}] {vuln['name']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    result = main(target)
    print(json.dumps(result, indent=2))
