#!/usr/bin/env python3
"""
Recon Scanner Plugin
Wrapper around ReconModule for plugin system integration
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'tools'))
sys.path.insert(0, str(project_root / 'pentest_suite' / 'modules'))

from plugin_system import PluginInterface
from recon import ReconModule


class ReconScannerPlugin(PluginInterface):
    """Plugin para reconhecimento e coleta de informações."""

    name = "recon_scanner"
    version = "1.0.0"
    author = "Penetration Test Suite"
    description = "Comprehensive reconnaissance and information gathering"
    category = "recon"
    requires = ["dnspython", "requests"]

    def __init__(self, config=None):
        super().__init__(config)
        self.recon = None

    def run(self, target: str, **kwargs):
        """
        Executa reconhecimento completo no alvo.

        Args:
            target: URL/domínio/IP alvo
            **kwargs: Opções adicionais

        Returns:
            Dict com resultados do reconhecimento
        """
        print(f"\n[*] Starting Reconnaissance on: {target}")
        print("=" * 60)

        # Opções
        subdomain_enum = kwargs.get('subdomain_enum', True)
        port_scan = kwargs.get('port_scan', True)
        tech_detection = kwargs.get('tech_detection', True)
        ssl_analysis = kwargs.get('ssl_analysis', True)
        top_ports = kwargs.get('top_ports', 100)
        timeout = kwargs.get('timeout', 5)

        # Initialize ReconModule
        self.recon = ReconModule(target, timeout=timeout)

        results = {
            'plugin': self.name,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'open_ports': [],
            'technologies': {},
            'ssl_info': {},
            'findings': []
        }

        try:
            # 1. Subdomain Enumeration
            if subdomain_enum:
                print("\n[*] Phase 1: Subdomain Enumeration")
                print("-" * 60)
                subdomains = self.recon.subdomain_enumeration()
                results['subdomains'] = list(subdomains)
                results['findings'].append({
                    'type': 'info',
                    'title': 'Subdomains Discovered',
                    'count': len(subdomains),
                    'subdomains': list(subdomains)[:10]  # First 10
                })
                print(f"[+] Found {len(subdomains)} subdomains")

            # 2. Port Scanning
            if port_scan:
                print("\n[*] Phase 2: Port Scanning")
                print("-" * 60)

                # Define port range
                if top_ports == 1000:
                    ports = self._get_top_1000_ports()
                elif top_ports == 'all' or top_ports == 65535:
                    ports = range(1, 65536)
                else:  # Default top 100
                    ports = self._get_top_100_ports()

                open_ports = self.recon.port_scan(ports)
                results['open_ports'] = open_ports

                if open_ports:
                    results['findings'].append({
                        'type': 'info',
                        'title': 'Open Ports Discovered',
                        'severity': 'medium',
                        'count': len(open_ports),
                        'ports': open_ports
                    })
                    print(f"[+] Found {len(open_ports)} open ports")
                else:
                    print("[!] No open ports found")

            # 3. Technology Detection
            if tech_detection:
                print("\n[*] Phase 3: Technology Detection")
                print("-" * 60)
                technologies = self.recon.detect_technologies()
                results['technologies'] = technologies

                if technologies:
                    results['findings'].append({
                        'type': 'info',
                        'title': 'Technologies Detected',
                        'technologies': technologies
                    })
                    print(f"[+] Detected {len(technologies)} technologies")
                    for tech, version in technologies.items():
                        print(f"  - {tech}: {version}")

            # 4. SSL/TLS Analysis
            if ssl_analysis and (target.startswith('https://') or ':443' in target):
                print("\n[*] Phase 4: SSL/TLS Analysis")
                print("-" * 60)
                ssl_info = self.recon.get_ssl_info()
                results['ssl_info'] = ssl_info

                if ssl_info and 'error' not in ssl_info:
                    results['findings'].append({
                        'type': 'info',
                        'title': 'SSL Certificate Information',
                        'ssl_info': ssl_info
                    })
                    print("[+] SSL certificate analyzed")

            # Generate summary
            print("\n" + "=" * 60)
            print("RECONNAISSANCE SUMMARY")
            print("=" * 60)
            print(f"Target:        {target}")
            print(f"Subdomains:    {len(results['subdomains'])}")
            print(f"Open Ports:    {len(results['open_ports'])}")
            print(f"Technologies:  {len(results['technologies'])}")
            print(f"Findings:      {len(results['findings'])}")
            print("=" * 60)

            self.results.append(results)
            return results

        except Exception as e:
            error_msg = f"Reconnaissance failed: {str(e)}"
            print(f"[!] {error_msg}")
            self.errors.append(error_msg)

            return {
                'plugin': self.name,
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'error': error_msg,
                'partial_results': results
            }

    def _get_top_100_ports(self):
        """Returns list of top 100 most common ports."""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
            # Common web ports
            8000, 8008, 8443, 8888, 9000, 9090, 9443,
            # Database ports
            1433, 1521, 3306, 5432, 6379, 27017, 27018,
            # Mail ports
            25, 110, 143, 465, 587, 993, 995,
            # FTP/SFTP
            20, 21, 22, 989, 990,
            # Remote access
            23, 3389, 5900, 5901,
            # DNS
            53,
            # HTTP/HTTPS
            80, 81, 280, 300, 443, 591, 593, 832, 981, 1010, 1311,
            # Proxy
            8080, 8118, 8888, 3128,
            # SMB/NetBIOS
            137, 138, 139, 445,
            # LDAP
            389, 636,
            # Various services
            161, 162, 179, 199, 311, 389, 427, 443, 444, 445, 464, 465,
            497, 512, 513, 514, 515, 524, 548, 554, 587, 631, 636, 646,
            873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
            1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000,
            3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
            5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
            7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999
        ][:100]

    def _get_top_1000_ports(self):
        """Returns list of top 1000 most common ports."""
        top_100 = self._get_top_100_ports()

        # Add more ports for top 1000
        additional = list(range(1, 1024))  # Well-known ports
        additional.extend(range(1024, 10000, 10))  # Sample of registered ports
        additional.extend([
            10000, 10001, 10002, 10003, 10004, 10009, 10010,
            10080, 11110, 11111, 12000, 12345, 13456, 14000,
            15000, 16000, 17000, 18000, 19000, 20000, 20031,
            21571, 22222, 23472, 24444, 25000, 25025, 26000,
            27000, 27352, 27353, 27355, 27356, 27715, 28201,
            30000, 30718, 31038, 31337, 32768, 32769, 32770,
            32771, 32772, 32773, 32774, 32775, 32776, 32777,
            33354, 35500, 38292, 40193, 40911, 41511, 42510,
            44176, 44501, 45100, 48080, 49152, 49153, 49154,
            49155, 49156, 49157, 50000, 50001, 50002, 50003,
            50006, 50300, 50389, 50500, 50636, 50800, 51103,
            51493, 52673, 52822, 52848, 52869, 54045, 54328,
            55055, 55056, 55555, 55600, 56737, 56738, 57294,
            57797, 58080, 60020, 60443, 61532, 61900, 62078,
            63331, 64623, 64680, 65000, 65129, 65389
        ])

        # Combine and remove duplicates
        all_ports = list(set(top_100 + additional))
        all_ports.sort()
        return all_ports[:1000]


# For direct testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 recon_scanner.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    plugin = ReconScannerPlugin()

    results = plugin.run(target)

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(json.dumps(results, indent=2))
