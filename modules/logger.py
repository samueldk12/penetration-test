"""
Bug Bounty Logging System
Professional logging for security testing with evidence collection
"""

import json
import datetime
from enum import Enum
from typing import Dict, List, Any
import os

class Severity(Enum):
    """CVSS-based severity levels"""
    CRITICAL = "Critical"  # CVSS 9.0-10.0
    HIGH = "High"          # CVSS 7.0-8.9
    MEDIUM = "Medium"      # CVSS 4.0-6.9
    LOW = "Low"            # CVSS 0.1-3.9
    INFO = "Informational" # CVSS 0.0

class BugBountyLogger:
    """
    Professional logging system for bug bounty programs
    Captures vulnerabilities with full evidence and POC
    """

    def __init__(self, output_dir="pentest_results", verbose=False):
        self.output_dir = output_dir
        self.verbose = verbose
        self.findings = []
        self.recon_data = {}
        self.scan_start = datetime.datetime.now()

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        # Initialize log file
        self.log_file = os.path.join(output_dir, f"scan_{self.scan_start.strftime('%Y%m%d_%H%M%S')}.log")
        self.json_file = os.path.join(output_dir, f"findings_{self.scan_start.strftime('%Y%m%d_%H%M%S')}.json")

    def log_info(self, message: str):
        """Log informational message"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[INFO] [{timestamp}] {message}"
        print(f"\033[94m{log_msg}\033[0m")  # Blue
        self._write_to_file(log_msg)

    def log_success(self, message: str):
        """Log success message"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[SUCCESS] [{timestamp}] {message}"
        print(f"\033[92m{log_msg}\033[0m")  # Green
        self._write_to_file(log_msg)

    def log_warning(self, message: str):
        """Log warning message"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[WARNING] [{timestamp}] {message}"
        print(f"\033[93m{log_msg}\033[0m")  # Yellow
        self._write_to_file(log_msg)

    def log_error(self, message: str):
        """Log error message"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[ERROR] [{timestamp}] {message}"
        print(f"\033[91m{log_msg}\033[0m")  # Red
        self._write_to_file(log_msg)

    def log_vulnerability(self, vuln_data: Dict[str, Any]):
        """
        Log a discovered vulnerability with full details for bug bounty submission

        Args:
            vuln_data: Dictionary containing:
                - name: Vulnerability name
                - severity: Severity level (use Severity enum)
                - url: Affected URL
                - parameter: Vulnerable parameter
                - payload: Successful payload
                - description: Detailed description
                - impact: Business impact
                - remediation: Fix recommendations
                - request: Full HTTP request
                - response: Full HTTP response
                - cvss_score: CVSS score (optional)
                - cwe_id: CWE identifier (optional)
        """
        vuln_data['timestamp'] = datetime.datetime.now().isoformat()
        vuln_data['id'] = f"VULN-{len(self.findings) + 1:04d}"

        self.findings.append(vuln_data)

        # Color-coded output based on severity
        severity = vuln_data.get('severity', Severity.INFO.value)
        color_map = {
            Severity.CRITICAL.value: '\033[95m',  # Magenta
            Severity.HIGH.value: '\033[91m',       # Red
            Severity.MEDIUM.value: '\033[93m',     # Yellow
            Severity.LOW.value: '\033[94m',        # Blue
            Severity.INFO.value: '\033[96m',       # Cyan
        }
        color = color_map.get(severity, '\033[0m')

        print(f"\n{color}{'='*70}")
        print(f"[VULNERABILITY FOUND] {vuln_data['id']}")
        print(f"{'='*70}\033[0m")
        print(f"Name: {vuln_data['name']}")
        print(f"Severity: {severity}")
        print(f"URL: {vuln_data.get('url', 'N/A')}")
        print(f"Parameter: {vuln_data.get('parameter', 'N/A')}")
        print(f"Payload: {vuln_data.get('payload', 'N/A')}")
        if self.verbose:
            print(f"\nDescription:\n{vuln_data.get('description', 'N/A')}")
            print(f"\nImpact:\n{vuln_data.get('impact', 'N/A')}")
            print(f"\nRemediation:\n{vuln_data.get('remediation', 'N/A')}")

        # Save to JSON immediately (for crash recovery)
        self._save_json()

    def log_recon_results(self, recon_data: Dict[str, Any]):
        """Log reconnaissance results"""
        self.recon_data = recon_data
        self.log_info("Reconnaissance phase completed")

        if self.verbose:
            print(f"\n\033[96m{'='*70}")
            print("RECONNAISSANCE RESULTS")
            print(f"{'='*70}\033[0m")

            if 'subdomains' in recon_data:
                print(f"\n[+] Subdomains found: {len(recon_data['subdomains'])}")
                for subdomain in recon_data['subdomains'][:10]:  # Show first 10
                    print(f"    - {subdomain}")

            if 'open_ports' in recon_data:
                print(f"\n[+] Open ports: {len(recon_data['open_ports'])}")
                for port in recon_data['open_ports']:
                    print(f"    - {port}")

            if 'technologies' in recon_data:
                print(f"\n[+] Technologies detected: {len(recon_data['technologies'])}")
                for tech in recon_data['technologies']:
                    print(f"    - {tech}")

    def log_vulnerability_results(self, vuln_results: Dict[str, List]):
        """Log vulnerability scanning results"""
        total_vulns = sum(len(vulns) for vulns in vuln_results.values())
        self.log_info(f"Vulnerability scanning completed. Total vulnerabilities: {total_vulns}")

    def generate_bug_bounty_report(self) -> str:
        """
        Generate a professional bug bounty report
        Suitable for submission to bug bounty platforms
        """
        report = []
        report.append("=" * 80)
        report.append("BUG BOUNTY SECURITY ASSESSMENT REPORT")
        report.append("=" * 80)
        report.append(f"\nScan Date: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Vulnerabilities Found: {len(self.findings)}")

        # Group by severity
        severity_groups = {}
        for finding in self.findings:
            severity = finding.get('severity', Severity.INFO.value)
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)

        # Summary
        report.append("\n" + "=" * 80)
        report.append("EXECUTIVE SUMMARY")
        report.append("=" * 80)
        for severity in [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value, Severity.INFO.value]:
            count = len(severity_groups.get(severity, []))
            if count > 0:
                report.append(f"{severity}: {count}")

        # Detailed findings
        report.append("\n" + "=" * 80)
        report.append("DETAILED FINDINGS")
        report.append("=" * 80)

        for severity in [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value, Severity.INFO.value]:
            findings = severity_groups.get(severity, [])
            if not findings:
                continue

            report.append(f"\n{'='*80}")
            report.append(f"{severity.upper()} SEVERITY VULNERABILITIES ({len(findings)})")
            report.append(f"{'='*80}")

            for finding in findings:
                report.append(f"\n{'-'*80}")
                report.append(f"ID: {finding['id']}")
                report.append(f"Name: {finding['name']}")
                report.append(f"URL: {finding.get('url', 'N/A')}")
                report.append(f"Parameter: {finding.get('parameter', 'N/A')}")
                report.append(f"\nPayload:")
                report.append(f"  {finding.get('payload', 'N/A')}")
                report.append(f"\nDescription:")
                report.append(f"  {finding.get('description', 'N/A')}")
                report.append(f"\nImpact:")
                report.append(f"  {finding.get('impact', 'N/A')}")
                report.append(f"\nRemediation:")
                report.append(f"  {finding.get('remediation', 'N/A')}")

                if finding.get('cvss_score'):
                    report.append(f"\nCVSS Score: {finding['cvss_score']}")
                if finding.get('cwe_id'):
                    report.append(f"CWE ID: {finding['cwe_id']}")

                report.append(f"\nProof of Concept:")
                if finding.get('request'):
                    report.append(f"Request:\n{finding['request']}")
                if finding.get('response'):
                    report.append(f"\nResponse:\n{finding['response'][:500]}...")  # Truncate

        # Recommendations
        report.append("\n" + "=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)
        report.append("""
1. Address Critical and High severity vulnerabilities immediately
2. Implement input validation and output encoding
3. Use parameterized queries to prevent SQL injection
4. Implement Content Security Policy (CSP) headers
5. Regular security testing and code reviews
6. Keep all software and dependencies up to date
7. Implement Web Application Firewall (WAF)
8. Use security headers (X-Frame-Options, X-Content-Type-Options, etc.)
        """)

        return "\n".join(report)

    def _write_to_file(self, message: str):
        """Write message to log file"""
        with open(self.log_file, 'a') as f:
            f.write(message + '\n')

    def _save_json(self):
        """Save findings to JSON file"""
        data = {
            'scan_info': {
                'start_time': self.scan_start.isoformat(),
                'end_time': datetime.datetime.now().isoformat(),
            },
            'recon_data': self.recon_data,
            'findings': self.findings,
            'statistics': {
                'total_vulnerabilities': len(self.findings),
                'by_severity': self._count_by_severity()
            }
        }

        with open(self.json_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _count_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {}
        for finding in self.findings:
            severity = finding.get('severity', Severity.INFO.value)
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def get_findings(self) -> List[Dict]:
        """Get all findings"""
        return self.findings

    def get_critical_findings(self) -> List[Dict]:
        """Get only critical findings"""
        return [f for f in self.findings if f.get('severity') == Severity.CRITICAL.value]

    def get_high_findings(self) -> List[Dict]:
        """Get only high severity findings"""
        return [f for f in self.findings if f.get('severity') == Severity.HIGH.value]
