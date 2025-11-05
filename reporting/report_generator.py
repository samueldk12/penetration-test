#!/usr/bin/env python3
"""
Security Testing Report Generator
Generate comprehensive reports from scan results
"""

import json
import sys
import os
import glob
from datetime import datetime
from collections import Counter
import csv

class ReportGenerator:
    def __init__(self, scan_dir=None, output_file=None, options=None):
        self.scan_dir = scan_dir
        self.output_file = output_file or 'security_report'
        self.options = options or {}

        self.format = self.options.get('format', 'html').lower()
        self.severity_filter = self.options.get('severity', 'all')
        self.include_info = self.options.get('include_info', False)
        self.include_executive_summary = self.options.get('executive_summary', True)

        self.scan_results = []
        self.all_vulnerabilities = []
        self.stats = {
            'total_scans': 0,
            'total_vulnerabilities': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_type': {},
            'targets': []
        }

    def load_scan_results(self):
        """Load scan results from directory or file"""
        print(f"[*] Loading scan results from {self.scan_dir}...")

        if os.path.isfile(self.scan_dir):
            # Single file
            self.load_result_file(self.scan_dir)
        elif os.path.isdir(self.scan_dir):
            # Directory with multiple result files
            result_files = glob.glob(os.path.join(self.scan_dir, '*.json'))
            for file in result_files:
                self.load_result_file(file)
        else:
            print(f"[!] Path not found: {self.scan_dir}")
            return False

        print(f"[+] Loaded {len(self.scan_results)} scan result(s)")
        return True

    def load_result_file(self, filepath):
        """Load a single result file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

                self.scan_results.append({
                    'filename': os.path.basename(filepath),
                    'data': data
                })

                # Extract vulnerabilities
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        vuln['source_file'] = os.path.basename(filepath)
                        vuln['target'] = data.get('target', 'N/A')
                        self.all_vulnerabilities.append(vuln)

                # Update stats
                self.stats['total_scans'] += 1

                if data.get('target'):
                    self.stats['targets'].append(data['target'])

        except Exception as e:
            print(f"[!] Failed to load {filepath}: {e}")

    def analyze_results(self):
        """Analyze loaded results and generate statistics"""
        print("[*] Analyzing results...")

        for vuln in self.all_vulnerabilities:
            severity = vuln.get('severity', 'info').lower()

            # Count by severity
            if severity in self.stats['by_severity']:
                self.stats['by_severity'][severity] += 1

            # Count by type
            vuln_type = vuln.get('type', 'unknown')
            if vuln_type not in self.stats['by_type']:
                self.stats['by_type'][vuln_type] = 0
            self.stats['by_type'][vuln_type] += 1

        self.stats['total_vulnerabilities'] = len(self.all_vulnerabilities)
        self.stats['targets'] = list(set(self.stats['targets']))

        print(f"[+] Total vulnerabilities: {self.stats['total_vulnerabilities']}")
        print(f"[+] Critical: {self.stats['by_severity']['critical']}")
        print(f"[+] High: {self.stats['by_severity']['high']}")
        print(f"[+] Medium: {self.stats['by_severity']['medium']}")

    def filter_vulnerabilities(self):
        """Filter vulnerabilities based on severity"""
        if self.severity_filter == 'all':
            return self.all_vulnerabilities

        severities = self.severity_filter.split(',')
        return [v for v in self.all_vulnerabilities if v.get('severity', '').lower() in severities]

    def generate_report(self):
        """Generate report in specified format"""
        print(f"[*] Generating {self.format.upper()} report...")

        if self.format == 'html':
            self.generate_html_report()
        elif self.format == 'json':
            self.generate_json_report()
        elif self.format == 'csv':
            self.generate_csv_report()
        elif self.format == 'markdown':
            self.generate_markdown_report()
        else:
            print(f"[!] Unsupported format: {self.format}")
            return False

        print(f"[+] Report generated: {self.output_file}")
        return True

    def generate_html_report(self):
        """Generate HTML report"""
        filtered_vulns = self.filter_vulnerabilities()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            overflow: hidden;
        }}

        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}

        .content {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.8em;
            color: #1e3c72;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}

        .stat-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .stat-card .label {{
            font-size: 0.9em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .severity-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}

        .severity-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}

        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #ff6b6b; }}
        .severity-medium {{ background: #ffa500; }}
        .severity-low {{ background: #ffd93d; color: #333; }}
        .severity-info {{ background: #17a2b8; }}

        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}

        .vuln-table th {{
            background: #1e3c72;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}

        .vuln-table td {{
            padding: 15px;
            border-bottom: 1px solid #ddd;
        }}

        .vuln-table tr:hover {{
            background: #f8f9fa;
        }}

        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #ff6b6b; color: white; }}
        .badge-medium {{ background: #ffa500; color: white; }}
        .badge-low {{ background: #ffd93d; color: #333; }}
        .badge-info {{ background: #17a2b8; color: white; }}

        .executive-summary {{
            background: #f8f9fa;
            padding: 30px;
            border-radius: 10px;
            border-left: 5px solid #667eea;
            margin-bottom: 30px;
        }}

        .executive-summary h3 {{
            color: #1e3c72;
            margin-bottom: 15px;
        }}

        .chart {{
            margin: 20px 0;
        }}

        footer {{
            background: #1e3c72;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }}

        @media print {{
            body {{
                background: white;
                padding: 0;
            }}

            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Security Testing Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>

        <div class="content">
"""

        # Executive Summary
        if self.include_executive_summary:
            risk_level = self.calculate_risk_level()
            html += f"""
            <div class="section">
                <h2 class="section-title">Executive Summary</h2>
                <div class="executive-summary">
                    <h3>Overall Risk Level: {risk_level}</h3>
                    <p>
                        This security assessment identified <strong>{self.stats['total_vulnerabilities']}</strong>
                        vulnerabilities across <strong>{len(self.stats['targets'])}</strong> target(s).
                    </p>
                    <p>
                        <strong>{self.stats['by_severity']['critical']}</strong> critical and
                        <strong>{self.stats['by_severity']['high']}</strong> high severity issues
                        require immediate attention.
                    </p>
                    <p><strong>Targets:</strong></p>
                    <ul>
"""
            for target in self.stats['targets']:
                html += f"                        <li>{target}</li>\n"

            html += """
                    </ul>
                </div>
            </div>
"""

        # Statistics
        html += f"""
            <div class="section">
                <h2 class="section-title">Overview Statistics</h2>

                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="number">{self.stats['total_vulnerabilities']}</div>
                        <div class="label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{len(self.stats['targets'])}</div>
                        <div class="label">Targets Scanned</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">{self.stats['total_scans']}</div>
                        <div class="label">Total Scans</div>
                    </div>
                </div>

                <h3>Vulnerabilities by Severity</h3>
                <div class="severity-stats">
                    <div class="severity-card severity-critical">
                        <div style="font-size: 2em; font-weight: bold;">{self.stats['by_severity']['critical']}</div>
                        <div>CRITICAL</div>
                    </div>
                    <div class="severity-card severity-high">
                        <div style="font-size: 2em; font-weight: bold;">{self.stats['by_severity']['high']}</div>
                        <div>HIGH</div>
                    </div>
                    <div class="severity-card severity-medium">
                        <div style="font-size: 2em; font-weight: bold;">{self.stats['by_severity']['medium']}</div>
                        <div>MEDIUM</div>
                    </div>
                    <div class="severity-card severity-low">
                        <div style="font-size: 2em; font-weight: bold;">{self.stats['by_severity']['low']}</div>
                        <div>LOW</div>
                    </div>
                    <div class="severity-card severity-info">
                        <div style="font-size: 2em; font-weight: bold;">{self.stats['by_severity']['info']}</div>
                        <div>INFO</div>
                    </div>
                </div>
            </div>
"""

        # Detailed Findings
        html += """
            <div class="section">
                <h2 class="section-title">Detailed Findings</h2>
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Target</th>
                            <th>Description</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
"""

        # Add vulnerabilities to table
        for vuln in filtered_vulns:
            severity = vuln.get('severity', 'info').lower()
            vuln_type = vuln.get('type', 'unknown')
            target = vuln.get('target', 'N/A')
            description = vuln.get('description', 'N/A')
            source = vuln.get('source_file', 'N/A')

            html += f"""
                        <tr>
                            <td><span class="badge badge-{severity}">{severity.upper()}</span></td>
                            <td>{vuln_type}</td>
                            <td>{target}</td>
                            <td>{description}</td>
                            <td>{source}</td>
                        </tr>
"""

        html += """
                    </tbody>
                </table>
            </div>
"""

        # Remediation Recommendations
        html += """
            <div class="section">
                <h2 class="section-title">Remediation Recommendations</h2>
                <div class="executive-summary">
                    <h3>Priority Actions:</h3>
                    <ol>
                        <li><strong>Critical Issues:</strong> Address immediately (within 24 hours)</li>
                        <li><strong>High Issues:</strong> Fix within 1 week</li>
                        <li><strong>Medium Issues:</strong> Plan remediation within 1 month</li>
                        <li><strong>Low Issues:</strong> Address in regular maintenance cycles</li>
                    </ol>

                    <h3>General Recommendations:</h3>
                    <ul>
                        <li>Implement regular security testing in CI/CD pipeline</li>
                        <li>Keep all dependencies and frameworks up to date</li>
                        <li>Follow OWASP security best practices</li>
                        <li>Implement proper input validation and sanitization</li>
                        <li>Use parameterized queries to prevent SQL injection</li>
                        <li>Implement proper authentication and authorization</li>
                        <li>Enable security headers (CSP, HSTS, X-Frame-Options)</li>
                        <li>Regular security audits and penetration testing</li>
                    </ul>
                </div>
            </div>
"""

        html += """
        </div>

        <footer>
            <p>Generated by Penetration Test Suite | © 2024</p>
            <p>This report is confidential and should be handled according to your security policies</p>
        </footer>
    </div>
</body>
</html>
"""

        output_path = f"{self.output_file}.html"
        with open(output_path, 'w') as f:
            f.write(html)

        self.output_file = output_path

    def generate_json_report(self):
        """Generate JSON report"""
        filtered_vulns = self.filter_vulnerabilities()

        report = {
            'generated_at': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': filtered_vulns,
            'risk_level': self.calculate_risk_level()
        }

        output_path = f"{self.output_file}.json"
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        self.output_file = output_path

    def generate_csv_report(self):
        """Generate CSV report"""
        filtered_vulns = self.filter_vulnerabilities()

        output_path = f"{self.output_file}.csv"
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['Severity', 'Type', 'Target', 'Description', 'Source'])

            # Data
            for vuln in filtered_vulns:
                writer.writerow([
                    vuln.get('severity', 'N/A'),
                    vuln.get('type', 'N/A'),
                    vuln.get('target', 'N/A'),
                    vuln.get('description', 'N/A'),
                    vuln.get('source_file', 'N/A')
                ])

        self.output_file = output_path

    def generate_markdown_report(self):
        """Generate Markdown report"""
        filtered_vulns = self.filter_vulnerabilities()

        md = f"""# Security Testing Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

- **Total Vulnerabilities:** {self.stats['total_vulnerabilities']}
- **Targets Scanned:** {len(self.stats['targets'])}
- **Risk Level:** {self.calculate_risk_level()}

### Vulnerabilities by Severity

| Severity | Count |
|----------|-------|
| Critical | {self.stats['by_severity']['critical']} |
| High     | {self.stats['by_severity']['high']} |
| Medium   | {self.stats['by_severity']['medium']} |
| Low      | {self.stats['by_severity']['low']} |
| Info     | {self.stats['by_severity']['info']} |

## Detailed Findings

"""

        for vuln in filtered_vulns:
            severity = vuln.get('severity', 'info').upper()
            vuln_type = vuln.get('type', 'unknown')
            target = vuln.get('target', 'N/A')
            description = vuln.get('description', 'N/A')

            md += f"""### [{severity}] {vuln_type}

- **Target:** {target}
- **Description:** {description}

---

"""

        md += """## Recommendations

1. Address critical vulnerabilities immediately
2. Implement security best practices
3. Regular security testing
4. Keep dependencies updated
"""

        output_path = f"{self.output_file}.md"
        with open(output_path, 'w') as f:
            f.write(md)

        self.output_file = output_path

    def calculate_risk_level(self):
        """Calculate overall risk level"""
        critical = self.stats['by_severity']['critical']
        high = self.stats['by_severity']['high']
        medium = self.stats['by_severity']['medium']

        if critical > 0:
            return "CRITICAL"
        elif high > 5:
            return "HIGH"
        elif high > 0 or medium > 10:
            return "MEDIUM"
        elif medium > 0:
            return "LOW"
        else:
            return "MINIMAL"

    def run(self):
        """Main execution"""
        if not self.load_scan_results():
            return False

        self.analyze_results()

        if not self.generate_report():
            return False

        return True


def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("Usage: python3 report_generator.py <scan_results_dir_or_file> [options]")
        print("\nOptions (as JSON string):")
        print("  {")
        print('    "format": "html|json|csv|markdown",')
        print('    "output": "report_name",')
        print('    "severity": "critical,high,medium,low,info|all",')
        print('    "include_info": true|false,')
        print('    "executive_summary": true|false')
        print("  }")
        print("\nExamples:")
        print('  python3 report_generator.py results/')
        print('  python3 report_generator.py results/ \'{"format": "html", "severity": "critical,high"}\'')
        sys.exit(1)

    scan_dir = sys.argv[1]
    options = {}

    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except:
            print("[!] Invalid JSON options")
            sys.exit(1)

    output_file = options.get('output', 'security_report')

    generator = ReportGenerator(scan_dir, output_file, options)

    if generator.run():
        print(f"\n[+] Report generated successfully: {generator.output_file}")
    else:
        print("\n[!] Report generation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
