"""
Professional Report Generator for Bug Bounty Programs
Generates HTML and text reports from scan results
"""

import datetime
import json
from typing import Dict, List

class ReportGenerator:
    """Generate professional security assessment reports"""

    def __init__(self, logger):
        self.logger = logger

    def generate_report(self, output_filename: str):
        """Generate HTML and text reports"""
        # Generate text report
        text_report = self.logger.generate_bug_bounty_report()
        with open(f"{output_filename}.txt", 'w') as f:
            f.write(text_report)

        # Generate HTML report
        html_report = self._generate_html_report()
        with open(f"{output_filename}.html", 'w') as f:
            f.write(html_report)

        # Save JSON file
        self.logger._save_json()

    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        findings = self.logger.get_findings()

        # Count by severity
        severity_counts = self.logger._count_by_severity()

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Report</title>
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
            color: #333;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }}

        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}

        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}

        .summary-card p {{
            color: #666;
            font-size: 0.9em;
        }}

        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #17a2b8; }}
        .info {{ color: #6c757d; }}

        .content {{
            padding: 40px;
        }}

        .vulnerability {{
            background: white;
            border-left: 5px solid #667eea;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }}

        .vulnerability.critical {{
            border-left-color: #dc3545;
        }}

        .vulnerability.high {{
            border-left-color: #fd7e14;
        }}

        .vulnerability.medium {{
            border-left-color: #ffc107;
        }}

        .vulnerability.low {{
            border-left-color: #17a2b8;
        }}

        .vulnerability.info {{
            border-left-color: #6c757d;
        }}

        .vulnerability h3 {{
            margin-bottom: 10px;
            font-size: 1.5em;
        }}

        .vulnerability .meta {{
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}

        .vulnerability .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            font-weight: bold;
        }}

        .vulnerability .badge.critical {{
            background: #dc3545;
            color: white;
        }}

        .vulnerability .badge.high {{
            background: #fd7e14;
            color: white;
        }}

        .vulnerability .badge.medium {{
            background: #ffc107;
            color: #333;
        }}

        .vulnerability .badge.low {{
            background: #17a2b8;
            color: white;
        }}

        .vulnerability .badge.info {{
            background: #6c757d;
            color: white;
        }}

        .vulnerability .section {{
            margin: 15px 0;
        }}

        .vulnerability .section h4 {{
            color: #667eea;
            margin-bottom: 5px;
        }}

        .vulnerability .code {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}

        .footer {{
            background: #343a40;
            color: white;
            padding: 20px;
            text-align: center;
        }}

        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}

        .no-findings h2 {{
            color: #28a745;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Assessment Report</h1>
            <p>Professional Penetration Testing Results</p>
            <p style="font-size: 0.9em; margin-top: 10px;">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>{len(findings)}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-card">
                <h3 class="critical">{severity_counts.get('Critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card">
                <h3 class="high">{severity_counts.get('High', 0)}</h3>
                <p>High</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">{severity_counts.get('Medium', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="summary-card">
                <h3 class="low">{severity_counts.get('Low', 0)}</h3>
                <p>Low</p>
            </div>
        </div>

        <div class="content">
            <h2 style="margin-bottom: 30px; color: #667eea;">Detailed Findings</h2>
"""

        if not findings:
            html += """
            <div class="no-findings">
                <h2>✅ No Vulnerabilities Found</h2>
                <p>The security assessment did not identify any vulnerabilities in the tested scope.</p>
            </div>
"""
        else:
            for finding in findings:
                severity_class = finding.get('severity', 'Info').lower()
                html += f"""
            <div class="vulnerability {severity_class}">
                <h3>{finding.get('id', 'N/A')}: {finding.get('name', 'Unknown Vulnerability')}</h3>
                <div class="meta">
                    <span class="badge {severity_class}">{finding.get('severity', 'Info')}</span>
                    <span><strong>CVSS:</strong> {finding.get('cvss_score', 'N/A')}</span>
                    <span><strong>CWE:</strong> {finding.get('cwe_id', 'N/A')}</span>
                </div>

                <div class="section">
                    <h4>🎯 Affected Resource</h4>
                    <p><strong>URL:</strong> {finding.get('url', 'N/A')}</p>
                    <p><strong>Parameter:</strong> {finding.get('parameter', 'N/A')}</p>
                </div>

                <div class="section">
                    <h4>📝 Description</h4>
                    <p>{finding.get('description', 'No description available')}</p>
                </div>

                <div class="section">
                    <h4>💥 Impact</h4>
                    <p>{finding.get('impact', 'No impact description available')}</p>
                </div>

                <div class="section">
                    <h4>🔧 Remediation</h4>
                    <p>{finding.get('remediation', 'No remediation steps available')}</p>
                </div>

                <div class="section">
                    <h4>🔬 Proof of Concept</h4>
                    <p><strong>Payload:</strong></p>
                    <div class="code">{self._escape_html(finding.get('payload', 'N/A'))}</div>
                </div>

                <div class="section">
                    <h4>📤 Request</h4>
                    <div class="code">{self._escape_html(finding.get('request', 'N/A')[:500])}</div>
                </div>

                <div class="section">
                    <h4>📥 Response (Excerpt)</h4>
                    <div class="code">{self._escape_html(finding.get('response', 'N/A')[:500])}...</div>
                </div>
            </div>
"""

        html += """
        </div>

        <div class="footer">
            <p><strong>Advanced Penetration Testing Scanner v2.0</strong></p>
            <p>Professional Security Testing Tool for Bug Bounty Programs</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                ⚠️ This report contains sensitive security information. Handle with care.
            </p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        if not text:
            return ''
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
