#!/usr/bin/env python3
"""
Report Generator
Generates HTML and other format reports for scan results
"""

import json
from datetime import datetime
from pathlib import Path


class Reporter:
    """Generate reports in various formats"""

    def __init__(self, report_dir='reports'):
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, results):
        """Generate HTML report from scan results"""

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud API Key Vulnerability Scan Report</title>
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
            border-radius: 15px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
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
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .content {{
            padding: 40px;
        }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .summary-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}

        .summary-card:hover {{
            transform: translateY(-5px);
        }}

        .summary-card h3 {{
            font-size: 1.2em;
            color: #667eea;
            margin-bottom: 10px;
        }}

        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #764ba2;
        }}

        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-right: 10px;
        }}

        .severity-critical {{
            background: #e74c3c;
            color: white;
        }}

        .severity-high {{
            background: #e67e22;
            color: white;
        }}

        .severity-medium {{
            background: #f39c12;
            color: white;
        }}

        .severity-low {{
            background: #3498db;
            color: white;
        }}

        .vulnerability-item {{
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid #667eea;
            border-radius: 5px;
        }}

        .vulnerability-item h4 {{
            color: #333;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}

        .vulnerability-item p {{
            color: #666;
            line-height: 1.6;
            margin-bottom: 8px;
        }}

        .recommendation {{
            background: #e8f5e9;
            padding: 15px;
            border-left: 5px solid #4caf50;
            border-radius: 5px;
            margin-top: 10px;
        }}

        .recommendation strong {{
            color: #2e7d32;
        }}

        .api-key-finding {{
            background: #ffebee;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid #e74c3c;
            border-radius: 5px;
        }}

        .api-key-finding.valid {{
            background: #ffcdd2;
            border-left-color: #c62828;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}

        table th {{
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}

        table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}

        table tr:hover {{
            background: #f5f5f5;
        }}

        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
        }}

        .tool-output {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }}

        .collapsible {{
            cursor: pointer;
            padding: 10px;
            background: #667eea;
            color: white;
            border: none;
            text-align: left;
            width: 100%;
            border-radius: 5px;
            margin-top: 10px;
            font-size: 1em;
        }}

        .collapsible:hover {{
            background: #5568d3;
        }}

        .collapsible-content {{
            display: none;
            padding: 15px;
            background: #f9f9f9;
            margin-top: 5px;
            border-radius: 5px;
        }}

        .timestamp {{
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Cloud API Key Vulnerability Scan Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="content">
            {self._generate_summary_section(results)}
            {self._generate_api_keys_section(results)}
            {self._generate_vulnerabilities_section(results)}
            {self._generate_recommendations_section(results)}
            {self._generate_pentest_results_section(results)}
        </div>

        <div class="footer">
            <p>&copy; 2024 Cloud Pentest Framework - Automated Security Assessment</p>
        </div>
    </div>

    <script>
        // Make collapsible sections work
        document.querySelectorAll('.collapsible').forEach(button => {{
            button.addEventListener('click', function() {{
                this.classList.toggle('active');
                const content = this.nextElementSibling;
                if (content.style.display === 'block') {{
                    content.style.display = 'none';
                }} else {{
                    content.style.display = 'block';
                }}
            }});
        }});
    </script>
</body>
</html>
"""
        return html

    def _generate_summary_section(self, results):
        """Generate summary section"""
        # Count vulnerabilities by severity
        total_issues = 0
        critical = 0
        high = 0
        medium = 0
        low = 0

        # Count from URL vulnerabilities
        for vuln in results.get('url_vulnerabilities', []):
            for v in vuln.get('vulnerabilities', []):
                severity = v.get('severity', '').upper()
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                elif severity == 'LOW':
                    low += 1
                total_issues += 1

        # Count API key vulnerabilities
        api_key_count = 0
        for provider, keys in results.get('api_key_vulnerabilities', {}).items():
            if isinstance(keys, list):
                for key in keys:
                    if key.get('vulnerable'):
                        api_key_count += 1
                        critical += 1
                        total_issues += 1

        # Count from recommendations
        rec_count = len(results.get('recommendations', []))

        html = f"""
        <div class="section">
            <h2 class="section-title">📊 Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Issues</h3>
                    <div class="value">{total_issues}</div>
                </div>
                <div class="summary-card">
                    <h3>Critical</h3>
                    <div class="value" style="color: #e74c3c;">{critical}</div>
                </div>
                <div class="summary-card">
                    <h3>High</h3>
                    <div class="value" style="color: #e67e22;">{high}</div>
                </div>
                <div class="summary-card">
                    <h3>Medium</h3>
                    <div class="value" style="color: #f39c12;">{medium}</div>
                </div>
                <div class="summary-card">
                    <h3>Low</h3>
                    <div class="value" style="color: #3498db;">{low}</div>
                </div>
                <div class="summary-card">
                    <h3>Exposed API Keys</h3>
                    <div class="value" style="color: #c0392b;">{api_key_count}</div>
                </div>
            </div>
        </div>
        """

        return html

    def _generate_api_keys_section(self, results):
        """Generate API keys section"""
        api_keys = results.get('api_key_vulnerabilities', {})

        if not api_keys:
            return ""

        html = '<div class="section"><h2 class="section-title">🔑 Exposed API Keys</h2>'

        for provider, keys in api_keys.items():
            if not keys:
                continue

            html += f'<h3 style="margin-top: 20px; color: #764ba2;">Provider: {provider.upper()}</h3>'

            for key_data in keys:
                if not key_data.get('vulnerable'):
                    continue

                risk_level = key_data.get('risk_level', 'UNKNOWN')
                severity_class = f"severity-{risk_level.lower()}"

                html += f'''
                <div class="api-key-finding valid">
                    <span class="severity-badge {severity_class}">{risk_level}</span>
                    <h4>Valid {provider.upper()} Credentials Found</h4>
                '''

                # Add specific details based on provider
                if 'key_id' in key_data:
                    html += f'<p><strong>Key ID:</strong> {key_data["key_id"][:20]}...</p>'

                if 'account_id' in key_data:
                    html += f'<p><strong>Account ID:</strong> {key_data["account_id"]}</p>'

                if 'user_arn' in key_data:
                    html += f'<p><strong>User ARN:</strong> {key_data["user_arn"]}</p>'

                # Findings
                if key_data.get('findings'):
                    html += '<p><strong>Findings:</strong></p><ul>'
                    for finding in key_data['findings']:
                        html += f'<li>{finding}</li>'
                    html += '</ul>'

                # Permissions
                if key_data.get('permissions'):
                    html += '<button class="collapsible">View Detailed Permissions</button>'
                    html += '<div class="collapsible-content">'
                    html += f'<pre>{json.dumps(key_data["permissions"], indent=2)}</pre>'
                    html += '</div>'

                html += '</div>'

        html += '</div>'
        return html

    def _generate_vulnerabilities_section(self, results):
        """Generate vulnerabilities section"""
        url_vulns = results.get('url_vulnerabilities', [])

        if not url_vulns:
            return ""

        html = '<div class="section"><h2 class="section-title">🐛 Web Vulnerabilities</h2>'

        for url_result in url_vulns:
            url = url_result.get('url', 'Unknown')
            html += f'<h3 style="margin-top: 20px; color: #764ba2;">URL: {url}</h3>'

            vulnerabilities = url_result.get('vulnerabilities', [])

            if not vulnerabilities:
                html += '<p>No vulnerabilities detected.</p>'
            else:
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'UNKNOWN')
                    severity_class = f"severity-{severity.lower()}"

                    html += f'''
                    <div class="vulnerability-item">
                        <span class="severity-badge {severity_class}">{severity}</span>
                        <h4>{vuln.get('type', 'Unknown Vulnerability')}</h4>
                        <p>{vuln.get('description', 'No description available')}</p>
                    '''

                    if vuln.get('fix'):
                        html += f'''
                        <div class="recommendation">
                            <strong>Fix:</strong> {vuln['fix']}
                        </div>
                        '''

                    html += '</div>'

        html += '</div>'
        return html

    def _generate_recommendations_section(self, results):
        """Generate recommendations section"""
        recommendations = results.get('recommendations', [])

        if not recommendations:
            return ""

        html = '<div class="section"><h2 class="section-title">💡 Security Recommendations</h2>'

        for rec in recommendations:
            severity = rec.get('severity', 'MEDIUM')
            severity_class = f"severity-{severity.lower()}"

            html += f'''
            <div class="vulnerability-item">
                <span class="severity-badge {severity_class}">{severity}</span>
                <p>{rec.get('recommendation', 'No recommendation provided')}</p>
            </div>
            '''

        html += '</div>'
        return html

    def _generate_pentest_results_section(self, results):
        """Generate pentest tools results section"""
        pentest_results = results.get('pentest_results', {})

        if not pentest_results:
            return ""

        html = '<div class="section"><h2 class="section-title">🛠️ Penetration Testing Tools Results</h2>'

        for tool_name, tool_result in pentest_results.items():
            if not isinstance(tool_result, dict):
                continue

            success = tool_result.get('success', False)
            status = '✅ Success' if success else '❌ Failed'

            html += f'<h3 style="margin-top: 20px; color: #764ba2;">{tool_name.upper()} {status}</h3>'

            if tool_result.get('output'):
                html += '<button class="collapsible">View Output</button>'
                html += '<div class="collapsible-content">'
                html += f'<div class="tool-output">{self._escape_html(tool_result["output"][:5000])}</div>'
                html += '</div>'

            if tool_result.get('error'):
                html += f'<p style="color: red;"><strong>Error:</strong> {tool_result["error"]}</p>'

        html += '</div>'
        return html

    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#x27;'))

    def save_json_report(self, results, filename):
        """Save results as JSON"""
        filepath = self.report_dir / filename

        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)

        return filepath
