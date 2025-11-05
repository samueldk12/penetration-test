#!/usr/bin/env python3
"""
Advanced Reporting System
Sistema avançado de relatórios com filtros e merge de dados
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from collections import defaultdict
import re


class AdvancedReporter:
    """Sistema avançado de relatórios com filtros e agregação."""

    def __init__(self, db_path: str = "recon_discoveries.db"):
        self.db_path = db_path
        self.conn = None
        self._connect()

    def _connect(self):
        """Conecta ao banco de dados."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row

    def generate_comprehensive_report(self, **filters) -> Dict:
        """
        Gera relatório abrangente com todos os dados.

        Filtros disponíveis:
            - domain: Filtra por domínio
            - severity: Filtra por severidade (critical, high, medium, low)
            - vuln_type: Filtra por tipo de vulnerabilidade
            - date_from: Data inicial
            - date_to: Data final
            - tested_only: Apenas secrets testadas
            - alive_only: Apenas URLs ativas

        Returns:
            Dict com relatório completo
        """
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'filters_applied': filters,
                'report_type': 'comprehensive'
            },
            'executive_summary': {},
            'osint_findings': {},
            'vulnerability_findings': {},
            'api_keys_and_secrets': {},
            'recon_data': {},
            'recommendations': []
        }

        # Executive Summary
        report['executive_summary'] = self._generate_executive_summary(filters)

        # OSINT Findings
        report['osint_findings'] = self._aggregate_osint_data(filters)

        # Vulnerability Findings
        report['vulnerability_findings'] = self._aggregate_vulnerability_data(filters)

        # API Keys and Secrets
        report['api_keys_and_secrets'] = self._aggregate_secrets_data(filters)

        # Reconnaissance Data
        report['recon_data'] = self._aggregate_recon_data(filters)

        # Recommendations
        report['recommendations'] = self._generate_recommendations(report)

        return report

    def generate_filtered_report(self, report_type: str, **filters) -> Dict:
        """
        Gera relatório específico filtrado.

        Tipos disponíveis:
            - vulnerabilities: Apenas vulnerabilidades
            - secrets: Apenas secrets/API keys
            - osint: Apenas dados OSINT
            - recon: Apenas dados de reconnaissance
            - critical: Apenas findings críticos
        """
        if report_type == 'vulnerabilities':
            return self._vulnerability_report(filters)
        elif report_type == 'secrets':
            return self._secrets_report(filters)
        elif report_type == 'osint':
            return self._osint_report(filters)
        elif report_type == 'recon':
            return self._recon_report(filters)
        elif report_type == 'critical':
            filters['severity'] = 'critical'
            return self.generate_comprehensive_report(**filters)
        else:
            return {'error': f'Unknown report type: {report_type}'}

    def _generate_executive_summary(self, filters: Dict) -> Dict:
        """Gera resumo executivo."""
        cursor = self.conn.cursor()

        summary = {
            'total_urls': 0,
            'total_endpoints': 0,
            'total_subdomains': 0,
            'total_secrets': 0,
            'total_vulnerabilities': 0,
            'severity_distribution': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'top_findings': [],
            'risk_score': 0
        }

        # Total URLs
        query = "SELECT COUNT(*) FROM urls WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND domain = ?"
            params.append(filters['domain'])

        if filters.get('alive_only'):
            query += " AND is_alive = 1"

        cursor.execute(query, params)
        summary['total_urls'] = cursor.fetchone()[0]

        # Total Endpoints
        query = "SELECT COUNT(*) FROM endpoints WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND url_id IN (SELECT id FROM urls WHERE domain = ?)"
            params.append(filters['domain'])

        cursor.execute(query, params)
        summary['total_endpoints'] = cursor.fetchone()[0]

        # Total Subdomains
        query = "SELECT COUNT(*) FROM subdomains WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND root_domain = ?"
            params.append(filters['domain'])

        cursor.execute(query, params)
        summary['total_subdomains'] = cursor.fetchone()[0]

        # Total Secrets
        query = "SELECT COUNT(*) FROM secrets WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND url_id IN (SELECT id FROM urls WHERE domain = ?)"
            params.append(filters['domain'])

        cursor.execute(query, params)
        summary['total_secrets'] = cursor.fetchone()[0]

        # Severity distribution (baseado em secrets e vulnerabilidades)
        summary['severity_distribution'] = self._calculate_severity_distribution(filters)

        # Risk score (0-100)
        summary['risk_score'] = self._calculate_risk_score(summary)

        return summary

    def _calculate_severity_distribution(self, filters: Dict) -> Dict:
        """Calcula distribuição de severidade."""
        distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        cursor = self.conn.cursor()

        # Secrets por risk level
        query = "SELECT risk_level, COUNT(*) FROM secrets WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND url_id IN (SELECT id FROM urls WHERE domain = ?)"
            params.append(filters['domain'])

        query += " GROUP BY risk_level"

        cursor.execute(query, params)
        for row in cursor.fetchall():
            risk_level = row[0] or 'info'
            count = row[1]
            if risk_level in distribution:
                distribution[risk_level] += count

        return distribution

    def _calculate_risk_score(self, summary: Dict) -> int:
        """Calcula score de risco (0-100)."""
        score = 0

        # Pesos por severidade
        severity = summary['severity_distribution']
        score += severity['critical'] * 10
        score += severity['high'] * 5
        score += severity['medium'] * 2
        score += severity['low'] * 1

        # Limita a 100
        return min(score, 100)

    def _aggregate_osint_data(self, filters: Dict) -> Dict:
        """Agrega dados OSINT."""
        cursor = self.conn.cursor()

        osint_data = {
            'subdomains': [],
            'dns_records': {},
            'whois_info': {},
            'ssl_certificates': [],
            'technologies': [],
            'social_media': [],
            'email_addresses': []
        }

        # Subdomains
        query = "SELECT * FROM subdomains WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND root_domain = ?"
            params.append(filters['domain'])

        query += " ORDER BY discovered_at DESC"

        cursor.execute(query, params)
        osint_data['subdomains'] = [dict(row) for row in cursor.fetchall()]

        # Parse DNS records dos subdomínios
        for subdomain in osint_data['subdomains']:
            dns_records = subdomain.get('dns_records')
            if dns_records:
                try:
                    osint_data['dns_records'][subdomain['subdomain']] = json.loads(dns_records)
                except:
                    pass

        return osint_data

    def _aggregate_vulnerability_data(self, filters: Dict) -> Dict:
        """Agrega dados de vulnerabilidades."""
        cursor = self.conn.cursor()

        vuln_data = {
            'by_type': defaultdict(list),
            'by_severity': defaultdict(list),
            'by_endpoint': defaultdict(list),
            'total_count': 0,
            'unique_types': set()
        }

        # Endpoints vulneráveis
        query = """
            SELECT e.*, u.url, u.domain
            FROM endpoints e
            JOIN urls u ON e.url_id = u.id
            WHERE e.vulnerable = 1
        """
        params = []

        if filters.get('domain'):
            query += " AND u.domain = ?"
            params.append(filters['domain'])

        if filters.get('vuln_type'):
            query += " AND e.vulnerability_type = ?"
            params.append(filters['vuln_type'])

        cursor.execute(query, params)

        for row in cursor.fetchall():
            vuln = dict(row)
            vuln_type = vuln.get('vulnerability_type', 'unknown')

            # Por tipo
            vuln_data['by_type'][vuln_type].append(vuln)

            # Por endpoint
            endpoint = vuln.get('endpoint', '')
            vuln_data['by_endpoint'][endpoint].append(vuln)

            # Tipos únicos
            vuln_data['unique_types'].add(vuln_type)

            vuln_data['total_count'] += 1

        # Converte sets para lists para JSON
        vuln_data['unique_types'] = list(vuln_data['unique_types'])

        # Converte defaultdict para dict
        vuln_data['by_type'] = dict(vuln_data['by_type'])
        vuln_data['by_endpoint'] = dict(vuln_data['by_endpoint'])

        return vuln_data

    def _aggregate_secrets_data(self, filters: Dict) -> Dict:
        """Agrega dados de secrets e API keys."""
        cursor = self.conn.cursor()

        secrets_data = {
            'by_type': defaultdict(list),
            'by_service': defaultdict(list),
            'by_risk_level': defaultdict(list),
            'tested_secrets': [],
            'untested_secrets': [],
            'high_risk_secrets': [],
            'total_count': 0,
            'api_keys_breakdown': {}
        }

        query = """
            SELECT s.*, u.url, u.domain
            FROM secrets s
            LEFT JOIN urls u ON s.url_id = u.id
            WHERE 1=1
        """
        params = []

        if filters.get('domain'):
            query += " AND u.domain = ?"
            params.append(filters['domain'])

        if filters.get('tested_only'):
            query += " AND s.permissions_tested = 1"

        if filters.get('severity'):
            query += " AND s.risk_level = ?"
            params.append(filters['severity'])

        cursor.execute(query, params)

        for row in cursor.fetchall():
            secret = dict(row)
            secret_type = secret.get('secret_type', 'unknown')
            service = secret.get('service', 'unknown')
            risk_level = secret.get('risk_level', 'unknown')

            # Por tipo
            secrets_data['by_type'][secret_type].append(secret)

            # Por serviço
            secrets_data['by_service'][service].append(secret)

            # Por risk level
            secrets_data['by_risk_level'][risk_level].append(secret)

            # Testadas vs não testadas
            if secret.get('permissions_tested'):
                secrets_data['tested_secrets'].append(secret)
            else:
                secrets_data['untested_secrets'].append(secret)

            # Alto risco
            if risk_level in ['critical', 'high']:
                secrets_data['high_risk_secrets'].append(secret)

            secrets_data['total_count'] += 1

        # API Keys breakdown
        secrets_data['api_keys_breakdown'] = {
            'aws_keys': len(secrets_data['by_type'].get('aws_access_key', [])),
            'gcp_keys': len(secrets_data['by_type'].get('gcp_service_account', [])),
            'azure_keys': len(secrets_data['by_type'].get('azure_storage_key', [])),
            'generic_api_keys': len(secrets_data['by_type'].get('api_key', [])),
            'github_tokens': len(secrets_data['by_type'].get('github_token', [])),
            'slack_tokens': len(secrets_data['by_type'].get('slack_token', [])),
            'stripe_keys': len(secrets_data['by_type'].get('stripe_key', []))
        }

        # Converte defaultdict para dict
        secrets_data['by_type'] = dict(secrets_data['by_type'])
        secrets_data['by_service'] = dict(secrets_data['by_service'])
        secrets_data['by_risk_level'] = dict(secrets_data['by_risk_level'])

        return secrets_data

    def _aggregate_recon_data(self, filters: Dict) -> Dict:
        """Agrega dados de reconnaissance."""
        cursor = self.conn.cursor()

        recon_data = {
            'urls': [],
            'endpoints': [],
            'subdomains': [],
            'technologies': set(),
            'interesting_files': []
        }

        # URLs
        query = "SELECT * FROM urls WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND domain = ?"
            params.append(filters['domain'])

        if filters.get('alive_only'):
            query += " AND is_alive = 1"

        query += " ORDER BY discovered_at DESC LIMIT 100"

        cursor.execute(query, params)
        recon_data['urls'] = [dict(row) for row in cursor.fetchall()]

        # Endpoints
        query = "SELECT e.*, u.url FROM endpoints e JOIN urls u ON e.url_id = u.id WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND u.domain = ?"
            params.append(filters['domain'])

        query += " LIMIT 100"

        cursor.execute(query, params)
        recon_data['endpoints'] = [dict(row) for row in cursor.fetchall()]

        # Subdomains
        query = "SELECT * FROM subdomains WHERE 1=1"
        params = []

        if filters.get('domain'):
            query += " AND root_domain = ?"
            params.append(filters['domain'])

        cursor.execute(query, params)
        recon_data['subdomains'] = [dict(row) for row in cursor.fetchall()]

        # Detecta tecnologias baseado em content_type e headers
        for url in recon_data['urls']:
            content_type = url.get('content_type') or ''
            if 'json' in content_type:
                recon_data['technologies'].add('API/JSON')
            if 'xml' in content_type:
                recon_data['technologies'].add('XML')

        # Arquivos interessantes
        interesting_extensions = ['.git', '.env', '.config', '.sql', '.bak', '.old']
        for url in recon_data['urls']:
            url_path = url.get('path') or ''
            if any(ext in url_path for ext in interesting_extensions):
                recon_data['interesting_files'].append(url)

        recon_data['technologies'] = list(recon_data['technologies'])

        return recon_data

    def _generate_recommendations(self, report: Dict) -> List[Dict]:
        """Gera recomendações baseadas nos findings."""
        recommendations = []

        # Secrets não testadas
        untested = len(report['api_keys_and_secrets'].get('untested_secrets', []))
        if untested > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'secrets',
                'title': f'{untested} secrets encontradas não foram testadas',
                'description': 'Execute testes de permissões nas secrets encontradas',
                'action': 'Run permission_tester.py on discovered secrets'
            })

        # Vulnerabilidades críticas
        critical_vulns = report['executive_summary']['severity_distribution']['critical']
        if critical_vulns > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'vulnerability',
                'title': f'{critical_vulns} vulnerabilidades críticas encontradas',
                'description': 'Corrija imediatamente as vulnerabilidades críticas',
                'action': 'Review and patch critical vulnerabilities'
            })

        # API Keys expostas
        high_risk_secrets = len(report['api_keys_and_secrets'].get('high_risk_secrets', []))
        if high_risk_secrets > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'secrets',
                'title': f'{high_risk_secrets} secrets de alto risco expostas',
                'description': 'Revogue e rotacione imediatamente as API keys expostas',
                'action': 'Rotate all exposed API keys and secrets'
            })

        # Subdomínios não monitorados
        total_subdomains = len(report['osint_findings'].get('subdomains', []))
        if total_subdomains > 20:
            recommendations.append({
                'priority': 'medium',
                'category': 'attack_surface',
                'title': f'{total_subdomains} subdomínios descobertos',
                'description': 'Grande superfície de ataque - considere consolidar ou proteger subdomínios',
                'action': 'Review and secure all subdomains'
            })

        return recommendations

    def _vulnerability_report(self, filters: Dict) -> Dict:
        """Relatório focado em vulnerabilidades."""
        return {
            'report_type': 'vulnerabilities',
            'generated_at': datetime.now().isoformat(),
            'data': self._aggregate_vulnerability_data(filters)
        }

    def _secrets_report(self, filters: Dict) -> Dict:
        """Relatório focado em secrets."""
        return {
            'report_type': 'secrets',
            'generated_at': datetime.now().isoformat(),
            'data': self._aggregate_secrets_data(filters)
        }

    def _osint_report(self, filters: Dict) -> Dict:
        """Relatório focado em OSINT."""
        return {
            'report_type': 'osint',
            'generated_at': datetime.now().isoformat(),
            'data': self._aggregate_osint_data(filters)
        }

    def _recon_report(self, filters: Dict) -> Dict:
        """Relatório focado em reconnaissance."""
        return {
            'report_type': 'reconnaissance',
            'generated_at': datetime.now().isoformat(),
            'data': self._aggregate_recon_data(filters)
        }

    def export_report(self, report: Dict, output_file: str, format: str = 'json'):
        """
        Exporta relatório em diferentes formatos.

        Formatos suportados: json, html, markdown
        """
        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

        elif format == 'html':
            html = self._generate_html_report(report)
            with open(output_file, 'w') as f:
                f.write(html)

        elif format == 'markdown':
            md = self._generate_markdown_report(report)
            with open(output_file, 'w') as f:
                f.write(md)

        return output_file

    def _generate_html_report(self, report: Dict) -> str:
        """Gera relatório HTML."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; border-bottom: 2px solid #ddd; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p>Generated: {report['metadata']['generated_at']}</p>

    <h2>Executive Summary</h2>
    <p>Risk Score: <strong>{report['executive_summary']['risk_score']}/100</strong></p>
    <p>Total URLs: {report['executive_summary']['total_urls']}</p>
    <p>Total Secrets: {report['executive_summary']['total_secrets']}</p>
    <p>Total Subdomains: {report['executive_summary']['total_subdomains']}</p>

    <h3>Severity Distribution</h3>
    <ul>
        <li class="critical">Critical: {report['executive_summary']['severity_distribution']['critical']}</li>
        <li class="high">High: {report['executive_summary']['severity_distribution']['high']}</li>
        <li class="medium">Medium: {report['executive_summary']['severity_distribution']['medium']}</li>
        <li class="low">Low: {report['executive_summary']['severity_distribution']['low']}</li>
    </ul>

    <h2>API Keys & Secrets</h2>
    <p>Total: {report['api_keys_and_secrets']['total_count']}</p>
    <p>High Risk: {len(report['api_keys_and_secrets']['high_risk_secrets'])}</p>

    <h2>Recommendations</h2>
    <ul>
"""

        for rec in report['recommendations']:
            html += f"        <li class=\"{rec['priority']}\">{rec['title']}: {rec['description']}</li>\n"

        html += """
    </ul>
</body>
</html>
"""
        return html

    def _generate_markdown_report(self, report: Dict) -> str:
        """Gera relatório Markdown."""
        md = f"""# Security Assessment Report

**Generated:** {report['metadata']['generated_at']}

## Executive Summary

- **Risk Score:** {report['executive_summary']['risk_score']}/100
- **Total URLs:** {report['executive_summary']['total_urls']}
- **Total Secrets:** {report['executive_summary']['total_secrets']}
- **Total Subdomains:** {report['executive_summary']['total_subdomains']}

### Severity Distribution

- **Critical:** {report['executive_summary']['severity_distribution']['critical']}
- **High:** {report['executive_summary']['severity_distribution']['high']}
- **Medium:** {report['executive_summary']['severity_distribution']['medium']}
- **Low:** {report['executive_summary']['severity_distribution']['low']}

## API Keys & Secrets

- **Total:** {report['api_keys_and_secrets']['total_count']}
- **High Risk:** {len(report['api_keys_and_secrets']['high_risk_secrets'])}
- **Untested:** {len(report['api_keys_and_secrets']['untested_secrets'])}

### API Keys Breakdown

"""

        for key, count in report['api_keys_and_secrets']['api_keys_breakdown'].items():
            md += f"- **{key}:** {count}\n"

        md += "\n## Recommendations\n\n"

        for rec in report['recommendations']:
            md += f"### [{rec['priority'].upper()}] {rec['title']}\n\n"
            md += f"{rec['description']}\n\n"
            md += f"**Action:** {rec['action']}\n\n"

        return md

    def close(self):
        """Fecha conexão com banco de dados."""
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    import sys

    reporter = AdvancedReporter()

    # Gera relatório abrangente
    print("[*] Generating comprehensive security report...")
    report = reporter.generate_comprehensive_report()

    # Exporta em múltiplos formatos
    print("[*] Exporting reports...")
    reporter.export_report(report, 'security_report.json', format='json')
    reporter.export_report(report, 'security_report.html', format='html')
    reporter.export_report(report, 'security_report.md', format='markdown')

    print("\n[+] Reports generated:")
    print("  - security_report.json")
    print("  - security_report.html")
    print("  - security_report.md")

    # Resumo
    print("\n" + "="*60)
    print("SECURITY ASSESSMENT SUMMARY")
    print("="*60)
    print(f"Risk Score: {report['executive_summary']['risk_score']}/100")
    print(f"Total Secrets: {report['api_keys_and_secrets']['total_count']}")
    print(f"High Risk Secrets: {len(report['api_keys_and_secrets']['high_risk_secrets'])}")
    print(f"Vulnerabilities: {report['vulnerability_findings']['total_count']}")
    print(f"Recommendations: {len(report['recommendations'])}")
    print("="*60)

    reporter.close()
