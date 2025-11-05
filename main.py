#!/usr/bin/env python3
"""
Cloud API Key Vulnerability Scanner
Main orchestrator for automated penetration testing
"""

import argparse
import sys
import json
from datetime import datetime
from pathlib import Path

from modules.aws_tester import AWSKeyTester
from modules.azure_tester import AzureKeyTester
from modules.gcp_tester import GCPKeyTester
from modules.generic_cloud_tester import GenericCloudTester
from scanners.url_scanner import URLScanner
from scanners.api_key_scanner import APIKeyScanner
from tools.pentest_manager import PentestManager
from utils.logger import setup_logger, get_logger
from utils.reporter import Reporter
from config.settings import Settings


class CloudPentestFramework:
    """Main framework for cloud API key penetration testing"""

    def __init__(self, config_file=None):
        self.settings = Settings(config_file)
        self.logger = setup_logger(self.settings.log_level)
        self.reporter = Reporter(self.settings.report_dir)
        self.pentest_manager = PentestManager(self.settings)

        # Initialize testers
        self.testers = {
            'aws': AWSKeyTester(self.settings),
            'azure': AzureKeyTester(self.settings),
            'gcp': GCPKeyTester(self.settings),
            'generic': GenericCloudTester(self.settings)
        }

        # Initialize scanners
        self.url_scanner = URLScanner(self.settings)
        self.api_key_scanner = APIKeyScanner(self.settings)

    def scan_urls(self, target_urls):
        """Scan URLs for vulnerabilities"""
        self.logger.info(f"Starting URL scan for {len(target_urls)} targets")
        results = []

        for url in target_urls:
            self.logger.info(f"Scanning URL: {url}")
            result = self.url_scanner.scan(url)
            results.append(result)

            # Run automated pentest tools on URL
            pentest_results = self.pentest_manager.run_all_tools(url)
            result['pentest_results'] = pentest_results

        return results

    def scan_api_keys(self, keys_file=None, keys_list=None):
        """Scan and test API keys"""
        self.logger.info("Starting API key vulnerability scan")

        # Discover keys from file or use provided list
        if keys_file:
            discovered_keys = self.api_key_scanner.scan_file(keys_file)
        elif keys_list:
            discovered_keys = keys_list
        else:
            # Scan current directory for exposed keys
            discovered_keys = self.api_key_scanner.scan_directory('.')

        results = {
            'aws': [],
            'azure': [],
            'gcp': [],
            'generic': []
        }

        for key_data in discovered_keys:
            provider = key_data.get('provider', 'generic')
            key = key_data.get('key')

            self.logger.info(f"Testing {provider} key: {key[:10]}...")

            if provider in self.testers:
                test_result = self.testers[provider].test_key(key_data)
                results[provider].append(test_result)
            else:
                test_result = self.testers['generic'].test_key(key_data)
                results['generic'].append(test_result)

        return results

    def run_comprehensive_scan(self, target):
        """Run comprehensive security scan"""
        self.logger.info(f"Starting comprehensive scan on: {target}")

        comprehensive_results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'url_vulnerabilities': [],
            'api_key_vulnerabilities': [],
            'pentest_results': {},
            'recommendations': []
        }

        # URL scanning
        if target.startswith('http'):
            url_results = self.scan_urls([target])
            comprehensive_results['url_vulnerabilities'] = url_results

            # Extract any API keys found in responses
            found_keys = self.api_key_scanner.scan_text(
                str(url_results)
            )

            if found_keys:
                key_results = self.scan_api_keys(keys_list=found_keys)
                comprehensive_results['api_key_vulnerabilities'] = key_results

        # Run all pentest tools
        pentest_results = self.pentest_manager.run_comprehensive_test(target)
        comprehensive_results['pentest_results'] = pentest_results

        # Generate recommendations
        comprehensive_results['recommendations'] = self._generate_recommendations(
            comprehensive_results
        )

        return comprehensive_results

    def _generate_recommendations(self, results):
        """Generate security recommendations based on findings"""
        recommendations = []

        # Check for vulnerable API keys
        for provider, keys in results.get('api_key_vulnerabilities', {}).items():
            for key_result in keys:
                if key_result.get('vulnerable'):
                    recommendations.append({
                        'severity': 'CRITICAL',
                        'type': 'exposed_api_key',
                        'provider': provider,
                        'recommendation': f'Immediately revoke and rotate {provider} API key. Enable MFA and implement key rotation policy.'
                    })

        # Check URL vulnerabilities
        for url_result in results.get('url_vulnerabilities', []):
            if url_result.get('vulnerabilities'):
                for vuln in url_result['vulnerabilities']:
                    recommendations.append({
                        'severity': vuln.get('severity', 'MEDIUM'),
                        'type': 'url_vulnerability',
                        'vulnerability': vuln.get('type'),
                        'recommendation': vuln.get('fix')
                    })

        return recommendations

    def save_results(self, results, output_file=None):
        """Save scan results to file and generate report"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"scan_results_{timestamp}.json"

        # Save JSON results
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to: {output_file}")

        # Generate HTML report
        html_report = self.reporter.generate_html_report(results)
        report_file = output_file.replace('.json', '.html')

        with open(report_file, 'w') as f:
            f.write(html_report)

        self.logger.info(f"HTML report generated: {report_file}")

        return output_file, report_file


def main():
    parser = argparse.ArgumentParser(
        description='Cloud API Key Vulnerability Scanner - Automated Pentest Framework'
    )

    parser.add_argument(
        '-t', '--target',
        help='Target URL or domain to scan'
    )

    parser.add_argument(
        '-u', '--urls-file',
        help='File containing list of URLs to scan'
    )

    parser.add_argument(
        '-k', '--keys-file',
        help='File containing API keys to test'
    )

    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default='config/config.yaml'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output file for results'
    )

    parser.add_argument(
        '--comprehensive',
        action='store_true',
        help='Run comprehensive scan (all modules)'
    )

    parser.add_argument(
        '--scan-keys',
        action='store_true',
        help='Scan for exposed API keys in current directory'
    )

    parser.add_argument(
        '--providers',
        nargs='+',
        choices=['aws', 'azure', 'gcp', 'all'],
        default=['all'],
        help='Cloud providers to test'
    )

    args = parser.parse_args()

    # Initialize framework
    framework = CloudPentestFramework(args.config)

    results = None

    try:
        if args.comprehensive and args.target:
            # Comprehensive scan
            results = framework.run_comprehensive_scan(args.target)

        elif args.urls_file:
            # URL scanning
            with open(args.urls_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            results = framework.scan_urls(urls)

        elif args.target:
            # Single URL scan
            results = framework.scan_urls([args.target])

        elif args.keys_file:
            # API key testing
            results = framework.scan_api_keys(keys_file=args.keys_file)

        elif args.scan_keys:
            # Scan directory for keys
            results = framework.scan_api_keys()

        else:
            parser.print_help()
            sys.exit(1)

        # Save results
        if results:
            framework.save_results(results, args.output)

            # Print summary
            print("\n" + "="*60)
            print("SCAN COMPLETED")
            print("="*60)

            if isinstance(results, dict):
                if 'recommendations' in results:
                    print(f"\nFound {len(results['recommendations'])} security issues")
                    for rec in results['recommendations'][:5]:  # Show top 5
                        print(f"  [{rec['severity']}] {rec.get('recommendation', 'N/A')}")

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        framework.logger.error(f"Error during scan: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
