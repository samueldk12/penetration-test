#!/usr/bin/env python3
"""
GraphQL API Scanner
Introspection, enumeration, and vulnerability testing
"""

import requests
import json
import argparse
import sys
from urllib.parse import urljoin

class GraphQLScanner:
    def __init__(self, url, headers=None):
        self.url = url
        self.headers = headers or {
            "Content-Type": "application/json",
            "User-Agent": "GraphQL Scanner v1.0"
        }
        self.session = requests.Session()
        self.schema = None

    def test_introspection(self):
        """Test if introspection is enabled"""
        print("\n[*] Testing introspection...")

        query = {
            "query": """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                }
            }
            """
        }

        try:
            response = self.session.post(
                self.url,
                json=query,
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    print("[+] Introspection is ENABLED")
                    return True
                else:
                    print("[-] Introspection appears to be DISABLED")
                    return False
            else:
                print(f"[-] Request failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def get_full_schema(self):
        """Get complete schema via introspection"""
        print("\n[*] Extracting full schema...")

        query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        kind
                        description
                        fields {
                            name
                            description
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                }
                            }
                        }
                    }
                }
            }
            """
        }

        try:
            response = self.session.post(
                self.url,
                json=query,
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    self.schema = data['data']['__schema']
                    types = self.schema.get('types', [])
                    print(f"[+] Extracted {len(types)} types")
                    return self.schema
                else:
                    print("[-] Failed to extract schema")
                    return None
            else:
                print(f"[-] Request failed: {response.status_code}")
                return None

        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def analyze_schema(self):
        """Analyze schema for interesting types and fields"""
        if not self.schema:
            print("[!] No schema loaded. Run get_full_schema() first")
            return

        print("\n" + "="*60)
        print("SCHEMA ANALYSIS")
        print("="*60)

        types = self.schema.get('types', [])

        # Filter out built-in types
        custom_types = [t for t in types if not t['name'].startswith('__')]

        # Categorize types
        queries = []
        mutations = []
        objects = []
        sensitive_fields = []

        for type_obj in custom_types:
            name = type_obj['name']
            kind = type_obj['kind']
            fields = type_obj.get('fields', [])

            if kind == 'OBJECT':
                objects.append(name)

                # Look for sensitive fields
                for field in fields:
                    field_name = field['name'].lower()
                    sensitive_keywords = [
                        'password', 'secret', 'token', 'key',
                        'ssn', 'credit', 'api_key', 'private',
                        'confidential', 'admin'
                    ]

                    if any(kw in field_name for kw in sensitive_keywords):
                        sensitive_fields.append({
                            'type': name,
                            'field': field['name'],
                            'description': field.get('description', 'N/A')
                        })

        # Print results
        print(f"\n[*] Custom Object Types: {len(objects)}")
        for obj in objects[:20]:
            print(f"    - {obj}")
        if len(objects) > 20:
            print(f"    ... and {len(objects)-20} more")

        if sensitive_fields:
            print(f"\n[!] Sensitive Fields Found: {len(sensitive_fields)}")
            for item in sensitive_fields:
                print(f"    - {item['type']}.{item['field']}")
                if item['description'] != 'N/A':
                    print(f"      Description: {item['description']}")

        print("\n" + "="*60)

    def test_batch_queries(self, test_query="{ __typename }"):
        """Test if batch queries are allowed"""
        print("\n[*] Testing batch query support...")

        batch = [
            {"query": test_query},
            {"query": test_query},
            {"query": test_query}
        ]

        try:
            response = self.session.post(
                self.url,
                json=batch,
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list) and len(data) == 3:
                    print("[+] Batch queries are SUPPORTED")
                    print("[!] This could be used for rate limit bypass")
                    return True
                else:
                    print("[-] Batch queries not supported")
                    return False
            else:
                print(f"[-] Request failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def test_field_suggestions(self):
        """Test for field name suggestions (information disclosure)"""
        print("\n[*] Testing field suggestions...")

        # Intentionally misspell a field
        query = {
            "query": "{ __typename userz }"
        }

        try:
            response = self.session.post(
                self.url,
                json=query,
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    error_msg = str(data['errors'])
                    if 'did you mean' in error_msg.lower():
                        print("[+] Field suggestions are ENABLED")
                        print(f"[!] Server response: {error_msg}")
                        return True

            print("[-] No field suggestions detected")
            return False

        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def test_query_depth(self, max_depth=20):
        """Test for query depth limits"""
        print(f"\n[*] Testing query depth (max {max_depth})...")

        # Build deeply nested query
        query_str = "{ __typename "
        for i in range(max_depth):
            query_str += "{ __typename "

        # Close all brackets
        query_str += "}" * (max_depth + 1)

        query = {"query": query_str}

        try:
            response = self.session.post(
                self.url,
                json=query,
                headers=self.headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    error = data['errors'][0].get('message', '')
                    if 'depth' in error.lower():
                        print(f"[-] Query depth limit enforced: {error}")
                        return False
                    else:
                        print(f"[+] Deep query executed (possible DoS vector)")
                        return True
                else:
                    print(f"[+] Deep query executed successfully (DoS possible)")
                    return True
            else:
                print(f"[-] Request failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[!] Error: {e}")
            return False

    def save_schema(self, filename="graphql_schema.json"):
        """Save schema to file"""
        if not self.schema:
            print("[!] No schema to save")
            return

        with open(filename, 'w') as f:
            json.dump(self.schema, f, indent=2)

        print(f"\n[+] Schema saved to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description='GraphQL API Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan
  %(prog)s -u https://api.example.com/graphql

  # With authentication
  %(prog)s -u https://api.example.com/graphql -H "Authorization: Bearer TOKEN"

  # Full scan and save schema
  %(prog)s -u https://api.example.com/graphql --all --save schema.json
        '''
    )

    parser.add_argument('-u', '--url', required=True,
                        help='GraphQL endpoint URL')
    parser.add_argument('-H', '--header', action='append',
                        help='Custom header (e.g., "Authorization: Bearer token")')
    parser.add_argument('--all', action='store_true',
                        help='Run all tests')
    parser.add_argument('--introspection', action='store_true',
                        help='Test introspection')
    parser.add_argument('--schema', action='store_true',
                        help='Extract full schema')
    parser.add_argument('--analyze', action='store_true',
                        help='Analyze schema for sensitive fields')
    parser.add_argument('--batch', action='store_true',
                        help='Test batch queries')
    parser.add_argument('--suggestions', action='store_true',
                        help='Test field suggestions')
    parser.add_argument('--depth', action='store_true',
                        help='Test query depth limits')
    parser.add_argument('--save', metavar='FILE',
                        help='Save schema to file')

    args = parser.parse_args()

    # Parse custom headers
    headers = {"Content-Type": "application/json"}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()

    # Banner
    print("""
    ╔══════════════════════════════════════╗
    ║      GraphQL API Scanner v1.0        ║
    ║   Introspection & Vulnerability Test ║
    ╚══════════════════════════════════════╝
    """)

    print(f"[*] Target: {args.url}")

    # Initialize scanner
    scanner = GraphQLScanner(args.url, headers)

    # Run tests
    if args.all or args.introspection:
        scanner.test_introspection()

    if args.all or args.schema:
        scanner.get_full_schema()

    if args.all or args.analyze:
        if not scanner.schema:
            scanner.get_full_schema()
        scanner.analyze_schema()

    if args.all or args.batch:
        scanner.test_batch_queries()

    if args.all or args.suggestions:
        scanner.test_field_suggestions()

    if args.all or args.depth:
        scanner.test_query_depth()

    # Save schema
    if args.save:
        if not scanner.schema:
            scanner.get_full_schema()
        scanner.save_schema(args.save)

    print("\n[*] Scan complete")

if __name__ == "__main__":
    main()
