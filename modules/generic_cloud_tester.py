#!/usr/bin/env python3
"""
Generic Cloud Service API Key Tester
Tests API keys for various cloud services: DigitalOcean, Heroku, GitHub, Slack, etc.
"""

import re
import requests
from utils.logger import get_logger


class GenericCloudTester:
    """Test API keys for various cloud services"""

    # API key patterns for various services
    PATTERNS = {
        'github': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'github_token': r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
        'slack': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'heroku': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        'digitalocean': r'dop_v1_[a-f0-9]{64}',
        'stripe': r'sk_live_[0-9a-zA-Z]{24,}',
        'stripe_restricted': r'rk_live_[0-9a-zA-Z]{24,}',
        'mailgun': r'key-[0-9a-zA-Z]{32}',
        'twilio': r'SK[0-9a-f]{32}',
        'sendgrid': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'square': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'square_oauth': r'sq0csp-[0-9A-Za-z\-_]{43}',
        'paypal': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        'facebook': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'google_oauth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'telegram': r'[0-9]{8,10}:[0-9A-Za-z_-]{35}',
        'discord': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
        'gitlab': r'glpat-[0-9a-zA-Z\-_]{20}',
        'npm': r'npm_[A-Za-z0-9]{36}',
        'docker': r'dckr_pat_[a-zA-Z0-9_-]{32}',
        'cloudflare': r'[a-z0-9]{37}',
        'datadog': r'[a-f0-9]{32}',
        'algolia': r'[a-f0-9]{32}',
    }

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.tested_keys = set()

    def test_key(self, key_data):
        """Test generic cloud service API key"""
        service = key_data.get('service', 'unknown')
        api_key = key_data.get('key', '')

        result = {
            'provider': 'generic',
            'service': service,
            'api_key': api_key[:20] + '...' if len(api_key) > 20 else api_key,
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        if not api_key:
            result['findings'].append('Missing API key')
            return result

        # Avoid duplicate testing
        if api_key in self.tested_keys:
            result['findings'].append('Already tested')
            return result

        self.tested_keys.add(api_key)

        # Route to specific tester based on service
        testers = {
            'github': self._test_github,
            'slack': self._test_slack,
            'heroku': self._test_heroku,
            'digitalocean': self._test_digitalocean,
            'stripe': self._test_stripe,
            'mailgun': self._test_mailgun,
            'twilio': self._test_twilio,
            'sendgrid': self._test_sendgrid,
            'gitlab': self._test_gitlab,
            'npm': self._test_npm,
            'docker': self._test_docker,
            'cloudflare': self._test_cloudflare,
            'telegram': self._test_telegram,
            'discord': self._test_discord,
        }

        tester = testers.get(service)
        if tester:
            return tester(api_key)
        else:
            result['findings'].append(f'No tester available for service: {service}')
            return result

    def _test_github(self, token):
        """Test GitHub token"""
        result = {
            'provider': 'github',
            'service': 'github',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            response = requests.get('https://api.github.com/user', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['username'] = data.get('login')
                result['findings'].append(f"Valid GitHub token for user: {data.get('login')}")
                result['risk_level'] = 'HIGH'

                self.logger.warning(f"VALID GITHUB TOKEN FOUND: {data.get('login')}")

                # Check scopes
                scopes = response.headers.get('X-OAuth-Scopes', '')
                result['scopes'] = scopes.split(', ') if scopes else []
                result['findings'].append(f"Token scopes: {scopes}")

                if 'repo' in scopes or 'admin' in scopes:
                    result['risk_level'] = 'CRITICAL'

            elif response.status_code == 401:
                result['findings'].append('Invalid or expired token')

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_slack(self, token):
        """Test Slack token"""
        result = {
            'provider': 'slack',
            'service': 'slack',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            response = requests.post(
                'https://slack.com/api/auth.test',
                headers={'Authorization': f'Bearer {token}'}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    result['valid'] = True
                    result['vulnerable'] = True
                    result['team'] = data.get('team')
                    result['user'] = data.get('user')
                    result['findings'].append(f"Valid Slack token for team: {data.get('team')}")
                    result['risk_level'] = 'HIGH'

                    self.logger.warning(f"VALID SLACK TOKEN FOUND")
                else:
                    result['findings'].append(f"Invalid token: {data.get('error')}")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_heroku(self, api_key):
        """Test Heroku API key"""
        result = {
            'provider': 'heroku',
            'service': 'heroku',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Accept': 'application/vnd.heroku+json; version=3'
            }

            response = requests.get('https://api.heroku.com/account', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['email'] = data.get('email')
                result['findings'].append(f"Valid Heroku API key for: {data.get('email')}")
                result['risk_level'] = 'HIGH'

                self.logger.warning(f"VALID HEROKU API KEY FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_digitalocean(self, token):
        """Test DigitalOcean token"""
        result = {
            'provider': 'digitalocean',
            'service': 'digitalocean',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }

            response = requests.get('https://api.digitalocean.com/v2/account', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['email'] = data.get('account', {}).get('email')
                result['findings'].append(f"Valid DigitalOcean token")
                result['risk_level'] = 'HIGH'

                self.logger.warning(f"VALID DIGITALOCEAN TOKEN FOUND")

                # Check droplets
                droplets_response = requests.get('https://api.digitalocean.com/v2/droplets', headers=headers)
                if droplets_response.status_code == 200:
                    droplets = droplets_response.json().get('droplets', [])
                    result['findings'].append(f"Account has {len(droplets)} droplet(s)")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_stripe(self, api_key):
        """Test Stripe API key"""
        result = {
            'provider': 'stripe',
            'service': 'stripe',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            auth = (api_key, '')
            response = requests.get('https://api.stripe.com/v1/balance', auth=auth)

            if response.status_code == 200:
                result['valid'] = True
                result['vulnerable'] = True
                result['findings'].append("Valid Stripe API key")
                result['risk_level'] = 'CRITICAL'  # Payment data is critical

                self.logger.warning(f"VALID STRIPE API KEY FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_mailgun(self, api_key):
        """Test Mailgun API key"""
        result = {
            'provider': 'mailgun',
            'service': 'mailgun',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            auth = ('api', api_key)
            response = requests.get('https://api.mailgun.net/v3/domains', auth=auth)

            if response.status_code == 200:
                result['valid'] = True
                result['vulnerable'] = True
                result['findings'].append("Valid Mailgun API key")
                result['risk_level'] = 'MEDIUM'

                self.logger.warning(f"VALID MAILGUN API KEY FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_twilio(self, api_key):
        """Test Twilio API key"""
        result = {
            'provider': 'twilio',
            'service': 'twilio',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        # Note: Twilio requires both SID and token, this is simplified
        result['findings'].append('Twilio testing requires both SID and token')
        return result

    def _test_sendgrid(self, api_key):
        """Test SendGrid API key"""
        result = {
            'provider': 'sendgrid',
            'service': 'sendgrid',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }

            response = requests.get('https://api.sendgrid.com/v3/user/account', headers=headers)

            if response.status_code == 200:
                result['valid'] = True
                result['vulnerable'] = True
                result['findings'].append("Valid SendGrid API key")
                result['risk_level'] = 'MEDIUM'

                self.logger.warning(f"VALID SENDGRID API KEY FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_gitlab(self, token):
        """Test GitLab token"""
        result = {
            'provider': 'gitlab',
            'service': 'gitlab',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {'PRIVATE-TOKEN': token}
            response = requests.get('https://gitlab.com/api/v4/user', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['username'] = data.get('username')
                result['findings'].append(f"Valid GitLab token for: {data.get('username')}")
                result['risk_level'] = 'HIGH'

                self.logger.warning(f"VALID GITLAB TOKEN FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_npm(self, token):
        """Test NPM token"""
        result = {
            'provider': 'npm',
            'service': 'npm',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get('https://registry.npmjs.org/-/whoami', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['username'] = data.get('username')
                result['findings'].append(f"Valid NPM token")
                result['risk_level'] = 'HIGH'

                self.logger.warning(f"VALID NPM TOKEN FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_docker(self, token):
        """Test Docker Hub token"""
        result = {
            'provider': 'docker',
            'service': 'docker',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        result['findings'].append('Docker Hub token testing not fully implemented')
        return result

    def _test_cloudflare(self, api_key):
        """Test Cloudflare API key"""
        result = {
            'provider': 'cloudflare',
            'service': 'cloudflare',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        result['findings'].append('Cloudflare requires both API key and email')
        return result

    def _test_telegram(self, bot_token):
        """Test Telegram bot token"""
        result = {
            'provider': 'telegram',
            'service': 'telegram',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            response = requests.get(f'https://api.telegram.org/bot{bot_token}/getMe')

            if response.status_code == 200:
                data = response.json()
                if data.get('ok'):
                    result['valid'] = True
                    result['vulnerable'] = True
                    result['bot_username'] = data.get('result', {}).get('username')
                    result['findings'].append(f"Valid Telegram bot token")
                    result['risk_level'] = 'MEDIUM'

                    self.logger.warning(f"VALID TELEGRAM BOT TOKEN FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _test_discord(self, token):
        """Test Discord bot token"""
        result = {
            'provider': 'discord',
            'service': 'discord',
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        try:
            headers = {'Authorization': f'Bot {token}'}
            response = requests.get('https://discord.com/api/v9/users/@me', headers=headers)

            if response.status_code == 200:
                data = response.json()
                result['valid'] = True
                result['vulnerable'] = True
                result['bot_username'] = data.get('username')
                result['findings'].append(f"Valid Discord bot token")
                result['risk_level'] = 'MEDIUM'

                self.logger.warning(f"VALID DISCORD BOT TOKEN FOUND")

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    @staticmethod
    def extract_keys_from_text(text):
        """Extract API keys from text"""
        found_keys = []

        for service, pattern in GenericCloudTester.PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                found_keys.append({
                    'provider': 'generic',
                    'service': service,
                    'key': match
                })

        return found_keys
