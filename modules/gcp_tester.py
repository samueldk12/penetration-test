#!/usr/bin/env python3
"""
GCP (Google Cloud Platform) API Key Vulnerability Tester
Tests GCP service account keys and API keys for valid access
"""

import re
import json
import base64
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from utils.logger import get_logger


class GCPKeyTester:
    """Test GCP credentials for vulnerabilities and permissions"""

    # GCP key patterns
    SERVICE_ACCOUNT_PATTERN = r'[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com'
    API_KEY_PATTERN = r'AIza[0-9A-Za-z-_]{35}'

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.tested_keys = set()

    def test_key(self, key_data):
        """Test GCP credentials for validity and permissions"""
        result = {
            'provider': 'gcp',
            'key_type': key_data.get('key_type', 'unknown'),
            'valid': False,
            'vulnerable': False,
            'permissions': [],
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        key_type = key_data.get('key_type')

        if key_type == 'service_account':
            return self._test_service_account(key_data)
        elif key_type == 'api_key':
            return self._test_api_key(key_data)
        else:
            result['findings'].append('Unknown GCP key type')
            return result

    def _test_service_account(self, key_data):
        """Test GCP service account credentials"""
        result = {
            'provider': 'gcp',
            'key_type': 'service_account',
            'service_account_email': key_data.get('service_account_email', ''),
            'valid': False,
            'vulnerable': False,
            'permissions': {},
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        service_account_json = key_data.get('service_account_json')

        if not service_account_json:
            result['findings'].append('Missing service account JSON')
            return result

        # Avoid duplicate testing
        key_hash = str(service_account_json)
        if key_hash in self.tested_keys:
            result['findings'].append('Already tested')
            return result

        self.tested_keys.add(key_hash)

        try:
            # Parse service account JSON
            if isinstance(service_account_json, str):
                sa_data = json.loads(service_account_json)
            else:
                sa_data = service_account_json

            # Create credentials
            credentials = service_account.Credentials.from_service_account_info(
                sa_data,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )

            # Test if credentials are valid
            credentials.refresh(Request())

            result['valid'] = True
            result['vulnerable'] = True
            result['project_id'] = sa_data.get('project_id')
            result['service_account_email'] = sa_data.get('client_email')

            self.logger.warning(f"VALID GCP SERVICE ACCOUNT FOUND: {sa_data.get('client_email')}")

            # Test permissions
            permissions = self._test_service_account_permissions(credentials, sa_data.get('project_id'))
            result['permissions'] = permissions

            # Assess risk
            result['risk_level'] = self._assess_risk(permissions)
            result['findings'] = self._generate_findings(permissions)

        except json.JSONDecodeError:
            result['findings'].append('Invalid JSON format')
        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')
            self.logger.error(f"Error testing GCP service account: {str(e)}")

        return result

    def _test_service_account_permissions(self, credentials, project_id):
        """Test GCP service account permissions"""
        permissions = {
            'compute': self._test_compute(credentials, project_id),
            'storage': self._test_storage(credentials, project_id),
            'iam': self._test_iam(credentials, project_id),
            'cloud_functions': self._test_cloud_functions(credentials, project_id),
            'cloud_sql': self._test_cloud_sql(credentials, project_id),
            'secrets': self._test_secrets_manager(credentials, project_id)
        }

        return permissions

    def _test_compute(self, credentials, project_id):
        """Test Compute Engine permissions"""
        try:
            service = discovery.build('compute', 'v1', credentials=credentials)
            result = service.instances().aggregatedList(project=project_id, maxResults=10).execute()

            instances = []
            for zone, data in result.get('items', {}).items():
                if 'instances' in data:
                    instances.extend(data['instances'])

            return {
                'accessible': True,
                'instance_count': len(instances),
                'risk': 'HIGH' if instances else 'MEDIUM'
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_storage(self, credentials, project_id):
        """Test Cloud Storage permissions"""
        try:
            service = discovery.build('storage', 'v1', credentials=credentials)
            result = service.buckets().list(project=project_id, maxResults=10).execute()

            buckets = result.get('items', [])

            return {
                'accessible': True,
                'bucket_count': len(buckets),
                'buckets': [b['name'] for b in buckets[:10]],
                'risk': 'HIGH' if buckets else 'MEDIUM'
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_iam(self, credentials, project_id):
        """Test IAM permissions"""
        try:
            service = discovery.build('iam', 'v1', credentials=credentials)
            result = service.projects().serviceAccounts().list(
                name=f'projects/{project_id}',
                pageSize=10
            ).execute()

            accounts = result.get('accounts', [])

            return {
                'accessible': True,
                'service_account_count': len(accounts),
                'risk': 'CRITICAL'  # IAM access is always critical
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_cloud_functions(self, credentials, project_id):
        """Test Cloud Functions permissions"""
        try:
            service = discovery.build('cloudfunctions', 'v1', credentials=credentials)
            result = service.projects().locations().list(
                name=f'projects/{project_id}'
            ).execute()

            return {
                'accessible': True,
                'risk': 'HIGH'
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_cloud_sql(self, credentials, project_id):
        """Test Cloud SQL permissions"""
        try:
            service = discovery.build('sqladmin', 'v1beta4', credentials=credentials)
            result = service.instances().list(project=project_id).execute()

            instances = result.get('items', [])

            return {
                'accessible': True,
                'instance_count': len(instances),
                'risk': 'HIGH' if instances else 'MEDIUM'
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_secrets_manager(self, credentials, project_id):
        """Test Secret Manager permissions"""
        try:
            service = discovery.build('secretmanager', 'v1', credentials=credentials)
            result = service.projects().secrets().list(
                parent=f'projects/{project_id}',
                pageSize=10
            ).execute()

            secrets = result.get('secrets', [])

            return {
                'accessible': True,
                'secret_count': len(secrets),
                'risk': 'CRITICAL' if secrets else 'HIGH'
            }
        except HttpError as e:
            return {
                'accessible': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_api_key(self, key_data):
        """Test GCP API key"""
        result = {
            'provider': 'gcp',
            'key_type': 'api_key',
            'api_key': key_data.get('api_key', ''),
            'valid': False,
            'vulnerable': False,
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        api_key = key_data.get('api_key')

        if not api_key:
            result['findings'].append('Missing API key')
            return result

        try:
            # Test API key with various Google APIs
            import requests

            # Try Maps API
            maps_url = f'https://maps.googleapis.com/maps/api/geocode/json?address=test&key={api_key}'
            response = requests.get(maps_url)

            if response.status_code == 200 and 'status' in response.json():
                result['valid'] = True
                result['vulnerable'] = True
                result['findings'].append('API key works with Maps API')
                result['risk_level'] = 'MEDIUM'
                self.logger.warning(f"VALID GCP API KEY FOUND")

            # Try other APIs...
            # (Can be extended)

        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')

        return result

    def _assess_risk(self, permissions):
        """Assess overall risk level"""
        accessible_services = sum(
            1 for p in permissions.values()
            if isinstance(p, dict) and p.get('accessible')
        )

        # IAM or Secrets access is critical
        if permissions.get('iam', {}).get('accessible'):
            return 'CRITICAL'
        if permissions.get('secrets', {}).get('accessible'):
            return 'CRITICAL'

        # Multiple services accessible
        if accessible_services >= 4:
            return 'HIGH'
        elif accessible_services >= 2:
            return 'MEDIUM'
        elif accessible_services >= 1:
            return 'LOW'

        return 'UNKNOWN'

    def _generate_findings(self, permissions):
        """Generate security findings"""
        findings = []

        accessible_services = []
        for service, perms in permissions.items():
            if isinstance(perms, dict) and perms.get('accessible'):
                accessible_services.append(service)

        if accessible_services:
            findings.append(f"Service account has access to {len(accessible_services)} GCP services: {', '.join(accessible_services)}")

        if permissions.get('iam', {}).get('accessible'):
            findings.append("CRITICAL: IAM access - can manage service accounts")

        if permissions.get('secrets', {}).get('accessible'):
            findings.append("CRITICAL: Secret Manager access - can retrieve secrets")

        if permissions.get('storage', {}).get('accessible'):
            bucket_count = permissions['storage'].get('bucket_count', 0)
            findings.append(f"Access to {bucket_count} Cloud Storage buckets")

        if not findings:
            findings.append("Valid credentials but limited access")

        return findings

    @staticmethod
    def extract_keys_from_text(text):
        """Extract GCP credentials from text"""
        keys = []

        # Look for service account JSON
        try:
            # Find JSON patterns
            json_pattern = r'\{[^{}]*"type"\s*:\s*"service_account"[^{}]*\}'
            matches = re.findall(json_pattern, text, re.DOTALL)

            for match in matches:
                try:
                    sa_data = json.loads(match)
                    if 'private_key' in sa_data and 'client_email' in sa_data:
                        keys.append({
                            'provider': 'gcp',
                            'key_type': 'service_account',
                            'service_account_json': sa_data,
                            'service_account_email': sa_data.get('client_email')
                        })
                except:
                    pass
        except:
            pass

        # Look for API keys
        api_keys = re.findall(GCPKeyTester.API_KEY_PATTERN, text)
        for api_key in api_keys:
            keys.append({
                'provider': 'gcp',
                'key_type': 'api_key',
                'api_key': api_key
            })

        return keys
