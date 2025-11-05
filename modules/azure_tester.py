#!/usr/bin/env python3
"""
Azure API Key Vulnerability Tester
Tests Azure credentials and service principals for valid access
"""

import re
import requests
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from utils.logger import get_logger


class AzureKeyTester:
    """Test Azure credentials for vulnerabilities and permissions"""

    # Azure credential patterns
    TENANT_ID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    CLIENT_ID_PATTERN = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    CLIENT_SECRET_PATTERN = r'[A-Za-z0-9~._-]{34,40}'
    STORAGE_KEY_PATTERN = r'[A-Za-z0-9+/]{86}=='

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.tested_creds = set()

    def test_key(self, key_data):
        """Test Azure credentials for validity and permissions"""
        result = {
            'provider': 'azure',
            'tenant_id': key_data.get('tenant_id', ''),
            'client_id': key_data.get('client_id', ''),
            'valid': False,
            'vulnerable': False,
            'permissions': [],
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        tenant_id = key_data.get('tenant_id')
        client_id = key_data.get('client_id')
        client_secret = key_data.get('client_secret')

        if not all([tenant_id, client_id, client_secret]):
            result['findings'].append('Incomplete Azure credentials')
            return result

        # Avoid duplicate testing
        cred_hash = f"{tenant_id}:{client_id}:{client_secret}"
        if cred_hash in self.tested_creds:
            result['findings'].append('Already tested')
            return result

        self.tested_creds.add(cred_hash)

        try:
            # Test authentication
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )

            # Try to get token
            token = credential.get_token("https://management.azure.com/.default")

            result['valid'] = True
            result['vulnerable'] = True

            self.logger.warning(f"VALID AZURE CREDENTIALS FOUND: {client_id}")

            # Test subscriptions
            subscriptions = self._get_subscriptions(credential)
            result['subscriptions'] = subscriptions

            if subscriptions:
                # Test permissions on first subscription
                subscription_id = subscriptions[0]['id']
                permissions = self._test_permissions(credential, subscription_id)
                result['permissions'] = permissions

                # Assess risk
                result['risk_level'] = self._assess_risk(permissions)
                result['findings'] = self._generate_findings(permissions, subscriptions)
            else:
                result['findings'].append('Valid credentials but no subscriptions accessible')
                result['risk_level'] = 'LOW'

        except ClientAuthenticationError as e:
            result['findings'].append(f'Authentication failed: {str(e)}')
        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')
            self.logger.error(f"Error testing Azure credentials: {str(e)}")

        return result

    def _get_subscriptions(self, credential):
        """Get accessible Azure subscriptions"""
        try:
            # Use REST API to get subscriptions
            token = credential.get_token("https://management.azure.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                'https://management.azure.com/subscriptions?api-version=2020-01-01',
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                return [
                    {
                        'id': sub['subscriptionId'],
                        'name': sub['displayName']
                    }
                    for sub in data.get('value', [])
                ]

        except Exception as e:
            self.logger.error(f"Error getting subscriptions: {str(e)}")

        return []

    def _test_permissions(self, credential, subscription_id):
        """Test Azure permissions"""
        permissions = {
            'resource_groups': self._test_resource_groups(credential, subscription_id),
            'storage_accounts': self._test_storage_accounts(credential, subscription_id),
            'virtual_machines': self._test_virtual_machines(credential, subscription_id),
            'key_vaults': self._test_key_vaults(credential, subscription_id)
        }

        return permissions

    def _test_resource_groups(self, credential, subscription_id):
        """Test resource group permissions"""
        try:
            client = ResourceManagementClient(credential, subscription_id)
            resource_groups = list(client.resource_groups.list())

            return {
                'accessible': True,
                'count': len(resource_groups),
                'groups': [rg.name for rg in resource_groups[:10]],
                'risk': 'HIGH' if resource_groups else 'MEDIUM'
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_storage_accounts(self, credential, subscription_id):
        """Test storage account permissions"""
        try:
            client = StorageManagementClient(credential, subscription_id)
            storage_accounts = list(client.storage_accounts.list())

            return {
                'accessible': True,
                'count': len(storage_accounts),
                'accounts': [sa.name for sa in storage_accounts[:10]],
                'risk': 'HIGH' if storage_accounts else 'MEDIUM'
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_virtual_machines(self, credential, subscription_id):
        """Test virtual machine permissions"""
        try:
            client = ComputeManagementClient(credential, subscription_id)
            vms = list(client.virtual_machines.list_all())

            return {
                'accessible': True,
                'count': len(vms),
                'vms': [vm.name for vm in vms[:10]],
                'risk': 'HIGH' if vms else 'MEDIUM'
            }
        except Exception as e:
            return {
                'accessible': False,
                'error': str(e)
            }

    def _test_key_vaults(self, credential, subscription_id):
        """Test Key Vault permissions"""
        try:
            token = credential.get_token("https://management.azure.com/.default")
            headers = {
                'Authorization': f'Bearer {token.token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(
                f'https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01',
                headers=headers
            )

            if response.status_code == 200:
                data = response.json()
                vaults = data.get('value', [])

                return {
                    'accessible': True,
                    'count': len(vaults),
                    'vaults': [v['name'] for v in vaults[:10]],
                    'risk': 'CRITICAL' if vaults else 'HIGH'
                }

        except Exception as e:
            pass

        return {
            'accessible': False,
            'error': 'Unable to access Key Vaults'
        }

    def _assess_risk(self, permissions):
        """Assess overall risk level"""
        accessible_services = sum(
            1 for p in permissions.values()
            if isinstance(p, dict) and p.get('accessible')
        )

        # Key Vault access is critical
        if permissions.get('key_vaults', {}).get('accessible'):
            return 'CRITICAL'

        # Multiple services accessible
        if accessible_services >= 3:
            return 'HIGH'
        elif accessible_services >= 2:
            return 'MEDIUM'
        elif accessible_services >= 1:
            return 'LOW'

        return 'UNKNOWN'

    def _generate_findings(self, permissions, subscriptions):
        """Generate security findings"""
        findings = []

        findings.append(f"Credentials have access to {len(subscriptions)} Azure subscription(s)")

        accessible_services = []
        for service, perms in permissions.items():
            if isinstance(perms, dict) and perms.get('accessible'):
                accessible_services.append(service)
                count = perms.get('count', 0)
                if count > 0:
                    findings.append(f"{service}: {count} resource(s) accessible")

        if permissions.get('key_vaults', {}).get('accessible'):
            findings.append("CRITICAL: Access to Key Vaults - potential secret exposure")

        if permissions.get('storage_accounts', {}).get('accessible'):
            findings.append("Access to Storage Accounts - potential data exposure")

        if not accessible_services:
            findings.append("Valid credentials but limited resource access")

        return findings

    @staticmethod
    def extract_keys_from_text(text):
        """Extract Azure credentials from text"""
        keys = []

        tenant_ids = re.findall(AzureKeyTester.TENANT_ID_PATTERN, text)
        client_ids = re.findall(AzureKeyTester.CLIENT_ID_PATTERN, text)
        secrets = re.findall(AzureKeyTester.CLIENT_SECRET_PATTERN, text)

        # Try to match credentials that appear together
        for tenant_id in tenant_ids:
            for client_id in client_ids:
                for secret in secrets:
                    keys.append({
                        'provider': 'azure',
                        'tenant_id': tenant_id,
                        'client_id': client_id,
                        'client_secret': secret
                    })

        return keys
