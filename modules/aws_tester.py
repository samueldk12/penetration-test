#!/usr/bin/env python3
"""
AWS API Key Vulnerability Tester
Tests AWS Access Keys and Secret Keys for valid access and permissions
"""

import boto3
import re
from botocore.exceptions import ClientError, NoCredentialsError
from utils.logger import get_logger


class AWSKeyTester:
    """Test AWS API keys for vulnerabilities and permissions"""

    # AWS key patterns
    ACCESS_KEY_PATTERN = r'AKIA[0-9A-Z]{16}'
    SECRET_KEY_PATTERN = r'[A-Za-z0-9/+=]{40}'

    def __init__(self, settings):
        self.settings = settings
        self.logger = get_logger()
        self.tested_keys = set()

    def test_key(self, key_data):
        """Test AWS API key for validity and permissions"""
        result = {
            'provider': 'aws',
            'key_id': key_data.get('key', ''),
            'secret_key': key_data.get('secret', ''),
            'valid': False,
            'vulnerable': False,
            'permissions': [],
            'findings': [],
            'risk_level': 'UNKNOWN'
        }

        access_key = key_data.get('key', '')
        secret_key = key_data.get('secret', '')

        if not access_key or not secret_key:
            result['findings'].append('Incomplete credentials')
            return result

        # Avoid duplicate testing
        key_hash = f"{access_key}:{secret_key}"
        if key_hash in self.tested_keys:
            result['findings'].append('Already tested')
            return result

        self.tested_keys.add(key_hash)

        try:
            # Test basic connectivity
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            # Test STS GetCallerIdentity (lowest privilege check)
            sts = session.client('sts')
            identity = sts.get_caller_identity()

            result['valid'] = True
            result['vulnerable'] = True
            result['account_id'] = identity.get('Account')
            result['user_arn'] = identity.get('Arn')

            self.logger.warning(f"VALID AWS KEY FOUND: {access_key}")

            # Test various AWS services for permissions
            permissions = self._test_permissions(session)
            result['permissions'] = permissions

            # Assess risk level
            result['risk_level'] = self._assess_risk(permissions)
            result['findings'] = self._generate_findings(permissions)

        except NoCredentialsError:
            result['findings'].append('Invalid credentials format')
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidClientTokenId':
                result['findings'].append('Invalid access key')
            elif error_code == 'SignatureDoesNotMatch':
                result['findings'].append('Invalid secret key')
            elif error_code == 'AccessDenied':
                result['valid'] = True
                result['vulnerable'] = True
                result['findings'].append('Valid credentials but access denied to STS')
                result['risk_level'] = 'MEDIUM'
            else:
                result['findings'].append(f'AWS Error: {error_code}')
        except Exception as e:
            result['findings'].append(f'Error: {str(e)}')
            self.logger.error(f"Error testing AWS key: {str(e)}")

        return result

    def _test_permissions(self, session):
        """Test what permissions the key has"""
        permissions = {
            's3': self._test_s3(session),
            'ec2': self._test_ec2(session),
            'iam': self._test_iam(session),
            'lambda': self._test_lambda(session),
            'rds': self._test_rds(session),
            'dynamodb': self._test_dynamodb(session),
            'sns': self._test_sns(session),
            'sqs': self._test_sqs(session),
            'cloudformation': self._test_cloudformation(session),
            'secrets_manager': self._test_secrets_manager(session)
        }

        return permissions

    def _test_s3(self, session):
        """Test S3 permissions"""
        try:
            s3 = session.client('s3')
            response = s3.list_buckets()
            buckets = [b['Name'] for b in response.get('Buckets', [])]

            return {
                'accessible': True,
                'list_buckets': True,
                'bucket_count': len(buckets),
                'buckets': buckets[:10],  # Limit to first 10
                'risk': 'HIGH' if buckets else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_ec2(self, session):
        """Test EC2 permissions"""
        try:
            ec2 = session.client('ec2', region_name='us-east-1')
            response = ec2.describe_instances(MaxResults=10)
            instance_count = len(response.get('Reservations', []))

            return {
                'accessible': True,
                'describe_instances': True,
                'instance_count': instance_count,
                'risk': 'HIGH' if instance_count > 0 else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_iam(self, session):
        """Test IAM permissions"""
        try:
            iam = session.client('iam')
            response = iam.list_users(MaxItems=10)
            user_count = len(response.get('Users', []))

            return {
                'accessible': True,
                'list_users': True,
                'user_count': user_count,
                'risk': 'CRITICAL'  # IAM access is always critical
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_lambda(self, session):
        """Test Lambda permissions"""
        try:
            lambda_client = session.client('lambda', region_name='us-east-1')
            response = lambda_client.list_functions(MaxItems=10)
            function_count = len(response.get('Functions', []))

            return {
                'accessible': True,
                'list_functions': True,
                'function_count': function_count,
                'risk': 'HIGH' if function_count > 0 else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_rds(self, session):
        """Test RDS permissions"""
        try:
            rds = session.client('rds', region_name='us-east-1')
            response = rds.describe_db_instances(MaxRecords=10)
            db_count = len(response.get('DBInstances', []))

            return {
                'accessible': True,
                'describe_databases': True,
                'database_count': db_count,
                'risk': 'HIGH' if db_count > 0 else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_dynamodb(self, session):
        """Test DynamoDB permissions"""
        try:
            dynamodb = session.client('dynamodb', region_name='us-east-1')
            response = dynamodb.list_tables(Limit=10)
            table_count = len(response.get('TableNames', []))

            return {
                'accessible': True,
                'list_tables': True,
                'table_count': table_count,
                'risk': 'HIGH' if table_count > 0 else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_sns(self, session):
        """Test SNS permissions"""
        try:
            sns = session.client('sns', region_name='us-east-1')
            response = sns.list_topics()
            topic_count = len(response.get('Topics', []))

            return {
                'accessible': True,
                'list_topics': True,
                'topic_count': topic_count,
                'risk': 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_sqs(self, session):
        """Test SQS permissions"""
        try:
            sqs = session.client('sqs', region_name='us-east-1')
            response = sqs.list_queues()
            queue_count = len(response.get('QueueUrls', []))

            return {
                'accessible': True,
                'list_queues': True,
                'queue_count': queue_count,
                'risk': 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_cloudformation(self, session):
        """Test CloudFormation permissions"""
        try:
            cf = session.client('cloudformation', region_name='us-east-1')
            response = cf.list_stacks(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE'])
            stack_count = len(response.get('StackSummaries', []))

            return {
                'accessible': True,
                'list_stacks': True,
                'stack_count': stack_count,
                'risk': 'HIGH' if stack_count > 0 else 'MEDIUM'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _test_secrets_manager(self, session):
        """Test Secrets Manager permissions"""
        try:
            secrets = session.client('secretsmanager', region_name='us-east-1')
            response = secrets.list_secrets(MaxResults=10)
            secret_count = len(response.get('SecretList', []))

            return {
                'accessible': True,
                'list_secrets': True,
                'secret_count': secret_count,
                'risk': 'CRITICAL' if secret_count > 0 else 'HIGH'
            }
        except ClientError as e:
            return {
                'accessible': False,
                'error': e.response.get('Error', {}).get('Code', 'Unknown')
            }

    def _assess_risk(self, permissions):
        """Assess overall risk level based on permissions"""
        risk_scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'UNKNOWN': 0
        }

        max_risk = 0
        accessible_services = 0

        for service, perms in permissions.items():
            if isinstance(perms, dict) and perms.get('accessible'):
                accessible_services += 1
                service_risk = perms.get('risk', 'UNKNOWN')
                risk_value = risk_scores.get(service_risk, 0)
                max_risk = max(max_risk, risk_value)

        # If IAM is accessible, always CRITICAL
        if permissions.get('iam', {}).get('accessible'):
            return 'CRITICAL'

        # If many services accessible, escalate risk
        if accessible_services >= 5:
            max_risk = min(max_risk + 1, 4)

        risk_levels = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        return risk_levels[max_risk]

    def _generate_findings(self, permissions):
        """Generate security findings based on permissions"""
        findings = []

        accessible_services = []
        for service, perms in permissions.items():
            if isinstance(perms, dict) and perms.get('accessible'):
                accessible_services.append(service)

        if accessible_services:
            findings.append(f"Key has access to {len(accessible_services)} AWS services: {', '.join(accessible_services)}")

        if permissions.get('iam', {}).get('accessible'):
            findings.append("CRITICAL: Key has IAM access - can potentially manage users and permissions")

        if permissions.get('s3', {}).get('accessible'):
            bucket_count = permissions['s3'].get('bucket_count', 0)
            findings.append(f"Key can list {bucket_count} S3 buckets - potential data exposure")

        if permissions.get('secrets_manager', {}).get('accessible'):
            findings.append("CRITICAL: Key has access to Secrets Manager - can retrieve sensitive credentials")

        if permissions.get('ec2', {}).get('accessible'):
            findings.append("Key has EC2 access - can potentially manage instances")

        if not findings:
            findings.append("Key is valid but has limited permissions")

        return findings

    @staticmethod
    def extract_keys_from_text(text):
        """Extract AWS keys from text"""
        keys = []

        access_keys = re.findall(AWSKeyTester.ACCESS_KEY_PATTERN, text)

        for access_key in access_keys:
            # Try to find associated secret key nearby
            # Look for secret within 500 characters
            start_pos = text.find(access_key)
            search_text = text[max(0, start_pos - 250):start_pos + 250]

            secret_matches = re.findall(AWSKeyTester.SECRET_KEY_PATTERN, search_text)

            for secret in secret_matches:
                keys.append({
                    'provider': 'aws',
                    'key': access_key,
                    'secret': secret
                })

        return keys
