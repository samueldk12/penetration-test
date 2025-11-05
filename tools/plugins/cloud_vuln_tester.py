#!/usr/bin/env python3
"""
Cloud Vulnerability Tester Plugin - Testa vulnerabilidades específicas em cloud keys
Detecta: overly permissive keys, privilege escalation paths, misconfigurations
"""

from typing import Dict, Any, List
import sys
sys.path.append('..')
from plugin_system import PluginInterface


class CloudVulnTesterPlugin(PluginInterface):
    """Plugin para testar vulnerabilidades em cloud credentials."""

    name = "cloud_vuln_tester"
    version = "1.0.0"
    author = "Auto Recon System"
    description = "Tests for cloud credential vulnerabilities and misconfigurations"
    category = "vuln_scan"
    requires = []  # boto3, google-cloud são opcionais

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Testa vulnerabilidades em cloud keys.

        Args:
            target: Not used (uses kwargs for credentials)
            **kwargs:
                service: aws|gcp|azure
                credentials: Dict com credenciais

        Returns:
            Dicionário com vulnerabilidades encontradas
        """
        service = kwargs.get('service')
        credentials = kwargs.get('credentials', {})

        if not service:
            return {'error': 'Service not specified (aws, gcp, or azure)'}

        print(f"[*] Testing {service.upper()} credentials for vulnerabilities...")

        vulnerabilities = []

        if service == 'aws':
            vulns = self._test_aws_vulns(credentials)
            vulnerabilities.extend(vulns)
        elif service == 'gcp':
            vulns = self._test_gcp_vulns(credentials)
            vulnerabilities.extend(vulns)
        elif service == 'azure':
            vulns = self._test_azure_vulns(credentials)
            vulnerabilities.extend(vulns)
        else:
            return {'error': f'Unknown service: {service}'}

        print(f"\n[+] Found {len(vulnerabilities)} potential vulnerabilities")

        self.results = vulnerabilities

        return {
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'service': service
        }

    def _test_aws_vulns(self, creds: Dict) -> List[Dict]:
        """
        Testa vulnerabilidades AWS específicas.

        Args:
            creds: Credenciais AWS

        Returns:
            Lista de vulnerabilidades
        """
        vulnerabilities = []

        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            self.errors.append("boto3 not installed")
            return []

        access_key_id = creds.get('access_key_id')
        secret_access_key = creds.get('secret_access_key')
        session_token = creds.get('session_token')

        if not access_key_id or not secret_access_key:
            return []

        session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            aws_session_token=session_token,
            region_name=creds.get('region', 'us-east-1')
        )

        # ============================================
        # VULN 1: Privilege Escalation via IAM
        # ============================================
        print("[*] Testing for IAM privilege escalation vectors...")

        dangerous_iam_permissions = [
            'iam:CreateUser',
            'iam:CreateAccessKey',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
            'iam:CreatePolicyVersion',
            'iam:SetDefaultPolicyVersion',
            'iam:PassRole',
            'iam:UpdateAssumeRolePolicy',
            'sts:AssumeRole'
        ]

        try:
            iam = session.client('iam')
            sts = session.client('sts')

            # Get current identity
            identity = sts.get_caller_identity()
            current_arn = identity.get('Arn', '')

            # Try to get user policies
            if ':user/' in current_arn:
                username = current_arn.split('/')[-1]

                try:
                    # List attached policies
                    attached = iam.list_attached_user_policies(UserName=username)

                    for policy in attached.get('AttachedPolicies', []):
                        if 'AdministratorAccess' in policy.get('PolicyName', ''):
                            vulnerabilities.append({
                                'type': 'overly_permissive',
                                'severity': 'critical',
                                'service': 'aws',
                                'resource': username,
                                'description': 'User has AdministratorAccess policy attached',
                                'impact': 'Full administrative access to AWS account',
                                'remediation': 'Remove AdministratorAccess and apply principle of least privilege'
                            })

                    # List inline policies
                    inline = iam.list_user_policies(UserName=username)

                    for policy_name in inline.get('PolicyNames', []):
                        policy_doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                        policy_str = str(policy_doc)

                        # Check for dangerous permissions
                        for perm in dangerous_iam_permissions:
                            if perm in policy_str:
                                vulnerabilities.append({
                                    'type': 'privilege_escalation',
                                    'severity': 'high',
                                    'service': 'aws',
                                    'resource': username,
                                    'permission': perm,
                                    'description': f'User has dangerous permission: {perm}',
                                    'impact': 'Potential privilege escalation to administrator',
                                    'remediation': f'Remove {perm} permission or restrict its scope'
                                })

                except ClientError:
                    pass

        except Exception as e:
            self.errors.append(f"Error testing IAM: {str(e)}")

        # ============================================
        # VULN 2: S3 Bucket Public Access
        # ============================================
        print("[*] Testing for public S3 buckets...")

        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()

            for bucket in buckets.get('Buckets', [])[:10]:  # Limita a 10
                bucket_name = bucket['Name']

                try:
                    # Check ACL
                    acl = s3.get_bucket_acl(Bucket=bucket_name)

                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')

                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            vulnerabilities.append({
                                'type': 'public_access',
                                'severity': 'critical',
                                'service': 'aws',
                                'resource': bucket_name,
                                'description': f'S3 bucket {bucket_name} has public ACL',
                                'impact': 'Anyone can access bucket contents',
                                'remediation': 'Remove public ACL grants and enable bucket encryption'
                            })

                    # Check bucket policy
                    try:
                        policy = s3.get_bucket_policy(Bucket=bucket_name)
                        policy_str = policy.get('Policy', '')

                        if '"Principal":"*"' in policy_str or '"Principal":{"AWS":"*"}' in policy_str:
                            vulnerabilities.append({
                                'type': 'overly_permissive',
                                'severity': 'high',
                                'service': 'aws',
                                'resource': bucket_name,
                                'description': f'S3 bucket {bucket_name} has wildcard principal in policy',
                                'impact': 'Bucket policy allows access from any AWS account',
                                'remediation': 'Restrict bucket policy to specific principals'
                            })

                    except ClientError:
                        pass  # No bucket policy

                except ClientError:
                    pass  # Access denied

        except Exception as e:
            self.errors.append(f"Error testing S3: {str(e)}")

        # ============================================
        # VULN 3: Lambda Function with Excessive Permissions
        # ============================================
        print("[*] Testing Lambda functions for excessive permissions...")

        try:
            lambda_client = session.client('lambda')
            functions = lambda_client.list_functions(MaxItems=10)

            for function in functions.get('Functions', []):
                function_name = function['FunctionName']
                role_arn = function.get('Role', '')

                if role_arn:
                    role_name = role_arn.split('/')[-1]

                    try:
                        # Check role policies
                        attached = iam.list_attached_role_policies(RoleName=role_name)

                        for policy in attached.get('AttachedPolicies', []):
                            if 'AdministratorAccess' in policy.get('PolicyName', ''):
                                vulnerabilities.append({
                                    'type': 'overly_permissive',
                                    'severity': 'high',
                                    'service': 'aws',
                                    'resource': function_name,
                                    'description': f'Lambda function {function_name} has AdministratorAccess',
                                    'impact': 'Function can perform any action in AWS account',
                                    'remediation': 'Apply least privilege principle to Lambda execution role'
                                })

                    except ClientError:
                        pass

        except Exception as e:
            self.errors.append(f"Error testing Lambda: {str(e)}")

        # ============================================
        # VULN 4: EC2 Instances with IMDSv1 (Metadata Service)
        # ============================================
        print("[*] Testing EC2 instances for IMDSv1...")

        try:
            ec2 = session.client('ec2')
            instances = ec2.describe_instances(MaxResults=10)

            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    metadata_options = instance.get('MetadataOptions', {})

                    http_tokens = metadata_options.get('HttpTokens', 'optional')

                    if http_tokens == 'optional':
                        vulnerabilities.append({
                            'type': 'misconfiguration',
                            'severity': 'medium',
                            'service': 'aws',
                            'resource': instance_id,
                            'description': f'EC2 instance {instance_id} allows IMDSv1 (unencrypted metadata)',
                            'impact': 'SSRF attacks can steal instance credentials',
                            'remediation': 'Enforce IMDSv2 by setting HttpTokens=required'
                        })

        except Exception as e:
            self.errors.append(f"Error testing EC2: {str(e)}")

        # ============================================
        # VULN 5: Secrets Manager - Secrets without Rotation
        # ============================================
        print("[*] Testing Secrets Manager for rotation policy...")

        try:
            secrets = session.client('secretsmanager')
            secret_list = secrets.list_secrets(MaxResults=10)

            for secret in secret_list.get('SecretList', []):
                secret_name = secret['Name']
                rotation_enabled = secret.get('RotationEnabled', False)

                if not rotation_enabled:
                    vulnerabilities.append({
                        'type': 'misconfiguration',
                        'severity': 'medium',
                        'service': 'aws',
                        'resource': secret_name,
                        'description': f'Secret {secret_name} does not have rotation enabled',
                        'impact': 'Long-lived secrets increase compromise risk',
                        'remediation': 'Enable automatic rotation for this secret'
                    })

        except Exception as e:
            self.errors.append(f"Error testing Secrets Manager: {str(e)}")

        return vulnerabilities

    def _test_gcp_vulns(self, creds: Dict) -> List[Dict]:
        """
        Testa vulnerabilidades GCP específicas.

        Args:
            creds: Credenciais GCP

        Returns:
            Lista de vulnerabilidades
        """
        vulnerabilities = []

        try:
            from google.oauth2 import service_account
            from googleapiclient import discovery
            from googleapiclient.errors import HttpError
        except ImportError:
            self.errors.append("google-cloud libraries not installed")
            return []

        credentials_json = creds.get('credentials_json')

        if not credentials_json:
            return []

        print("[*] Testing GCP for vulnerabilities...")

        try:
            if isinstance(credentials_json, str):
                import json
                credentials_json = json.loads(credentials_json)

            credentials = service_account.Credentials.from_service_account_info(credentials_json)
            project_id = credentials_json.get('project_id')

            # ============================================
            # VULN 1: Service Account with Owner Role
            # ============================================
            print("[*] Testing for overly permissive service accounts...")

            try:
                iam_service = discovery.build('iam', 'v1', credentials=credentials)
                crm_service = discovery.build('cloudresourcemanager', 'v1', credentials=credentials)

                # Get project IAM policy
                policy = crm_service.projects().getIamPolicy(
                    resource=project_id,
                    body={}
                ).execute()

                for binding in policy.get('bindings', []):
                    role = binding.get('role', '')
                    members = binding.get('members', [])

                    # Check for Owner/Editor roles
                    if 'roles/owner' in role or 'roles/editor' in role:
                        for member in members:
                            if 'serviceAccount' in member:
                                vulnerabilities.append({
                                    'type': 'overly_permissive',
                                    'severity': 'critical',
                                    'service': 'gcp',
                                    'resource': member,
                                    'description': f'Service account has {role} role',
                                    'impact': 'Service account can perform any action in project',
                                    'remediation': 'Apply principle of least privilege'
                                })

            except HttpError as e:
                self.errors.append(f"Error testing IAM: {e}")

            # ============================================
            # VULN 2: Public Cloud Storage Buckets
            # ============================================
            print("[*] Testing for public GCS buckets...")

            try:
                storage_service = discovery.build('storage', 'v1', credentials=credentials)
                buckets = storage_service.buckets().list(project=project_id, maxResults=10).execute()

                for bucket in buckets.get('items', []):
                    bucket_name = bucket['name']

                    # Get bucket IAM policy
                    bucket_policy = storage_service.buckets().getIamPolicy(bucket=bucket_name).execute()

                    for binding in bucket_policy.get('bindings', []):
                        members = binding.get('members', [])

                        if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                            vulnerabilities.append({
                                'type': 'public_access',
                                'severity': 'critical',
                                'service': 'gcp',
                                'resource': bucket_name,
                                'description': f'GCS bucket {bucket_name} is publicly accessible',
                                'impact': 'Anyone can access bucket contents',
                                'remediation': 'Remove allUsers and allAuthenticatedUsers from IAM policy'
                            })

            except HttpError as e:
                self.errors.append(f"Error testing Storage: {e}")

        except Exception as e:
            self.errors.append(f"Error testing GCP: {str(e)}")

        return vulnerabilities

    def _test_azure_vulns(self, creds: Dict) -> List[Dict]:
        """
        Testa vulnerabilidades Azure específicas.

        Args:
            creds: Credenciais Azure

        Returns:
            Lista de vulnerabilidades
        """
        vulnerabilities = []

        try:
            from azure.storage.blob import BlobServiceClient
            from azure.core.exceptions import AzureError
        except ImportError:
            self.errors.append("azure-storage-blob not installed")
            return []

        connection_string = creds.get('connection_string')
        account_name = creds.get('account_name')
        account_key = creds.get('account_key')

        print("[*] Testing Azure for vulnerabilities...")

        try:
            if connection_string:
                client = BlobServiceClient.from_connection_string(connection_string)
            elif account_name and account_key:
                client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net",
                    credential=account_key
                )
            else:
                return []

            # ============================================
            # VULN 1: Public Blob Containers
            # ============================================
            print("[*] Testing for public blob containers...")

            containers = list(client.list_containers(results_per_page=10))

            for container in containers:
                container_name = container['name']
                public_access = container.get('public_access')

                if public_access and public_access != 'off':
                    vulnerabilities.append({
                        'type': 'public_access',
                        'severity': 'critical',
                        'service': 'azure',
                        'resource': container_name,
                        'description': f'Blob container {container_name} allows public access',
                        'impact': 'Anyone can access container blobs',
                        'remediation': 'Set public access level to private (off)'
                    })

        except Exception as e:
            self.errors.append(f"Error testing Azure: {str(e)}")

        return vulnerabilities
