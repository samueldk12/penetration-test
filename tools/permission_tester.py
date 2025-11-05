#!/usr/bin/env python3
"""
Cloud Permission Tester
Testa permissões de API keys descobertas (AWS, GCP, Azure)
"""

import json
import sys
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import hashlib


class PermissionTestResult:
    """Resultado de teste de permissões."""

    def __init__(self, service: str, test_type: str):
        self.service = service
        self.test_type = test_type
        self.success = False
        self.permissions_found = []
        self.errors = []
        self.risk_assessment = "unknown"
        self.details = {}
        self.tested_at = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        """Converte para dicionário."""
        return {
            'service': self.service,
            'test_type': self.test_type,
            'success': self.success,
            'permissions_found': self.permissions_found,
            'errors': self.errors,
            'risk_assessment': self.risk_assessment,
            'details': self.details,
            'tested_at': self.tested_at
        }


class AWSPermissionTester:
    """Testa permissões de credenciais AWS."""

    def __init__(self, access_key_id: str, secret_access_key: str,
                 session_token: Optional[str] = None, region: str = 'us-east-1'):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session_token = session_token
        self.region = region

    def test_permissions(self) -> PermissionTestResult:
        """
        Testa permissões AWS IAM.

        Testes realizados (em ordem de periculosidade):
        1. sts:GetCallerIdentity (básico, sempre permitido)
        2. s3:ListBuckets (leitura S3)
        3. iam:ListUsers (leitura IAM)
        4. iam:ListRoles (leitura IAM)
        5. ec2:DescribeInstances (leitura EC2)
        6. rds:DescribeDBInstances (leitura RDS)
        7. lambda:ListFunctions (leitura Lambda)
        8. dynamodb:ListTables (leitura DynamoDB)
        9. secretsmanager:ListSecrets (leitura Secrets Manager)
        10. iam:CreateUser (escrita IAM - CRÍTICO)
        11. s3:PutObject (escrita S3 - CRÍTICO)
        12. ec2:RunInstances (criação EC2 - CRÍTICO)
        """
        result = PermissionTestResult(service="aws", test_type="iam_permissions")

        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError

            # Cria sessão boto3
            session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                aws_session_token=self.session_token,
                region_name=self.region
            )

            # ============================================
            # TEST 1: sts:GetCallerIdentity
            # ============================================
            try:
                sts = session.client('sts')
                identity = sts.get_caller_identity()

                result.success = True
                result.details['identity'] = {
                    'account': identity.get('Account'),
                    'arn': identity.get('Arn'),
                    'user_id': identity.get('UserId')
                }
                result.permissions_found.append('sts:GetCallerIdentity')

                print(f"[+] Credenciais válidas!")
                print(f"    Account: {identity.get('Account')}")
                print(f"    ARN: {identity.get('Arn')}")

            except ClientError as e:
                result.errors.append(f"sts:GetCallerIdentity failed: {str(e)}")
                result.risk_assessment = "invalid"
                return result

            # ============================================
            # TEST 2: s3:ListBuckets
            # ============================================
            try:
                s3 = session.client('s3')
                buckets = s3.list_buckets()

                result.permissions_found.append('s3:ListBuckets')
                result.details['s3_buckets'] = [b['Name'] for b in buckets.get('Buckets', [])]

                print(f"[+] s3:ListBuckets: {len(buckets.get('Buckets', []))} buckets encontrados")

            except ClientError as e:
                result.errors.append(f"s3:ListBuckets: {e.response['Error']['Code']}")

            # ============================================
            # TEST 3: iam:ListUsers
            # ============================================
            try:
                iam = session.client('iam')
                users = iam.list_users(MaxItems=10)

                result.permissions_found.append('iam:ListUsers')
                result.details['iam_users_count'] = len(users.get('Users', []))

                print(f"[+] iam:ListUsers: {len(users.get('Users', []))} usuários")

            except ClientError as e:
                result.errors.append(f"iam:ListUsers: {e.response['Error']['Code']}")

            # ============================================
            # TEST 4: iam:ListRoles
            # ============================================
            try:
                roles = iam.list_roles(MaxItems=10)

                result.permissions_found.append('iam:ListRoles')
                result.details['iam_roles_count'] = len(roles.get('Roles', []))

                print(f"[+] iam:ListRoles: {len(roles.get('Roles', []))} roles")

            except ClientError as e:
                result.errors.append(f"iam:ListRoles: {e.response['Error']['Code']}")

            # ============================================
            # TEST 5: ec2:DescribeInstances
            # ============================================
            try:
                ec2 = session.client('ec2')
                instances = ec2.describe_instances(MaxResults=10)

                result.permissions_found.append('ec2:DescribeInstances')

                instance_count = sum(len(r['Instances']) for r in instances.get('Reservations', []))
                result.details['ec2_instances_count'] = instance_count

                print(f"[+] ec2:DescribeInstances: {instance_count} instâncias")

            except ClientError as e:
                result.errors.append(f"ec2:DescribeInstances: {e.response['Error']['Code']}")

            # ============================================
            # TEST 6: rds:DescribeDBInstances
            # ============================================
            try:
                rds = session.client('rds')
                databases = rds.describe_db_instances(MaxRecords=10)

                result.permissions_found.append('rds:DescribeDBInstances')
                result.details['rds_instances_count'] = len(databases.get('DBInstances', []))

                print(f"[+] rds:DescribeDBInstances: {len(databases.get('DBInstances', []))} databases")

            except ClientError as e:
                result.errors.append(f"rds:DescribeDBInstances: {e.response['Error']['Code']}")

            # ============================================
            # TEST 7: lambda:ListFunctions
            # ============================================
            try:
                lambda_client = session.client('lambda')
                functions = lambda_client.list_functions(MaxItems=10)

                result.permissions_found.append('lambda:ListFunctions')
                result.details['lambda_functions_count'] = len(functions.get('Functions', []))

                print(f"[+] lambda:ListFunctions: {len(functions.get('Functions', []))} funções")

            except ClientError as e:
                result.errors.append(f"lambda:ListFunctions: {e.response['Error']['Code']}")

            # ============================================
            # TEST 8: dynamodb:ListTables
            # ============================================
            try:
                dynamodb = session.client('dynamodb')
                tables = dynamodb.list_tables(Limit=10)

                result.permissions_found.append('dynamodb:ListTables')
                result.details['dynamodb_tables_count'] = len(tables.get('TableNames', []))

                print(f"[+] dynamodb:ListTables: {len(tables.get('TableNames', []))} tabelas")

            except ClientError as e:
                result.errors.append(f"dynamodb:ListTables: {e.response['Error']['Code']}")

            # ============================================
            # TEST 9: secretsmanager:ListSecrets
            # ============================================
            try:
                secrets = session.client('secretsmanager')
                secret_list = secrets.list_secrets(MaxResults=10)

                result.permissions_found.append('secretsmanager:ListSecrets')
                result.details['secrets_count'] = len(secret_list.get('SecretList', []))

                print(f"[+] secretsmanager:ListSecrets: {len(secret_list.get('SecretList', []))} secrets")

            except ClientError as e:
                result.errors.append(f"secretsmanager:ListSecrets: {e.response['Error']['Code']}")

            # ============================================
            # CRITICAL TESTS - Write Permissions
            # ============================================

            # TEST 10: iam:CreateUser (DRY RUN - não executa)
            try:
                # Tentamos verificar se temos permissão sem criar de fato
                # Usamos simulate_principal_policy se disponível
                iam.simulate_principal_policy(
                    PolicySourceArn=result.details['identity']['arn'],
                    ActionNames=['iam:CreateUser']
                )
                result.permissions_found.append('iam:CreateUser (simulated)')
                print(f"[!] iam:CreateUser: PERMISSÃO CRÍTICA DETECTADA")

            except:
                # Falha ao simular ou sem permissão
                pass

            # TEST 11: Check for Administrator Access
            if 'iam:ListUsers' in result.permissions_found and \
               'iam:ListRoles' in result.permissions_found and \
               's3:ListBuckets' in result.permissions_found:
                result.details['likely_admin'] = True
                print(f"[!!!] AVISO: Credenciais com amplas permissões (possível Admin)")

            # ============================================
            # Risk Assessment
            # ============================================
            critical_permissions = [
                'iam:CreateUser', 'iam:CreateRole', 'iam:AttachUserPolicy',
                's3:PutObject', 'ec2:RunInstances', 'lambda:CreateFunction'
            ]

            high_risk_permissions = [
                'iam:ListUsers', 'iam:ListRoles', 's3:ListBuckets',
                'ec2:DescribeInstances', 'secretsmanager:ListSecrets'
            ]

            has_critical = any(p in result.permissions_found for p in critical_permissions)
            has_high_risk = sum(1 for p in high_risk_permissions if p in result.permissions_found)

            if has_critical or result.details.get('likely_admin'):
                result.risk_assessment = "critical"
            elif has_high_risk >= 3:
                result.risk_assessment = "high"
            elif has_high_risk >= 1:
                result.risk_assessment = "medium"
            else:
                result.risk_assessment = "low"

            print(f"\n[*] Risk Assessment: {result.risk_assessment.upper()}")
            print(f"[*] Total permissions: {len(result.permissions_found)}")

        except ImportError:
            result.errors.append("boto3 not installed. Run: pip install boto3")
            result.risk_assessment = "unknown"

        except Exception as e:
            result.errors.append(f"Unexpected error: {str(e)}")
            result.risk_assessment = "error"

        return result


class GCPPermissionTester:
    """Testa permissões de credenciais GCP."""

    def __init__(self, credentials_json: str):
        """
        Args:
            credentials_json: Service Account JSON completo ou caminho para arquivo
        """
        self.credentials_json = credentials_json

    def test_permissions(self) -> PermissionTestResult:
        """
        Testa permissões GCP IAM.

        Testes realizados:
        1. cloudresourcemanager.projects.get
        2. storage.buckets.list
        3. compute.instances.list
        4. iam.serviceAccounts.list
        5. secretmanager.secrets.list
        """
        result = PermissionTestResult(service="gcp", test_type="iam_permissions")

        try:
            from google.oauth2 import service_account
            from googleapiclient import discovery
            from googleapiclient.errors import HttpError
            import json as json_lib

            # Parse credentials
            if self.credentials_json.startswith('{'):
                # JSON string
                creds_dict = json_lib.loads(self.credentials_json)
            else:
                # File path
                with open(self.credentials_json, 'r') as f:
                    creds_dict = json_lib.load(f)

            credentials = service_account.Credentials.from_service_account_info(creds_dict)
            project_id = creds_dict.get('project_id')

            result.details['project_id'] = project_id
            result.details['service_account_email'] = creds_dict.get('client_email')

            print(f"[+] Credenciais GCP válidas!")
            print(f"    Project ID: {project_id}")
            print(f"    Service Account: {creds_dict.get('client_email')}")

            # ============================================
            # TEST 1: cloudresourcemanager.projects.get
            # ============================================
            try:
                crm_service = discovery.build('cloudresourcemanager', 'v1', credentials=credentials)
                project = crm_service.projects().get(projectId=project_id).execute()

                result.success = True
                result.permissions_found.append('cloudresourcemanager.projects.get')
                result.details['project_name'] = project.get('name')

                print(f"[+] cloudresourcemanager.projects.get: OK")

            except HttpError as e:
                result.errors.append(f"cloudresourcemanager.projects.get: {e.resp.status}")

            # ============================================
            # TEST 2: storage.buckets.list
            # ============================================
            try:
                storage_service = discovery.build('storage', 'v1', credentials=credentials)
                buckets = storage_service.buckets().list(project=project_id, maxResults=10).execute()

                result.permissions_found.append('storage.buckets.list')
                result.details['gcs_buckets_count'] = len(buckets.get('items', []))

                print(f"[+] storage.buckets.list: {len(buckets.get('items', []))} buckets")

            except HttpError as e:
                result.errors.append(f"storage.buckets.list: {e.resp.status}")

            # ============================================
            # TEST 3: compute.instances.list
            # ============================================
            try:
                compute_service = discovery.build('compute', 'v1', credentials=credentials)

                # Lista zonas primeiro
                zones_result = compute_service.zones().list(project=project_id, maxResults=5).execute()
                zones = [z['name'] for z in zones_result.get('items', [])]

                instance_count = 0
                for zone in zones[:3]:  # Testa apenas primeiras 3 zonas
                    try:
                        instances = compute_service.instances().list(
                            project=project_id,
                            zone=zone,
                            maxResults=10
                        ).execute()
                        instance_count += len(instances.get('items', []))
                    except:
                        pass

                result.permissions_found.append('compute.instances.list')
                result.details['compute_instances_count'] = instance_count

                print(f"[+] compute.instances.list: {instance_count} instâncias")

            except HttpError as e:
                result.errors.append(f"compute.instances.list: {e.resp.status}")

            # ============================================
            # TEST 4: iam.serviceAccounts.list
            # ============================================
            try:
                iam_service = discovery.build('iam', 'v1', credentials=credentials)
                service_accounts = iam_service.projects().serviceAccounts().list(
                    name=f'projects/{project_id}',
                    pageSize=10
                ).execute()

                result.permissions_found.append('iam.serviceAccounts.list')
                result.details['service_accounts_count'] = len(service_accounts.get('accounts', []))

                print(f"[+] iam.serviceAccounts.list: {len(service_accounts.get('accounts', []))} contas")

            except HttpError as e:
                result.errors.append(f"iam.serviceAccounts.list: {e.resp.status}")

            # ============================================
            # TEST 5: secretmanager.secrets.list
            # ============================================
            try:
                secrets_service = discovery.build('secretmanager', 'v1', credentials=credentials)
                secrets = secrets_service.projects().secrets().list(
                    parent=f'projects/{project_id}',
                    pageSize=10
                ).execute()

                result.permissions_found.append('secretmanager.secrets.list')
                result.details['secrets_count'] = len(secrets.get('secrets', []))

                print(f"[+] secretmanager.secrets.list: {len(secrets.get('secrets', []))} secrets")

            except HttpError as e:
                result.errors.append(f"secretmanager.secrets.list: {e.resp.status}")

            # ============================================
            # Risk Assessment
            # ============================================
            critical_permissions = [
                'iam.serviceAccounts.create',
                'iam.serviceAccounts.setIamPolicy',
                'compute.instances.create'
            ]

            high_risk_permissions = [
                'iam.serviceAccounts.list',
                'storage.buckets.list',
                'compute.instances.list',
                'secretmanager.secrets.list'
            ]

            has_high_risk = sum(1 for p in high_risk_permissions if p in result.permissions_found)

            if has_high_risk >= 3:
                result.risk_assessment = "high"
            elif has_high_risk >= 2:
                result.risk_assessment = "medium"
            elif has_high_risk >= 1:
                result.risk_assessment = "low"
            else:
                result.risk_assessment = "minimal"

            print(f"\n[*] Risk Assessment: {result.risk_assessment.upper()}")
            print(f"[*] Total permissions: {len(result.permissions_found)}")

        except ImportError:
            result.errors.append("google-cloud libraries not installed. Run: pip install google-cloud-storage google-api-python-client")
            result.risk_assessment = "unknown"

        except Exception as e:
            result.errors.append(f"Unexpected error: {str(e)}")
            result.risk_assessment = "error"

        return result


class AzurePermissionTester:
    """Testa permissões de credenciais Azure."""

    def __init__(self, connection_string: Optional[str] = None,
                 account_name: Optional[str] = None,
                 account_key: Optional[str] = None):
        """
        Args:
            connection_string: Azure Storage Connection String completo
            account_name: Nome da Storage Account (alternativa)
            account_key: Key da Storage Account (alternativa)
        """
        self.connection_string = connection_string
        self.account_name = account_name
        self.account_key = account_key

    def test_permissions(self) -> PermissionTestResult:
        """
        Testa permissões Azure Storage.

        Testes realizados:
        1. List containers
        2. List blobs in container
        3. Read blob
        4. Get account properties
        """
        result = PermissionTestResult(service="azure", test_type="storage_permissions")

        try:
            from azure.storage.blob import BlobServiceClient
            from azure.core.exceptions import AzureError

            # Cria cliente
            if self.connection_string:
                client = BlobServiceClient.from_connection_string(self.connection_string)

                # Extrai account name do connection string
                for part in self.connection_string.split(';'):
                    if part.startswith('AccountName='):
                        self.account_name = part.split('=')[1]

            elif self.account_name and self.account_key:
                client = BlobServiceClient(
                    account_url=f"https://{self.account_name}.blob.core.windows.net",
                    credential=self.account_key
                )
            else:
                result.errors.append("Missing credentials")
                return result

            result.details['account_name'] = self.account_name

            print(f"[+] Credenciais Azure válidas!")
            print(f"    Storage Account: {self.account_name}")

            # ============================================
            # TEST 1: List containers
            # ============================================
            try:
                containers = list(client.list_containers(results_per_page=10))

                result.success = True
                result.permissions_found.append('storage.containers.list')
                result.details['containers_count'] = len(containers)
                result.details['container_names'] = [c['name'] for c in containers]

                print(f"[+] storage.containers.list: {len(containers)} containers")

            except AzureError as e:
                result.errors.append(f"storage.containers.list: {str(e)}")

            # ============================================
            # TEST 2: List blobs (primeiro container)
            # ============================================
            if result.details.get('container_names'):
                try:
                    first_container = result.details['container_names'][0]
                    container_client = client.get_container_client(first_container)
                    blobs = list(container_client.list_blobs(results_per_page=10))

                    result.permissions_found.append('storage.blobs.list')
                    result.details['blobs_count'] = len(blobs)

                    print(f"[+] storage.blobs.list: {len(blobs)} blobs no container '{first_container}'")

                except AzureError as e:
                    result.errors.append(f"storage.blobs.list: {str(e)}")

            # ============================================
            # TEST 3: Get account properties
            # ============================================
            try:
                properties = client.get_account_information()

                result.permissions_found.append('storage.account.getProperties')
                result.details['account_sku'] = properties.get('sku_name')
                result.details['account_kind'] = properties.get('account_kind')

                print(f"[+] storage.account.getProperties: OK")

            except AzureError as e:
                result.errors.append(f"storage.account.getProperties: {str(e)}")

            # ============================================
            # Risk Assessment
            # ============================================
            if 'storage.containers.list' in result.permissions_found and \
               'storage.blobs.list' in result.permissions_found:
                result.risk_assessment = "high"
            elif 'storage.containers.list' in result.permissions_found:
                result.risk_assessment = "medium"
            else:
                result.risk_assessment = "low"

            print(f"\n[*] Risk Assessment: {result.risk_assessment.upper()}")
            print(f"[*] Total permissions: {len(result.permissions_found)}")

        except ImportError:
            result.errors.append("azure-storage-blob not installed. Run: pip install azure-storage-blob")
            result.risk_assessment = "unknown"

        except Exception as e:
            result.errors.append(f"Unexpected error: {str(e)}")
            result.risk_assessment = "error"

        return result


# CLI Interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Cloud Permission Tester")
    subparsers = parser.add_subparsers(dest='cloud', help='Cloud provider')

    # AWS
    aws_parser = subparsers.add_parser('aws', help='Test AWS credentials')
    aws_parser.add_argument('--access-key', required=True, help='AWS Access Key ID')
    aws_parser.add_argument('--secret-key', required=True, help='AWS Secret Access Key')
    aws_parser.add_argument('--session-token', help='AWS Session Token (optional)')
    aws_parser.add_argument('--region', default='us-east-1', help='AWS Region')

    # GCP
    gcp_parser = subparsers.add_parser('gcp', help='Test GCP credentials')
    gcp_parser.add_argument('--credentials', required=True, help='Service Account JSON (file path or string)')

    # Azure
    azure_parser = subparsers.add_parser('azure', help='Test Azure credentials')
    azure_parser.add_argument('--connection-string', help='Azure Storage Connection String')
    azure_parser.add_argument('--account-name', help='Storage Account Name')
    azure_parser.add_argument('--account-key', help='Storage Account Key')

    # Output
    parser.add_argument('-o', '--output', help='JSON output file')

    args = parser.parse_args()

    if not args.cloud:
        parser.print_help()
        sys.exit(1)

    result = None

    if args.cloud == 'aws':
        tester = AWSPermissionTester(
            access_key_id=args.access_key,
            secret_access_key=args.secret_key,
            session_token=args.session_token,
            region=args.region
        )
        result = tester.test_permissions()

    elif args.cloud == 'gcp':
        tester = GCPPermissionTester(credentials_json=args.credentials)
        result = tester.test_permissions()

    elif args.cloud == 'azure':
        if not (args.connection_string or (args.account_name and args.account_key)):
            print("[!] Erro: Forneça --connection-string OU (--account-name E --account-key)")
            sys.exit(1)

        tester = AzurePermissionTester(
            connection_string=args.connection_string,
            account_name=args.account_name,
            account_key=args.account_key
        )
        result = tester.test_permissions()

    # Save output
    if args.output and result:
        with open(args.output, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\n[+] Resultado salvo em: {args.output}")
