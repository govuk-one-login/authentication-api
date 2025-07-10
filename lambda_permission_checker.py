#!/usr/bin/env python3
"""
Lambda Permission Checker

Analyzes Java Lambda handlers to determine required AWS permissions
and validates them using IAM Policy Simulator.
"""

import boto3
import re
import json
import sys
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

@dataclass
class RequiredPermission:
    service: str
    action: str
    resource_type: str
    description: str

class LambdaPermissionChecker:
    def __init__(self, lambda_role_arn: str, account_id: str, region: str):
        self.lambda_role_arn = lambda_role_arn
        self.account_id = account_id
        self.region = region
        self.iam_client = boto3.client('iam')
        
        # Service patterns to detect AWS SDK usage
        self.service_patterns = {
            'dynamodb': [
                (r'dynamoService\.get.*\(', 'dynamodb:GetItem', 'table', 'Read user profile data'),
                (r'dynamoService\.update.*\(', 'dynamodb:UpdateItem', 'table', 'Update user data'),
                (r'dynamoService\.put.*\(', 'dynamodb:PutItem', 'table', 'Create user data'),
                (r'dynamoService\.delete.*\(', 'dynamodb:DeleteItem', 'table', 'Delete user data'),
            ],
            'sqs': [
                (r'sqsClient\.send\(', 'sqs:SendMessage', 'queue', 'Send notification messages'),
                (r'sqsClient\.receive\(', 'sqs:ReceiveMessage', 'queue', 'Receive messages'),
            ],
            'kms': [
                (r'kmsClient\.decrypt\(', 'kms:Decrypt', 'key', 'Decrypt sensitive data'),
                (r'kmsClient\.encrypt\(', 'kms:Encrypt', 'key', 'Encrypt sensitive data'),
            ],
            'ssm': [
                (r'configurationService\.get.*\(', 'ssm:GetParameter', 'parameter', 'Read configuration'),
            ]
        }

    def analyze_mfa_delete_handler(self) -> List[RequiredPermission]:
        """Analyze MFAMethodsDeleteHandler for required permissions"""
        
        # Based on code analysis, this handler needs:
        required_permissions = [
            RequiredPermission(
                service='dynamodb',
                action='dynamodb:GetItem',
                resource_type='table',
                description='Read user profile from DynamoDB'
            ),
            RequiredPermission(
                service='dynamodb', 
                action='dynamodb:UpdateItem',
                resource_type='table',
                description='Update user MFA methods in DynamoDB'
            ),
            RequiredPermission(
                service='sqs',
                action='sqs:SendMessage', 
                resource_type='queue',
                description='Send notification to email queue'
            ),
            RequiredPermission(
                service='ssm',
                action='ssm:GetParameter',
                resource_type='parameter',
                description='Read configuration parameters'
            )
        ]
        
        return required_permissions

    def analyze_java_file(self, file_path: str) -> List[RequiredPermission]:
        """Analyze Java file for AWS service usage patterns"""
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"❌ File not found: {file_path}")
            return []
        
        required_permissions = []
        
        for service, patterns in self.service_patterns.items():
            for pattern, action, resource_type, description in patterns:
                if re.search(pattern, content):
                    required_permissions.append(
                        RequiredPermission(service, action, resource_type, description)
                    )
        
        return required_permissions

    def build_resource_arn(self, permission: RequiredPermission) -> str:
        """Build ARN for the resource type"""
        
        arn_templates = {
            'table': f'arn:aws:dynamodb:{self.region}:{self.account_id}:table/*',
            'queue': f'arn:aws:sqs:{self.region}:{self.account_id}:*',
            'key': f'arn:aws:kms:{self.region}:{self.account_id}:key/*',
            'parameter': f'arn:aws:ssm:{self.region}:{self.account_id}:parameter/*'
        }
        
        return arn_templates.get(permission.resource_type, '*')

    def check_permission(self, permission: RequiredPermission) -> Tuple[bool, str]:
        """Check if Lambda role has the required permission"""
        
        resource_arn = self.build_resource_arn(permission)
        
        try:
            response = self.iam_client.simulate_principal_policy(
                PolicySourceArn=self.lambda_role_arn,
                ActionNames=[permission.action],
                ResourceArns=[resource_arn]
            )
            
            result = response['EvaluationResults'][0]
            decision = result['EvalDecision']
            
            if decision == 'allowed':
                return True, "✅ Permission granted"
            else:
                reason = result.get('EvalDecisionDetails', {}).get('DenyReason', 'Unknown')
                return False, f"❌ Permission denied: {reason}"
                
        except Exception as e:
            return False, f"❌ Error checking permission: {str(e)}"

    def validate_all_permissions(self, permissions: List[RequiredPermission]) -> Dict:
        """Validate all required permissions"""
        
        results = {
            'total': len(permissions),
            'passed': 0,
            'failed': 0,
            'details': []
        }
        
        print(f"\n🔍 Checking {len(permissions)} required permissions for Lambda role:")
        print(f"   Role ARN: {self.lambda_role_arn}\n")
        
        for permission in permissions:
            is_allowed, message = self.check_permission(permission)
            
            result_detail = {
                'service': permission.service,
                'action': permission.action,
                'resource_type': permission.resource_type,
                'description': permission.description,
                'allowed': is_allowed,
                'message': message
            }
            
            results['details'].append(result_detail)
            
            if is_allowed:
                results['passed'] += 1
                print(f"✅ {permission.action:<25} | {permission.description}")
            else:
                results['failed'] += 1
                print(f"❌ {permission.action:<25} | {permission.description}")
                print(f"   {message}")
        
        return results

    def generate_missing_policy(self, failed_permissions: List[Dict]) -> str:
        """Generate IAM policy for missing permissions"""
        
        statements = []
        
        # Group by service
        by_service = {}
        for perm in failed_permissions:
            service = perm['service']
            if service not in by_service:
                by_service[service] = []
            by_service[service].append(perm)
        
        for service, perms in by_service.items():
            actions = [p['action'] for p in perms]
            resource_arn = self.build_resource_arn(
                RequiredPermission(service, '', perms[0]['resource_type'], '')
            )
            
            statements.append({
                "Effect": "Allow",
                "Action": actions,
                "Resource": resource_arn
            })
        
        policy = {
            "Version": "2012-10-17",
            "Statement": statements
        }
        
        return json.dumps(policy, indent=2)

def main():
    # Configuration - these would typically come from command line args or config
    LAMBDA_ROLE_ARN = "arn:aws:iam::123456789012:role/mfa-delete-lambda-role"
    ACCOUNT_ID = "123456789012"
    REGION = "us-east-1"
    
    if len(sys.argv) > 1:
        LAMBDA_ROLE_ARN = sys.argv[1]
    
    print("🔐 Lambda Permission Checker")
    print("=" * 50)
    
    checker = LambdaPermissionChecker(LAMBDA_ROLE_ARN, ACCOUNT_ID, REGION)
    
    # Analyze MFAMethodsDeleteHandler
    print("📋 Analyzing MFAMethodsDeleteHandler...")
    required_permissions = checker.analyze_mfa_delete_handler()
    
    # Validate permissions
    results = checker.validate_all_permissions(required_permissions)
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"   Total permissions checked: {results['total']}")
    print(f"   ✅ Passed: {results['passed']}")
    print(f"   ❌ Failed: {results['failed']}")
    
    # Generate policy for missing permissions
    if results['failed'] > 0:
        failed_perms = [d for d in results['details'] if not d['allowed']]
        missing_policy = checker.generate_missing_policy(failed_perms)
        
        print(f"\n🔧 Missing Permissions Policy:")
        print(missing_policy)
        
        return 1  # Exit with error code
    else:
        print(f"\n🎉 All permissions are correctly configured!")
        return 0

if __name__ == "__main__":
    sys.exit(main())