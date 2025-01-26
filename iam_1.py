"""IAM Security Check Flask Application."""

import os
import json
import time
import boto3
import psycopg2
import csv
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from flask import Flask
from psycopg2.extras import RealDictCursor


app = Flask(__name__)


def get_db_connection():
    """Get PostgreSQL database connection with environment variables."""
    config = {
        'host': os.getenv('POSTGRES_HOST', 'localhost'),
        'database': os.getenv('POSTGRES_DB', 'aws_security'),
        'user': os.getenv('POSTGRES_USER', 'postgres'),
        'password': os.getenv('POSTGRES_PASSWORD', 'postgres'),
        'port': os.getenv('POSTGRES_PORT', '5432')
    }
    try:
        return psycopg2.connect(**config)
    except psycopg2.Error as e:
        print(f"Database connection error: {str(e)}")
        return None


def get_aws_client(service_name: str) -> boto3.client:
    """Get AWS client for specified service."""
    return boto3.client(service_name)


def check_iam_access_analyzer_enabled_without_findings(
        iam_client: boto3.client,
        accessanalyzer_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check if IAM Access Analyzer is enabled and has no active findings"""
    try:
        # List analyzers in the account
        analyzers = accessanalyzer_client.list_analyzers()['analyzers']
        
        if not analyzers:
            return [{
                'reason': 'No IAM Access Analyzer enabled',
                'resource': (f'arn:aws:access-analyzer:{os.getenv("AWS_REGION")}:'
                           f'{account_id}:analyzer/*'),
                'status': 'alarm',
                'type': 'iam_access_analyzer_enabled_without_findings'
            }]
        
        # Check findings for each analyzer
        for analyzer in analyzers:
            analyzer_arn = analyzer['arn']
            
            # List active findings
            findings = []
            paginator = accessanalyzer_client.get_paginator('list_findings')
            
            for page in paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={
                    'status': {
                        'eq': ['ACTIVE']
                    }
                }
            ):
                findings.extend(page['findings'])
            
            if findings:
                return [{
                    'reason': (f'IAM Access Analyzer {analyzer["name"]} has '
                              f'{len(findings)} active findings'),
                    'resource': analyzer_arn,
                    'status': 'alarm',
                    'type': 'iam_access_analyzer_enabled_without_findings'
                }]
            
            return [{
                'reason': (
                    f'IAM Access Analyzer {analyzer["name"]} enabled '
                    'with no active findings'
                ),
                'resource': analyzer_arn,
                'status': 'ok',
                'type': 'iam_access_analyzer_enabled_without_findings'
            }]

    except Exception as e:
        return [{
            'reason': (
                f'Error checking IAM Access Analyzer: {str(e)}'
            ),
            'resource': (
                f'arn:aws:access-analyzer:{os.getenv("AWS_REGION")}:'
                f'{account_id}:analyzer/*'
            ),
            'status': 'error',
            'type': 'iam_access_analyzer_enabled_without_findings'
        }]


def check_iam_user_no_policies(
        iam_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check for IAM users with attached policies.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID

    Returns:
        List of dictionaries containing check results
    """
    try:
        results = []
        paginator = iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                user_arn = user['Arn']
                
                # Get attached policies
                attached_policies = iam_client.list_attached_user_policies(
                    UserName=user_name
                )['AttachedPolicies']
                
                if attached_policies:
                    results.append({
                        'reason': (
                            f'User {user_name} has {len(attached_policies)} '
                            'attached policies'
                        ),
                        'resource': user_arn,
                        'status': 'alarm',
                        'type': 'iam_user_no_policies'
                    })
                else:
                    results.append({
                        'reason': f'User {user_name} has no attached policies',
                        'resource': user_arn,
                        'status': 'ok',
                        'type': 'iam_user_no_policies'
                    })
        
        return results
    
    except Exception as e:
        return [{
            'reason': f'Error checking user policies: {str(e)}',
            'resource': f'arn:aws:iam::{account_id}:user/*',
            'status': 'error',
            'type': 'iam_user_no_policies'
        }]


def check_iam_user_one_active_key(
        iam_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check for IAM users with multiple active access keys.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        results = []
        paginator = iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                user_arn = user['Arn']
                
                # Get access keys
                access_keys = iam_client.list_access_keys(
                    UserName=user_name
                )['AccessKeyMetadata']
                
                active_keys = [
                    key for key in access_keys
                    if key['Status'] == 'Active'
                ]
                
                if len(active_keys) > 1:
                    results.append({
                        'reason': (
                            f'User {user_name} has {len(active_keys)} '
                            'active access keys'
                        ),
                        'resource': user_arn,
                        'status': 'alarm',
                        'type': 'iam_user_one_active_key'
                    })
                else:
                    results.append({
                        'reason': (
                            f'User {user_name} has {len(active_keys)} '
                            'active access keys'
                        ),
                        'resource': user_arn,
                        'status': 'ok',
                        'type': 'iam_user_one_active_key'
                    })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking access keys: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:user/*'
            ),
            'status': 'error',
            'type': 'iam_user_one_active_key'
        }]


def check_iam_policy_custom_attached_no_star_star(
        iam_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check customer managed policies for * access.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        results = []
        
        # List customer managed policies
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local', OnlyAttached=True):
            for policy in page['Policies']:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                # Get policy version details
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                # Count statements with *:* permissions
                bad_statements = 0
                for statement in policy_version['PolicyVersion']['Document'].get('Statement', []):
                    if isinstance(statement, dict):  # Handle single statement
                        if statement.get('Effect') == 'Allow':
                            resources = statement.get('Resource', [])
                            actions = statement.get('Action', [])
                            
                            # Convert to lists if string
                            if isinstance(resources, str):
                                resources = [resources]
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            # Check for * in both resource and action
                            if '*' in resources:
                                if '*' in actions or '*:*' in actions:
                                    bad_statements += 1
                
                if bad_statements > 0:
                    results.append({
                        'reason': (
                            f'{policy_name} contains {bad_statements} statements '
                            'that allow action "*" on resource "*".'
                        ),
                        'resource': policy_arn,
                        'status': 'alarm',
                        'type': 'iam_policy_custom_attached_no_star_star'
                    })
                else:
                    results.append({
                        'reason': (
                            f'{policy_name} contains {bad_statements} statements '
                            'that allow action "*" on resource "*".'
                        ),
                        'resource': policy_arn,
                        'status': 'ok',
                        'type': 'iam_policy_custom_attached_no_star_star'
                    })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking IAM policies: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:policy/*'
            ),
            'status': 'error',
            'type': 'iam_policy_custom_attached_no_star_star'
        }]


def check_iam_user_unused_credentials_45(
        iam_client: boto3.client,
        account_id: str,
        report: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Check for unused credentials older than 45 days.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
        report: Optional credential report dictionary
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        # Use provided report or generate a new one
        if not report:
            try:
                iam_client.generate_credential_report()
                while True:
                    report = iam_client.get_credential_report()
                    if report['GeneratedTime']:
                        break
                    time.sleep(1)
            except iam_client.exceptions.CredentialReportNotPresentException:
                return [{
                    'reason': 'Credential report not available',
                    'resource': f'arn:aws:iam::{account_id}:user/*',
                    'status': 'error',
                    'type': 'iam_user_unused_credentials_45'
                }]
        
        # Parse CSV report
        report_csv = csv.DictReader(report['Content'].decode('utf-8').splitlines())
        results = []
        current_date = datetime.now(timezone.utc)
        
        for user in report_csv:
            if user['user'] == '<root_account>':
                continue
            
            user_arn = user['arn']
            password_enabled = user['password_enabled'] == 'true'
            password_last_used = user['password_last_used']
            key1_active = user['access_key_1_active'] == 'true'
            key1_last_used = user['access_key_1_last_used_date']
            key2_active = user['access_key_2_active'] == 'true'
            key2_last_used = user['access_key_2_last_used_date']
            
            unused_days = 0
            reason_parts = []
            
            # Check password usage
            if password_enabled:
                if password_last_used == 'N/A':
                    unused_days = max(unused_days, 999)  # Never used
                    reason_parts.append('Password never used')
                else:
                    last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                    days = (current_date - last_used).days
                    unused_days = max(unused_days, days)
                    reason_parts.append(f'Password last used {last_used.strftime("%d-%b-%Y")} ({days} days)')
            
            # Check access key 1 usage
            if key1_active:
                if key1_last_used == 'N/A':
                    unused_days = max(unused_days, 999)  # Never used
                    reason_parts.append('Access Key 1 never used')
                else:
                    last_used = datetime.fromisoformat(key1_last_used.replace('Z', '+00:00'))
                    days = (current_date - last_used).days
                    unused_days = max(unused_days, days)
                    reason_parts.append(f'Access Key 1 last used {last_used.strftime("%d-%b-%Y")} ({days} days)')
            
            # Check access key 2 usage
            if key2_active:
                if key2_last_used == 'N/A':
                    unused_days = max(unused_days, 999)  # Never used
                    reason_parts.append('Access Key 2 never used')
                else:
                    last_used = datetime.fromisoformat(key2_last_used.replace('Z', '+00:00'))
                    days = (current_date - last_used).days
                    unused_days = max(unused_days, days)
                    reason_parts.append(f'Access Key 2 last used {last_used.strftime("%d-%b-%Y")} ({days} days)')
            
            if not reason_parts:
                reason_parts.append('No active credentials')
            
            results.append({
                'reason': '. '.join(reason_parts) + '.',
                'resource': user_arn,
                'status': 'alarm' if unused_days > 45 else 'ok',
                'type': 'iam_user_unused_credentials_45'
            })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking unused credentials: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:user/*'
            ),
            'status': 'error',
            'type': 'iam_user_unused_credentials_45'
        }]


def check_iam_root_last_used(
        iam_client: boto3.client,
        account_id: str,
        report: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Check when root account was last used.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
        report: Optional credential report dictionary
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        # Use provided report or generate a new one
        if not report:
            try:
                iam_client.generate_credential_report()
                while True:
                    report = iam_client.get_credential_report()
                    if report['GeneratedTime']:
                        break
                    time.sleep(1)
            except iam_client.exceptions.CredentialReportNotPresentException:
                return [{
                    'reason': 'Credential report not available',
                    'resource': f'arn:aws:iam::{account_id}:root',
                    'status': 'error',
                    'type': 'iam_root_last_used'
                }]
        
        # Parse CSV report
        report_csv = csv.DictReader(report['Content'].decode('utf-8').splitlines())
        current_date = datetime.now(timezone.utc)
        
        for user in report_csv: 
            if user['user'] != '<root_account>':
                continue
            
            user_arn = user['arn']
            reason_parts = []
            status = 'ok'  # Default to ok if no recent activity
            
            # Check password last used
            if user['password_last_used'] == 'N/A':
                reason_parts.append('Password never used')
            else:
                password_last_used = datetime.fromisoformat(
                    user['password_last_used'].replace('Z', '+00:00')
                )
                days_since_password = (current_date - password_last_used).days
                reason_parts.append(
                    f'Password used {password_last_used.strftime("%d-%b-%Y")} '
                    f'({days_since_password} days)'
                )
                
                if days_since_password <= 90:  # Within last 90 days
                    status = 'alarm'
            
            # Check access key 1
            if user['access_key_1_last_used_date'] == 'N/A':
                reason_parts.append('Access Key 1 never used')
            else:
                key1_last_used = datetime.fromisoformat(
                    user['access_key_1_last_used_date'].replace('Z', '+00:00')
                )
                days_since_key1 = (current_date - key1_last_used).days
                reason_parts.append(
                    f'Access Key 1 used {key1_last_used.strftime("%d-%b-%Y")} '
                    f'({days_since_key1} days)'
                )
                
                if days_since_key1 <= 90:  # Within last 90 days
                    status = 'alarm'
            
            # Check access key 2
            if user['access_key_2_last_used_date'] == 'N/A':
                reason_parts.append('Access Key 2 never used')
            else:
                key2_last_used = datetime.fromisoformat(
                    user['access_key_2_last_used_date'].replace('Z', '+00:00')
                )
                days_since_key2 = (current_date - key2_last_used).days
                reason_parts.append(
                    f'Access Key 2 used {key2_last_used.strftime("%d-%b-%Y")} '
                    f'({days_since_key2} days)'
                )
                
                if days_since_key2 <= 90:  # Within last 90 days
                    status = 'alarm'
            
            return [{
                'reason': '. '.join(reason_parts) + '.',
                'resource': user_arn,
                'status': status,
                'type': 'iam_root_last_used'
            }]
        
        return []
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking root account usage: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:root'
            ),
            'status': 'error',
            'type': 'iam_root_last_used'
        }]


def check_iam_user_access_keys_and_password_at_setup(
        iam_client: boto3.client,
        account_id: str,
        report: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Check for users with access keys created during user creation.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
        report: Optional credential report dictionary
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        # Use provided report or generate a new one
        if not report:
            try:
                iam_client.generate_credential_report()
                while True:
                    report = iam_client.get_credential_report()
                    if report['GeneratedTime']:
                        break
                    time.sleep(1)
            except iam_client.exceptions.CredentialReportNotPresentException:
                return [{
                    'reason': 'Credential report not available',
                    'resource': f'arn:aws:iam::{account_id}:user/*',
                    'status': 'error',
                    'type': 'iam_user_access_keys_and_password_at_setup'
                }]
        
        # Parse CSV report
        report_csv = csv.DictReader(report['Content'].decode('utf-8').splitlines())
        results = []
        
        for user in report_csv:
            if user['user'] == '<root_account>':
                continue
            
            user_name = user['user']
            user_arn = user['arn']
            password_enabled = user['password_enabled'] == 'true'
            
            # Get timestamps
            user_created = datetime.fromisoformat(
                user['user_creation_time'].replace('Z', '+00:00')
            )
            key1_rotated = (
                None
                if user['access_key_1_last_rotated'] == 'N/A'
                else datetime.fromisoformat(
                    user['access_key_1_last_rotated'].replace('Z', '+00:00')
                )
            )
            
            if not password_enabled:
                reason = f'{user_name} password login disabled.'
                status = 'ok'
            elif not key1_rotated:
                reason = f'{user_name} has no access keys.'
                status = 'ok'
            else:
                # Check if key was created within 10 seconds of user creation
                time_diff = (key1_rotated - user_created).total_seconds()
                if password_enabled and time_diff < 10:
                    reason = (
                        f'{user_name} has access key created during user creation '
                        f'and password login enabled.'
                    )
                    status = 'alarm'
                else:
                    reason = (
                        f'{user_name} has access key not created during user creation.'
                    )
                    status = 'ok'
            
            results.append({
                'reason': reason,
                'resource': user_arn,
                'status': status,
                'type': 'iam_user_access_keys_and_password_at_setup'
            })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking user access keys and password setup: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:user/*'
            ),
            'status': 'error',
            'type': 'iam_user_access_keys_and_password_at_setup'
        }]


def check_iam_server_certificate_not_expired(
        iam_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check for expired IAM server certificates.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        results = []
        current_date = datetime.now(timezone.utc)
        
        # List all server certificates
        paginator = iam_client.get_paginator('list_server_certificates')
        for page in paginator.paginate():
            for cert in page['ServerCertificateMetadataList']:
                cert_name = cert['ServerCertificateName']
                cert_arn = cert['Arn']
                expiration = cert['Expiration']
                
                # Check if certificate is expired
                is_expired = expiration < current_date
                
                results.append({
                    'reason': (
                        f'{cert_name} '
                        f'{"expired" if is_expired else "valid until"} '
                        f'{expiration.strftime("%d-%b-%Y")}.'
                    ),
                    'resource': cert_arn,
                    'status': 'alarm' if is_expired else 'ok',
                    'type': 'iam_server_certificate_not_expired'
                })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking server certificates: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:server-certificate/*'
            ),
            'status': 'error',
            'type': 'iam_server_certificate_not_expired'
        }]

def check_iam_policy_all_attached_no_star_star(
    iam_client: boto3.client,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check all attached policies (AWS and customer managed) for * access"""
    try:
        results = []
        
        # List all attached policies (both AWS and customer managed)
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(OnlyAttached=True):
            for policy in page['Policies']:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                is_aws_managed = policy['Arn'].startswith('arn:aws:iam::aws:')
                
                # Get policy version details
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                # Count statements with *:* permissions
                bad_statements = 0
                for statement in policy_version['PolicyVersion']['Document'].get('Statement', []):
                    if isinstance(statement, dict):  # Handle single statement
                        if statement.get('Effect') == 'Allow':
                            resources = statement.get('Resource', [])
                            actions = statement.get('Action', [])
                            
                            # Convert to lists if string
                            if isinstance(resources, str):
                                resources = [resources]
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            # Check for * in both resource and action
                            if '*' in resources:
                                if '*' in actions or '*:*' in actions:
                                    bad_statements += 1
                
                if bad_statements > 0:
                    if is_aws_managed:
                        status = 'info'
                        reason = (
                            f'{policy_name} is an AWS managed policy with '
                            f'{bad_statements} statements that allow action "*" '
                            'on resource "*".'
                        )
                    else:
                        status = 'alarm'
                        reason = (
                            f'{policy_name} contains {bad_statements} statements '
                            f'that allow action "*" on resource "*".'
                        )
                else:
                    status = 'ok'
                    reason = (
                        f'{policy_name} contains {bad_statements} statements '
                        f'that allow action "*" on resource "*".'
                    )
                
                results.append({
                    'reason': reason,
                    'resource': policy_arn,
                    'status': status,
                    'type': 'iam_policy_all_attached_no_star_star'
                })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking IAM policies: {str(e)}'
            ),
            'resource': (
                f'arn:aws:iam::{account_id}:policy/*'
            ),
            'status': 'error',
            'type': 'iam_policy_all_attached_no_star_star'
        }]


def check_iam_user_group_role_cloudshell_fullaccess_restricted(
        iam_client: boto3.client,
        account_id: str) -> List[Dict[str, Any]]:
    """Check for IAM users, roles, and groups with CloudShell full access.
    
    Args:
        iam_client: Boto3 IAM client
        account_id: AWS account ID
    
    Returns:
        List of dictionaries containing check results
    """
    try:
        results = []
        cloudshell_policy_arn = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess'
        
        # Check Users
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                user_arn = user['Arn']
                
                # Get attached policies
                attached_policies = iam_client.list_attached_user_policies(
                    UserName=user_name
                )['AttachedPolicies']
                has_cloudshell = any(
                    p['PolicyArn'] == cloudshell_policy_arn for p in attached_policies
                )
                
                results.append({
                    'reason': (
                        f'User {user_name} '
                        f'{"has" if has_cloudshell else "no"} '
                        'access to AWSCloudShellFullAccess.'
                    ),
                    'resource': user_arn,
                    'status': 'alarm' if has_cloudshell else 'ok',
                    'type': 'iam_user_group_role_cloudshell_fullaccess_restricted'
                })
        
        # Check Roles
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                role_name = role['RoleName']
                role_arn = role['Arn']
                
                # Get attached policies
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=role_name
                )['AttachedPolicies']
                has_cloudshell = any(
                    p['PolicyArn'] == cloudshell_policy_arn for p in attached_policies
                )
                
                results.append({
                    'reason': (
                        f'Role {role_name} '
                        f'{"has" if has_cloudshell else "no"} '
                        'access to AWSCloudShellFullAccess.'
                    ),
                    'resource': role_arn,
                    'status': 'alarm' if has_cloudshell else 'ok',
                    'type': 'iam_user_group_role_cloudshell_fullaccess_restricted'
                })
        
        # Check Groups
        paginator = iam_client.get_paginator('list_groups')
        for page in paginator.paginate():
            for group in page['Groups']:
                group_name = group['GroupName']
                group_arn = group['Arn']
                
                # Get attached policies
                attached_policies = iam_client.list_attached_group_policies(
                    GroupName=group_name
                )['AttachedPolicies']
                has_cloudshell = any(
                    p['PolicyArn'] == cloudshell_policy_arn for p in attached_policies
                )
                
                results.append({
                    'reason': (
                        f'Group {group_name} '
                        f'{"has" if has_cloudshell else "no"} '
                        'access to AWSCloudShellFullAccess.'
                    ),
                    'resource': group_arn,
                    'status': 'alarm' if has_cloudshell else 'ok',
                    'type': 'iam_user_group_role_cloudshell_fullaccess_restricted'
                })
        
        return results
    
    except Exception as e:
        return [{
            'reason': (
                f'Error checking CloudShell access: {str(e)}'
            ),
            'resource': f'arn:aws:iam::{account_id}:*',
            'status': 'error',
            'type': 'iam_user_group_role_cloudshell_fullaccess_restricted'
        }]

def get_credential_report(iam_client):
    """Generate and retrieve IAM credential report with retries"""
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            try:
                response = iam_client.get_credential_report()
                return response
            except iam_client.exceptions.CredentialReportNotPresent:
                iam_client.generate_credential_report()
                
            # Wait for report generation
            for _ in range(5):  # Try up to 5 times with shorter intervals
                time.sleep(retry_delay)
                try:
                    response = iam_client.get_credential_report()
                    if response['GeneratedTime']:
                        return response
                except iam_client.exceptions.CredentialReportNotPresent:
                    continue
                
        except Exception as e:
            if attempt == max_retries - 1:
                print(f'Error generating credential report after {max_retries} attempts: {str(e)}')
                return None
            time.sleep(retry_delay)
            
    return None

@app.route('/check-iam_1')
def run_checks():
    """API endpoint to run all checks"""
    start_time = time.time()
    conn = None
    cur = None
    
    try:
        # Get AWS account ID and region from environment
        account_id = os.getenv('AWS_ACCOUNT_ID')
        os.environ['AWS_DEFAULT_REGION'] = os.getenv('AWS_REGION', 'us-east-1')
        
        # Initialize AWS clients once
        iam_client = get_aws_client('iam')
        accessanalyzer_client = get_aws_client('accessanalyzer')
        
        # Generate credential report once
        credential_report = get_credential_report(iam_client)
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        # Define all checks
        report_checks = [
            check_iam_user_unused_credentials_45,
            check_iam_root_last_used,
            check_iam_user_access_keys_and_password_at_setup,
        ]
        
        independent_checks = [
            lambda: check_iam_access_analyzer_enabled_without_findings(
                iam_client, accessanalyzer_client, account_id
            ),
            lambda: check_iam_user_no_policies(iam_client, account_id),
            lambda: check_iam_user_one_active_key(iam_client, account_id),
            lambda: check_iam_policy_custom_attached_no_star_star(
                iam_client, account_id
            ),
            lambda: check_iam_server_certificate_not_expired(
                iam_client, account_id
            ),
            lambda: check_iam_policy_all_attached_no_star_star(
                iam_client, account_id
            ),
            lambda: check_iam_user_group_role_cloudshell_fullaccess_restricted(
                iam_client, account_id
            ),
        ]
        
        all_results = []
        
        # Run independent checks in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_check = {
                executor.submit(check): check for check in independent_checks
            }
            for future in as_completed(future_to_check):
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                except Exception as e:
                    print(f'Error running check: {str(e)}')
        
        # Run credential report dependent checks in parallel if report is available
        if credential_report:
            def run_check_with_report(check_func):
                try:
                    return check_func(iam_client, account_id, credential_report)
                except Exception as e:
                    print(f'Error running check with credential report: {str(e)}')
                    return None
            
            # Run checks in parallel
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(run_check_with_report, check)
                    for check in report_checks
                ]
                for future in as_completed(futures):
                    try:
                        results = future.result()
                        if results:
                            all_results.extend(results)
                    except Exception as e:
                        print(f'Error running check: {str(e)}')
        
        # Store results in database using batch insert with proper error handling
        conn = None
        cur = None
        response = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Prepare batch insert data with type validation
            insert_data = []
            for result in all_results:
                required_keys = ['reason', 'resource', 'status', 'type']
                if not all(k in result for k in required_keys):
                    print(f'Warning: Skipping malformed result: {result}')
                    continue
                insert_data.append((
                    result['reason'],
                    result['resource'],
                    result['status'],
                    result['type'],  # Maps to check_type column
                ))
            
            if insert_data:
                # Execute batch insert
                cur.executemany(
                    """
                    INSERT INTO aws_project_status
                    (description, resource, status, check_type)
                    VALUES (%s, %s, %s, %s)""",
                    insert_data,
                )
                conn.commit()
            
            execution_time = time.time() - start_time
            
            # Format response with detailed metadata
            response = {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': {
                    'metadata': {
                        'execution_time': execution_time,
                        'checks_performed': len(all_results),
                        'database_records_inserted': len(insert_data),
                        'checks_by_type': {
                            result['type']: len([
                                r for r in all_results
                                if r['type'] == result['type']
                            ])
                            for result in all_results
                            if 'type' in result
                        },
                    },
                    'results': all_results,
                    'summary': {
                        'total': len(all_results),
                        'ok': len([
                            r for r in all_results
                            if r['status'] == 'ok']),
                        'alarm': len([
                            r for r in all_results
                            if r['status'] == 'alarm']),
                        'skip': len([
                            r for r in all_results
                            if r['status'] == 'skip']),
                        'info': len([
                            r for r in all_results
                            if r['status'] == 'info']),
                        'error': len([
                            r for r in all_results
                            if r['status'] == 'error'
                        ]),
                    },
                },
            }
            
            return (
                json.dumps(response, indent=2),
                200,
                {'Content-Type': 'application/json'},
            )
        
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
    
    except Exception as e:
        if conn:
            conn.rollback()
        error_response = {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': {
                'error': str(e),
                'message': 'Internal server error',
                'execution_time': time.time() - start_time,
            },
        }
        return (
            json.dumps(error_response, indent=2),
            500,
            {'Content-Type': 'application/json'},
        )
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(port=5004)
