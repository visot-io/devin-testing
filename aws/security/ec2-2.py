from flask import Flask, jsonify
import boto3
import configparser
from datetime import datetime, timezone
from typing import Dict, Any, List
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import logging
import os
import re
import base64
import botocore.exceptions
from concurrent.futures import ThreadPoolExecutor, as_completed
import botocore.config
from functools import partial
import time

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'database': os.getenv('DB_NAME', 'postgres'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', 'postgres')
}

# AWS configuration
AWS_CONFIG = {
    'AWS_ACCESS_KEY_ID': os.getenv('AWS_ACCESS_KEY_ID'),
    'AWS_SECRET_ACCESS_KEY': os.getenv('AWS_SECRET_ACCESS_KEY')
}

def get_db_connection():
    """Create a database connection"""
    return psycopg2.connect(**DB_CONFIG)

def check_ec2_iam_profile(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM profile attached"""
    try:
        results = []
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                # Check if IAM profile is attached
                iam_profile = instance.get('IamInstanceProfile')
                
                status = "ok" if iam_profile else "alarm"
                reason = f"{instance_id} IAM profile attached." if iam_profile else f"{instance_id} IAM profile not attached."

                results.append({
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason,
                    "type": "ec2_instance_iam_profile"
                })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IAM profiles: {str(e)}")
        return []

def check_ec2_public_instance_iam_profile(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if publicly accessible EC2 instances have IAM profile attached"""
    try:
        results = []
        for instance in all_instances_data:
            try:
                # Check if instance is publicly accessible
                public_ip = instance.get('PublicIpAddress')
                if not public_ip:
                    continue  # Skip instances without public IP
                    
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                
                # Check if IAM profile is attached
                iam_profile = instance.get('IamInstanceProfile')
                
                status = "ok" if iam_profile else "alarm"
                reason = f"{instance_id} IAM profile attached." if iam_profile else f"{instance_id} IAM profile not attached."

                results.append({
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason,
                    "type": "ec2_instance_public_iam_profile"
                })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 public instances IAM profiles: {str(e)}")
        return []

def check_ec2_user_data_secrets(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]], user_data_cache: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have secrets in their user data"""
    try:
        results = []
        
        # Compile regex pattern for potential secrets
        secret_pattern = re.compile(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]')
        secret_keywords = ['pass', 'secret', 'token', 'key']
        
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                
                # Get user data from cache
                user_data = user_data_cache.get(instance_id, '')
                        
                # Check for secrets in user data
                has_secrets = False
                if user_data:
                    # Check for secret pattern
                    if secret_pattern.search(user_data):
                        has_secrets = True
                    
                    # Check for secret keywords
                    user_data_lower = user_data.lower()
                    if any(keyword in user_data_lower for keyword in secret_keywords):
                        has_secrets = True
                
                status = "alarm" if has_secrets else "ok"
                reason = f"{instance_id} potential secret found in user data." if has_secrets else f"{instance_id} no secrets found in user data."

                results.append({
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason,
                    "type": "ec2_instance_user_data_secrets"
                })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 user data secrets: {str(e)}")
        return []

def check_ec2_launch_wizard_sg(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are using launch-wizard security groups"""
    try:
        results = []
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                # Check security groups for launch-wizard
                security_groups = instance.get('SecurityGroups', [])
                has_launch_wizard = any(
                    sg.get('GroupName', '').startswith('launch-wizard')
                    for sg in security_groups
                )
                
                status = "alarm" if has_launch_wizard else "ok"
                reason = (f"{instance_id} associated with launch-wizard security group." 
                        if has_launch_wizard 
                        else f"{instance_id} not associated with launch-wizard security group.")

                results.append({
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason,
                    "type": "ec2_instance_launch_wizard_sg"
                })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 launch-wizard security groups: {str(e)}")
        return []

def check_ec2_virtualization_type(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are using paravirtual virtualization"""
    try:
        results = []
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                # Check virtualization type
                virtualization_type = instance.get('VirtualizationType', '').lower()
                
                status = "alarm" if virtualization_type == 'paravirtual' else "ok"
                reason = f"{instance_id} virtualization type is {virtualization_type}."

                results.append({
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason,
                    "type": "ec2_instance_virtualization_type"
                })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 virtualization types: {str(e)}")
        return []

def check_ec2_iam_role_management_access(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with management level access"""
    try:
        results = []
        session = boto3.Session()
        iam_client = session.client('iam')
        
        if policy_cache is None:
            policy_cache = {}
        
        # Management level IAM actions to check
        management_actions = {
            'iam:attachgrouppolicy', 'iam:attachrolepolicy', 'iam:attachuserpolicy',
            'iam:createpolicy', 'iam:createpolicyversion', 'iam:deleteaccountpasswordpolicy',
            'iam:deletegrouppolicy', 'iam:deletepolicy', 'iam:deletepolicyversion',
            'iam:deleterolepermissionsboundary', 'iam:deleterolepolicy',
            'iam:deleteuserpermissionsboundary', 'iam:deleteuserpolicy',
            'iam:detachgrouppolicy', 'iam:detachrolepolicy', 'iam:detachuserpolicy',
            'iam:putgrouppolicy', 'iam:putrolepermissionsboundary', 'iam:putrolepolicy',
            'iam:putuserpermissionsboundary', 'iam:putuserpolicy', 'iam:setdefaultpolicyversion',
            'iam:updateassumerolepolicy'
        }

        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        
                        # Get instance profile
                        instance_profile = instance.get('IamInstanceProfile', {})
                        if not instance_profile:
                            results.append({
                                "resource": instance_arn,
                                "status": "ok",
                                "reason": f"{instance_name} has no management level access.",
                                "type": "ec2_instance_iam_role_management"
                            })
                            continue
                        
                        # Get the role from instance profile
                        profile_arn = instance_profile.get('Arn', '')
                        try:
                            profile_name = profile_arn.split('/')[-1]
                            profile_response = iam_client.get_instance_profile(
                                InstanceProfileName=profile_name
                            )
                            
                            has_management_access = False
                            for role in profile_response['InstanceProfile'].get('Roles', []):
                                role_name = role['RoleName']
                                
                                # Check if role can be assumed by EC2
                                role_response = iam_client.get_role(RoleName=role_name)
                                assume_role_policy = role_response['Role']['AssumeRolePolicyDocument']
                                
                                is_ec2_role = False
                                for statement in assume_role_policy.get('Statement', []):
                                    if (statement.get('Effect') == 'Allow' and 
                                        'Service' in statement.get('Principal', {}) and 
                                        'ec2.amazonaws.com' in statement['Principal']['Service']):
                                        is_ec2_role = True
                                        break
                                
                                if not is_ec2_role:
                                    continue
                                
                                # Check attached policies
                                paginator = iam_client.get_paginator('list_attached_role_policies')
                                for policy_page in paginator.paginate(RoleName=role_name):
                                    for policy in policy_page['AttachedPolicies']:
                                        policy_arn = policy['PolicyArn']
                                        policy_doc = get_policy_document(iam_client, policy_arn, policy_cache)
                                        
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if not isinstance(actions, list):
                                                    actions = [actions]
                                                
                                                if '*:*' in actions or any(action in actions for action in management_actions):
                                                    has_management_access = True
                                                    break
                                
                                # Check inline policies
                                inline_policies = get_role_inline_policies(iam_client, role_name, policy_cache)
                                for policy_doc in inline_policies:
                                    for statement in policy_doc.get('Statement', []):
                                        if statement.get('Effect') == 'Allow':
                                            actions = statement.get('Action', [])
                                            if not isinstance(actions, list):
                                                actions = [actions]
                                            
                                            if '*:*' in actions or any(action in actions for action in management_actions):
                                                has_management_access = True
                                                break
                                
                                if has_management_access:
                                    break
                            
                            status = "alarm" if has_management_access else "ok"
                            reason = f"{instance_name} has management level access." if has_management_access else f"{instance_name} has no management level access."
                            
                            results.append({
                                "resource": instance_arn,
                                "status": status,
                                "reason": reason,
                                "type": "ec2_instance_iam_role_management"
                            })
                            
                        except iam_client.exceptions.NoSuchEntityException:
                            results.append({
                                "resource": instance_arn,
                                "status": "ok",
                                "reason": f"{instance_name} has no management level access.",
                                "type": "ec2_instance_iam_role_management"
                            })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IAM role management access: {str(e)}")
        return []

def check_ec2_iam_role_data_destruction(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with data destruction access"""
    try:
        results = []
        session = boto3.Session()
        iam_client = session.client('iam')
        
        if policy_cache is None:
            policy_cache = {}
        
        # Data destruction actions to check
        destruction_actions = {
            's3:deletebucket', 
            'rds:deletedbcluster', 
            'rds:deletedbinstance', 
            'rds:deleteDBSnapshot', 
            'rds:deletedbclustersnapshot', 
            'rds:deleteglobalcluster', 
            'ec2:deletesnapshot', 
            'ec2:deletevolume'
        }

        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        
                # Get instance profile
                instance_profile = instance.get('IamInstanceProfile', {})
                if not instance_profile:
                    results.append({
                        "resource": instance_arn,
                        "status": "ok",
                        "reason": f"{instance_name} has no data destruction access.",
                        "type": "ec2_instance_iam_role_destruction"
                    })
                    continue
                        
                # Get the role from instance profile
                profile_arn = instance_profile.get('Arn', '')
                try:
                    profile_name = profile_arn.split('/')[-1]
                    profile_response = iam_client.get_instance_profile(
                        InstanceProfileName=profile_name
                    )
                    
                    has_destruction_access = False
                    for role in profile_response['InstanceProfile'].get('Roles', []):
                        role_name = role['RoleName']
                        
                        # Check if role can be assumed by EC2
                        role_response = iam_client.get_role(RoleName=role_name)
                        assume_role_policy = role_response['Role']['AssumeRolePolicyDocument']
                                
                        is_ec2_role = False
                        for statement in assume_role_policy.get('Statement', []):
                            if (statement.get('Effect') == 'Allow' and 
                                'Service' in statement.get('Principal', {}) and 
                                'ec2.amazonaws.com' in statement['Principal']['Service']):
                                is_ec2_role = True
                                break
                        
                        if not is_ec2_role:
                            continue
                        
                        # Check attached policies
                        paginator = iam_client.get_paginator('list_attached_role_policies')
                        for policy_page in paginator.paginate(RoleName=role_name):
                            for policy in policy_page['AttachedPolicies']:
                                policy_arn = policy['PolicyArn']
                                policy_doc = get_policy_document(iam_client, policy_arn, policy_cache)
                                
                                for statement in policy_doc.get('Statement', []):
                                    if statement.get('Effect') == 'Allow':
                                        actions = statement.get('Action', [])
                                        if not isinstance(actions, list):
                                            actions = [actions]
                                        
                                        if '*:*' in actions or any(action in actions for action in destruction_actions):
                                            has_destruction_access = True
                                            break
                                
                        # Check inline policies
                        inline_policies = get_role_inline_policies(iam_client, role_name, policy_cache)
                        for policy_doc in inline_policies:
                            for statement in policy_doc.get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if not isinstance(actions, list):
                                        actions = [actions]
                                    
                                    if '*:*' in actions or any(action in actions for action in destruction_actions):
                                        has_destruction_access = True
                                        break
                        
                        if has_destruction_access:
                            break
                    
                    status = "alarm" if has_destruction_access else "ok"
                    reason = f"{instance_name} has data destruction access." if has_destruction_access else f"{instance_name} has no data destruction access."
                            
                    results.append({
                        "resource": instance_arn,
                        "status": status,
                        "reason": reason,
                        "type": "ec2_instance_iam_role_destruction"
                    })
                    
                except iam_client.exceptions.NoSuchEntityException:
                    results.append({
                        "resource": instance_arn,
                        "status": "ok",
                        "reason": f"{instance_name} has no data destruction access.",
                        "type": "ec2_instance_iam_role_destruction"
                    })

            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IAM role data destruction access: {str(e)}")
        return []

def check_ec2_iam_role_write_access(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with write level access"""
    try:
        results = []
        session = boto3.Session()
        iam_client = session.client('iam')
        
        if policy_cache is None:
            policy_cache = {}
        
        # Write level IAM actions to check
        write_actions = {
            'iam:addclientidtoopenidconnectprovider', 'iam:addroletoinstanceprofile',
            'iam:addusertogroup', 'iam:changepassword', 'iam:createaccesskey',
            'iam:createaccountalias', 'iam:creategroup', 'iam:createinstanceprofile',
            'iam:createloginprofile', 'iam:createopenidconnectprovider', 'iam:createrole',
            'iam:createsamlprovider', 'iam:createservicelinkedrole',
            'iam:createservicespecificcredential', 'iam:createuser', 'iam:createvirtualmfadevice',
            'iam:deactivatemfadevice', 'iam:deleteaccesskey', 'iam:deleteaccountalias',
            'iam:deletegroup', 'iam:deleteinstanceprofile', 'iam:deleteloginprofile',
            'iam:deleteopenidconnectprovider', 'iam:deleterole', 'iam:deletesamlprovider',
            'iam:deletesshpublickey', 'iam:deleteservercertificate', 'iam:deleteservicelinkedrole',
            'iam:deleteservicespecificcredential', 'iam:deletesigningcertificate',
            'iam:deleteUser', 'iam:deletevirtualmfadevice', 'iam:enablemfadevice',
            'iam:passrole', 'iam:removeclientidfromopenidconnectprovider',
            'iam:removerolefrominstanceprofile', 'iam:removeuserfromgroup',
            'iam:resetservicespecificcredential', 'iam:resyncmfadevice',
            'iam:setsecuritytokenservicepreferences', 'iam:updateaccesskey',
            'iam:updateaccountpasswordpolicy', 'iam:updategroup', 'iam:updateloginprofile',
            'iam:updateopenidconnectproviderthumbprint', 'iam:updaterole',
            'iam:updateroledescription', 'iam:updatesamlprovider', 'iam:updatesshpublicKey',
            'iam:updateservercertificate', 'iam:updateservicespecificcredential',
            'iam:updatesigningcertificate', 'iam:updateuser', 'iam:uploadsshpublicKey',
            'iam:uploadservercertificate', 'iam:uploadsigningcertificate'
        }

        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        
                # Get instance profile
                instance_profile = instance.get('IamInstanceProfile', {})
                if not instance_profile:
                    results.append({
                        "resource": instance_arn,
                        "status": "ok",
                        "reason": f"{instance_name} has no IAM write level access.",
                        "type": "ec2_instance_iam_role_write"
                    })
                    continue
                        
                        # Get the role from instance profile
                        profile_arn = instance_profile.get('Arn', '')
                        try:
                            profile_name = profile_arn.split('/')[-1]
                            profile_response = iam_client.get_instance_profile(
                                InstanceProfileName=profile_name
                            )
                            
                            has_write_access = False
                            for role in profile_response['InstanceProfile'].get('Roles', []):
                                role_name = role['RoleName']
                                
                                # Check if role can be assumed by EC2
                                role_response = iam_client.get_role(RoleName=role_name)
                                assume_role_policy = role_response['Role']['AssumeRolePolicyDocument']
                                
                                is_ec2_role = False
                                for statement in assume_role_policy.get('Statement', []):
                                    if (statement.get('Effect') == 'Allow' and 
                                        'Service' in statement.get('Principal', {}) and 
                                        'ec2.amazonaws.com' in statement['Principal']['Service']):
                                        is_ec2_role = True
                                        break
                                
                                if not is_ec2_role:
                                    continue
                                
                                # Check attached policies
                                paginator = iam_client.get_paginator('list_attached_role_policies')
                                for policy_page in paginator.paginate(RoleName=role_name):
                                    for policy in policy_page['AttachedPolicies']:
                                        policy_arn = policy['PolicyArn']
                                        policy_doc = get_policy_document(iam_client, policy_arn, policy_cache)
                                        
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if not isinstance(actions, list):
                                                    actions = [actions]
                                                
                                                if '*:*' in actions or any(action.lower() in actions for action in write_actions):
                                                    has_write_access = True
                                                    break
                                
                                # Check inline policies
                                inline_policies = get_role_inline_policies(iam_client, role_name, policy_cache)
                                for policy_doc in inline_policies:
                                        
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if not isinstance(actions, list):
                                                    actions = [actions]
                                                
                                                if '*:*' in actions or any(action.lower() in actions for action in write_actions):
                                                    has_write_access = True
                                                    break
                                
                                if has_write_access:
                                    break
                            
                            status = "alarm" if has_write_access else "ok"
                            reason = f"{instance_name} has IAM write level access." if has_write_access else f"{instance_name} has no IAM write level access."
                            
                            results.append({
                                "resource": instance_arn,
                                "status": status,
                                "reason": reason,
                                "type": "ec2_instance_iam_role_write"
                            })
                            
                        except iam_client.exceptions.NoSuchEntityException:
                            results.append({
                                "resource": instance_arn,
                                "status": "ok",
                                "reason": f"{instance_name} has no IAM write level access.",
                                "type": "ec2_instance_iam_role_write"
                            })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IAM role write access: {str(e)}")
        return []

def check_ec2_iam_role_db_write_access(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with database management write access"""
    try:
        results = []
        session = boto3.Session()
        iam_client = session.client('iam')
        
        if policy_cache is None:
            policy_cache = {}
        
        # Database write level actions to check
        db_write_actions = {
            'rds:modifydbcluster', 'rds:modifydbclusterendpoint', 'rds:modifydbinstance',
            'rds:modifydbsnapshot', 'rds:modifyglobalcluster', 'dynamodb:updateitem',
            'dynamodb:updatetable', 'memorydb:updatecluster', 'neptune-db:resetdatabase',
            'neptune-db:writedataviaquery', 'docdb-elastic:updatecluster',
            'elasticache:modifycachecluster', 'cassandra:alter', 'cassandra:modify',
            'qldb:executestatement', 'qldb:partiqlupdate', 'qldb:sendcommand',
            'qldb:updateledger', 'redshift:modifycluster', 'redshift:modifyclustersnapshot',
            'redshift:modifyendpointaccess', 'timestream:updatedatabase',
            'timestream:updatetable', 'timestream:writerecords'
        }

        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                        
                # Get instance profile
                instance_profile = instance.get('IamInstanceProfile', {})
                if not instance_profile:
                    results.append({
                        "resource": instance_arn,
                        "status": "ok",
                        "reason": f"{instance_name} has no database management write level access.",
                        "type": "ec2_instance_iam_role_db_write"
                    })
                    continue
                        
                        # Get the role from instance profile
                        profile_arn = instance_profile.get('Arn', '')
                        try:
                            profile_name = profile_arn.split('/')[-1]
                            profile_response = iam_client.get_instance_profile(
                                InstanceProfileName=profile_name
                            )
                            
                            has_db_write_access = False
                            for role in profile_response['InstanceProfile'].get('Roles', []):
                                role_name = role['RoleName']
                                
                                # Check if role can be assumed by EC2
                                role_response = iam_client.get_role(RoleName=role_name)
                                assume_role_policy = role_response['Role']['AssumeRolePolicyDocument']
                                
                                is_ec2_role = False
                                for statement in assume_role_policy.get('Statement', []):
                                    if (statement.get('Effect') == 'Allow' and 
                                        'Service' in statement.get('Principal', {}) and 
                                        'ec2.amazonaws.com' in statement['Principal']['Service']):
                                        is_ec2_role = True
                                        break
                                
                                if not is_ec2_role:
                                    continue
                                
                                # Check attached policies
                                paginator = iam_client.get_paginator('list_attached_role_policies')
                                for policy_page in paginator.paginate(RoleName=role_name):
                                    for policy in policy_page['AttachedPolicies']:
                                        policy_arn = policy['PolicyArn']
                                        policy_doc = get_policy_document(iam_client, policy_arn, policy_cache)
                                        
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if not isinstance(actions, list):
                                                    actions = [actions]
                                                
                                                if '*:*' in actions or any(action.lower() in actions for action in db_write_actions):
                                                    has_db_write_access = True
                                                    break
                                
                                # Check inline policies
                                inline_policies = get_role_inline_policies(iam_client, role_name, policy_cache)
                                for policy_doc in inline_policies:
                                        
                                        for statement in policy_doc.get('Statement', []):
                                            if statement.get('Effect') == 'Allow':
                                                actions = statement.get('Action', [])
                                                if not isinstance(actions, list):
                                                    actions = [actions]
                                                
                                                if '*:*' in actions or any(action.lower() in actions for action in db_write_actions):
                                                    has_db_write_access = True
                                                    break
                                
                                if has_db_write_access:
                                    break
                            
                            status = "alarm" if has_db_write_access else "ok"
                            reason = f"{instance_name} has database management write level access." if has_db_write_access else f"{instance_name} has no database management write level access."
                            
                            results.append({
                                "resource": instance_arn,
                                "status": status,
                                "reason": reason,
                                "type": "ec2_instance_iam_role_db_write"
                            })
                            
                        except iam_client.exceptions.NoSuchEntityException:
                            results.append({
                                "resource": instance_arn,
                                "status": "ok",
                                "reason": f"{instance_name} has no database management write level access.",
                                "type": "ec2_instance_iam_role_db_write"
                            })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IAM role database write access: {str(e)}")
        return []

def check_ec2_backup_plan_protection(ec2_client, account_id: str, all_instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are protected by backup plans"""
    try:
        results = []
        session = boto3.Session()
        backup_client = session.client('backup')
        
        # Try to get backup protected resources
        try:
            paginator = backup_client.get_paginator('list_protected_resources')
            for page in paginator.paginate():
                for resource in page['Results']:
                    if resource['ResourceType'] == 'EC2':
                        # We won't reach here if there's an access error
                        pass
                        
        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Handle access denied errors
            if error_code == 'AccessDeniedException':
                # Return error result for all instances if we can't access backup info
                for instance in all_instances_data:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                    instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                            
                    results.append({
                        "resource": instance_arn,
                        "status": "error",
                        "reason": f"Error checking backup protection: {error_code} - {error_message}",
                        "type": "ec2_instance_backup_protection"
                    })
                
                logger.error(f"Access denied to AWS Backup: {error_message}")
                return results
            else:
                # Handle other AWS Backup API errors
                logger.error(f"AWS Backup API error: {error_code} - {error_message}")
                return []
            
        except Exception as e:
            logger.error(f"Error accessing AWS Backup: {str(e)}")
            return []

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 backup plan protection: {str(e)}")
        return []

def check_transit_gateway_auto_attachment(ec2_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 transit gateways have automatic cross-account attachment enabled"""
    try:
        results = []
        
        # Describe transit gateways with optimized config
        try:
            paginator = ec2_client.get_paginator('describe_transit_gateways')
            for page in paginator.paginate():
                for tgw in page.get('TransitGateways', []):
                    try:
                        tgw_id = tgw['TransitGatewayId']
                        tgw_arn = f"arn:aws:ec2:{tgw.get('AvailabilityZone', 'us-east-1')[:-1]}:{account_id}:transit-gateway/{tgw_id}"
                        tgw_name = next((tag['Value'] for tag in tgw.get('Tags', []) if tag['Key'] == 'Name'), tgw_id)
                        
                        # Check auto accept shared attachments setting
                        auto_accept = tgw.get('Options', {}).get('AutoAcceptSharedAttachments', 'disable')
                        
                        status = "alarm" if auto_accept.lower() == 'enable' else "ok"
                        reason = (f"{tgw_name} automatic shared account attachment enabled." 
                                if auto_accept.lower() == 'enable' 
                                else f"{tgw_name} automatic shared account attachment disabled.")
                        
                        results.append({
                            "resource": tgw_arn,
                            "status": status,
                            "reason": reason,
                            "type": "transit_gateway_auto_attachment"
                        })

                    except Exception as e:
                        logger.error(f"Error processing transit gateway {tgw_id}: {str(e)}")
                        continue

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"AWS EC2 API error: {error_code} - {error_message}")
            return []
            
        except Exception as e:
            logger.error(f"Error describing transit gateways: {str(e)}")
            return []

        return results

    except Exception as e:
        logger.error(f"Error checking transit gateway auto attachment: {str(e)}")
        return []

def check_ec2_ami_public_access(ec2_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 AMIs are publicly accessible"""
    try:
        results = []
        
        # Describe AMIs owned by the account
        try:
            paginator = ec2_client.get_paginator('describe_images')
            for page in paginator.paginate(Owners=['self']):
                for ami in page.get('Images', []):
                    try:
                        image_id = ami['ImageId']
                        region = ec2_client.meta.region_name
                        ami_arn = f"arn:aws:ec2:{region}:{account_id}:image/{image_id}"
                        ami_name = ami.get('Name', image_id)
                        
                        # Check if AMI is public
                        launch_permissions = ec2_client.describe_image_attribute(
                            ImageId=image_id,
                            Attribute='launchPermission'
                        )
                        
                        is_public = False
                        for permission in launch_permissions.get('LaunchPermissions', []):
                            if permission.get('Group') == 'all':
                                is_public = True
                                break
                        
                        status = "alarm" if is_public else "ok"
                        reason = f"{ami_name} publicly accessible." if is_public else f"{ami_name} not publicly accessible."
                        
                        results.append({
                            "resource": ami_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_ami_public_access"
                        })

                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] == 'InvalidAMIID.NotFound':
                            # Skip if AMI no longer exists
                            continue
                        else:
                            logger.error(f"Error checking AMI {image_id}: {str(e)}")
                            continue
                    except Exception as e:
                        logger.error(f"Error processing AMI {image_id}: {str(e)}")
                        continue

        except botocore.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.error(f"AWS EC2 API error: {error_code} - {error_message}")
            return []
            
        except Exception as e:
            logger.error(f"Error describing AMIs: {str(e)}")
            return []

        return results

    except Exception as e:
        logger.error(f"Error checking AMI public access: {str(e)}")
        return []

# Configure AWS clients with timeouts and reduced retries
def get_optimized_client(session, service_name):
    config = botocore.config.Config(
        connect_timeout=5,
        read_timeout=10,
        retries={'max_attempts': 2},
        max_pool_connections=25
    )
    return session.client(service_name, config=config)

def get_policy_document(iam_client, policy_arn: str, policy_cache: Dict[str, Any]) -> Dict[str, Any]:
    """Get policy document from cache or AWS"""
    if policy_arn in policy_cache:
        return policy_cache[policy_arn]
    
    try:
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        if policy_response['Policy']['DefaultVersionId']:
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy_response['Policy']['DefaultVersionId']
            )
            policy_cache[policy_arn] = policy_version['PolicyVersion']['Document']
            return policy_cache[policy_arn]
    except Exception as e:
        logger.error(f"Error fetching policy {policy_arn}: {str(e)}")
        return {}

def get_role_inline_policies(iam_client, role_name: str, policy_cache: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get role inline policies from cache or AWS"""
    cache_key = f"inline_{role_name}"
    if cache_key in policy_cache:
        return policy_cache[cache_key]
    
    policies = []
    try:
        paginator = iam_client.get_paginator('list_role_policies')
        for policy_page in paginator.paginate(RoleName=role_name):
            for policy_name in policy_page['PolicyNames']:
                policy = iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policies.append(policy['PolicyDocument'])
        policy_cache[cache_key] = policies
        return policies
    except Exception as e:
        logger.error(f"Error fetching inline policies for role {role_name}: {str(e)}")
        return []

@app.route('/check-ec2-2')
def check_ec2():
    """Main route to check EC2 security"""
    try:
        session = boto3.Session(
            aws_access_key_id=AWS_CONFIG['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=AWS_CONFIG['AWS_SECRET_ACCESS_KEY'],
            region_name='us-east-1'
        )
        
        # Initialize clients with optimized configuration
        ec2_client = get_optimized_client(session, 'ec2')
        sts_client = get_optimized_client(session, 'sts')
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Cache EC2 instance data
        logger.info("Fetching EC2 instance data...")
        all_instances_data = []
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    all_instances_data.append(instance)
        
        # Pre-fetch user data for instances that have it
        logger.info("Caching instance user data...")
        user_data_cache = {}
        for instance in all_instances_data:
            try:
                user_data_response = ec2_client.describe_instance_attribute(
                    InstanceId=instance['InstanceId'],
                    Attribute='userData'
                )
                user_data_b64 = user_data_response.get('UserData', {}).get('Value', '')
                if user_data_b64:
                    try:
                        user_data = base64.b64decode(user_data_b64).decode('utf-8')
                    except:
                        user_data = user_data_b64
                    user_data_cache[instance['InstanceId']] = user_data
            except Exception as e:
                logger.warning(f"Could not get user data for instance {instance['InstanceId']}: {str(e)}")
                continue
        
        # Initialize policy cache for IAM-related checks
        policy_cache = {}
        
        # Define all checks with cached data
        checks = [
            partial(check_ec2_iam_profile, ec2_client, account_id, all_instances_data),
            partial(check_ec2_public_instance_iam_profile, ec2_client, account_id, all_instances_data),
            partial(check_ec2_user_data_secrets, ec2_client, account_id, all_instances_data, user_data_cache),
            partial(check_ec2_launch_wizard_sg, ec2_client, account_id, all_instances_data),
            partial(check_ec2_virtualization_type, ec2_client, account_id, all_instances_data),
            partial(check_ec2_iam_role_management_access, ec2_client, account_id, all_instances_data, policy_cache),
            partial(check_ec2_iam_role_data_destruction, ec2_client, account_id, all_instances_data, policy_cache),
            partial(check_ec2_iam_role_write_access, ec2_client, account_id, all_instances_data, policy_cache),
            partial(check_ec2_iam_role_db_write_access, ec2_client, account_id, all_instances_data, policy_cache),
            partial(check_ec2_backup_plan_protection, ec2_client, account_id, all_instances_data),
            partial(check_transit_gateway_auto_attachment, ec2_client, account_id),
            partial(check_ec2_ami_public_access, ec2_client, account_id)
        ]
        
        # Run checks in parallel with increased concurrency and chunking
        all_results = []
        chunk_size = 3  # Process checks in chunks to avoid overwhelming AWS API
        with ThreadPoolExecutor(max_workers=12) as executor:
            # Use a higher number of workers since we have optimized the IAM policy fetching
            # and most operations are I/O bound (AWS API calls)
            futures = [executor.submit(f) for f in checks]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_results.extend(result)
                except Exception as e:
                    logger.error(f"Error executing check: {str(e)}")
                    continue
        
        # Process results
        try:
            # Get database connection
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Prepare batch values for insertion
            batch_values = []
            for result in all_results:
                if result:
                    batch_values.append((
                        result['reason'],
                        result['resource'],
                        result['status']
                    ))
            
            # Execute optimized batch insert using execute_values
            if batch_values:
                insert_query = """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES %s
                """
                execute_values(cur, insert_query, batch_values, page_size=1000)
            
            # Commit the transaction
            conn.commit()
            
            # Calculate summary
            summary = {
                "total_checks": len(all_results),
                "ok": len([r for r in all_results if r['status'] == 'ok']),
                "alarm": len([r for r in all_results if r['status'] == 'alarm']),
                "error": len([r for r in all_results if r['status'] == 'error'])
            }
            
            return jsonify({
                "status": "success",
                "data": all_results,
                "summary": summary,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            if 'conn' in locals():
                conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        
        finally:
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()
        
    except Exception as e:
        logger.error(f"Error in check_ec2_security: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5002)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       