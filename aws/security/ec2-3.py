from flask import Flask, jsonify
import boto3
import configparser
from datetime import datetime, timezone
from typing import Dict, Any, List, Set
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import logging
import os
import json
import botocore.exceptions
from concurrent.futures import ThreadPoolExecutor, as_completed
import botocore.config
from functools import partial

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'database': 'postgres',
    'user': 'postgres',
    'password': 'postgres'
}

def get_db_connection():
    """Create a database connection"""
    return psycopg2.connect(**DB_CONFIG)

def get_aws_client(service_name: str, session: boto3.Session = None) -> boto3.client:
    """Create an AWS client with retry configuration"""
    config = botocore.config.Config(
        retries=dict(
            max_attempts=3,
            mode='adaptive'
        )
    )
    if session:
        return session.client(service_name, config=config)
    return boto3.client(service_name, config=config)

# Cache for IAM policy documents and role data
policy_cache: Dict[str, Dict] = {}
role_cache: Dict[str, Dict] = {}
instance_profile_cache: Dict[str, Dict] = {}

def get_policy_document(iam_client: boto3.client, policy_arn: str, policy_cache: Dict[str, Dict]) -> Dict:
    """Get policy document with caching"""
    if policy_arn in policy_cache:
        return policy_cache[policy_arn]
    
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )
        doc = policy_version['PolicyVersion']['Document']
        policy_cache[policy_arn] = doc
        return doc
    except Exception as e:
        logger.error(f"Error getting policy document for {policy_arn}: {str(e)}")
        return {}

def get_role_data(iam_client: boto3.client, role_name: str, role_cache: Dict[str, Dict]) -> Dict:
    """Get role data with caching"""
    if role_name in role_cache:
        return role_cache[role_name]
    
    try:
        role = iam_client.get_role(RoleName=role_name)
        role_cache[role_name] = role['Role']
        return role['Role']
    except Exception as e:
        logger.error(f"Error getting role data for {role_name}: {str(e)}")
        return {}

def get_role_inline_policies(iam_client: boto3.client, role_name: str, policy_cache: Dict[str, Dict]) -> List[Dict]:
    """Get role inline policies with caching"""
    cache_key = f"inline_{role_name}"
    if cache_key in policy_cache:
        return policy_cache[cache_key]
    
    try:
        policies = []
        paginator = iam_client.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy_name in page['PolicyNames']:
                try:
                    policy = iam_client.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    policies.append(policy['PolicyDocument'])
                except Exception as e:
                    logger.error(f"Error getting inline policy {policy_name} for role {role_name}: {str(e)}")
                    continue
        
        policy_cache[cache_key] = policies
        return policies
    except Exception as e:
        logger.error(f"Error getting inline policies for role {role_name}: {str(e)}")
        return []

def get_instance_profile_data(iam_client: boto3.client, profile_name: str, instance_profile_cache: Dict[str, Dict]) -> Dict:
    """Get instance profile data with caching"""
    if profile_name in instance_profile_cache:
        return instance_profile_cache[profile_name]
    
    try:
        profile = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        instance_profile_cache[profile_name] = profile['InstanceProfile']
        return profile['InstanceProfile']
    except Exception as e:
        logger.error(f"Error getting instance profile data for {profile_name}: {str(e)}")
        return {}

def check_role_permissions(iam_client: boto3.client, role_name: str, actions: Set[str], policy_cache: Dict[str, Dict], role_cache: Dict[str, Dict]) -> bool:
    """Check if a role has specific permissions"""
    try:
        # Check if role can be assumed by EC2
        role_data = get_role_data(iam_client, role_name, role_cache)
        if not role_data:
            return False
            
        assume_role_policy = json.loads(role_data['AssumeRolePolicyDocument'])
        is_ec2_role = False
        for statement in assume_role_policy.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                service = principal.get('Service', [])
                if isinstance(service, str):
                    service = [service]
                if 'ec2.amazonaws.com' in service:
                    is_ec2_role = True
                    break
        
        if not is_ec2_role:
            return False
        
        # Check attached policies
        paginator = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            for policy in page['AttachedPolicies']:
                policy_doc = get_policy_document(iam_client, policy['PolicyArn'], policy_cache)
                
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        policy_actions = statement.get('Action', [])
                        if isinstance(policy_actions, str):
                            policy_actions = [policy_actions]
                        policy_actions = {a.lower() for a in policy_actions}
                        
                        if '*:*' in policy_actions or any(action.lower() in policy_actions for action in actions):
                            return True
        
        # Check inline policies
        inline_policies = get_role_inline_policies(iam_client, role_name, policy_cache)
        for policy_doc in inline_policies:
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    policy_actions = statement.get('Action', [])
                    if isinstance(policy_actions, str):
                        policy_actions = [policy_actions]
                    policy_actions = {a.lower() for a in policy_actions}
                    
                    if '*:*' in policy_actions or any(action.lower() in policy_actions for action in actions):
                        return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error checking permissions for role {role_name}: {str(e)}")
        return False

def check_instance_role_permissions(instance: Dict[str, Any], iam_client: boto3.client, actions: Set[str], policy_cache: Dict[str, Dict], role_cache: Dict[str, Dict], instance_profile_cache: Dict[str, Dict]) -> bool:
    """Check if an EC2 instance's IAM role has specific permissions"""
    try:
        # Get instance profile
        instance_profile = instance.get('IamInstanceProfile', {})
        if not instance_profile:
            return False
            
        # Get role name from instance profile
        profile_arn = instance_profile.get('Arn', '')
        if not profile_arn:
            return False
            
        try:
            profile_name = profile_arn.split('/')[-1]
            profile_data = get_instance_profile_data(iam_client, profile_name, instance_profile_cache)
            
            # Check each role in the instance profile
            for role in profile_data.get('Roles', []):
                role_name = role['RoleName']
                if check_role_permissions(iam_client, role_name, actions, policy_cache, role_cache):
                    return True
                    
            return False
            
        except iam_client.exceptions.NoSuchEntityException:
            logger.warning(f"Instance profile {profile_name} not found")
            return False
            
    except Exception as e:
        logger.error(f"Error checking instance role permissions: {str(e)}")
        return False

@app.route('/check-ec2-3')
def check_ec2():
    """Main route to check EC2 security"""
    try:
        # Initialize AWS clients with retry configuration
        session = boto3.Session(
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID_AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY_AWS_SECRET_ACCESS_KEY'),
            region_name=os.getenv('AWS_DEFAULT_REGION_AWS_DEFAULT_REGION', 'us-east-1')
        )
        ec2_client = get_aws_client('ec2', session)
        iam_client = get_aws_client('iam', session)
        sts_client = get_aws_client('sts', session)
        
        # Get AWS account ID
        account_id = sts_client.get_caller_identity()['Account']
        
        # Cache EC2 instance data
        logger.info("Fetching EC2 instance data...")
        all_instances_data = []
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    all_instances_data.append(instance)
        
        # Initialize caches
        policy_cache = {}
        role_cache = {}
        instance_profile_cache = {}
        
        # Get database connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Run all checks in parallel using ThreadPoolExecutor
            check_results = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                # Define all security checks to run in parallel
                checks = [
                    {
                        'name': 'org_write_access',
                        'fn': check_ec2_instance_no_iam_role_with_org_write_access,
                        'args': [ec2_client, iam_client, account_id, all_instances_data, policy_cache, role_cache, instance_profile_cache]
                    },
                    {
                        'name': 'privilege_escalation',
                        'fn': check_ec2_instance_no_iam_role_with_privilege_escalation_risk_access,
                        'args': [ec2_client, iam_client, account_id, all_instances_data, policy_cache, role_cache, instance_profile_cache]
                    },
                    {
                        'name': 'group_creation',
                        'fn': check_ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access,
                        'args': [ec2_client, iam_client, account_id, all_instances_data, policy_cache, role_cache, instance_profile_cache]
                    },
                    {
                        'name': 'role_creation',
                        'fn': check_ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access,
                        'args': [ec2_client, iam_client, account_id, all_instances_data, policy_cache, role_cache, instance_profile_cache]
                    }
                ]
                
                # Submit all checks to the executor
                future_to_check = {
                    executor.submit(check['fn'], *check['args']): check['name']
                    for check in checks
                }
                
                for future in as_completed(future_to_check):
                    check_name = future_to_check[future]
                    try:
                        data = future.result()
                        if data:
                            if isinstance(data, list):
                                check_results.extend(data)
                            else:
                                check_results.append(data)
                    except Exception as e:
                        logger.error(f"Error in {check_name}: {str(e)}")
                        continue
            
            # Process all results in batch
            result_tuples = []
            for result in check_results:
                if result:
                    result_tuples.append((
                        result['reason'],
                        result['resource'],
                        result['status']
                    ))
            
            if result_tuples:
                insert_query = """
                INSERT INTO aws_project_status (description, resource, status)
                VALUES %s
                """
                execute_values(cur, insert_query, result_tuples)
                conn.commit()
            
            # Calculate summary
            summary = {
                "total_checks": len(check_results),
                "ok": len([r for r in check_results if r['status'] == 'ok']),
                "alarm": len([r for r in check_results if r['status'] == 'alarm']),
                "error": len([r for r in check_results if r['status'] == 'error'])
            }
            
            return jsonify({
                "status": "success",
                "data": check_results,
                "summary": summary,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        logger.error(f"Error in check_ec2_security: {str(e)}")
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

def check_ec2_instance_no_iam_role_with_privilege_escalation_risk_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Dict] = None, role_cache: Dict[str, Dict] = None, instance_profile_cache: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with privilege escalation risk access"""
    try:
        if policy_cache is None:
            policy_cache = {}
        if role_cache is None:
            role_cache = {}
        if instance_profile_cache is None:
            instance_profile_cache = {}
            
        results = []
        
        # Privilege escalation risk actions to check
        privilege_escalation_actions = {
            'iam:createpolicy',
            'iam:createpolicyversion',
            'iam:setdefaultpolicyversion',
            'iam:passrole',
            'iam:createaccesskey',
            'iam:createloginprofile',
            'iam:updateloginprofile',
            'iam:attachuserpolicy',
            'iam:attachgrouppolicy',
            'iam:attachrolepolicy',
            'iam:putuserpolicy',
            'iam:putgrouppolicy',
            'iam:putrolepolicy',
            'iam:addusertogroup',
            'iam:updateassumerolepolicy'
        }
        
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                
                has_privilege_escalation = check_instance_role_permissions(
                    instance=instance,
                    iam_client=iam_client,
                    actions=privilege_escalation_actions,
                    policy_cache=policy_cache,
                    role_cache=role_cache,
                    instance_profile_cache=instance_profile_cache
                )
                
                status = "alarm" if has_privilege_escalation else "ok"
                reason = f"{instance_name} has privilege escalation access." if has_privilege_escalation else f"{instance_name} has no privilege escalation access."
                
                results.append({
                    "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access",
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue
                
        return results
        
    except Exception as e:
        logger.error(f"Error checking EC2 instance IAM roles for privilege escalation access: {str(e)}")
        return [{
            "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "reason": f"Error checking EC2 instance IAM roles for privilege escalation access: {str(e)}"
        }]

def check_ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Dict] = None, role_cache: Dict[str, Dict] = None, instance_profile_cache: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with group creation and policy attachment access"""
    try:
        if policy_cache is None:
            policy_cache = {}
        if role_cache is None:
            role_cache = {}
        if instance_profile_cache is None:
            instance_profile_cache = {}
            
        results = []
        
        # Group creation and policy attachment actions to check
        group_actions = {
            'iam:creategroup',
            'iam:attachgrouppolicy'
        }
        
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                
                has_group_access = check_instance_role_permissions(
                    instance=instance,
                    iam_client=iam_client,
                    actions=group_actions,
                    policy_cache=policy_cache,
                    role_cache=role_cache,
                    instance_profile_cache=instance_profile_cache
                )
                
                status = "alarm" if has_group_access else "ok"
                reason = f"{instance_name} has group creation access." if has_group_access else f"{instance_name} has no group creation access."
                
                results.append({
                    "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access",
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue
                
        return results
        
    except Exception as e:
        logger.error(f"Error checking EC2 instance IAM roles for group creation access: {str(e)}")
        return [{
            "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "reason": f"Error checking EC2 instance IAM roles for group creation access: {str(e)}"
        }]

def check_ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Dict] = None, role_cache: Dict[str, Dict] = None, instance_profile_cache: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with role creation and policy attachment access"""
    try:
        if policy_cache is None:
            policy_cache = {}
        if role_cache is None:
            role_cache = {}
        if instance_profile_cache is None:
            instance_profile_cache = {}
            
        results = []
        
        # Role creation and policy attachment actions to check
        role_actions = {
            'iam:createrole',
            'iam:attachrolepolicy'
        }
        
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                
                has_role_access = check_instance_role_permissions(
                    instance=instance,
                    iam_client=iam_client,
                    actions=role_actions,
                    policy_cache=policy_cache,
                    role_cache=role_cache,
                    instance_profile_cache=instance_profile_cache
                )
                
                status = "alarm" if has_role_access else "ok"
                reason = f"{instance_name} has role creation access." if has_role_access else f"{instance_name} has no role creation access."
                
                results.append({
                    "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access",
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue
                
        return results
        
    except Exception as e:
        logger.error(f"Error checking EC2 instance IAM roles for role creation access: {str(e)}")
        return [{
            "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "reason": f"Error checking EC2 instance IAM roles for role creation access: {str(e)}"
        }]

def check_ec2_instance_no_iam_role_with_org_write_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, all_instances_data: List[Dict[str, Any]], policy_cache: Dict[str, Dict] = None, role_cache: Dict[str, Dict] = None, instance_profile_cache: Dict[str, Dict] = None) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with organization write access"""
    try:
        if policy_cache is None:
            policy_cache = {}
        if role_cache is None:
            role_cache = {}
        if instance_profile_cache is None:
            instance_profile_cache = {}
            
        results = []
        
        # Organization management actions to check
        org_actions = {
            'organizations:accepthandshake',
            'organizations:attachpolicy',
            'organizations:cancelhandshake',
            'organizations:createaccount',
            'organizations:createorganization',
            'organizations:createorganizationalunit',
            'organizations:createpolicy',
            'organizations:deletepolicy',
            'organizations:deleteorganization',
            'organizations:deleteorganizationalunit',
            'organizations:detachpolicy',
            'organizations:disablepolicytype',
            'organizations:enablepolicytype',
            'organizations:inviteaccounttoorganization',
            'organizations:moveaccount',
            'organizations:removeaccountfromorganization',
            'organizations:updatepolicy',
            'organizations:updateorganizationalunit'
        }
        
        for instance in all_instances_data:
            try:
                instance_id = instance['InstanceId']
                instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), instance_id)
                
                has_org_access = check_instance_role_permissions(
                    instance=instance,
                    iam_client=iam_client,
                    actions=org_actions,
                    policy_cache=policy_cache,
                    role_cache=role_cache,
                    instance_profile_cache=instance_profile_cache
                )
                
                status = "alarm" if has_org_access else "ok"
                reason = f"{instance_name} has organization write access." if has_org_access else f"{instance_name} has no organization write access."
                
                results.append({
                    "type": "ec2_instance_no_iam_role_with_org_write_access",
                    "resource": instance_arn,
                    "status": status,
                    "reason": reason
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance_id}: {str(e)}")
                continue
                
        return results
        
    except Exception as e:
        logger.error(f"Error checking EC2 instance IAM roles for organization write access: {str(e)}")
        return [{
            "type": "ec2_instance_no_iam_role_with_org_write_access",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "reason": f"Error checking EC2 instance IAM roles for organization write access: {str(e)}"
        }]

if __name__ == '__main__':
    print("Starting Flask server on port 5004...")
    app.run(host='0.0.0.0', debug=True, port=5004)
