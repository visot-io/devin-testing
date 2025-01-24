from flask import Flask, jsonify
from typing import List, Dict, Any
import boto3
import os
import psycopg2
import json
from datetime import datetime, timezone

app = Flask(__name__)

# Global caches
ec2_cache = None
role_cache = {}
policy_version_cache = {}
role_policy_cache = {}

def get_all_ec2_instances(ec2_client: boto3.client = None) -> List[Dict[str, Any]]:
    """Get all EC2 instances from all regions with caching to avoid redundant API calls"""
    global ec2_cache
    if ec2_cache is not None:
        return ec2_cache
        
    ec2_cache = []
    try:
        # Get list of all regions
        if not ec2_client:
            ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        
        # Fetch instances from each region
        for region in regions:
            try:
                regional_client = boto3.client('ec2', region_name=region)
                paginator = regional_client.get_paginator('describe_instances')
                for page in paginator.paginate():
                    for reservation in page['Reservations']:
                        # Add region information to each instance
                        for instance in reservation['Instances']:
                            instance['Region'] = region
                            ec2_cache.append(instance)
            except Exception as e:
                print(f"Error fetching instances from region {region}: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Error fetching EC2 instances: {str(e)}")
        return []
        
    return ec2_cache

def get_db_connection():
    """Create a database connection"""
    try:
        # Try connecting with peer authentication
        conn = psycopg2.connect(
            dbname="postgres",
            user="postgres",
            password="postgres",
            host="localhost",
            port="5432"
        )
        
        # Create table if it doesn't exist
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS aws_project_status (
                    id SERIAL PRIMARY KEY,
                    description TEXT,
                    resource TEXT,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        return conn
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        raise

def get_aws_client(service: str):
    """Get AWS client for the specified service"""
    return boto3.client(
        service,
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        aws_session_token=os.getenv('AWS_SESSION_TOKEN'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )

def check_ec2_instance_no_iam_role_with_security_group_write_access(instances: List[Dict[str, Any]], ec2_client: boto3.client, iam_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with security group write access"""
    try:
        results = []
        
        # Security group related actions to check
        SECURITY_GROUP_ACTIONS = {
            'rds:createdbsecuritygroup',
            'rds:deletedbsecuritygroup',
            'rds:revokedbsecuritygroupingress',
            'ec2:authorizesecuritygroupegress',
            'ec2:authorizesecuritygroupingress',
            'ec2:createsecuritygroup',
            'ec2:deletesecuritygroup',
            'ec2:modifysecuritygrouprules',
            'ec2:revokesecuritygroupegress',
            'ec2:revokesecuritygroupingress',
            'elasticloadbalancing:applysecuritygroupstoloadbalancer',
            'elasticloadbalancing:setsecuritygroups',
            'redshift:authorizeclustersecuritygroupingress',
            'redshift:createclustersecuritygroup',
            'redshift:deleteclustersecuritygroup'
        }
        
        def get_role_permissions(iam_client: boto3.client, role_name: str) -> Dict[str, Any]:
            """Get role permissions with caching to avoid redundant API calls"""
            if role_name in role_cache:
                return role_cache[role_name]
                
            try:
                # Get role and assume role policy
                role_data = {
                    'role': iam_client.get_role(RoleName=role_name),
                    'is_ec2_service': False,
                    'attached_policies': [],
                    'inline_policies': []
                }
                
                # Check assume role policy
                assume_role_policy = json.loads(role_data['role']['Role']['AssumeRolePolicyDocument'])
                for statement in assume_role_policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        service = principal.get('Service', [])
                        if isinstance(service, str):
                            service = [service]
                        if 'ec2.amazonaws.com' in service:
                            role_data['is_ec2_service'] = True
                            break
                
                # Get attached policies if it's an EC2 service role
                if role_data['is_ec2_service']:
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies['AttachedPolicies']:
                        if policy['PolicyArn'] not in policy_version_cache:
                            policy_version = iam_client.get_policy_version(
                                PolicyArn=policy['PolicyArn'],
                                VersionId=iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                            )
                            policy_version_cache[policy['PolicyArn']] = policy_version
                        role_data['attached_policies'].append({
                            'arn': policy['PolicyArn'],
                            'version': policy_version_cache[policy['PolicyArn']]
                        })
                    
                    # Get inline policies
                    if role_name not in role_policy_cache:
                        inline_policies = iam_client.list_role_policies(RoleName=role_name)
                        role_policy_cache[role_name] = []
                        for policy_name in inline_policies['PolicyNames']:
                            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            role_policy_cache[role_name].append(policy)
                    role_data['inline_policies'] = role_policy_cache[role_name]
                
                role_cache[role_name] = role_data
                return role_data
                
            except iam_client.exceptions.NoSuchEntityException:
                role_cache[role_name] = None
                return None
            except Exception as e:
                print(f"Error getting role permissions for {role_name}: {str(e)}")
                return None

        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has security group write permissions"""
            try:
                role_name = role_arn.split('/')[-1]
                role_data = get_role_permissions(iam_client, role_name)
                
                if not role_data or not role_data['is_ec2_service']:
                    return False
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in SECURITY_GROUP_ACTIONS):
                                return True
                
                # Check inline policies
                for policy in role_data['inline_policies']:
                    for statement in policy['PolicyDocument'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in SECURITY_GROUP_ACTIONS):
                                return True
                
                return False
            except Exception:
                return False
        
        # Get all EC2 instances
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        status = "ok"
                        reason = f"{instance_id} has no IAM role with security group write access."
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            status = "alarm"
                            reason = f"{instance_id} has IAM role with security group write access."
                        else:
                            status = "ok"
                            reason = f"{instance_id} has no IAM role with security group write access."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_instance_no_iam_role_with_security_group_write_access"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_security_group_write_access"
        }]

def check_ec2_instance_no_iam_role_with_defense_evasion_impact(instances: List[Dict[str, Any]], ec2_client: boto3.client, iam_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with defense evasion impact permissions"""
    try:
        results = []
        
        # Defense evasion related actions to check
        DEFENSE_EVASION_ACTIONS = {
            'guardduty:updatedetector',
            'guardduty:deletedetector',
            'guardduty:deletemembers',
            'guardduty:updatefilter',
            'guardduty:deletefilter',
            'shield:disableapplicationlayerautomaticresponse',
            'shield:updateprotectiongroup',
            'shield:deletesubscription',
            'detective:disassociatemembership',
            'detective:deletemembers',
            'inspector:disable',
            'config:stopconfigurationrecorder',
            'config:deleteconfigurationrecorder',
            'config:deleteconfigrule',
            'config:deleteorganizationconfigrule',
            'cloudwatch:disablealarmactions',
            'cloudwatch:disableinsightrules'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has defense evasion permissions"""
            try:
                role_name = role_arn.split('/')[-1]
                role_data = get_role_permissions(iam_client, role_name)
                
                if not role_data or not role_data['is_ec2_service']:
                    return False
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in DEFENSE_EVASION_ACTIONS):
                                return True
                    
                # Check inline policies
                for policy in role_data['inline_policies']:
                    for statement in policy['PolicyDocument'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in DEFENSE_EVASION_ACTIONS):
                                return True
                
                return False
            except Exception:
                return False
        
        # Get all EC2 instances
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        status = "ok"
                        reason = f"{instance_id} has no IAM role with defense evasion impact of AWS security services access."
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            status = "alarm"
                            reason = f"{instance_id} has IAM role with defense evasion impact of AWS security services access."
                        else:
                            status = "ok"
                            reason = f"{instance_id} has no IAM role with defense evasion impact of AWS security services access."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_instance_no_iam_role_with_defense_evasion_impact"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for defense evasion: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_defense_evasion_impact"
        }]

def check_ec2_instance_no_iam_role_with_elastic_ip_hijacking_access(instances: List[Dict[str, Any]], ec2_client: boto3.client, iam_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with elastic IP hijacking permissions"""
    try:
        results = []
        
        # Elastic IP hijacking related actions to check
        ELASTIC_IP_ACTIONS = {
            'ec2:disassociateaddress',
            'ec2:enableaddresstransfer'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has elastic IP hijacking permissions"""
            try:
                role_name = role_arn.split('/')[-1]
                role_data = get_role_permissions(iam_client, role_name)
                
                if not role_data or not role_data['is_ec2_service']:
                    return False
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in ELASTIC_IP_ACTIONS):
                                return True
                    
                # Check inline policies
                for policy in role_data['inline_policies']:
                    for statement in policy['PolicyDocument'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            if any(action in actions for action in ELASTIC_IP_ACTIONS):
                                return True
                
                return False
            except Exception:
                return False
        
        # Get all EC2 instances
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        status = "ok"
                        reason = f"{instance_id} has no IAM role with elastic IP hijacking access."
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            status = "alarm"
                            reason = f"{instance_id} has IAM role with elastic IP hijacking access."
                        else:
                            status = "ok"
                            reason = f"{instance_id} has no IAM role with elastic IP hijacking access."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_instance_no_iam_role_with_elastic_ip_hijacking_access"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for elastic IP hijacking: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_elastic_ip_hijacking_access"
        }]

def check_ec2_instance_no_iam_passrole_and_lambda_invoke_function_access(instances: List[Dict[str, Any]], ec2_client: boto3.client, iam_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with PassRole and Lambda invoke permissions"""
    try:
        results = []
        
        # PassRole and Lambda related actions to check
        SENSITIVE_ACTIONS = {
            'iam:passrole',
            'lambda:createfunction',
            'lambda:invokefunction'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has PassRole and Lambda permissions"""
            try:
                role_name = role_arn.split('/')[-1]
                role_data = get_role_permissions(iam_client, role_name)
                
                if not role_data or not role_data['is_ec2_service']:
                    return False
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            # Check if all required actions are present
                            if all(action in actions for action in SENSITIVE_ACTIONS):
                                return True
                    
                # Check inline policies
                for policy in role_data['inline_policies']:
                    for statement in policy['PolicyDocument'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*:*' in actions:
                                return True
                                
                            actions = {a.lower() for a in actions}
                            # Check if all required actions are present
                            if all(action in actions for action in SENSITIVE_ACTIONS):
                                return True
                
                return False
            except Exception:
                return False
        
        # Get all EC2 instances
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        status = "ok"
                        reason = f"{instance_id} has no IAM pass role and lambda invoke function access."
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            status = "alarm"
                            reason = f"{instance_id} has IAM pass role and lambda invoke function access."
                        else:
                            status = "ok"
                            reason = f"{instance_id} has no IAM pass role and lambda invoke function access."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_instance_no_iam_passrole_and_lambda_invoke_function_access"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for PassRole and Lambda access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_passrole_and_lambda_invoke_function_access"
        }]

def check_ec2_instance_not_older_than_180_days(instances: List[Dict[str, Any]], ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances are not older than 180 days"""
    try:
        results = []
        
        # Get current time using timezone-aware datetime
        current_time = datetime.now(timezone.utc)
        
        # Use cached EC2 instances
        for instance in instances:
                    instance_id = instance['InstanceId']
                    launch_time = instance.get('LaunchTime')
                    
                    if not launch_time:
                        continue
                    
                    # Calculate age in days (launch_time from AWS is already UTC)
                    age_days = (current_time - launch_time).days
                    
                    # Format date string
                    formatted_date = launch_time.strftime('%d-%b-%Y')
                    
                    if age_days <= 180:
                        status = "ok"
                    else:
                        status = "alarm"
                    
                    reason = f"{instance_id} created {formatted_date} ({age_days} days)."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_id,
                        "status": status,
                        "type": "ec2_instance_not_older_than_180_days"
                    })
        
        # If no instances found, return informational message
        if not results:
            results.append({
                "reason": "No EC2 instances found",
                "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
                "status": "ok",
                "type": "ec2_instance_not_older_than_180_days"
            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance age: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_not_older_than_180_days"
        }]

def check_ec2_instance_attached_ebs_volume_delete_on_termination_enabled(instances: List[Dict[str, Any]], ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have EBS volumes with delete on termination enabled"""
    try:
        results = []
        
        # Use cached EC2 instances
        for instance in instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Count volumes with delete on termination disabled
                    volumes_with_no_deletion = 0
                    
                    # Check block device mappings
                    for block_device in instance.get('BlockDeviceMappings', []):
                        if 'Ebs' in block_device:
                            ebs = block_device['Ebs']
                            if not ebs.get('DeleteOnTermination', True):
                                volumes_with_no_deletion += 1
                    
                    if volumes_with_no_deletion > 0:
                        status = "alarm"
                        reason = f"EBS volume(s) attached to {instance_id} has delete on termination disabled."
                    else:
                        status = "ok"
                        reason = f"EBS volume(s) attached to {instance_id} has delete on termination enabled."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_instance_attached_ebs_volume_delete_on_termination_enabled"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance EBS volume delete on termination: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_attached_ebs_volume_delete_on_termination_enabled"
        }]

def check_ec2_stopped_instance_90_days(instances: List[Dict[str, Any]], ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 instances have been stopped for more than 90 days"""
    try:
        results = []
        
        # Get current time
        current_time = datetime.now(timezone.utc)
        
        # Use cached EC2 instances
        for instance in instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    instance_state = instance['State']['Name']
                    
                    # Skip if instance is not stopped/stopping
                    if instance_state not in ['stopped', 'stopping']:
                        results.append({
                            "reason": f"{instance_id} is in {instance_state} state.",
                            "resource": instance_arn,
                            "status": "skip",
                            "type": "ec2_stopped_instance_90_days"
                        })
                        continue
                    
                    # Get state transition time
                    state_transition_time = None
                    for state_transition in instance.get('StateTransitionReason', '').split():
                        try:
                            state_transition_time = datetime.strptime(state_transition, '(%Y-%m-%d')
                            break
                        except ValueError:
                            continue
                    
                    if not state_transition_time:
                        # If we can't determine the transition time, assume it's recent
                        status = "ok"
                        reason = f"{instance_id} stop time cannot be determined."
                    else:
                        # Calculate days since stopping
                        days_stopped = (current_time - state_transition_time).days
                        formatted_date = state_transition_time.strftime('%d-%b-%Y')
                        
                        if days_stopped > 90:
                            status = "alarm"
                        else:
                            status = "ok"
                            
                        reason = f"{instance_id} stopped since {formatted_date} ({days_stopped} days)."
                    
                    results.append({
                        "reason": reason,
                        "resource": instance_arn,
                        "status": status,
                        "type": "ec2_stopped_instance_90_days"
                    })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 stopped instances: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_stopped_instance_90_days"
        }]

def check_ec2_client_vpn_endpoint_client_connection_logging_enabled(ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 Client VPN endpoints have connection logging enabled"""
    try:
        results = []
        
        # Get all Client VPN endpoints
        try:
            response = ec2_client.describe_client_vpn_endpoints()
            vpn_endpoints = response.get('ClientVpnEndpoints', [])
        except ec2_client.exceptions.ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                # If the service is not available or user doesn't have permission
                return [{
                    "reason": "Unable to check Client VPN endpoints - service may not be available in this region or missing permissions",
                    "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:client-vpn-endpoint/*",
                    "status": "error",
                    "type": "ec2_client_vpn_endpoint_client_connection_logging_enabled"
                }]
            raise
            
        for endpoint in vpn_endpoints:
            endpoint_id = endpoint['ClientVpnEndpointId']
            
            # Check connection logging options
            connection_log_options = endpoint.get('ConnectionLogOptions', {})
            is_logging_enabled = connection_log_options.get('Enabled', False)
            
            if is_logging_enabled:
                status = "ok"
                reason = f"{endpoint_id} client connection logging enabled."
            else:
                status = "alarm"
                reason = f"{endpoint_id} client connection logging disabled."
            
            results.append({
                "reason": reason,
                "resource": endpoint_id,
                "status": status,
                "type": "ec2_client_vpn_endpoint_client_connection_logging_enabled"
            })
        
        # If no endpoints found, return informational message
        if not vpn_endpoints:
            results.append({
                "reason": "No Client VPN endpoints found in the region",
                "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:client-vpn-endpoint/*",
                "status": "ok",
                "type": "ec2_client_vpn_endpoint_client_connection_logging_enabled"
            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking Client VPN endpoint logging: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:client-vpn-endpoint/*",
            "status": "error",
            "type": "ec2_client_vpn_endpoint_client_connection_logging_enabled"
        }]

def check_ec2_ami_ebs_encryption_enabled(ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 AMIs have EBS encryption enabled for all volumes"""
    try:
        results = []
        
        # Get all AMIs owned by the account
        try:
            response = ec2_client.describe_images(Owners=['self'])
            images = response.get('Images', [])
        except ec2_client.exceptions.ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                return [{
                    "reason": "Unable to check AMI encryption - missing permissions",
                    "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
                    "status": "error",
                    "type": "ec2_ami_ebs_encryption_enabled"
                }]
            raise
            
        for image in images:
            image_id = image['ImageId']
            block_device_mappings = image.get('BlockDeviceMappings', [])
            
            # Skip if no block device mappings
            if not block_device_mappings:
                continue
            
            # Check if all EBS volumes are encrypted
            all_encrypted = True
            for mapping in block_device_mappings:
                if 'Ebs' in mapping:
                    ebs = mapping['Ebs']
                    if not ebs.get('Encrypted', False):
                        all_encrypted = False
                        break
            
            if all_encrypted:
                status = "ok"
                reason = f"{image_id} all EBS volumes are encrypted."
            else:
                status = "alarm"
                reason = f"{image_id} all EBS volumes are not encrypted."
            
            results.append({
                "reason": reason,
                "resource": image_id,
                "status": status,
                "type": "ec2_ami_ebs_encryption_enabled"
            })
        
        # If no AMIs found, return informational message
        if not images:
            results.append({
                "reason": "No AMIs found owned by the account",
                "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
                "status": "ok",
                "type": "ec2_ami_ebs_encryption_enabled"
            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking AMI EBS encryption: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
            "status": "error",
            "type": "ec2_ami_ebs_encryption_enabled"
        }]

def check_ec2_ami_not_older_than_90_days(ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 AMIs are not older than 90 days"""
    try:
        results = []
        
        # Get current time
        current_time = datetime.now(timezone.utc)
        
        # Get all AMIs owned by the account
        try:
            response = ec2_client.describe_images(Owners=['self'])
            images = response.get('Images', [])
        except ec2_client.exceptions.ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                return [{
                    "reason": "Unable to check AMI age - missing permissions",
                    "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
                    "status": "error",
                    "type": "ec2_ami_not_older_than_90_days"
                }]
            raise
            
        for image in images:
            image_id = image['ImageId']
            creation_date = image.get('CreationDate')
            
            if not creation_date:
                continue
            
            # Parse creation date
            try:
                # AWS returns creation date in ISO format
                creation_time = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                try:
                    # Try alternative format without milliseconds
                    creation_time = datetime.strptime(creation_date, '%Y-%m-%dT%H:%M:%SZ')
                except ValueError:
                    continue
            
            # Calculate age in days
            age_days = (current_time - creation_time).days
            
            # Format date string
            formatted_date = creation_time.strftime('%d-%b-%Y')
            
            if age_days <= 90:
                status = "ok"
            else:
                status = "alarm"
            
            reason = f"{image_id} created {formatted_date} ({age_days} days)."
            
            results.append({
                "reason": reason,
                "resource": image_id,
                "status": status,
                "type": "ec2_ami_not_older_than_90_days"
            })
        
        # If no AMIs found, return informational message
        if not images:
            results.append({
                "reason": "No AMIs found owned by the account",
                "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
                "status": "ok",
                "type": "ec2_ami_not_older_than_90_days"
            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking AMI age: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:image/*",
            "status": "error",
            "type": "ec2_ami_not_older_than_90_days"
        }]

def check_ec2_network_interface_unused(ec2_client: boto3.client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 network interfaces are unused"""
    try:
        results = []
        
        # Get all network interfaces
        try:
            paginator = ec2_client.get_paginator('describe_network_interfaces')
            for page in paginator.paginate():
                for eni in page['NetworkInterfaces']:
                    eni_id = eni['NetworkInterfaceId']
                    status = eni.get('Status', '').lower()
                    attached_instance = eni.get('Attachment', {}).get('InstanceId')
                    
                    # Check if network interface is unused
                    if status == 'available' and not attached_instance:
                        status_result = "alarm"
                        reason = f"{eni_id} not in use."
                    else:
                        status_result = "ok"
                        reason = f"{eni_id} in use."
                    
                    results.append({
                        "reason": reason,
                        "resource": eni_id,
                        "status": status_result,
                        "type": "ec2_network_interface_unused"
                    })
                    
        except ec2_client.exceptions.ClientError as e:
            if 'UnauthorizedOperation' in str(e):
                return [{
                    "reason": "Unable to check network interfaces - missing permissions",
                    "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:network-interface/*",
                    "status": "error",
                    "type": "ec2_network_interface_unused"
                }]
            raise
        
        # If no network interfaces found, return informational message
        if not results:
            results.append({
                "reason": "No network interfaces found",
                "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:network-interface/*",
                "status": "ok",
                "type": "ec2_network_interface_unused"
            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking network interfaces: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:network-interface/*",
            "status": "error",
            "type": "ec2_network_interface_unused"
        }]

@app.route('/check-ec2-4')
def check_ec2():
    """Main route to check EC2 security"""
    try:
        # Initialize clients
        ec2_client = get_aws_client('ec2')
        iam_client = get_aws_client('iam')
        sts_client = get_aws_client('sts')
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Get all EC2 instances once and cache them
        instances = get_all_ec2_instances(ec2_client)
        
        results = []
        checks = [
            lambda: check_ec2_instance_no_iam_role_with_security_group_write_access(instances, ec2_client, iam_client, account_id),
            lambda: check_ec2_instance_no_iam_role_with_defense_evasion_impact(instances, ec2_client, iam_client, account_id),
            lambda: check_ec2_instance_no_iam_role_with_elastic_ip_hijacking_access(instances, ec2_client, iam_client, account_id),
            lambda: check_ec2_instance_no_iam_passrole_and_lambda_invoke_function_access(instances, ec2_client, iam_client, account_id),
            lambda: check_ec2_instance_not_older_than_180_days(instances, ec2_client, account_id),
            lambda: check_ec2_instance_attached_ebs_volume_delete_on_termination_enabled(instances, ec2_client, account_id),
            lambda: check_ec2_stopped_instance_90_days(instances, ec2_client, account_id),
            lambda: check_ec2_client_vpn_endpoint_client_connection_logging_enabled(ec2_client, account_id),
            lambda: check_ec2_ami_ebs_encryption_enabled(ec2_client, account_id),
            lambda: check_ec2_ami_not_older_than_90_days(ec2_client, account_id),
            lambda: check_ec2_network_interface_unused(ec2_client, account_id)
        ]
        
        # Run all checks
        for check in checks:
            try:
                check_results = check()
                if isinstance(check_results, list):
                    results.extend(check_results)
                else:
                    results.append(check_results)
            except Exception as e:
                results.append({
                    "status": "error",
                    "reason": str(e),
                    "resource": "Unknown",
                    "type": "Unknown"
                })
        
        # Save results to database in batch
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Prepare batch insert values
        insert_values = [(
            result.get('reason'),
            result.get('resource'),
            result.get('status')
        ) for result in results]
        
        # Execute batch insert
        cur.executemany("""
            INSERT INTO aws_project_status (description, resource, status)
            VALUES (%s, %s, %s)
            """, insert_values)
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Calculate summary statistics
        summary = {
            "total_checks": len(results),
            "ok": len([r for r in results if r['status'] == 'ok']),
            "alarm": len([r for r in results if r['status'] == 'alarm']),
            "error": len([r for r in results if r['status'] == 'error'])
        }

        # Return results with summary
        response_data = {
            "summary": summary,
            "results": results
        }
        
        return app.response_class(
            response=json.dumps(response_data, indent=2),
            status=200,
            mimetype='application/json'
        )
        
    except Exception as e:
        return app.response_class(
            response=json.dumps({"error": str(e)}, indent=2),
            status=500,
            mimetype='application/json'
        )

if __name__ == '__main__':
    app.run(port=5004)


