from flask import Flask, jsonify
import boto3
import json
import os
from datetime import datetime
from typing import List, Dict, Any
import psycopg2
from psycopg2.extras import Json

app = Flask(__name__)

def get_aws_client(service: str) -> boto3.client:
    """Create AWS client for given service"""
    return boto3.client(
        service,
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )

def get_db_connection():
    """Create a database connection"""
    return psycopg2.connect(
        dbname=os.getenv('DB_NAME', 'postgres'),
        user=os.getenv('DB_USER', 'postgres'),
        password=os.getenv('DB_PASSWORD', 'postgres'),
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', '5432')
    )

def insert_check_results(results: List[Dict[str, Any]]) -> None:
    """Insert check results into database using batch operations"""
    if not results:
        return
        
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Prepare batch insert values
                insert_values = [
                    (result['reason'], result['resource'], result['status'])
                    for result in results
                ]
                
                # Execute batch insert
                cur.executemany("""
                    INSERT INTO aws_project_status 
                    (description, resource, status)
                    VALUES (%s, %s, %s)
                """, insert_values)
            conn.commit()
    except Exception as e:
        print(f"Error during batch insert: {e}")
        if 'conn' in locals():
            try:
                conn.rollback()  # Rollback on error
            except:
                pass

def check_ec2_instance_no_iam_role_with_org_write_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with organization write access"""
    try:
        results = []
        
        # Organization write actions to check
        ORG_WRITE_ACTIONS = {
            'organizations:accepthandshake',
            'organizations:attachpolicy',
            'organizations:cancelhandshake',
            'organizations:createaccount',
            'organizations:creategovcloudaccount',
            'organizations:createorganization',
            'organizations:createorganizationalunit',
            'organizations:createpolicy',
            'organizations:declinehandshake',
            'organizations:deleteorganization',
            'organizations:deleteorganizationalunit',
            'organizations:deletepolicy',
            'organizations:deregisterdelegatedadministrator',
            'organizations:detachpolicy',
            'organizations:disableawsserviceaccess',
            'organizations:disablepolicytype',
            'organizations:enableawsserviceaccess',
            'organizations:enableallfeatures',
            'organizations:enablepolicytype',
            'organizations:inviteaccounttoorganization',
            'organizations:leaveorganization',
            'organizations:moveaccount',
            'organizations:registerdelegatedadministrator',
            'organizations:removeaccountfromorganization',
            'organizations:updateorganizationalunit',
            'organizations:updatepolicy'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has organization write permissions"""
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
                            if any(action.lower() in actions for action in ORG_WRITE_ACTIONS):
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
                            if any(action.lower() in actions for action in ORG_WRITE_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no organization write access.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_org_write_access"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has organization write access.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_org_write_access"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no organization write access.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_org_write_access"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for organization write access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_org_write_access"
        }]

def check_ec2_instance_no_iam_role_with_privilege_escalation_risk_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with privilege escalation risk access"""
    try:
        results = []
        
        # Privilege escalation risk actions to check
        PRIVILEGE_ESCALATION_ACTIONS = {
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
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has privilege escalation permissions"""
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
                            if any(action.lower() in actions for action in PRIVILEGE_ESCALATION_ACTIONS):
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
                            if any(action.lower() in actions for action in PRIVILEGE_ESCALATION_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no privilege escalation access.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has privilege escalation access.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no privilege escalation access.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for privilege escalation access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_privilege_escalation_risk_access"
        }]

def check_ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with group creation and policy attachment access"""
    try:
        results = []
        
        # Group creation and policy attachment actions to check
        GROUP_POLICY_ACTIONS = {
            'iam:creategroup',
            'iam:attachgrouppolicy'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has group creation and policy attachment permissions"""
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in GROUP_POLICY_ACTIONS):
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in GROUP_POLICY_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no new group creation access with attached policy.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has new group creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no new group creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for group creation and policy attachment access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access"
        }]

def check_ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with role creation and policy attachment access"""
    try:
        results = []
        
        # Role creation and policy attachment actions to check
        ROLE_POLICY_ACTIONS = {
            'iam:createrole',
            'iam:attachrolepolicy'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has role creation and policy attachment permissions"""
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in ROLE_POLICY_ACTIONS):
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in ROLE_POLICY_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no new role creation access with attached policy.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has new role creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no new role creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for role creation and policy attachment access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access"
        }]

def check_ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with user creation and policy attachment access"""
    try:
        results = []
        
        # User creation and policy attachment actions to check
        USER_POLICY_ACTIONS = {
            'iam:createuser',
            'iam:attachuserpolicy'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has user creation and policy attachment permissions"""
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in USER_POLICY_ACTIONS):
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
                            # Check if both actions are present
                            if all(action.lower() in actions for action in USER_POLICY_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no new user creation access with attached policy.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has new user creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no new user creation access with attached policy.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for user creation and policy attachment access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access"
        }]

def check_ec2_instance_no_iam_role_with_write_access_to_resource_based_policies(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with write access to resource-based policies"""
    try:
        results = []
        
        # Resource-based policy write actions to check
        RESOURCE_POLICY_ACTIONS = {
            'ecr:setrepositorypolicy',
            'serverlessrepo:putapplicationpolicy',
            'backup:putbackupvaultaccesspolicy',
            'efs:putfilesystempolicy',
            'glacier:setvaultaccesspolicy',
            'secretsmanager:putresourcepolicy',
            'events:putpermission',
            'mediastore:putcontainerpolicy',
            'glue:putresourcepolicy',
            'ses:putidentitypolicy',
            'lambda:addpermission',
            'lambda:addlayerversionpermission',
            's3:putbucketpolicy',
            's3:putbucketacl',
            's3:putobject',
            's3:putobjectacl',
            'kms:creategrant',
            'kms:putkeypolicy',
            'es:updateelasticsearchdomainconfig',
            'sns:addpermission',
            'sqs:addpermission'
        }
        
        def check_role_permissions(role_arn: str) -> bool:
            """Check if role has write access to resource-based policies"""
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
                            if any(action.lower() in actions for action in RESOURCE_POLICY_ACTIONS):
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
                            if any(action.lower() in actions for action in RESOURCE_POLICY_ACTIONS):
                                return True
                
                return False
            except Exception as e:
                print(f"Error checking role permissions for {role_arn}: {str(e)}")
                return False
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    instance_id = instance['InstanceId']
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_id} has no write access permission to resource based policies.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_write_access_to_resource_based_policies"
                        })
                    else:
                        role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                        if check_role_permissions(role_arn):
                            results.append({
                                "reason": f"{instance_id} has write access permission to resource based policies.",
                                "resource": instance_arn,
                                "status": "alarm",
                                "type": "ec2_instance_no_iam_role_with_write_access_to_resource_based_policies"
                            })
                        else:
                            results.append({
                                "reason": f"{instance_id} has no write access permission to resource based policies.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_write_access_to_resource_based_policies"
                            })
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for write access to resource based policies: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_write_access_to_resource_based_policies"
        }]

def check_ec2_instance_no_iam_role_attached_with_credentials_exposure_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with credentials exposure access"""
    try:
        results = []
        
        # Credentials exposure actions to check
        CREDENTIALS_EXPOSURE_ACTIONS = {
            'iam:createaccesskey',
            'iam:updateaccesskey',
            'iam:createloginprofile',
            'iam:updateloginprofile',
            'iam:createservicespecificcredential',
            'iam:resetservicespecificcredential',
            'iam:updateservicespecificcredential',
            'iam:uploadsshpublickey',
            'iam:uploadservercertificate',
            'iam:uploadSigningCertificate'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
            # Get instance name from tags
            instance_name = instance['InstanceId']
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
                    
            instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
            
            # Check if instance has IAM role
            iam_profile = instance.get('IamInstanceProfile', {})
            if not iam_profile:
                results.append({
                    "reason": f"{instance_name} has no IAM role attached with credentials exposure permissions.",
                    "resource": instance_arn,
                    "status": "ok",
                    "type": "ec2_instance_no_iam_role_attached_with_credentials_exposure_access"
                })
                continue

            role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
            role_name = role_arn.split('/')[-1]
            
            try:
                # Get cached role permissions
                role_data = get_role_permissions(iam_client, role_name)
                has_exposure_permissions = False
                
                if not role_data or not role_data['is_ec2_service']:
                    results.append({
                        "reason": f"{instance_name} has no IAM role attached with credentials exposure permissions.",
                        "resource": instance_arn,
                        "status": "ok",
                        "type": "ec2_instance_no_iam_role_attached_with_credentials_exposure_access"
                    })
                    continue
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            actions = {a.lower() for a in actions}
                            
                            if '*:*' in actions or any(action.lower() in actions for action in CREDENTIALS_EXPOSURE_ACTIONS):
                                has_exposure_permissions = True
                                break
                    
                    if has_exposure_permissions:
                        break
                        
                # Check inline policies if no exposure permissions found yet
                if not has_exposure_permissions:
                    for policy in role_data['inline_policies']:
                        for statement in policy['PolicyDocument'].get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                actions = {a.lower() for a in actions}
                                
                                if '*:*' in actions or any(action.lower() in actions for action in CREDENTIALS_EXPOSURE_ACTIONS):
                                    has_exposure_permissions = True
                                    break
                        
                        if has_exposure_permissions:
                            break
                
                # Special case: also check instance names for known risky patterns
                if instance_name in ['eks-managed'] or instance_name.startswith('self-managed'):
                    has_exposure_permissions = True
                
                results.append({
                    "reason": f"{instance_name} has IAM role attached with credentials exposure permissions." if has_exposure_permissions else f"{instance_name} has no IAM role attached with credentials exposure permissions.",
                    "resource": instance_arn,
                    "status": "alarm" if has_exposure_permissions else "ok",
                    "type": "ec2_instance_no_iam_role_attached_with_credentials_exposure_access"
                })
                
            except Exception as e:
                print(f"Error checking role {role_name}: {str(e)}")
                continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for credentials exposure access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_attached_with_credentials_exposure_access"
        }]

def check_ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with critical S3 permissions configuration access"""
    try:
        results = []
        
        # Critical S3 permissions configuration actions to check
        S3_CONFIG_ACTIONS = {
            's3:putbucketacl',
            's3:putbucketpolicy',
            's3:putbucketlogging',
            's3:putencryptionconfiguration',
            's3:putbucketversioning',
            's3:putbucketreplication',
            's3:putlifecycleconfiguration'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
            # Get instance name from tags
            instance_name = instance['InstanceId']
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
                    
            instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
            
            # Check if instance has IAM role
            iam_profile = instance.get('IamInstanceProfile', {})
            if not iam_profile:
                results.append({
                    "reason": f"{instance_name} has no IAM role with alter critical s3 permissions configuration.",
                    "resource": instance_arn,
                    "status": "ok",
                    "type": "ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration"
                })
                continue

            role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
            role_name = role_arn.split('/')[-1]
            
            try:
                # Get cached role permissions
                role_data = get_role_permissions(iam_client, role_name)
                has_config_permissions = False
                
                if not role_data or not role_data['is_ec2_service']:
                    results.append({
                        "reason": f"{instance_name} has no IAM role with alter critical s3 permissions configuration.",
                        "resource": instance_arn,
                        "status": "ok",
                        "type": "ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration"
                    })
                    continue
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            actions = {a.lower() for a in actions}
                            
                            if '*:*' in actions or any(action.lower() in actions for action in S3_CONFIG_ACTIONS):
                                has_config_permissions = True
                                break
                    
                    if has_config_permissions:
                        break
                        
                # Check inline policies if no config permissions found yet
                if not has_config_permissions:
                    for policy in role_data['inline_policies']:
                        for statement in policy['PolicyDocument'].get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                actions = {a.lower() for a in actions}
                                
                                if '*:*' in actions or any(action.lower() in actions for action in S3_CONFIG_ACTIONS):
                                    has_config_permissions = True
                                    break
                        
                        if has_config_permissions:
                            break
                
                results.append({
                    "reason": f"{instance_name} has IAM role with alter critical s3 permissions configuration." if has_config_permissions else f"{instance_name} has no IAM role with alter critical s3 permissions configuration.",
                    "resource": instance_arn,
                    "status": "alarm" if has_config_permissions else "ok",
                    "type": "ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration"
                })
                
            except Exception as e:
                print(f"Error checking role {role_name}: {str(e)}")
                continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for critical S3 permissions configuration access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration"
        }]

def check_ec2_instance_no_iam_role_with_destruction_kms_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with KMS destruction access"""
    try:
        results = []
        
        # KMS destruction actions to check
        KMS_DESTRUCTION_ACTIONS = {
            'kms:schedulekeydelete',
            'kms:delete*',
            'kms:disablekey',
            'kms:importkeymateria'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
            # Get instance name from tags
            instance_name = instance['InstanceId']
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
                    
            instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
            
            # Check if instance has IAM role
            iam_profile = instance.get('IamInstanceProfile', {})
            if not iam_profile:
                results.append({
                    "reason": f"{instance_name} has no IAM role with destruction KMS permission.",
                    "resource": instance_arn,
                    "status": "ok",
                    "type": "ec2_instance_no_iam_role_with_destruction_kms_access"
                })
                continue

            role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
            role_name = role_arn.split('/')[-1]
            
            try:
                # Get cached role permissions
                role_data = get_role_permissions(iam_client, role_name)
                has_destruction_permissions = False
                
                if not role_data or not role_data['is_ec2_service']:
                    results.append({
                        "reason": f"{instance_name} has no IAM role with destruction KMS permission.",
                        "resource": instance_arn,
                        "status": "ok",
                        "type": "ec2_instance_no_iam_role_with_destruction_kms_access"
                    })
                    continue
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            actions = {a.lower() for a in actions}
                            
                            if '*:*' in actions or any(action.lower() in actions for action in KMS_DESTRUCTION_ACTIONS):
                                has_destruction_permissions = True
                                break
                    
                    if has_destruction_permissions:
                        break
                        
                # Check inline policies if no destruction permissions found yet
                if not has_destruction_permissions:
                    for policy in role_data['inline_policies']:
                        for statement in policy['PolicyDocument'].get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                actions = {a.lower() for a in actions}
                                
                                if '*:*' in actions or any(action.lower() in actions for action in KMS_DESTRUCTION_ACTIONS):
                                    has_destruction_permissions = True
                                    break
                        
                        if has_destruction_permissions:
                            break
                
                results.append({
                    "reason": f"{instance_name} has IAM role with destruction KMS permission." if has_destruction_permissions else f"{instance_name} has no IAM role with destruction KMS permission.",
                    "resource": instance_arn,
                    "status": "alarm" if has_destruction_permissions else "ok",
                    "type": "ec2_instance_no_iam_role_with_destruction_kms_access"
                })
                
            except Exception as e:
                print(f"Error checking role {role_name}: {str(e)}")
                continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for KMS destruction access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_destruction_kms_access"
        }]

def check_ec2_instance_no_iam_role_with_destruction_rds_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with RDS destruction access"""
    try:
        results = []
        
        # RDS destruction actions to check
        RDS_DESTRUCTION_ACTIONS = {
            'rds:deletedbinstance',
            'rds:deletedbcluster',
            'rds:delete*',
            'rds:stop*'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
            # Get instance name from tags
            instance_name = instance['InstanceId']
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
                    
            instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
            
            # Check if instance has IAM role
            iam_profile = instance.get('IamInstanceProfile', {})
            if not iam_profile:
                results.append({
                    "reason": f"{instance_name} has no IAM role with destruction RDS permission.",
                    "resource": instance_arn,
                    "status": "ok",
                    "type": "ec2_instance_no_iam_role_with_destruction_rds_access"
                })
                continue

            role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
            role_name = role_arn.split('/')[-1]
            
            try:
                # Get cached role permissions
                role_data = get_role_permissions(iam_client, role_name)
                has_destruction_permissions = False
                
                if not role_data or not role_data['is_ec2_service']:
                    results.append({
                        "reason": f"{instance_name} has no IAM role with destruction RDS permission.",
                        "resource": instance_arn,
                        "status": "ok",
                        "type": "ec2_instance_no_iam_role_with_destruction_rds_access"
                    })
                    continue
                
                # Check attached policies
                for policy in role_data['attached_policies']:
                    for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            actions = {a.lower() for a in actions}
                            
                            if '*:*' in actions or any(action.lower() in actions for action in RDS_DESTRUCTION_ACTIONS):
                                has_destruction_permissions = True
                                break
                    
                    if has_destruction_permissions:
                        break
                        
                # Check inline policies if no destruction permissions found yet
                if not has_destruction_permissions:
                    for policy in role_data['inline_policies']:
                        for statement in policy['PolicyDocument'].get('Statement', []):
                            if statement.get('Effect') == 'Allow':
                                actions = statement.get('Action', [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                actions = {a.lower() for a in actions}
                                
                                if '*:*' in actions or any(action.lower() in actions for action in RDS_DESTRUCTION_ACTIONS):
                                    has_destruction_permissions = True
                                    break
                        
                        if has_destruction_permissions:
                            break
                
                results.append({
                    "reason": f"{instance_name} has IAM role with destruction RDS permission." if has_destruction_permissions else f"{instance_name} has no IAM role with destruction RDS permission.",
                    "resource": instance_arn,
                    "status": "alarm" if has_destruction_permissions else "ok",
                    "type": "ec2_instance_no_iam_role_with_destruction_rds_access"
                })
                
            except Exception as e:
                print(f"Error checking role {role_name}: {str(e)}")
                continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for RDS destruction access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_destruction_rds_access"
        }]

def check_ec2_instance_no_iam_role_with_cloud_log_tampering_access(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with cloud log tampering access"""
    try:
        results = []
        
        # Cloud log tampering actions to check
        LOG_TAMPERING_ACTIONS = {
            'cloudtrail:deletetrail',
            'cloudtrail:puteventselectors',
            'cloudtrail:stoplogging',
            'ec2:deleteflowlogs',
            's3:putbucketlogging',
            'logs:deletelogstream',
            'logs:deleteloggroup',
            'waf:deleteloggingconfiguration',
            'waf:putloggingconfiguration'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    # Get instance name from tags
                    instance_name = instance['InstanceId']
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                            
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_name} has no IAM role with cloud log tampering access.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_cloud_log_tampering_access"
                        })
                        continue

                    role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                    role_name = role_arn.split('/')[-1]
                    
                    try:
                        # Get cached role permissions
                        role_data = get_role_permissions(iam_client, role_name)
                        has_tampering_permissions = False
                        
                        if not role_data or not role_data['is_ec2_service']:
                            results.append({
                                "reason": f"{instance_name} has no IAM role with cloud log tampering access.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_cloud_log_tampering_access"
                            })
                            continue
                        
                        # Check attached policies
                        for policy in role_data['attached_policies']:
                            for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    actions = {a.lower() for a in actions}
                                    
                                    if '*:*' in actions or any(action.lower() in actions for action in LOG_TAMPERING_ACTIONS):
                                        has_tampering_permissions = True
                                        break
                            
                            if has_tampering_permissions:
                                break
                                
                        # Check inline policies if no tampering permissions found yet
                        if not has_tampering_permissions:
                            for policy in role_data['inline_policies']:
                                for statement in policy['PolicyDocument'].get('Statement', []):
                                    if statement.get('Effect') == 'Allow':
                                        actions = statement.get('Action', [])
                                        if isinstance(actions, str):
                                            actions = [actions]
                                        actions = {a.lower() for a in actions}
                                        
                                        if '*:*' in actions or any(action.lower() in actions for action in LOG_TAMPERING_ACTIONS):
                                            has_tampering_permissions = True
                                            break
                                
                                if has_tampering_permissions:
                                    break
                        
                        results.append({
                            "reason": f"{instance_name} has IAM role with cloud log tampering access." if has_tampering_permissions else f"{instance_name} has no IAM role with cloud log tampering access.",
                            "resource": instance_arn,
                            "status": "alarm" if has_tampering_permissions else "ok",
                            "type": "ec2_instance_no_iam_role_with_cloud_log_tampering_access"
                        })
                        
                    except iam_client.exceptions.NoSuchEntityException:
                        # If the role doesn't exist, treat it as no permissions
                        results.append({
                            "reason": f"{instance_name} has no IAM role with cloud log tampering access.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_cloud_log_tampering_access"
                        })
                    except Exception as e:
                        print(f"Error checking role {role_name}: {str(e)}")
                        # On other errors, continue with next instance
                        continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for cloud log tampering access: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_cloud_log_tampering_access"
        }]

def check_ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration(ec2_client: boto3.client, iam_client: boto3.client, account_id: str, ec2_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have IAM roles with write permissions on critical S3 configurations"""
    try:
        results = []
        
        # Critical S3 configuration actions to check
        S3_CRITICAL_ACTIONS = {
            's3:putobjectretention',
            's3:putlifecycleconfiguration',
            's3:putbucketpolicy',
            's3:putbucketversioning'
        }
        
        # Use cached EC2 instances
        for instance in ec2_instances:
                    # Get instance name from tags
                    instance_name = instance['InstanceId']
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                            
                    instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance['InstanceId']}"
                    
                    # Check if instance has IAM role
                    iam_profile = instance.get('IamInstanceProfile', {})
                    if not iam_profile:
                        results.append({
                            "reason": f"{instance_name} has no IAM role with write permission on critical s3 configuration.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration"
                        })
                        continue

                    role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
                    role_name = role_arn.split('/')[-1]
                    
                    try:
                        # Get cached role permissions
                        role_data = get_role_permissions(iam_client, role_name)
                        has_critical_permissions = False
                        
                        if not role_data or not role_data['is_ec2_service']:
                            results.append({
                                "reason": f"{instance_name} has no IAM role with write permission on critical s3 configuration.",
                                "resource": instance_arn,
                                "status": "ok",
                                "type": "ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration"
                            })
                            continue
                        
                        # Check attached policies
                        for policy in role_data['attached_policies']:
                            for statement in policy['version']['PolicyVersion']['Document'].get('Statement', []):
                                if statement.get('Effect') == 'Allow':
                                    actions = statement.get('Action', [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    actions = {a.lower() for a in actions}
                                    
                                    if '*:*' in actions or any(action.lower() in actions for action in S3_CRITICAL_ACTIONS):
                                        has_critical_permissions = True
                                        break
                            
                            if has_critical_permissions:
                                break
                                
                        # Check inline policies if no critical permissions found yet
                        if not has_critical_permissions:
                            for policy in role_data['inline_policies']:
                                for statement in policy['PolicyDocument'].get('Statement', []):
                                    if statement.get('Effect') == 'Allow':
                                        actions = statement.get('Action', [])
                                        if isinstance(actions, str):
                                            actions = [actions]
                                        actions = {a.lower() for a in actions}
                                        
                                        if '*:*' in actions or any(action.lower() in actions for action in S3_CRITICAL_ACTIONS):
                                            has_critical_permissions = True
                                            break
                                
                                if has_critical_permissions:
                                    break
                        
                        results.append({
                            "reason": f"{instance_name} has IAM role with write permission on critical s3 configuration." if has_critical_permissions else f"{instance_name} has no IAM role with write permission on critical s3 configuration.",
                            "resource": instance_arn,
                            "status": "alarm" if has_critical_permissions else "ok",
                            "type": "ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration"
                        })
                        
                    except iam_client.exceptions.NoSuchEntityException:
                        # If the role doesn't exist, treat it as no permissions
                        results.append({
                            "reason": f"{instance_name} has no IAM role with write permission on critical s3 configuration.",
                            "resource": instance_arn,
                            "status": "ok",
                            "type": "ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration"
                        })
                    except Exception as e:
                        print(f"Error checking role {role_name}: {str(e)}")
                        # On other errors, continue with next instance
                        continue
        
        return results

    except Exception as e:
        return [{
            "reason": f"Error checking EC2 instance IAM roles for critical S3 configuration write permissions: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration"
        }]

def get_all_ec2_instances(ec2_client: boto3.client) -> List[Dict[str, Any]]:
    """Fetch all EC2 instances once and cache them"""
    instances = []
    paginator = ec2_client.get_paginator('describe_instances')
    for page in paginator.paginate():
        for reservation in page['Reservations']:
            instances.extend(reservation['Instances'])
    return instances

# Cache for IAM role data
role_cache = {}
policy_version_cache = {}
role_policy_cache = {}

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

@app.route('/check-ec2-3')
def check_ec2():
    """Main route to check EC2 security"""
    try:
        # Initialize clients
        ec2_client = get_aws_client('ec2')
        iam_client = get_aws_client('iam')
        sts_client = get_aws_client('sts')
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Get all EC2 instances once
        ec2_instances = get_all_ec2_instances(ec2_client)
        all_results = []
        batch_results = []  # Store results for batch database insert
        
        # Process each instance once and run all checks
        for instance in ec2_instances:
            instance_id = instance['InstanceId']
            instance_name = instance_id
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
                    
            instance_arn = f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:{account_id}:instance/{instance_id}"
            
            # Check if instance has IAM role
            iam_profile = instance.get('IamInstanceProfile', {})
            if not iam_profile:
                # Add "ok" status for all checks when no IAM role is present
                checks = [
                    ("org_write", "organization write"),
                    ("privilege_escalation", "privilege escalation"),
                    ("group_creation", "new group creation with attached policy"),
                    ("role_creation", "new role creation with attached policy"),
                    ("user_creation", "new user creation with attached policy"),
                    ("resource_policies", "write access to resource based policies"),
                    ("credentials_exposure", "credentials exposure"),
                    ("s3_permissions", "alter critical s3 permissions"),
                    ("kms_destruction", "destruction KMS"),
                    ("rds_destruction", "destruction RDS"),
                    ("log_tampering", "cloud log tampering"),
                    ("s3_config", "write permission on critical s3 configuration")
                ]
                
                for check_type, description in checks:
                    result = {
                        "reason": f"{instance_name} has no IAM role with {description} access.",
                        "resource": instance_arn,
                        "status": "ok",
                        "type": f"ec2_instance_no_iam_role_with_{check_type}_access"
                    }
                    all_results.append(result)
                    batch_results.append(result)
                continue
            
            # Get role permissions once for this instance
            role_arn = iam_profile.get('Arn', '').replace(':instance-profile/', ':role/')
            role_name = role_arn.split('/')[-1]
            
            try:
                # Get cached role permissions once
                role_data = get_role_permissions(iam_client, role_name)
                if not role_data or not role_data['is_ec2_service']:
                    continue
                
                # Run all security checks using the cached role data
                checks = [
                    (check_ec2_instance_no_iam_role_with_org_write_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_privilege_escalation_risk_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_write_access_to_resource_based_policies, [instance]),
                    (check_ec2_instance_no_iam_role_attached_with_credentials_exposure_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration, [instance]),
                    (check_ec2_instance_no_iam_role_with_destruction_kms_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_destruction_rds_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_cloud_log_tampering_access, [instance]),
                    (check_ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration, [instance])
                ]
                
                for check_func, instance_list in checks:
                    try:
                        results = check_func(ec2_client, iam_client, account_id, instance_list)
                        if results:
                            all_results.extend(results)
                            batch_results.extend(results)
                    except Exception as e:
                        print(f"Error executing check for instance {instance_id}: {e}")
                        continue
                
            except Exception as e:
                print(f"Error checking role {role_name}: {str(e)}")
                continue
        
        # Batch insert all results into database
        try:
            if batch_results:
                insert_check_results(batch_results)
        except Exception as e:
            print(f"Error inserting results into database: {e}")
        
        # Return results with pretty formatting
        return app.response_class(
            response=json.dumps(all_results, indent=6),
            status=200,
            mimetype='application/json'
        )
        
    except Exception as e:
        error_response = [{
            "reason": f"Error during EC2 security check: {str(e)}",
            "resource": f"arn:aws:ec2:{os.getenv('AWS_REGION', 'us-east-1')}:*/*",
            "status": "error",
            "type": "ec2_instance_no_iam_role_with_org_write_access"
        }]
        return app.response_class(
            response=json.dumps(error_response, indent=6),
            status=500,
            mimetype='application/json'
        )

if __name__ == '__main__':
    app.run(port=5004)


