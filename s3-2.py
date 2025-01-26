import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from datetime import datetime
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Database connection function
def get_db_connection():
    return psycopg2.connect(
        host=config['PostgreSQL']['HOST'],
        database=config['PostgreSQL']['DATABASE'],
        user=config['PostgreSQL']['USER'],
        password=config['PostgreSQL']['PASSWORD']
    )

def check_bucket_public_access(s3_client, bucket_name):
    """Check if S3 bucket allows public access through bucket policy"""
    try:
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            
            is_public = False
            for statement in policy_json.get('Statement', []):
                principal = statement.get('Principal', {})
                if (isinstance(principal, dict) and principal.get('AWS') == '*' and 
                    statement.get('Effect') == 'Allow'):
                    is_public = True
                    break
                elif (isinstance(principal, str) and principal == '*' and 
                      statement.get('Effect') == 'Allow'):
                    is_public = True
                    break
            
            if is_public:
                status = "alarm"
                reason = f"{bucket_name} publicly accessible."
            else:
                status = "ok"
                reason = f"{bucket_name} not publicly accessible."
                
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                status = "info"
                reason = f"{bucket_name} does not have defined policy or insufficient access to the policy."
            else:
                raise e

        return {
            "type": "public_access",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking public access for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_cross_account_access(s3_client, bucket_name, account_id):
    """Check if S3 bucket allows cross-account access for sensitive actions"""
    sensitive_actions = {
        's3:deletebucketpolicy',
        's3:putbucketacl',
        's3:putbucketpolicy',
        's3:putencryptionconfiguration',
        's3:putobjectacl'
    }

    try:
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            
            has_cross_account_access = False
            for statement in policy_json.get('Statement', []):
                if statement.get('Effect') != 'Allow':
                    continue

                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if not any(action.lower() in sensitive_actions for action in actions):
                    continue

                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    aws_principal = principal.get('AWS', [])
                    if isinstance(aws_principal, str):
                        aws_principal = [aws_principal]
                    
                    for p in aws_principal:
                        if p == '*':
                            has_cross_account_access = True
                            break
                        elif isinstance(p, str) and ':' in p:
                            principal_account = p.split(':')[4]
                            if principal_account != account_id:
                                has_cross_account_access = True
                                break
                
                if has_cross_account_access:
                    break

            if has_cross_account_access:
                status = "alarm"
                reason = f"{bucket_name} allows cross-account bucket access."
            else:
                status = "ok"
                reason = f"{bucket_name} restricts cross-account bucket access."
                
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                status = "ok"
                reason = f"{bucket_name} restricts cross-account bucket access."
            else:
                raise e

        return {
            "type": "cross_account_access",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking cross-account access for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_object_logging(s3_client, cloudtrail_client, bucket_name, bucket_region, buckets_with_logging, regions_with_logging):
    """Check if S3 bucket has object logging enabled through CloudTrail"""
    try:
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        has_logging = (
            bucket_arn in buckets_with_logging or 
            bucket_region in regions_with_logging
        )
        
        status = "ok" if has_logging else "alarm"
        reason = f"{bucket_name} object logging {'enabled' if has_logging else 'not enabled'}."

        return {
            "type": "object_logging",
            "resource": bucket_arn,
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking object logging for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_public_read_access(s3_client, bucket_name):
    """Check if S3 bucket allows public read access through ACLs or bucket policy"""
    try:
        # Check ACLs
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_acl_access = False
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check for public access through ACLs
                if (grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ] and permission in ['FULL_CONTROL', 'READ_ACP', 'READ']):
                    public_acl_access = True
                    break
                    
            # Get bucket public access block configuration
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                block_public_acls = public_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls']
                block_public_policy = public_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy']
            except s3_client.exceptions.ClientError:
                block_public_acls = False
                block_public_policy = False

            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy['Policy'])
                public_policy_access = False
                
                for statement in policy_json.get('Statement', []):
                    if statement.get('Effect') != 'Allow':
                        continue

                    # Check Principal
                    principal = statement.get('Principal', {})
                    if (isinstance(principal, dict) and principal.get('AWS') == '*') or principal == '*':
                        # Check Actions
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                            
                        for action in actions:
                            if (action in ['*', '*:*', 's3:*'] or 
                                action.lower().startswith('s3:get') or 
                                action.lower().startswith('s3:list')):
                                public_policy_access = True
                                break
                    
                    if public_policy_access:
                        break
                        
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    public_policy_access = False
                else:
                    raise e

            # Determine overall status
            if ((block_public_acls or not public_acl_access) and not public_policy_access):
                status = "ok"
                reason = f"{bucket_name} not publicly readable."
            elif ((block_public_acls or not public_acl_access) and 
                  (public_policy_access and block_public_policy)):
                status = "ok"
                reason = f"{bucket_name} not publicly readable."
            elif ((block_public_acls or not public_acl_access) and 
                  (public_policy_access and not public_policy_access)):
                status = "ok"
                reason = f"{bucket_name} not publicly readable."
            else:
                status = "alarm"
                reason = f"{bucket_name} publicly readable."

        except Exception as e:
            print(f"Error checking ACLs and policies for {bucket_name}: {str(e)}")
            status = "error"
            reason = f"Error checking public read access for {bucket_name}"

        return {
            "type": "public_read_access",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking public read access for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_public_write_access(s3_client, bucket_name):
    """Check if S3 bucket allows public write access through ACLs or bucket policy"""
    try:
        # Check ACLs
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_acl_access = False
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check for public write access through ACLs
                if (grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ] and permission in ['FULL_CONTROL', 'WRITE_ACP', 'WRITE']):
                    public_acl_access = True
                    break
                    
            # Get bucket public access block configuration
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                block_public_acls = public_access_block['PublicAccessBlockConfiguration']['BlockPublicAcls']
                block_public_policy = public_access_block['PublicAccessBlockConfiguration']['BlockPublicPolicy']
            except s3_client.exceptions.ClientError:
                block_public_acls = False
                block_public_policy = False

            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy['Policy'])
                public_policy_access = False
                
                for statement in policy_json.get('Statement', []):
                    if statement.get('Effect') != 'Allow':
                        continue

                    # Check Principal
                    principal = statement.get('Principal', {})
                    if (isinstance(principal, dict) and principal.get('AWS') == '*') or principal == '*':
                        # Check Actions
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                            
                        for action in actions:
                            if (action in ['*', '*:*', 's3:*'] or 
                                action.lower().startswith('s3:put') or 
                                action.lower().startswith('s3:delete') or
                                action.lower().startswith('s3:create') or
                                action.lower().startswith('s3:update') or
                                action.lower().startswith('s3:replicate') or
                                action.lower().startswith('s3:restore')):
                                public_policy_access = True
                                break
                    
                    if public_policy_access:
                        break
                        
            except s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    public_policy_access = False
                else:
                    raise e

            # Determine overall status
            if ((block_public_acls or not public_acl_access) and not public_policy_access):
                status = "ok"
                reason = f"{bucket_name} not publicly writable."
            elif ((block_public_acls or not public_acl_access) and 
                  (public_policy_access and block_public_policy)):
                status = "ok"
                reason = f"{bucket_name} not publicly writable."
            elif ((block_public_acls or not public_acl_access) and 
                  (public_policy_access and not public_policy_access)):
                status = "ok"
                reason = f"{bucket_name} not publicly writable."
            else:
                status = "alarm"
                reason = f"{bucket_name} publicly writable."

        except Exception as e:
            print(f"Error checking ACLs and policies for {bucket_name}: {str(e)}")
            status = "error"
            reason = f"Error checking public write access for {bucket_name}"

        return {
            "type": "public_write_access",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking public write access for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_website_hosting(s3_client, bucket_name):
    """Check if S3 bucket has static website hosting enabled"""
    try:
        try:
            website = s3_client.get_bucket_website(Bucket=bucket_name)
            # If we get here, website hosting is enabled
            status = "alarm"
            reason = f"{bucket_name} static website hosting enabled."
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
                status = "ok"
                reason = f"{bucket_name} static website hosting disabled."
            else:
                raise e

        return {
            "type": "website_hosting",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking website hosting for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_versioning_and_lifecycle(s3_client, bucket_name):
    """Check if S3 bucket has versioning enabled and lifecycle policy configured"""
    try:
        # Check versioning status
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_enabled = versioning.get('Status') == 'Enabled'
        except s3_client.exceptions.ClientError:
            versioning_enabled = False

        # Check lifecycle rules
        try:
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            has_enabled_rules = any(
                rule.get('Status') == 'Enabled'
                for rule in lifecycle.get('Rules', [])
            )
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['NoSuchLifecycleConfiguration', 'NoSuchConfiguration']:
                has_enabled_rules = False
            else:
                raise e

        # Determine status
        if not versioning_enabled:
            status = "alarm"
            reason = f"{bucket_name} versioning disabled."
        elif versioning_enabled and has_enabled_rules:
            status = "ok"
            reason = f"{bucket_name} lifecycle policy configured."
        else:
            status = "alarm"
            reason = f"{bucket_name} lifecycle policy not configured."

        return {
            "type": "versioning_and_lifecycle",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking versioning and lifecycle for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_versioning(s3_client, bucket_name):
    """Check if S3 bucket has versioning enabled"""
    try:
        # Check versioning status
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_enabled = versioning.get('Status') == 'Enabled'
            
            if versioning_enabled:
                status = "ok"
                reason = f"{bucket_name} versioning enabled."
            else:
                status = "alarm"
                reason = f"{bucket_name} versioning disabled."

        except s3_client.exceptions.ClientError as e:
            print(f"Error checking versioning for {bucket_name}: {str(e)}")
            status = "alarm"
            reason = f"{bucket_name} versioning disabled."

        return {
            "type": "versioning",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking versioning for bucket {bucket_name}: {str(e)}")
        return None

def check_account_public_access_block(s3control_client, account_id):
    """Check if account-level S3 public access block is properly configured"""
    try:
        try:
            response = s3control_client.get_public_access_block(
                AccountId=account_id
            )
            config = response['PublicAccessBlockConfiguration']
            
            # Check all required settings
            required_settings = {
                'BlockPublicAcls': 'block_public_acls',
                'BlockPublicPolicy': 'block_public_policy',
                'IgnorePublicAcls': 'ignore_public_acls',
                'RestrictPublicBuckets': 'restrict_public_buckets'
            }
            
            disabled_settings = [
                setting_name
                for aws_name, setting_name in required_settings.items()
                if not config.get(aws_name, False)
            ]
            
            if not disabled_settings:
                status = "ok"
                reason = "Account level public access blocks enabled."
            else:
                status = "alarm"
                reason = f"Account level public access blocks not enabled for: {', '.join(disabled_settings)}."

        except s3control_client.exceptions.ClientError as e:
            print(f"Error checking account public access block: {str(e)}")
            status = "alarm"
            reason = "Unable to verify account level public access blocks."

        return {
            "type": "account_public_access_block",
            "resource": f"arn:aws:::{account_id}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking account public access block: {str(e)}")
        return None

def check_bucket_account_public_access_block(s3_client, bucket_name, account_id, account_public_access_config):
    """Check if S3 bucket and account have public access blocks properly configured"""
    try:
        # Use cached account-level settings
        account_config = account_public_access_config or {
            'BlockPublicAcls': False,
            'BlockPublicPolicy': False,
            'IgnorePublicAcls': False,
            'RestrictPublicBuckets': False
        }

        # Get bucket-level settings
        try:
            bucket_response = s3_client.get_public_access_block(Bucket=bucket_name)
            bucket_config = bucket_response['PublicAccessBlockConfiguration']
        except s3_client.exceptions.ClientError:
            bucket_config = {
                'BlockPublicAcls': False,
                'BlockPublicPolicy': False,
                'IgnorePublicAcls': False,
                'RestrictPublicBuckets': False
            }

        # Check combined settings
        settings_to_check = {
            'BlockPublicAcls': 'block_public_acls',
            'BlockPublicPolicy': 'block_public_policy',
            'IgnorePublicAcls': 'ignore_public_acls',
            'RestrictPublicBuckets': 'restrict_public_buckets'
        }

        disabled_settings = [
            setting_name
            for aws_name, setting_name in settings_to_check.items()
            if not (bucket_config.get(aws_name, False) or account_config.get(aws_name, False))
        ]

        if not disabled_settings:
            status = "ok"
            reason = f"{bucket_name} all public access blocks enabled."
        else:
            status = "alarm"
            reason = f"{bucket_name} not enabled for: {', '.join(disabled_settings)}."

        return {
            "type": "bucket_account_public_access_block",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking bucket and account public access block for {bucket_name}: {str(e)}")
        return None

def check_bucket_public_access_block(s3_client, bucket_name):
    """Check if S3 bucket has all public access blocks enabled"""
    try:
        try:
            response = s3_client.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            
            # Check all required settings
            required_settings = {
                'BlockPublicAcls': 'block_public_acls',
                'BlockPublicPolicy': 'block_public_policy',
                'IgnorePublicAcls': 'ignore_public_acls',
                'RestrictPublicBuckets': 'restrict_public_buckets'
            }
            
            disabled_settings = [
                setting_name
                for aws_name, setting_name in required_settings.items()
                if not config.get(aws_name, False)
            ]
            
            if not disabled_settings:
                status = "ok"
                reason = f"{bucket_name} all public access blocks enabled."
            else:
                status = "alarm"
                reason = f"{bucket_name} not enabled for: {', '.join(disabled_settings)}."

        except s3_client.exceptions.ClientError as e:
            print(f"Error checking bucket public access block for {bucket_name}: {str(e)}")
            status = "alarm"
            reason = f"{bucket_name} not enabled for: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets."

        return {
            "type": "bucket_public_access_block",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking bucket public access block for {bucket_name}: {str(e)}")
        return None

def check_one_bucket(bucket, s3_client, cloudtrail_client, account_id, buckets_with_logging, regions_with_logging, account_public_access_config):
    """Helper function to check a single bucket with all security checks"""
    bucket_name = bucket['Name']
    
    try:
        bucket_location = s3_client.get_bucket_location(Bucket=bucket_name)
        bucket_region = bucket_location['LocationConstraint'] or 'us-east-1'
    except Exception as e:
        print(f"Error getting location for bucket {bucket_name}: {str(e)}")
        bucket_region = config['AWS']['AWS_REGION']

    # Run each check
    results = []
    checks = [
        (check_bucket_public_access, [s3_client, bucket_name]),
        (check_bucket_cross_account_access, [s3_client, bucket_name, account_id]),
        (check_bucket_object_logging, [s3_client, cloudtrail_client, bucket_name, bucket_region, buckets_with_logging, regions_with_logging]),
        (check_bucket_public_read_access, [s3_client, bucket_name]),
        (check_bucket_public_write_access, [s3_client, bucket_name]),
        (check_bucket_website_hosting, [s3_client, bucket_name]),
        (check_bucket_versioning_and_lifecycle, [s3_client, bucket_name]),
        (check_bucket_versioning, [s3_client, bucket_name]),
        (check_bucket_public_access_block, [s3_client, bucket_name]),
        (check_bucket_account_public_access_block, [s3_client, bucket_name, account_id, account_public_access_config])
    ]
    
    for check_func, args in checks:
        result = check_func(*args)
        if result:
            results.append(result)
    
    return results, bucket_name, bucket_region

@app.route('/check-s3-2')
def check_s3():
    try:
        # Initialize AWS clients
        session = boto3.Session(
            aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY'],
            region_name=config['AWS']['AWS_REGION']
        )
        
        s3_client = session.client('s3')
        cloudtrail_client = session.client('cloudtrail')
        s3control_client = session.client('s3control')
        
        # Get AWS account ID
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        all_results = []

        # Cache account-level public access block configuration
        try:
            response = s3control_client.get_public_access_block(AccountId=account_id)
            account_public_access_config = response['PublicAccessBlockConfiguration']
        except s3control_client.exceptions.ClientError:
            account_public_access_config = {
                'BlockPublicAcls': False,
                'BlockPublicPolicy': False,
                'IgnorePublicAcls': False,
                'RestrictPublicBuckets': False
            }

        # Get CloudTrail logging configuration
        trails = cloudtrail_client.list_trails()
        buckets_with_logging = set()
        regions_with_logging = set()

        # Check each trail for S3 object logging
        for trail in trails['Trails']:
            trail_arn = trail['TrailARN']
            trail_info = cloudtrail_client.get_trail(Name=trail_arn)
            trail_region = trail_info['Trail']['HomeRegion']
            
            # Check event selectors
            event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
            
            # Check standard event selectors
            for selector in event_selectors.get('EventSelectors', []):
                for data_resource in selector.get('DataResources', []):
                    if data_resource.get('Type') == 'AWS::S3::Object':
                        for value in data_resource.get('Values', []):
                            if value.endswith('/'):
                                value = value[:-1]
                            if value == 'arn:aws:s3':
                                regions_with_logging.add(trail_region)
                            else:
                                buckets_with_logging.add(value)

            # Check advanced event selectors
            advanced_selectors = event_selectors.get('AdvancedEventSelectors', [])
            for selector in advanced_selectors:
                for field_selector in selector.get('FieldSelectors', []):
                    if (field_selector.get('Field') != 'eventCategory' and 
                        'AWS::S3::Object' in field_selector.get('Equals', [])):
                        regions_with_logging.add(trail_region)

        # Get account-level public access block configuration once
        account_public_access_config = None
        account_public_access_result = check_account_public_access_block(s3control_client, account_id)
        if account_public_access_result:
            formatted_result = {
                "type": account_public_access_result['type'],
                "resource_id": account_public_access_result['resource'],
                "status": account_public_access_result['status'].upper(),
                "message": account_public_access_result['reason'],
                "timestamp": datetime.utcnow().isoformat(),
                "region": "global",
                "account": account_id
            }
            all_results.append(formatted_result)
            try:
                response = s3control_client.get_public_access_block(AccountId=account_id)
                account_public_access_config = response['PublicAccessBlockConfiguration']
            except s3control_client.exceptions.ClientError:
                account_public_access_config = {
                    'BlockPublicAcls': False,
                    'BlockPublicPolicy': False,
                    'IgnorePublicAcls': False,
                    'RestrictPublicBuckets': False
                }

        # Check all buckets using ThreadPoolExecutor
        buckets = s3_client.list_buckets()['Buckets']
        formatted_results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_bucket = {
                executor.submit(
                    check_one_bucket, 
                    bucket,
                    s3_client,
                    cloudtrail_client,
                    account_id,
                    buckets_with_logging,
                    regions_with_logging,
                    account_public_access_config
                ): bucket for bucket in buckets
            }
            
            for future in as_completed(future_to_bucket):
                results, bucket_name, bucket_region = future.result()
                for result in results:
                    formatted_result = {
                        "type": result['type'],
                        "resource_id": result['resource'],
                        "status": result['status'].upper(),
                        "message": result['reason'],
                        "timestamp": datetime.utcnow().isoformat(),
                        "region": bucket_region,
                        "account": account_id
                    }
                    formatted_results.append(formatted_result)

        # Batch insert all results into database
        conn = get_db_connection()
        cur = conn.cursor()
        
        insert_data = []
        for result in all_results + formatted_results:
            insert_data.append((
                result['message'],
                result['resource_id'],
                result['status'].lower()
            ))
        
        if insert_data:
            cur.executemany(
                """
                INSERT INTO aws_project_status (description, resource, status)
                VALUES (%s, %s, %s)
                """,
                insert_data
            )
            
        conn.commit()
        cur.close()
        conn.close()

        # Return results with metadata
        response = {
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "region": config['AWS']['AWS_REGION'],
                "account": account_id
            },
            "results": all_results + formatted_results
        }

        return jsonify(response)

    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

if __name__ == '__main__':
    print("Starting server on port 5001...")
    app.run(debug=True, port=5001)
