"""S3 Security Check Module.

This module provides functionality to check AWS S3 buckets for security compliance
using parallel processing and optimized database operations.
"""

import concurrent.futures
import configparser
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
import psycopg2
import psycopg2.extras
from flask import Flask, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Initialize cache for bucket attributes
bucket_cache = {}

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

def get_db_connection() -> psycopg2.extensions.connection:
    """Create and return a PostgreSQL database connection.
    
    Returns:
        psycopg2.extensions.connection: Database connection object
    """
    return psycopg2.connect(
        host=config['PostgreSQL']['HOST'],
        database=config['PostgreSQL']['DATABASE'],
        user=config['PostgreSQL']['USER'],
        password=config['PostgreSQL']['PASSWORD']
    )

def get_cached_bucket_attribute(
    attr_type: str,
    bucket_name: str,
    s3_client: boto3.client,
    method_name: str,
    **kwargs
) -> Dict:
    """Get cached bucket attribute or fetch from S3.
    
    Args:
        attr_type: Type of attribute (e.g., 'encryption', 'logging')
        bucket_name: Name of the S3 bucket
        s3_client: Boto3 S3 client
        method_name: Name of the S3 client method to call
        **kwargs: Additional arguments for the S3 client method
        
    Returns:
        Dict containing the requested bucket attribute
    """
    cache_key = f"{bucket_name}:{attr_type}"
    if cache_key not in bucket_cache:
        method = getattr(s3_client, method_name)
        bucket_cache[cache_key] = method(Bucket=bucket_name, **kwargs)
    return bucket_cache[cache_key]

def batch_insert_results(
    cur: psycopg2.extensions.cursor,
    results: List[Dict]
) -> None:
    """Insert multiple results into the database in a single batch.
    
    Args:
        cur: Database cursor for executing queries
        results: List of check results to insert
    """
    if not results:
        return
        
    values = [(r['reason'], r['resource'], r['status']) for r in results]
    psycopg2.extras.execute_values(
        cur,
        """
        INSERT INTO aws_project_status (description, resource, status)
        VALUES %s
        """,
        values
    )

@app.route('/')
def home():
    return "Server is running!"

def check_bucket_acls(s3_client, bucket_name):
    """Check S3 bucket ACLs"""
    try:
        # Get bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        # Get bucket ownership controls
        try:
            ownership = s3_client.get_bucket_ownership_controls(Bucket=bucket_name)
        except s3_client.exceptions.ClientError:
            ownership = {'Rules': [{'ObjectOwnership': 'None'}]}

        # Get bucket owner ID and check permissions
        bucket_owner = acl['Owner']['ID']
        additional_permissions = []
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            grantee_id = grantee.get('ID')
            if grantee_id and grantee_id != bucket_owner:
                additional_permissions.append(grantee_id)

        # Determine status and reason
        if ownership.get('Rules', [{}])[0].get('ObjectOwnership') == 'BucketOwnerEnforced':
            status = "ok"
            reason = f"{bucket_name} ACLs are disabled."
        elif not additional_permissions:
            status = "ok"
            reason = f"{bucket_name} does not have ACLs for user access."
        else:
            status = "alarm"
            reason = f"{bucket_name} has ACLs for user access."

        return {
            "check_type": "acl",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking ACLs for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_replication(s3_client, bucket_name):
    """Check S3 bucket cross-region replication"""
    try:
        replication = s3_client.get_bucket_replication(Bucket=bucket_name)
        rep_rules = replication.get('ReplicationConfiguration', {}).get('Rules', [])
        
        has_enabled_rule = any(rule.get('Status') == 'Enabled' for rule in rep_rules)
        
        status = "ok" if has_enabled_rule else "alarm"
        reason = (f"{bucket_name} enabled with cross-region replication." 
                if has_enabled_rule 
                else f"{bucket_name} not enabled with cross-region replication.")
        
    except s3_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ReplicationConfigurationNotFoundError':
            status = "alarm"
            reason = f"{bucket_name} not enabled with cross-region replication."
        else:
            raise e

    return {
        "check_type": "replication",
        "resource": f"arn:aws:s3:::{bucket_name}",
        "status": status,
        "reason": reason
    }

def check_access_points(s3control_client, account_id):
    """Check S3 access points"""
    results = []
    try:
        access_points = s3control_client.list_access_points(AccountId=account_id)
        
        for access_point in access_points.get('AccessPointList', []):
            try:
                name = access_point['Name']
                access_point_arn = access_point['AccessPointArn']
                
                public_access_block = s3control_client.get_access_point_policy_status(
                    AccountId=account_id,
                    Name=name
                )
                
                block_public_acls = public_access_block.get('PolicyStatus', {}).get('BlockPublicAcls', False)
                block_public_policy = public_access_block.get('PolicyStatus', {}).get('BlockPublicPolicy', False)
                ignore_public_acls = public_access_block.get('PolicyStatus', {}).get('IgnorePublicAcls', False)
                restrict_public_buckets = public_access_block.get('PolicyStatus', {}).get('RestrictPublicBuckets', False)
                
                if (block_public_acls and block_public_policy and 
                    ignore_public_acls and restrict_public_buckets):
                    status = "ok"
                    reason = f"{name} all public access blocks enabled."
                else:
                    status = "alarm"
                    disabled_blocks = []
                    if not block_public_acls:
                        disabled_blocks.append('block_public_acls')
                    if not block_public_policy:
                        disabled_blocks.append('block_public_policy')
                    if not ignore_public_acls:
                        disabled_blocks.append('ignore_public_acls')
                    if not restrict_public_buckets:
                        disabled_blocks.append('restrict_public_buckets')
                    
                    reason = f"{name} not enabled for: {', '.join(disabled_blocks)}."
                
                results.append({
                    "check_type": "access_point",
                    "resource": access_point_arn,
                    "status": status,
                    "reason": reason
                })
                
            except Exception as e:
                print(f"Error processing access point {name}: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Error listing access points: {str(e)}")
    
    return results

def check_bucket_encryption(s3_client, bucket_name):
    """Check S3 bucket default encryption"""
    try:
        # Get bucket encryption configuration
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            # If we get here, encryption is enabled
            status = "ok"
            reason = f"{bucket_name} default encryption enabled."
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                status = "alarm"
                reason = f"{bucket_name} default encryption disabled."
            else:
                raise e

        return {
            "check_type": "encryption",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_kms_encryption(s3_client, bucket_name):
    """Check S3 bucket default encryption with KMS"""
    try:
        try:
            encryption = get_cached_bucket_attribute(
                'encryption',
                bucket_name,
                s3_client,
                'get_bucket_encryption'
            )
            
            # Check if KMS is configured in any rule
            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            has_kms = False
            
            for rule in rules:
                default_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                if default_encryption.get('KMSMasterKeyID') is not None:
                    has_kms = True
                    break
            
            if has_kms:
                status = "ok"
                reason = f"{bucket_name} default encryption with KMS enabled."
            else:
                status = "alarm"
                reason = f"{bucket_name} default encryption with KMS disabled."
                
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                status = "alarm"
                reason = f"{bucket_name} default encryption with KMS disabled."
            else:
                raise e

        return {
            "check_type": "kms_encryption",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking KMS encryption for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_ssl_enforcement(s3_client, bucket_name):
    """Check if S3 bucket enforces SSL/HTTPS through bucket policy"""
    try:
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy['Policy'])
            
            # Check for SSL enforcement in policy
            has_ssl_enforcement = False
            
            for statement in policy_json.get('Statement', []):
                # Check if statement denies non-SSL access
                if (statement.get('Effect') == 'Deny' and 
                    statement.get('Principal', {}).get('AWS') == '*' and
                    'Condition' in statement and
                    'Bool' in statement['Condition'] and
                    'aws:securetransport' in statement['Condition']['Bool'] and
                    statement['Condition']['Bool']['aws:securetransport'] == False):
                    has_ssl_enforcement = True
                    break
            
            if has_ssl_enforcement:
                status = "ok"
                reason = f"{bucket_name} bucket policy enforces HTTPS."
            else:
                status = "alarm"
                reason = f"{bucket_name} bucket policy does not enforce HTTPS."
                
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                status = "alarm"
                reason = f"{bucket_name} bucket policy does not enforce HTTPS."
            else:
                raise e

        return {
            "check_type": "ssl_enforcement",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking SSL enforcement for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_event_notifications(s3_client, bucket_name):
    """Check if S3 bucket has event notifications enabled"""
    try:
        # Get bucket notification configuration
        notification = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        
        # Check for any type of notification configuration
        has_notifications = any([
            notification.get('EventBridgeConfiguration'),
            notification.get('LambdaFunctionConfigurations'),
            notification.get('QueueConfigurations'),
            notification.get('TopicConfigurations')
        ])
        
        if has_notifications:
            status = "ok"
            reason = f"{bucket_name} event notifications enabled."
        else:
            status = "alarm"
            reason = f"{bucket_name} event notifications disabled."

        return {
            "check_type": "event_notifications",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking event notifications for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_lifecycle_policy(s3_client, bucket_name):
    """Check if S3 bucket has lifecycle policies enabled"""
    try:
        try:
            # Get bucket lifecycle configuration
            lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            
            # Check for enabled rules
            has_enabled_rule = False
            for rule in lifecycle.get('Rules', []):
                if rule.get('Status') == 'Enabled':
                    has_enabled_rule = True
                    break
            
            if has_enabled_rule:
                status = "ok"
                reason = f"{bucket_name} lifecycle policy or rules configured."
            else:
                status = "alarm"
                reason = f"{bucket_name} lifecycle policy or rules not configured."
                
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
                status = "alarm"
                reason = f"{bucket_name} lifecycle policy or rules not configured."
            else:
                raise e

        return {
            "check_type": "lifecycle_policy",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking lifecycle policy for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_logging(s3_client, bucket_name):
    """Check if S3 bucket has logging enabled"""
    try:
        # Get bucket logging configuration
        logging = s3_client.get_bucket_logging(Bucket=bucket_name)
        
        # Check if logging is enabled (LoggingEnabled will exist if logging is configured)
        if logging.get('LoggingEnabled'):
            status = "ok"
            reason = f"{bucket_name} logging enabled."
        else:
            status = "alarm"
            reason = f"{bucket_name} logging disabled."

        return {
            "check_type": "logging",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking logging for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_mfa_delete(s3_client, bucket_name):
    """Check if S3 bucket has MFA Delete enabled"""
    try:
        # Get bucket versioning configuration
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        
        # Check if MFA Delete is enabled
        mfa_delete = versioning.get('MFADelete') == 'Enabled'
        
        if mfa_delete:
            status = "ok"
            reason = f"{bucket_name} MFA delete enabled."
        else:
            status = "alarm"
            reason = f"{bucket_name} MFA delete disabled."

        return {
            "check_type": "mfa_delete",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking MFA delete for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_authenticated_access(s3_client, bucket_name):
    """Check if S3 bucket is accessible to all authenticated users"""
    try:
        # Get bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        # Check for authenticated users access
        has_authenticated_access = False
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                has_authenticated_access = True
                break
        
        if not has_authenticated_access:
            status = "ok"
            reason = f"{bucket_name} not accessible to all authenticated user."
        else:
            status = "alarm"
            reason = f"{bucket_name} accessible to all authenticated user."

        return {
            "check_type": "authenticated_access",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking authenticated access for bucket {bucket_name}: {str(e)}")
        return None

def check_bucket_object_lock(s3_client, bucket_name):
    """Check if S3 bucket has object lock enabled"""
    try:
        # Get bucket object lock configuration
        try:
            object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
            # If we get here, object lock is configured
            status = "ok"
            reason = f"{bucket_name} object lock enabled."
        except s3_client.exceptions.ClientError as e:
            if e.response['Error']['Code'] in ['ObjectLockConfigurationNotFoundError', 'NoSuchObjectLockConfiguration']:
                status = "alarm"
                reason = f"{bucket_name} object lock not enabled."
            else:
                raise e

        return {
            "check_type": "object_lock",
            "resource": f"arn:aws:s3:::{bucket_name}",
            "status": status,
            "reason": reason
        }
    except Exception as e:
        print(f"Error checking object lock for bucket {bucket_name}: {str(e)}")
        return None

def process_bucket(
    bucket_name: str,
    s3_client: boto3.client,
    account_id: str
) -> List[Dict[str, Any]]:
    """Process all security checks for a single bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        s3_client: Boto3 S3 client
        account_id: AWS account ID
        
    Returns:
        List[Dict[str, Any]]: List of check results
    """
    bucket_results = []
    check_start = datetime.now()
    
    try:
        # Run all checks for the bucket
        check_functions = [
            check_bucket_acls,
            check_bucket_replication,
            check_bucket_encryption,
            check_bucket_kms_encryption,
            check_bucket_ssl_enforcement,
            check_bucket_event_notifications,
            check_bucket_lifecycle_policy,
            check_bucket_logging,
            check_bucket_mfa_delete,
            check_bucket_authenticated_access,
            check_bucket_object_lock
        ]
        
        for check_func in check_functions:
            try:
                result = check_func(s3_client, bucket_name)
                if result:
                    bucket_results.append(result)
            except Exception as e:
                logging.error(
                    f"Error running {check_func.__name__} for bucket {bucket_name}: {str(e)}"
                )
        
        check_duration = (datetime.now() - check_start).total_seconds()
        logging.info(
            f"Completed checks for bucket {bucket_name} in {check_duration:.2f}s"
        )
        
    except Exception as e:
        logging.error(f"Error processing bucket {bucket_name}: {str(e)}")
    
    return bucket_results

@app.route('/check-s3')
@app.route('/check-s3/<bucket_names>')
def check_s3(bucket_names: Optional[str] = None):
    """Main endpoint for checking S3 bucket security configurations.
    
    Performs security checks on all S3 buckets in parallel, including ACLs,
    replication, encryption, SSL enforcement, event notifications, lifecycle
    policies, logging, MFA delete, authenticated access, and object lock.
    
    Args:
        bucket_names: Optional comma-separated list of bucket names to check
        
    Returns:
        JSON response containing check results and summary statistics
    """
    try:
        start_time = datetime.now()
        logging.info("Starting S3 security check process...")
        
        # Initialize AWS clients
        session = boto3.Session(
            aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY'],
            region_name=config['AWS']['AWS_REGION']
        )
        
        s3_client = session.client('s3')
        s3control_client = session.client('s3control')
        
        # Get AWS account ID
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Use provided bucket names or try to list buckets
            if bucket_names:
                buckets = [{'Name': name.strip()} for name in bucket_names.split(',')]
            else:
                try:
                    buckets = s3_client.list_buckets()['Buckets']
                except Exception as e:
                    logging.error(f"Error listing buckets: {str(e)}")
                    buckets = []
            
            logging.info(f"Processing {len(buckets)} buckets in parallel...")
            
            # Process buckets in parallel using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_bucket = {
                    executor.submit(
                        process_bucket,
                        bucket['Name'],
                        s3_client,
                        account_id
                    ): bucket['Name']
                    for bucket in buckets
                }
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_bucket):
                    bucket_name = future_to_bucket[future]
                    try:
                        bucket_results = future.result()
                        if bucket_results:
                            # Batch insert results for this bucket
                            batch_insert_results(cur, bucket_results)
                            all_results.extend(bucket_results)
                    except Exception as e:
                        logging.error(
                            f"Error processing bucket {bucket_name}: {str(e)}"
                        )

            # Check access points in parallel
            access_point_results = check_access_points(s3control_client, account_id)
            if access_point_results:
                batch_insert_results(cur, access_point_results)
                all_results.extend(access_point_results)

            conn.commit()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            logging.info(
                f"Completed S3 security check in {duration:.2f} seconds"
            )
            
            return jsonify({
                "status": "success",
                "data": all_results,
                "summary": {
                    "total_checks": len(all_results),
                    "duration_seconds": duration,
                    "buckets_checked": len(buckets),
                    "checks_per_bucket": 11,
                    "ok": len([r for r in all_results if r['status'] == 'ok']),
                    "alarm": len([r for r in all_results if r['status'] == 'alarm']),
                    "error": len([r for r in all_results if r['status'] == 'error'])
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting server on port 5001...")
    app.run(debug=True, port=5001)
