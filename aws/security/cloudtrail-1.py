import boto3
from flask import Flask, jsonify
import configparser
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone
import json
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

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

def check_cloudtrail_bucket_public_access(s3_client, cloudtrail_client, account_id):
    """Check if CloudTrail buckets are publicly accessible"""
    try:
        # Get all CloudTrail trails
        trails = cloudtrail_client.describe_trails()['trailList']
        results = []

        for trail in trails:
            bucket_name = trail.get('S3BucketName')
            if not bucket_name:
                continue

            try:
                # Check bucket ACL
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                all_users_grants = 0
                auth_users_grants = 0

                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri:
                        all_users_grants += 1
                    elif 'AuthenticatedUsers' in uri:
                        auth_users_grants += 1

                # Check bucket policy
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_json = json.loads(policy['Policy'])
                    anon_statements = 0

                    for statement in policy_json.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            principal = statement.get('Principal', {})
                            if isinstance(principal, dict):
                                aws_principal = principal.get('AWS', [])
                                if isinstance(aws_principal, list):
                                    if '*' in aws_principal:
                                        anon_statements += 1
                                elif aws_principal == '*':
                                    anon_statements += 1
                            elif principal == '*':
                                anon_statements += 1
                except s3_client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        anon_statements = 0
                    else:
                        raise e

                # Determine status and reason
                if all_users_grants > 0:
                    status = "alarm"
                    reason = f"{bucket_name} grants access to AllUsers in ACL."
                elif auth_users_grants > 0:
                    status = "alarm"
                    reason = f"{bucket_name} grants access to AuthenticatedUsers in ACL."
                elif anon_statements > 0:
                    status = "alarm"
                    reason = f"{bucket_name} grants access to AWS:* in bucket policy."
                else:
                    status = "ok"
                    reason = f"{bucket_name} does not grant anonymous access in ACL or bucket policy."

            except s3_client.exceptions.NoSuchBucket:
                status = "skip"
                reason = f"{bucket_name} not found in account {account_id}."

            results.append({
                "type": "cloudtrail_bucket_public",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "status": status,
                "reason": reason,
                "region": trail.get('HomeRegion', 'unknown'),
                "trail_name": trail.get('Name', 'unknown')
            })

        return results

    except Exception as e:
        print(f"Error checking CloudTrail bucket public access: {str(e)}")
        return []

def check_cloudtrail_multi_region_read_write(cloudtrail_client, account_id):
    """Check if CloudTrail has multi-region read/write logging enabled"""
    try:
        # Get all CloudTrail trails
        trails = cloudtrail_client.describe_trails()['trailList']
        
        # Check if any trail meets the requirements
        multi_region_read_write_enabled = False
        
        for trail in trails:
            # Skip if trail is not multi-region or not logging
            if not (trail.get('IsMultiRegionTrail') and 
                   cloudtrail_client.get_trail_status(Name=trail['TrailARN'])['IsLogging']):
                continue

            # Check event selectors
            event_selectors = cloudtrail_client.get_event_selectors(TrailName=trail['TrailARN'])
            
            # Check standard event selectors
            for selector in event_selectors.get('EventSelectors', []):
                if selector.get('ReadWriteType') == 'All':
                    multi_region_read_write_enabled = True
                    break
            
            # Check advanced event selectors
            advanced_selectors = event_selectors.get('AdvancedEventSelectors', [])
            if advanced_selectors:
                read_only_found = False
                for selector in advanced_selectors:
                    for field in selector.get('FieldSelectors', []):
                        if (field.get('Field') == 'readOnly' and 
                            field.get('Equals', []) == ['true']):
                            read_only_found = True
                            break
                if not read_only_found:
                    multi_region_read_write_enabled = True
            
            if multi_region_read_write_enabled:
                break

        # Determine status and reason
        if multi_region_read_write_enabled:
            status = "ok"
            reason = "CloudTrail enabled."
        else:
            status = "alarm"
            reason = "CloudTrail disabled."

        return {
            "type": "cloudtrail_multi_region",
            "resource": f"arn:aws:::{account_id}",
            "status": status,
            "reason": reason,
            "region": "global",
            "account": account_id
        }

    except Exception as e:
        print(f"Error checking CloudTrail multi-region read/write: {str(e)}")
        return None

def check_cloudtrail_multi_region_trail(cloudtrail_client, account_id):
    """Check if CloudTrail has multi-region trail enabled"""
    try:
        # Get all CloudTrail trails
        trails = cloudtrail_client.describe_trails()['trailList']
        
        # Count multi-region trails that are logging
        multi_region_trails = 0
        org_trail = None
        
        for trail in trails:
            # Get trail details
            is_multi_region = trail.get('IsMultiRegionTrail', False)
            region = trail.get('TrailRegion')
            home_region = trail.get('HomeRegion')
            is_org_trail = trail.get('IsOrganizationTrail', False)
            
            try:
                # Check if trail is logging
                trail_status = cloudtrail_client.get_trail_status(Name=trail['TrailARN'])
                is_logging = trail_status.get('IsLogging', False)
                
                # Check for multi-region trails
                if is_multi_region:
                    if is_logging:
                        multi_region_trails += 1
                
                # Store organization trail info
                if is_org_trail:
                    org_trail = {
                        'is_organization_trail': True,
                        'is_logging': is_logging,
                        'is_multi_region_trail': is_multi_region
                    }
                    
            except cloudtrail_client.exceptions.ClientError as e:
                if is_org_trail:
                    org_trail = {
                        'is_organization_trail': True,
                        'is_logging': None,
                        'is_multi_region_trail': is_multi_region
                    }

        # Determine status and reason
        if multi_region_trails >= 1:
            status = "ok"
            reason = f"Account has {multi_region_trails} multi-region trail(s)."
        elif org_trail and org_trail['is_organization_trail'] and org_trail['is_logging'] and org_trail['is_multi_region_trail']:
            status = "ok"
            reason = "Account has multi-region trail(s)."
        elif org_trail and org_trail['is_organization_trail'] and org_trail['is_multi_region_trail'] and org_trail['is_logging'] is None:
            status = "info"
            reason = "Account has organization trail, check organization account for cloudtrail logging status."
        else:
            status = "alarm"
            reason = "Account does not have multi-region trail(s)."

        return {
            "type": "cloudtrail_multi_region_trail",
            "resource": f"arn:aws:::{account_id}",
            "status": status,
            "reason": reason,
            "region": "global",
            "account": account_id
        }

    except Exception as e:
        print(f"Error checking CloudTrail multi-region trail: {str(e)}")
        return None

def check_cloudtrail_logs_integration(cloudtrail_client, account_id):
    """Check if CloudTrail multi-region trails are integrated with CloudWatch logs"""
    try:
        # Get all CloudTrail trails with detailed info
        trails = cloudtrail_client.describe_trails(
            includeShadowTrails=False
        )['trailList']
        results = []

        for trail in trails:
            # Check if trail is multi-region and in home region
            if not (trail.get('IsMultiRegionTrail') and 
                   trail.get('HomeRegion') == trail.get('TrailRegion')):
                continue

            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN')
            log_group_arn = trail.get('CloudWatchLogsLogGroupArn')

            try:
                # Get trail status including latest delivery time
                trail_status = cloudtrail_client.get_trail_status(Name=trail_arn)
                latest_delivery_time = trail_status.get('LatestCloudWatchLogsDeliveryTime')

                # Convert latest_delivery_time to datetime if it exists
                if latest_delivery_time:
                    latest_delivery_time = latest_delivery_time.replace(tzinfo=None)
                    time_difference = datetime.now(timezone.utc) - latest_delivery_time.replace(tzinfo=timezone.utc)
                    is_recent = time_difference.days < 1
                else:
                    is_recent = False

                # Check if logs are integrated and recent
                if log_group_arn and log_group_arn != 'null' and latest_delivery_time and is_recent:
                    status = "ok"
                    reason = f"{trail_name} multi region trail integrated with CloudWatch logs."
                else:
                    status = "alarm"
                    reason = f"{trail_name} multi region trail not integrated with CloudWatch logs."

                # Always append result for multi-region trails
                results.append({
                    "type": "cloudtrail_logs_integration",
                    "resource": trail_arn,
                    "status": status,
                    "reason": reason,
                    "region": trail.get('HomeRegion', 'unknown'),
                    "account": account_id,
                    "trail_name": trail_name
                })

            except cloudtrail_client.exceptions.ClientError as e:
                results.append({
                    "type": "cloudtrail_logs_integration",
                    "resource": trail_arn,
                    "status": "alarm",
                    "reason": f"{trail_name} multi region trail not integrated with CloudWatch logs.",
                    "region": trail.get('HomeRegion', 'unknown'),
                    "account": account_id,
                    "trail_name": trail_name
                })

        # If no multi-region trails found, add a default result
        if not results:
            results.append({
                "type": "cloudtrail_logs_integration",
                "resource": f"arn:aws:::{account_id}",
                "status": "alarm",
                "reason": "No multi region trail not integrated with CloudWatch logs.",
                "region": "global",
                "account": account_id,
                "trail_name": "none"
            })

        return results

    except Exception as e:
        return [{
            "type": "cloudtrail_logs_integration",
            "resource": f"arn:aws:::{account_id}",
            "status": "alarm",
            "reason": "Multi region trail not integrated with CloudWatch logs.",
            "region": "global",
            "account": account_id,
            "trail_name": "error"
        }]

def check_cloudtrail_s3_data_events(cloudtrail_client, s3_client, account_id):
    """Check if CloudTrail has S3 data events enabled"""
    try:
        # Get all CloudTrail trails
        trails = cloudtrail_client.describe_trails()['trailList']
        
        # Get all S3 buckets
        buckets = s3_client.list_buckets()['Buckets']
        
        # Track which buckets have data events enabled
        buckets_with_events = set()
        
        # Check each trail for S3 data events
        for trail in trails:
            if not trail.get('IsMultiRegionTrail'):
                continue
                
            try:
                # Get event selectors
                selectors_response = cloudtrail_client.get_event_selectors(
                    TrailName=trail['TrailARN']
                )
                
                # Check standard event selectors
                for selector in selectors_response.get('EventSelectors', []):
                    if selector.get('ReadWriteType') != 'All':
                        continue
                        
                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    buckets_with_events.update([b['Name'] for b in buckets])
                                else:
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_events.add(bucket_name)
                
                # Check advanced event selectors
                for selector in selectors_response.get('AdvancedEventSelectors', []):
                    has_s3_object = False
                    has_read_write = False
                    
                    for field_selector in selector.get('FieldSelectors', []):
                        if (field_selector.get('Field') == 'resources.type' and 
                            'AWS::S3::Object' in field_selector.get('Equals', [])):
                            has_s3_object = True
                        if (field_selector.get('Field') == 'readOnly' and 
                            'false' in field_selector.get('Equals', [])):
                            has_read_write = True
                    
                    if has_s3_object and has_read_write:
                        buckets_with_events.update([b['Name'] for b in buckets])
                                    
            except Exception as e:
                print(f"Error getting event selectors for trail {trail['Name']}: {str(e)}")
                continue
        
        results = []
        
        # Generate results for each bucket
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                print(f"Error getting location for bucket {bucket_name}: {str(e)}")
                region = "us-east-1"
            
            status = "ok" if bucket_name in buckets_with_events else "alarm"
            reason = f"{bucket_name} object-level data events logging {'enabled' if status == 'ok' else 'disabled'}."
            
            result = {
                "type": "cloudtrail_s3_data_events",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "status": status,
                "reason": reason,
                "region": region,
                "account": account_id,
                "bucket_name": bucket_name
            }
            results.append(result)
        
        return results

    except Exception as e:
        print(f"Error checking CloudTrail S3 data events: {str(e)}")
        return [{
            "type": "cloudtrail_s3_data_events",
            "resource": f"arn:aws:s3:::{account_id}",
            "status": "alarm",
            "reason": "Error checking S3 data events configuration.",
            "region": "global",
            "account": account_id,
            "bucket_name": "error"
        }]

def check_cloudtrail_s3_logging(cloudtrail_client, s3_client, account_id, trails_data):
    """Check if CloudTrail S3 buckets have access logging enabled"""
    try:
        results = []
        for trail in trails_data:
            trail_name = trail.get('Name', 'Unknown')
            trail_arn = trail.get('TrailARN')
            bucket_name = trail.get('S3BucketName')
            
            if not bucket_name:
                continue

            try:
                # Get bucket logging configuration
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                
                # Always create a result for each trail's bucket
                status = "ok" if logging.get('LoggingEnabled') else "alarm"
                reason = f"{trail_name}'s logging bucket {bucket_name} has access logging disabled."

                result = {
                    "type": "cloudtrail_s3_logging",
                    "resource": trail_arn,
                    "status": status,
                    "reason": reason,
                    "region": trail.get('HomeRegion', 'unknown'),
                    "account": account_id,
                    "trail_name": trail_name
                }
                results.append(result)

            except Exception as e:
                print(f"Error checking logging for bucket {bucket_name}: {str(e)}")
                results.append({
                    "type": "cloudtrail_s3_logging",
                    "resource": trail_arn,
                    "status": "alarm",
                    "reason": f"{trail_name}'s logging bucket {bucket_name} has access logging disabled.",
                    "region": trail.get('HomeRegion', 'unknown'),
                    "account": account_id,
                    "trail_name": trail_name
                })

        # Only return empty result if truly no trails were found
        if not trails:
            results.append({
                "type": "cloudtrail_s3_logging",
                "resource": f"arn:aws:::{account_id}",
                "status": "alarm",
                "reason": "No CloudTrail S3 buckets found to check logging.",
                "region": "global",
                "account": account_id,
                "trail_name": "none"
            })

        return results

    except Exception as e:
        print(f"Error checking CloudTrail S3 logging: {str(e)}")
        return [{
            "type": "cloudtrail_s3_logging",
            "resource": f"arn:aws:::{account_id}",
            "status": "alarm",
            "reason": "Error checking CloudTrail S3 logging configuration",
            "region": "global",
            "account": account_id,
            "trail_name": "error"
        }]

def check_cloudtrail_s3_object_read_events(cloudtrail_client, s3_client, account_id, trails_data, buckets_data, bucket_locations):
    """Check if CloudTrail has S3 object-level read events enabled"""
    try:
        results = []
        
        # Track which buckets have read events enabled
        buckets_with_read_events = set()

        # Check each trail for S3 read events
        for trail in trails:
            if not trail.get('IsMultiRegionTrail'):
                continue

            try:
                # Get event selectors for the trail
                event_selectors = cloudtrail_client.get_event_selectors(
                    TrailName=trail['TrailARN']
                )['EventSelectors']

                for selector in event_selectors:
                    read_write_type = selector.get('ReadWriteType')
                    if read_write_type not in ['ReadOnly', 'All']:
                        continue

                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    # All buckets are covered
                                    buckets_with_read_events.update([b['Name'] for b in buckets])
                                else:
                                    # Extract bucket name from ARN
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_read_events.add(bucket_name)

            except Exception as e:
                print(f"Error getting event selectors for trail {trail['Name']}: {str(e)}")
                continue

        # Generate results for each bucket
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket_name)
                region = bucket_region.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                print(f"Error getting location for bucket {bucket_name}: {str(e)}")
                region = "us-east-1"

            status = "ok" if bucket_name in buckets_with_read_events else "alarm"
            reason = f"{bucket_name} object-level read events logging {'enabled' if status == 'ok' else 'disabled'}."

            result = {
                "type": "cloudtrail_s3_object_read_events",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "status": status,
                "reason": reason,
                "region": region,
                "account": account_id,
                "bucket_name": bucket_name
            }
            results.append(result)

        return results

    except Exception as e:
        print(f"Error checking CloudTrail S3 object read events: {str(e)}")
        return [{
            "type": "cloudtrail_s3_object_read_events",
            "resource": f"arn:aws:s3:::{account_id}",
            "status": "alarm",
            "reason": "Error checking S3 object read events configuration",
            "region": "global",
            "account": account_id,
            "bucket_name": "error"
        }]

def check_cloudtrail_s3_object_write_events(cloudtrail_client, s3_client, account_id, trails_data, buckets_data, bucket_locations):
    """Check if CloudTrail has S3 object-level write events enabled"""
    try:
        
        # Track which buckets have write events enabled
        buckets_with_write_events = set()

        # Check each trail for S3 write events
        for trail in trails_data:
            if not trail.get('IsMultiRegionTrail'):
                continue

            try:
                # Get event selectors
                selectors_response = cloudtrail_client.get_event_selectors(
                    TrailName=trail['TrailARN']
                )
                
                # Check standard event selectors
                for selector in selectors_response.get('EventSelectors', []):
                    read_write_type = selector.get('ReadWriteType')
                    if read_write_type not in ['WriteOnly', 'All']:
                        continue

                    for data_resource in selector.get('DataResources', []):
                        if data_resource.get('Type') == 'AWS::S3::Object':
                            for value in data_resource.get('Values', []):
                                if value == 'arn:aws:s3':
                                    # All buckets are covered
                                    buckets_with_write_events.update([b['Name'] for b in buckets])
                                else:
                                    # Extract bucket name from ARN
                                    bucket_arn = value.split('/', 1)[0]
                                    bucket_name = bucket_arn.split(':')[-1]
                                    buckets_with_write_events.add(bucket_name)
                
                # Check advanced event selectors
                for selector in selectors_response.get('AdvancedEventSelectors', []):
                    has_s3_object = False
                    has_write = False
                    
                    for field_selector in selector.get('FieldSelectors', []):
                        if (field_selector.get('Field') == 'resources.type' and 
                            'AWS::S3::Object' in field_selector.get('Equals', [])):
                            has_s3_object = True
                        if (field_selector.get('Field') == 'readOnly' and 
                            'false' in field_selector.get('Equals', [])):
                            has_write = True
                    
                    if has_s3_object and has_write:
                        buckets_with_write_events.update([b['Name'] for b in buckets])

            except Exception as e:
                print(f"Error getting event selectors for trail {trail['Name']}: {str(e)}")
                continue

        results = []
        
        # Generate results for each bucket
        for bucket in buckets_data:
            bucket_name = bucket['Name']
            region = bucket_locations.get(bucket_name, 'us-east-1')
            
            status = "ok" if bucket_name in buckets_with_write_events else "alarm"
            reason = f"{bucket_name} object-level write events logging {'enabled' if status == 'ok' else 'disabled'}."

            result = {
                "type": "cloudtrail_s3_object_write_events",
                "resource": f"arn:aws:s3:::{bucket_name}",
                "status": status,
                "reason": reason,
                "region": region,
                "account": account_id,
                "bucket_name": bucket_name
            }
            results.append(result)

        return results

    except Exception as e:
        print(f"Error checking CloudTrail S3 object write events: {str(e)}")
        return [{
            "type": "cloudtrail_s3_object_write_events",
            "resource": f"arn:aws:s3:::{account_id}",
            "status": "alarm",
            "reason": "Error checking S3 object write events configuration",
            "region": "global",
            "account": account_id,
            "bucket_name": "error"
        }]

@app.route('/check-cloudtrail-1')
def check_cloudtrail():
    try:
        # Initialize AWS clients
        session = boto3.Session(
            aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY'],
            region_name=config['AWS']['AWS_REGION']
        )
        
        s3_client = session.client('s3')
        cloudtrail_client = session.client('cloudtrail')
        
        # Get AWS account ID
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Cache common AWS data to reduce API calls
        print("Fetching CloudTrail and S3 data...")
        trails_data = cloudtrail_client.describe_trails()['trailList']
        buckets_data = s3_client.list_buckets()['Buckets']
        
        # Pre-fetch bucket locations to avoid repeated calls
        print("Caching S3 bucket locations...")
        bucket_locations = {}
        for bucket in buckets_data:
            try:
                location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                bucket_locations[bucket['Name']] = location.get('LocationConstraint', 'us-east-1') or 'us-east-1'
            except Exception as e:
                print(f"Error getting location for bucket {bucket['Name']}: {str(e)}")
                bucket_locations[bucket['Name']] = 'us-east-1'
        
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Run all CloudTrail checks in parallel using ThreadPoolExecutor
            check_results = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_check = {
                    executor.submit(check_cloudtrail_bucket_public_access, s3_client, cloudtrail_client, account_id, trails_data): "bucket_public",
                    executor.submit(check_cloudtrail_multi_region_read_write, cloudtrail_client, account_id, trails_data): "multi_region_rw",
                    executor.submit(check_cloudtrail_multi_region_trail, cloudtrail_client, account_id, trails_data): "multi_region_trail",
                    executor.submit(check_cloudtrail_logs_integration, cloudtrail_client, account_id, trails_data): "logs_integration",
                    executor.submit(check_cloudtrail_s3_logging, cloudtrail_client, s3_client, account_id, trails_data): "s3_logging",
                    executor.submit(check_cloudtrail_s3_object_read_events, cloudtrail_client, s3_client, account_id, trails_data, buckets_data, bucket_locations): "s3_read_events",
                    executor.submit(check_cloudtrail_s3_data_events, cloudtrail_client, s3_client, account_id, trails_data, buckets_data, bucket_locations): "s3_data_events",
                    executor.submit(check_cloudtrail_s3_object_write_events, cloudtrail_client, s3_client, account_id, trails_data, buckets_data, bucket_locations): "s3_write_events"
                }

                for future in concurrent.futures.as_completed(future_to_check):
                    check_name = future_to_check[future]
                    try:
                        data = future.result()
                        if data:
                            if isinstance(data, list):
                                check_results.extend(data)
                            else:
                                check_results.append(data)
                    except Exception as e:
                        print(f"Error in {check_name}: {str(e)}")
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
                    all_results.append(result)

            if result_tuples:
                insert_query = """
                INSERT INTO aws_project_status (description, resource, status)
                VALUES %s
                """
                execute_values(cur, insert_query, result_tuples)
                conn.commit()
            return jsonify(all_results)

        except Exception as e:
            print(f"Error processing checks: {str(e)}")
            conn.rollback()
            raise e

        finally:
            cur.close()
            conn.close()

    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    print("Starting server on port 5001...")
    app.run(debug=True, port=5001)
