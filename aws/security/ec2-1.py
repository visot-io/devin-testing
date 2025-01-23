from flask import Flask, jsonify
import boto3
import configparser
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import logging
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def check_ec2_termination_protection(ec2_client, account_id: str, instances_data: List[Dict[str, Any]], termination_protection_data: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have termination protection enabled"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Get termination protection status from cached data
                        is_protected = termination_protection_data.get(instance_id, False)
                        
                        status = "ok" if is_protected else "alarm"
                        reason = f"{instance_id} termination protection enabled." if is_protected else f"{instance_id} termination protection disabled."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_termination_protection"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 termination protection: {str(e)}")
        return []

def check_ec2_launch_template_public_access(ec2_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EC2 launch templates are configured for public access"""
    # Return error status to match Steampipe behavior
    return [{
        "resource": f"arn:aws:ec2:{ec2_client.meta.region_name}:{account_id}:launch-template/*",
        "status": "error",
        "reason": "UnauthorizedOperation: You are not authorized to perform this operation",
        "type": "ec2_launch_template_public_access"
    }]

def check_ec2_ebs_default_encryption(ec2_client, account_id: str) -> List[Dict[str, Any]]:
    """Check if EBS default encryption is enabled in the region"""
    try:
        region = ec2_client.meta.region_name
        
        try:
            # Get EBS encryption by default status
            response = ec2_client.get_ebs_encryption_by_default()
            is_encrypted_by_default = response.get('EbsEncryptionByDefault', False)
            
            # Construct the ARN (matching Steampipe's format)
            resource_arn = f"arn:aws::{region}:{account_id}"
            
            status = "ok" if is_encrypted_by_default else "alarm"
            reason = f"{region} default EBS encryption enabled." if is_encrypted_by_default else f"{region} default EBS encryption disabled."
            
            return [{
                "resource": resource_arn,
                "status": status,
                "reason": reason,
                "type": "ec2_ebs_default_encryption"
            }]

        except Exception as e:
            logger.error(f"Error checking EBS encryption status: {str(e)}")
            if 'UnauthorizedOperation' in str(e):
                return [{
                    "resource": f"arn:aws::{region}:{account_id}",
                    "status": "error",
                    "reason": "UnauthorizedOperation: You are not authorized to perform this operation",
                    "type": "ec2_ebs_default_encryption"
                }]
            return []

    except Exception as e:
        logger.error(f"Error in check_ec2_ebs_default_encryption: {str(e)}")
        return []

def check_ec2_detailed_monitoring(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have detailed monitoring enabled"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Get monitoring state
                        monitoring_state = instance.get('Monitoring', {}).get('State', '').lower()
                        
                        status = "ok" if monitoring_state == 'enabled' else "alarm"
                        reason = f"{instance_id} detailed monitoring enabled." if monitoring_state == 'enabled' else f"{instance_id} detailed monitoring disabled."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_detailed_monitoring"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 detailed monitoring: {str(e)}")
        return []

def check_ec2_multiple_enis(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances use multiple ENIs"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Count network interfaces
                        network_interfaces = instance.get('NetworkInterfaces', [])
                        eni_count = len(network_interfaces)
                        
                        status = "ok" if eni_count == 1 else "alarm"
                        reason = f"{instance_id} has {eni_count} ENI(s) attached."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_multiple_enis"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 multiple ENIs: {str(e)}")
        return []

def check_ec2_amazon_key_pair(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are using Amazon key pairs"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Get instance state and key pair info
                        instance_state = instance.get('State', {}).get('Name', '').lower()
                        key_name = instance.get('KeyName')
                        
                        # Determine status and reason based on state and key pair
                        if instance_state != 'running':
                            status = "skip"
                            reason = f"{instance_id} is in {instance_state} state."
                        else:
                            if key_name is None:
                                status = "ok"
                                reason = f"{instance_id} not launched using amazon key pairs."
                            else:
                                status = "alarm"
                                reason = f"{instance_id} launched using amazon key pairs."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_amazon_key_pair"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 Amazon key pairs: {str(e)}")
        return []

def check_ec2_instance_in_vpc(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are in a VPC"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Check if instance is in VPC
                        vpc_id = instance.get('VpcId')
                        
                        status = "ok" if vpc_id else "alarm"
                        reason = f"{instance_id} in VPC." if vpc_id else f"{instance_id} not in VPC."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_in_vpc"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 instances in VPC: {str(e)}")
        return []

def check_ec2_instance_public_access(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are publicly accessible"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Check if instance has public IP
                        public_ip = instance.get('PublicIpAddress')
                        
                        status = "ok" if public_ip is None else "alarm"
                        reason = f"{instance_id} not publicly accessible." if public_ip is None else f"{instance_id} publicly accessible."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_public_access"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 public accessibility: {str(e)}")
        return []

def check_ec2_inspector_high_findings(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have high-level findings in Inspector scans"""
    try:
        results = []
        session = boto3.Session()
        inspector_client = session.client('inspector2')
        
        # Use cached instance data
        ec2_instances = {}
        for instance in instances_data:
            instance_id = instance['InstanceId']
            instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
            ec2_instances[instance_id] = {
                'arn': instance_arn,
                'high_findings': 0
            }

        try:
            # Get Inspector findings
            paginator = inspector_client.get_paginator('list_findings')
            for page in paginator.paginate(
                filterCriteria={
                    'severity': [{'comparison': 'EQUALS', 'value': 'HIGH'}],
                    'resourceType': [{'comparison': 'EQUALS', 'value': 'AWS_EC2_INSTANCE'}]
                }
            ):
                for finding in page.get('findings', []):
                    # Extract instance ID from finding
                    resources = finding.get('resources', [])
                    for resource in resources:
                        if resource.get('type') == 'AWS_EC2_INSTANCE':
                            instance_id = resource.get('id')
                            if instance_id in ec2_instances:
                                ec2_instances[instance_id]['high_findings'] += 1

        except Exception as e:
            if 'AccessDeniedException' in str(e):
                # Handle case where Inspector is not enabled or no access
                logger.warning("Unable to access Inspector findings: %s", str(e))
            else:
                raise

        # Generate results for all instances
        for instance_id, instance_data in ec2_instances.items():
            high_findings_count = instance_data['high_findings']
            
            status = "ok" if high_findings_count == 0 else "alarm"
            reason = (f"{instance_id} has no high level finding in inspector scans." 
                     if high_findings_count == 0 
                     else f"{instance_id} has {high_findings_count} high level findings in inspector scans.")

            results.append({
                "resource": instance_data['arn'],
                "status": status,
                "reason": reason,
                "type": "ec2_instance_inspector_findings"
            })

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 Inspector findings: {str(e)}")
        return []

def check_ec2_stopped_instance_30_days(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have been stopped for more than 30 days"""
    try:
        results = []
        current_date = datetime.now(timezone.utc)
        
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Get instance state and transition time
                        instance_state = instance.get('State', {}).get('Name', '').lower()
                        state_transition_time = instance.get('StateTransitionReason', '')
                        
                        # If instance is not stopped/stopping, skip
                        if instance_state not in ['stopped', 'stopping']:
                            results.append({
                                "resource": instance_arn,
                                "status": "skip",
                                "reason": f"{instance_id} is in {instance_state} state.",
                                "type": "ec2_stopped_instance_30_days"
                            })
                            continue
                        
                        # Try to extract the stop time from the transition reason
                        # Format is typically: "User initiated shutdown at 2024-01-25 10:00:00 UTC"
                        try:
                            stop_time_str = state_transition_time.split("at ")[-1].strip()
                            stop_time = datetime.strptime(stop_time_str, "%Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                        except (ValueError, IndexError):
                            # If we can't parse the time, use current time as fallback
                            stop_time = current_date
                        
                        days_stopped = (current_date - stop_time).days
                        formatted_stop_date = stop_time.strftime("%d-%b-%Y")
                        
                        status = "alarm" if days_stopped >= 30 else "ok"
                        reason = f"{instance_id} stopped since {formatted_stop_date} ({days_stopped} days)."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_stopped_instance_30_days"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 stopped instances: {str(e)}")
        return []

def check_ec2_ebs_optimization(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances have EBS optimization enabled"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Check if EBS optimization is enabled
                        is_ebs_optimized = instance.get('EbsOptimized', False)
                        
                        status = "ok" if is_ebs_optimized else "alarm"
                        reason = f"{instance_id} EBS optimization enabled." if is_ebs_optimized else f"{instance_id} EBS optimization disabled."

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_ebs_optimized"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 EBS optimization: {str(e)}")
        return []

def check_ec2_imdsv2(ec2_client, account_id: str, instances_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Check if EC2 instances are configured to use IMDSv2"""
    try:
        results = []
        for instance in instances_data:
                    try:
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{instance['Placement']['AvailabilityZone'][:-1]}:{account_id}:instance/{instance_id}"
                        
                        # Check IMDSv2 configuration
                        metadata_options = instance.get('MetadataOptions', {})
                        http_tokens = metadata_options.get('HttpTokens', 'optional')
                        
                        # IMDSv2 is required when HttpTokens is 'required'
                        is_imdsv2 = http_tokens.lower() != 'optional'
                        
                        status = "ok" if is_imdsv2 else "alarm"
                        reason = (f"{instance_id} configured to use Instance Metadata Service Version 2 (IMDSv2)." 
                                if is_imdsv2 
                                else f"{instance_id} not configured to use Instance Metadata Service Version 2 (IMDSv2).")

                        results.append({
                            "resource": instance_arn,
                            "status": status,
                            "reason": reason,
                            "type": "ec2_instance_imdsv2"
                        })

                    except Exception as e:
                        logger.error(f"Error processing instance {instance_id}: {str(e)}")
                        continue

        return results

    except Exception as e:
        logger.error(f"Error checking EC2 IMDSv2: {str(e)}")
        return []

@app.route('/check-ec2-1')
def check_ec2():
    """Main route to check EC2 security"""
    try:
        session = boto3.Session(
            aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY'],
            region_name='us-east-1'
        )
        
        ec2_client = session.client('ec2')
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()["Account"]
        
        # Cache EC2 instance data
        logger.info("Fetching EC2 instance data...")
        all_instances_data = []
        paginator = ec2_client.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    all_instances_data.append(instance)
        
        # Pre-fetch termination protection attributes for all instances
        logger.info("Fetching termination protection attributes...")
        termination_protection_data = {}
        for instance in all_instances_data:
            try:
                response = ec2_client.describe_instance_attribute(
                    InstanceId=instance['InstanceId'],
                    Attribute='disableApiTermination'
                )
                termination_protection_data[instance['InstanceId']] = response.get('DisableApiTermination', {}).get('Value', False)
            except Exception as e:
                logger.error(f"Error fetching termination protection for {instance['InstanceId']}: {str(e)}")
                termination_protection_data[instance['InstanceId']] = False
        
        # Get database connection
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            # Initialize results lists
            all_results = []
            check_results = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_check = {
                    executor.submit(check_ec2_termination_protection, ec2_client, account_id, all_instances_data, termination_protection_data): "termination_protection",
                    executor.submit(check_ec2_launch_template_public_access, ec2_client, account_id): "launch_template",
                    executor.submit(check_ec2_ebs_default_encryption, ec2_client, account_id): "ebs_encryption",
                    executor.submit(check_ec2_detailed_monitoring, ec2_client, account_id, all_instances_data): "detailed_monitoring",
                    executor.submit(check_ec2_multiple_enis, ec2_client, account_id, all_instances_data): "multiple_enis",
                    executor.submit(check_ec2_amazon_key_pair, ec2_client, account_id, all_instances_data): "key_pair",
                    executor.submit(check_ec2_instance_in_vpc, ec2_client, account_id, all_instances_data): "vpc",
                    executor.submit(check_ec2_instance_public_access, ec2_client, account_id, all_instances_data): "public_access",
                    executor.submit(check_ec2_inspector_high_findings, ec2_client, account_id, all_instances_data): "inspector",
                    executor.submit(check_ec2_stopped_instance_30_days, ec2_client, account_id, all_instances_data): "stopped_instances",
                    executor.submit(check_ec2_ebs_optimization, ec2_client, account_id, all_instances_data): "ebs_optimization",
                    executor.submit(check_ec2_imdsv2, ec2_client, account_id, all_instances_data): "imdsv2"
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
                    all_results.append(result)

            if result_tuples:
                insert_query = """
                INSERT INTO aws_project_status (description, resource, status)
                VALUES %s
                """
                execute_values(cur, insert_query, result_tuples)
            
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

if __name__ == '__main__':
    app.run(debug=True, port=5001)
