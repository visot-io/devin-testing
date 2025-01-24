"""SNS Security Check Module.

This module provides functionality to check AWS SNS topics for security compliance
across multiple regions using parallel processing and optimized database operations.
"""

import concurrent.futures
import configparser
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
import psycopg2
import psycopg2.extras
from flask import Flask, jsonify


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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


def _fetch_sns_topics_in_region(
    sns_client: boto3.client,
    region: str
) -> Dict:
    """Fetch all SNS topics in a specific region with pre-parsed policies.

    Args:
        sns_client: Boto3 SNS client for the region
        region: AWS region name to fetch topics from

    Returns:
        Dict containing topic information with pre-parsed policies
    """
    region_topics = {}
    try:
        logging.info(f"Starting SNS topic check in region {region}...")
        start_time = datetime.now()
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page['Topics']:
                topic_arn = topic['TopicArn']
                if topic_arn not in region_topics:
                    # Get topic attributes once
                    attributes = sns_client.get_topic_attributes(
                        TopicArn=topic_arn
                    )['Attributes']

                    # Pre-parse the policy if it exists
                    policy_str = attributes.get('Policy', '{}')
                    parsed_policy = json.loads(policy_str)

                    region_topics[topic_arn] = {
                        'attributes': attributes,
                        'parsed_policy': parsed_policy,
                        'region': region,
                        'name': topic_arn.split(':')[-1]
                    }

        duration = (datetime.now() - start_time).total_seconds()
        logging.info(
            f"Completed SNS topic check in region {region} - "
            f"Found {len(region_topics)} topics in {duration:.2f}s"
        )
    except Exception as e:
        logging.error(f"Error getting topics in region {region}: {str(e)}")
    return region_topics

def get_all_sns_topics(session: boto3.Session) -> Dict:
    """Get all SNS topics across all regions using parallel processing.

    Uses ThreadPoolExecutor to fetch topics from multiple regions concurrently,
    improving overall performance. Pre-parses topic policies to avoid redundant
    JSON parsing operations.

    Args:
        session: Boto3 session for AWS API access

    Returns:
        Dict containing all SNS topics across regions with their attributes
        and pre-parsed policies
    """
    topics = {}
    start_time = datetime.now()

    # Get all regions
    ec2_client = session.client('ec2', region_name='us-east-1')
    regions = [
        region['RegionName']
        for region in ec2_client.describe_regions()['Regions']
    ]

    logging.info(f"Starting parallel processing of {len(regions)} regions...")

    # Process regions in parallel using ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_region = {}
        for region in regions:
            sns_client = session.client('sns', region_name=region)
            future = executor.submit(
                _fetch_sns_topics_in_region,
                sns_client,
                region
            )
            future_to_region[future] = region

        for future in concurrent.futures.as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_topics = future.result()
                topics.update(region_topics)
            except Exception as e:
                logging.error(f"Error processing region {region}: {str(e)}")

    duration = (datetime.now() - start_time).total_seconds()
    logging.info(
        f"Completed processing all regions in {duration:.2f}s - "
        f"Found {len(topics)} total topics"
    )
    return topics

def check_sns_topic_encrypted_at_rest(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics are encrypted at rest using KMS.

    Verifies that each SNS topic has KMS encryption enabled for data at rest
    by checking for the presence of a KMS master key ID in the topic attributes.

    Args:
        topics: Dictionary of SNS topics with their attributes
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating encryption status for each topic
    """
    results = []
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        kms_master_key_id = attributes.get('KmsMasterKeyId')
        result = {
            "type": "sns_topic_encrypted_at_rest",
            "resource": topic_arn,
            "status": "ok" if kms_master_key_id else "alarm",
            "reason": (
                f"{topic_name} encryption at rest enabled."
                if kms_master_key_id
                else f"{topic_name} encryption at rest disabled."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_public_access(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow public access.

    Examines each topic's policy for statements that allow unrestricted access
    through wildcard principals ('*') in the policy. This includes checking for
    both direct wildcard principals and AWS-specific wildcard principals.

    Args:
        topics: Dictionary of SNS topics with their attributes and parsed policies
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating public access policy status for each topic
    """
    results = []
    for topic_arn, topic_data in topics.items():
        topic_name = topic_data['name']
        region = topic_data['region']
        policy = topic_data['parsed_policy']
        public_statements = 0
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    has_wildcard = (
                        principal == '*' or
                        principal == {"AWS": "*"} or
                        (isinstance(principal.get('AWS'), list) and
                         '*' in principal['AWS'])
                    )
                    if has_wildcard:
                        public_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_public_access",
            "resource": topic_arn,
            "status": "alarm" if public_statements > 0 else "ok",
            "reason": (
                f"{topic_name} contains {public_statements} statements that "
                f"allow public access."
                if public_statements > 0
                else f"{topic_name} does not allow public access."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_notification_delivery_status_enabled(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics have notification delivery status logging enabled.

    Verifies that each SNS topic has at least one delivery status feedback role
    configured for monitoring notification delivery status. Checks for Application,
    Firehose, HTTP, Lambda, and SQS feedback roles.

    Args:
        topics: Dictionary of SNS topics with their attributes
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating delivery status logging configuration
        for each topic
    """
    results = []
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        # Check for all feedback role ARNs
        feedback_roles = [
            attributes.get('ApplicationFailureFeedbackRoleArn'),
            attributes.get('FirehoseFailureFeedbackRoleArn'),
            attributes.get('HTTPFailureFeedbackRoleArn'),
            attributes.get('LambdaFailureFeedbackRoleArn'),
            attributes.get('SQSFailureFeedbackRoleArn')
        ]
        # Check if any feedback role exists
        has_feedback_role = any(feedback_roles)
        result = {
            "type": "sns_topic_notification_delivery_status_enabled",
            "resource": topic_arn,
            "status": "ok" if has_feedback_role else "alarm",
            "reason": (
                f"{topic_name} has delivery status logging enabled."
                if has_feedback_role
                else f"{topic_name} has delivery status logging disabled."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_publishing_access(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow unrestricted publish access.

    Examines each topic's policy for statements that allow unrestricted publish
    access through wildcard principals without conditions. This includes checking
    for both direct wildcard principals and AWS-specific wildcard principals,
    specifically looking for 'sns:publish' actions.

    Args:
        topics: Dictionary of SNS topics with their attributes and parsed policies
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating publish access policy status for each topic
    """
    results = []
    for topic_arn, topic_data in topics.items():
        topic_name = topic_data['name']
        region = topic_data['region']
        policy = topic_data['parsed_policy']
        public_publish_statements = 0
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    # Check Principal
                    principal = statement.get('Principal', {})
                    has_wildcard = (
                        principal == '*' or
                        principal == {"AWS": "*"} or
                        (isinstance(principal.get('AWS'), list) and
                         '*' in principal['AWS'])
                    )
                    if has_wildcard:
                        # Check Action
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for sns:publish and condition
                        has_publish = 'sns:publish' in actions
                        has_condition = 'Condition' in statement
                        
                        if has_publish and not has_condition:
                            public_publish_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_publishing_access",
            "resource": topic_arn,
            "status": "alarm" if public_publish_statements > 0 else "ok",
            "reason": (
                f"{topic_name} contains {public_publish_statements} statements "
                f"that allow publish access without condition."
                if public_publish_statements > 0
                else f"{topic_name} does not allow publish access without condition."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_subscription_access(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow unrestricted subscription access.

    Examines each topic's policy for statements that allow unrestricted subscription
    access through wildcard principals without conditions. This includes checking for
    both direct wildcard principals and AWS-specific wildcard principals,
    specifically looking for 'sns:subscribe' and 'sns:receive' actions.

    Args:
        topics: Dictionary of SNS topics with their attributes and parsed policies
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating subscription access policy status for each
        topic
    """
    results = []
    for topic_arn, topic_data in topics.items():
        topic_name = topic_data['name']
        region = topic_data['region']
        policy = topic_data['parsed_policy']
        public_subscribe_statements = 0
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    # Check Principal
                    principal = statement.get('Principal', {})
                    has_wildcard = (
                        principal == '*' or
                        principal == {"AWS": "*"} or
                        (isinstance(principal.get('AWS'), list) and
                         '*' in principal['AWS'])
                    )
                    if has_wildcard:
                        # Check Action
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for sns:subscribe or sns:receive
                        has_subscribe = any(
                            action in ['sns:subscribe', 'sns:receive']
                            for action in actions
                        )
                        
                        # Check Condition
                        has_condition = 'Condition' in statement
                        
                        if has_subscribe and not has_condition:
                            public_subscribe_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_subscription_access",
            "resource": topic_arn,
            "status": "alarm" if public_subscribe_statements > 0 else "ok",
            "reason": (
                f"{topic_name} contains {public_subscribe_statements} statements "
                f"that allow subscribe access without condition."
                if public_subscribe_statements > 0
                else f"{topic_name} does not allow subscribe access without condition."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_cross_account_access(
    topics: Dict,
    account_id: str
) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow cross-account access.

    Examines each topic's policy for statements that allow access from different
    AWS accounts. This includes checking for both wildcard principals and explicit
    cross-account access through AWS account IDs that differ from the current
    account.

    Args:
        topics: Dictionary of SNS topics with their attributes and parsed policies
        account_id: AWS account ID for the check

    Returns:
        List of check results indicating cross-account access policy status
    """
    results = []
    for topic_arn, topic_data in topics.items():
        topic_name = topic_data['name']
        region = topic_data['region']
        policy = topic_data['parsed_policy']
        cross_account_statements = 0
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    # Check for wildcard principal
                    if principal == '*' or principal == {"AWS": "*"}:
                        cross_account_statements += 1
                        continue
                    # Check AWS principals
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        # Check if principal is '*' or from different account
                        if p == '*' or (
                            isinstance(p, str) and
                            len(p.split(':')) >= 5 and
                            p.split(':')[4] != account_id
                        ):
                            cross_account_statements += 1
                            break
        
        result = {
            "type": "sns_topic_policy_prohibit_cross_account_access",
            "resource": topic_arn,
            "status": "alarm" if cross_account_statements > 0 else "ok",
            "reason": (
                f"{topic_name} contains {cross_account_statements} statements "
                f"that allow cross account access."
                if cross_account_statements > 0
                else f"{topic_name} does not allow cross account access."
            ),
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

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

def get_aws_session() -> boto3.Session:
    """Get a reusable AWS session configured with credentials.

    Returns:
        boto3.Session: Configured AWS session object
    """
    return boto3.Session(
        aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY']
    )


def get_aws_account_id(session: boto3.Session) -> str:
    """Get AWS account ID using STS.

    Args:
        session: AWS session to use for the STS client

    Returns:
        str: AWS account ID
    """
    sts_client = session.client('sts')
    return sts_client.get_caller_identity()['Account']

@app.route('/check-sns')
def check_sns():
    """Main endpoint for checking SNS topic security configurations.

    Performs security checks on all SNS topics across regions in parallel,
    including encryption, public access, notification delivery status,
    publishing access, subscription access, and cross-account access checks.

    Returns:
        JSON response containing check results and summary statistics
    """
    try:
        start_time = datetime.now()
        logging.info("Starting SNS security check process...")

        # Create a single reusable session
        session = get_aws_session()
        # Get AWS account ID once
        account_id = get_aws_account_id(session)
        logging.info(f"Running checks for AWS account: {account_id}")
        # Get all SNS topics with cached attributes
        topics = get_all_sns_topics(session)
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Run all checks and collect results
            check_functions = [
                check_sns_topic_encrypted_at_rest,
                check_sns_topic_policy_prohibit_public_access,
                check_sns_topic_notification_delivery_status_enabled,
                check_sns_topic_policy_prohibit_publishing_access,
                check_sns_topic_policy_prohibit_subscription_access,
                check_sns_topic_policy_prohibit_cross_account_access
            ]
            
            # Execute all checks
            for check_function in check_functions:
                check_start = datetime.now()
                logging.info(f"Running check: {check_function.__name__}")
                results = check_function(topics, account_id)
                
                if results:
                    all_results.extend(results)
                    # Batch insert results for this check
                    batch_insert_results(cur, results)
                    
                check_duration = (datetime.now() - check_start).total_seconds()
                logging.info(
                    f"Completed {check_function.__name__} in {check_duration:.2f}s - "
                    f"Found {len(results)} issues"
                )

            conn.commit()
            total_duration = (datetime.now() - start_time).total_seconds()
            
            response_data = {
                "status": "success",
                "data": all_results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_checks": len(all_results),
                    "ok": len([r for r in all_results if r['status'] == 'ok']),
                    "alarm": len([r for r in all_results if r['status'] == 'alarm']),
                    "error": len([r for r in all_results if r['status'] == 'error']),
                    "duration_seconds": total_duration
                }
            }
            logging.info(
                f"Completed all checks in {total_duration:.2f}s - "
                f"Total issues found: {len(all_results)}"
            )
            return jsonify(response_data)

        except Exception as e:
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
    app.run(debug=True, port=5003)
