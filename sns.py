from flask import Flask, jsonify
import boto3
import configparser
from datetime import datetime, timezone
from typing import Dict, Any, List
import psycopg2
import json

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

def get_db_connection():
    return psycopg2.connect(
        host=config['PostgreSQL']['HOST'],
        database=config['PostgreSQL']['DATABASE'],
        user=config['PostgreSQL']['USER'],
        password=config['PostgreSQL']['PASSWORD']
    )

def get_all_sns_topics(session) -> Dict:
    """Get all SNS topics across all regions"""
    topics = {}
    
    # Get all regions
    ec2_client = session.client('ec2', region_name='us-east-1')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    for region in regions:
        sns_client = session.client('sns', region_name=region)
        try:
            paginator = sns_client.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page['Topics']:
                    topic_arn = topic['TopicArn']
                    if topic_arn not in topics:
                        attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)['Attributes']
                        topics[topic_arn] = {
                            'attributes': attributes,
                            'region': region,
                            'name': topic_arn.split(':')[-1]
                        }
        except Exception as e:
            print(f"Error getting topics in region {region}: {str(e)}")
            
    return topics

def check_sns_topic_encrypted_at_rest(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics are encrypted at rest"""
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
            "reason": f"{topic_name} encryption at rest enabled." if kms_master_key_id else f"{topic_name} encryption at rest disabled.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_public_access(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow public access"""
    results = []
    
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        
        policy = json.loads(attributes.get('Policy', '{}'))
        public_statements = 0
        
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal == {"AWS": "*"} or (
                        isinstance(principal.get('AWS'), list) and '*' in principal['AWS']
                    ):
                        public_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_public_access",
            "resource": topic_arn,
            "status": "alarm" if public_statements > 0 else "ok",
            "reason": f"{topic_name} contains {public_statements} statements that allows public access." if public_statements > 0 
                     else f"{topic_name} does not allow public access.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_notification_delivery_status_enabled(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics have notification delivery status logging enabled"""
    results = []
    
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        
        # Check for all feedback role ARNs exactly as per query
        application_feedback_role = attributes.get('ApplicationFailureFeedbackRoleArn')
        firehose_feedback_role = attributes.get('FirehoseFailureFeedbackRoleArn')
        http_feedback_role = attributes.get('HTTPFailureFeedbackRoleArn')
        lambda_feedback_role = attributes.get('LambdaFailureFeedbackRoleArn')
        sqs_feedback_role = attributes.get('SQSFailureFeedbackRoleArn')
        
        # Check if all feedback roles are missing
        has_feedback_role = any([
            application_feedback_role,
            firehose_feedback_role,
            http_feedback_role,
            lambda_feedback_role,
            sqs_feedback_role
        ])
        
        result = {
            "type": "sns_topic_notification_delivery_status_enabled",
            "resource": topic_arn,
            "status": "ok" if has_feedback_role else "alarm",
            "reason": f"{topic_name} has delivery status logging for notification messages enabled." 
                     if has_feedback_role 
                     else f"{topic_name} has delivery status logging for notification messages disabled.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_publishing_access(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow unrestricted publish access"""
    results = []
    
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        
        policy = json.loads(attributes.get('Policy', '{}'))
        public_publish_statements = 0
        
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    # Check Principal
                    principal = statement.get('Principal', {})
                    has_wildcard_principal = (
                        principal == '*' or 
                        principal == {"AWS": "*"} or 
                        (isinstance(principal.get('AWS'), list) and '*' in principal['AWS'])
                    )
                    
                    if has_wildcard_principal:
                        # Check Action
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for sns:publish
                        has_publish = 'sns:publish' in actions
                        
                        # Check Condition
                        has_condition = 'Condition' in statement
                        
                        if has_publish and not has_condition:
                            public_publish_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_publishing_access",
            "resource": topic_arn,
            "status": "alarm" if public_publish_statements > 0 else "ok",
            "reason": f"{topic_name} contains {public_publish_statements} statements that allows publish access without condition." 
                     if public_publish_statements > 0 
                     else f"{topic_name} does not allow publish access without condition.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_subscription_access(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow unrestricted subscription access"""
    results = []
    
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        
        policy = json.loads(attributes.get('Policy', '{}'))
        public_subscribe_statements = 0
        
        if policy and 'Statement' in policy:
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    # Check Principal
                    principal = statement.get('Principal', {})
                    has_wildcard_principal = (
                        principal == '*' or 
                        principal == {"AWS": "*"} or 
                        (isinstance(principal.get('AWS'), list) and '*' in principal['AWS'])
                    )
                    
                    if has_wildcard_principal:
                        # Check Action
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Check for sns:subscribe or sns:receive
                        has_subscribe_access = any(
                            action in ['sns:subscribe', 'sns:receive']
                            for action in actions
                        )
                        
                        # Check Condition
                        has_condition = 'Condition' in statement
                        
                        if has_subscribe_access and not has_condition:
                            public_subscribe_statements += 1
        
        result = {
            "type": "sns_topic_policy_prohibit_subscription_access",
            "resource": topic_arn,
            "status": "alarm" if public_subscribe_statements > 0 else "ok",
            "reason": f"{topic_name} contains {public_subscribe_statements} statements that allows subscribe access without condition." 
                     if public_subscribe_statements > 0 
                     else f"{topic_name} does not allow subscribe access without condition.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

def check_sns_topic_policy_prohibit_cross_account_access(topics: Dict, account_id: str) -> List[Dict[str, Any]]:
    """Check if SNS topics have policies that allow cross-account access"""
    results = []
    
    for topic_arn, topic_data in topics.items():
        attributes = topic_data['attributes']
        topic_name = topic_data['name']
        region = topic_data['region']
        
        policy = json.loads(attributes.get('Policy', '{}'))
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
            "reason": f"{topic_name} contains {cross_account_statements} statements that allows cross account access." 
                     if cross_account_statements > 0 
                     else f"{topic_name} does not allow cross account access.",
            "region": region,
            "account": account_id
        }
        results.append(result)
    
    return results

@app.route('/check-sns')
def check_sns():
    try:
        session = boto3.Session(
            aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY']
        )
        
        # Get AWS account ID
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Get all SNS topics
        topics = get_all_sns_topics(session)
        
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Check SNS topic encryption
            encryption_results = check_sns_topic_encrypted_at_rest(topics, account_id)
            for result in encryption_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)
            
            # Check SNS topic public access policies
            policy_results = check_sns_topic_policy_prohibit_public_access(topics, account_id)
            for result in policy_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)
            
            # Check SNS topic notification delivery status
            delivery_results = check_sns_topic_notification_delivery_status_enabled(topics, account_id)
            for result in delivery_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)
            
            # Check SNS topic publishing access policies
            publish_results = check_sns_topic_policy_prohibit_publishing_access(topics, account_id)
            for result in publish_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)
            
            # Check SNS topic subscription access policies
            subscribe_results = check_sns_topic_policy_prohibit_subscription_access(topics, account_id)
            for result in subscribe_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)
            
            # Check SNS topic cross-account access policies
            cross_account_results = check_sns_topic_policy_prohibit_cross_account_access(topics, account_id)
            for result in cross_account_results:
                cur.execute(
                    """
                    INSERT INTO aws_project_status (description, resource, status)
                    VALUES (%s, %s, %s)
                    """,
                    (result['reason'], result['resource'], result['status'])
                )
                all_results.append(result)

            conn.commit()
            return jsonify(all_results)

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
