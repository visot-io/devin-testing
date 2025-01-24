from flask import Flask, jsonify
import boto3
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
import configparser
import json
import re
import concurrent.futures
from functools import partial

app = Flask(__name__)

# Cache for API calls
function_url_config_cache = {}

def get_cached_function_url_config(lambda_client, function_name: str) -> Dict:
    """Get function URL configuration with caching"""
    cache_key = f"{lambda_client._endpoint.host}:{function_name}"
    if cache_key not in function_url_config_cache:
        try:
            function_url_config_cache[cache_key] = lambda_client.get_function_url_config(FunctionName=function_name)
        except lambda_client.exceptions.ResourceNotFoundException:
            function_url_config_cache[cache_key] = None
    return function_url_config_cache[cache_key]

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

LAMBDA_LATEST_RUNTIMES = [
    'python3.12%', 'python3.11%',  # Python latest
    'nodejs20.x%', 'nodejs18.x%',  # Node.js latest
    'java21%', 'java17%',          # Java latest
    'dotnet7%', 'dotnet6%',        # .NET latest
    'ruby3.2%',                    # Ruby latest
    'provided.al2023%'             # Custom runtime latest
]

LAMBDA_DEPRECATED_RUNTIMES = [
    'python3.7%', 'python3.6%', 'python2.7%',  # Python deprecated
    'nodejs16.x%', 'nodejs14.x%', 'nodejs12.x%', 'nodejs10.x%', 'nodejs8.10%', 'nodejs6.10%', 'nodejs4.3%',  # Node.js deprecated
    'java8%', 'java8.al2%',  # Java deprecated
    'dotnet5%', 'dotnet3.1%', 'dotnet2.1%',  # .NET deprecated
    'ruby2.7%', 'ruby2.5%',  # Ruby deprecated
    'provided%', 'provided.al2%'  # Custom runtime deprecated
]

def get_db_connection():
    return psycopg2.connect(
        host=config['PostgreSQL']['HOST'],
        database=config['PostgreSQL']['DATABASE'],
        user=config['PostgreSQL']['USER'],
        password=config['PostgreSQL']['PASSWORD']
    )

def check_lambda_function_dead_letter_queue(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has dead letter queue configured"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        dlq_arn = function.get('DeadLetterConfig', {}).get('TargetArn')
        
        return {
            "type": "lambda_function_dead_letter_queue_configured",
            "resource": function_arn,
            "status": "ok" if dlq_arn else "alarm",
            "reason": f"{function_name} configured with dead-letter queue." if dlq_arn 
                     else f"{function_name} not configured with dead-letter queue.",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function DLQ {function_name}: {str(e)}")
        return None

def check_lambda_function_in_vpc(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function is in VPC"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        vpc_config = function.get('VpcConfig', {})
        vpc_id = vpc_config.get('VpcId')
        
        return {
            "type": "lambda_function_in_vpc",
            "resource": function_arn,
            "status": "ok" if vpc_id else "alarm",
            "reason": f"{function_name} is in VPC {vpc_id}." if vpc_id 
                     else f"{function_name} is not in VPC.",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function VPC {function_name}: {str(e)}")
        return None

def check_lambda_function_restrict_public_access(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function allows public access"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Get the function policy
        try:
            policy_response = lambda_client.get_policy(FunctionName=function_name)
            policy = json.loads(policy_response['Policy'])
            
            # Count statements that allow public access
            public_statements = 0
            if 'Statement' in policy:
                for statement in policy['Statement']:
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        if principal == '*' or principal == {"AWS": "*"} or (
                            isinstance(principal.get('AWS'), list) and '*' in principal['AWS']
                        ):
                            public_statements += 1
            
            return {
                "type": "lambda_function_restrict_public_access",
                "resource": function_arn,
                "status": "ok" if public_statements == 0 else "alarm",
                "reason": f"{function_name} does not allow public access." if public_statements == 0
                         else f"{function_name} contains {public_statements} statements that allows public access.",
                "region": region,
                "account": account_id
            }
            
        except lambda_client.exceptions.ResourceNotFoundException:
            # No policy attached means no public access
            return {
                "type": "lambda_function_restrict_public_access",
                "resource": function_arn,
                "status": "ok",
                "reason": f"{function_name} does not allow public access.",
                "region": region,
                "account": account_id
            }
            
    except Exception as e:
        print(f"Error checking Lambda function public access {function_name}: {str(e)}")
        return None

def check_lambda_function_concurrent_execution_limit(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has concurrent execution limit configured"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        try:
            # Get detailed function configuration
            function_config = lambda_client.get_function(FunctionName=function_name)['Configuration']
            reserved_concurrent_executions = function_config.get('ReservedConcurrentExecutions')
            
            return {
                "type": "lambda_function_concurrent_execution_limit_configured",
                "resource": function_arn,
                "status": "ok" if reserved_concurrent_executions is not None else "alarm",
                "reason": f"{function_name} function-level concurrent execution limit configured." 
                         if reserved_concurrent_executions is not None 
                         else f"{function_name} function-level concurrent execution limit not configured.",
                "region": region,
                "account": account_id
            }
        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"Function {function_name} not found")
            return None
        except Exception as e:
            # Handle all other errors including permission issues
            error_message = str(e)
            if 'AccessDenied' in error_message:
                return {
                    "type": "lambda_function_concurrent_execution_limit_configured",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Access denied checking concurrent execution limit for {function_name}",
                    "region": region,
                    "account": account_id
                }
            else:
                print(f"Error getting function configuration for {function_name}: {error_message}")
                return {
                    "type": "lambda_function_concurrent_execution_limit_configured",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Error checking concurrent execution limit for {function_name}: {error_message}",
                    "region": region,
                    "account": account_id
                }
            
    except Exception as e:
        print(f"Error checking Lambda function concurrent execution limit {function_name}: {str(e)}")
        return None

def get_lambda_logging_cloudtrails(cloudtrail_client) -> Dict[str, List[str]]:
    """Get Lambda functions with CloudTrail logging enabled"""
    function_specific_arns = set()
    region_wide_logging = set()
    advanced_logging_regions = set()
    
    try:
        paginator = cloudtrail_client.get_paginator('list_trails')
        for page in paginator.paginate():
            for trail in page['Trails']:
                trail_arn = trail['TrailARN']
                trail_region = trail['HomeRegion']
                
                # Get trail configuration
                trail_info = cloudtrail_client.get_trail(Name=trail_arn)
                if not trail_info.get('Trail', {}).get('IsMultiRegionTrail'):
                    continue
                
                # Get event selectors
                try:
                    # Get standard event selectors
                    selectors = cloudtrail_client.get_event_selectors(TrailName=trail_arn)
                    for selector in selectors.get('EventSelectors', []):
                        for data_resource in selector.get('DataResources', []):
                            if data_resource.get('Type') == 'AWS::Lambda::Function':
                                for value in data_resource.get('Values', []):
                                    clean_arn = value.replace('"', '').replace('/', '')
                                    if clean_arn == 'arn:aws:lambda':
                                        region_wide_logging.add(trail_region)
                                    else:
                                        function_specific_arns.add(clean_arn)
                    
                    # Try to get advanced event selectors
                    try:
                        advanced_selectors = cloudtrail_client.get_trail_status(Name=trail_arn)
                        if advanced_selectors.get('HasCustomEventSelectors', False):
                            for selector in advanced_selectors.get('AdvancedEventSelectors', []):
                                for field_selector in selector.get('FieldSelectors', []):
                                    if (field_selector.get('Field') != 'eventCategory' and 
                                        'AWS::Lambda::Function' in field_selector.get('Equals', [])):
                                        advanced_logging_regions.add(trail_region)
                    except Exception as e:
                        print(f"Error getting advanced event selectors for trail {trail_arn}: {str(e)}")
                        
                except Exception as e:
                    print(f"Error getting event selectors for trail {trail_arn}: {str(e)}")
                    continue
                    
    except Exception as e:
        print(f"Error getting CloudTrail trails: {str(e)}")
    
    return {
        'function_arns': function_specific_arns,
        'region_logging': region_wide_logging,
        'advanced_logging': advanced_logging_regions
    }

def check_lambda_function_cloudtrail_logging(lambda_client, function: Dict, cloudtrail_info: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has CloudTrail logging enabled"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Check if function has logging enabled
        has_logging = (
            function_arn in cloudtrail_info['function_arns'] or
            region in cloudtrail_info['region_logging'] or
            region in cloudtrail_info['advanced_logging']
        )
        
        return {
            "type": "lambda_function_cloudtrail_logging_enabled",
            "resource": function_arn,
            "status": "ok" if has_logging else "alarm",
            "reason": f"{function_name} logging enabled." if has_logging 
                     else f"{function_name} logging not enabled.",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function CloudTrail logging {function_name}: {str(e)}")
        return None

def check_lambda_function_tracing(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has tracing enabled"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Get tracing configuration
        tracing_config = function.get('TracingConfig', {})
        tracing_mode = tracing_config.get('Mode', 'PassThrough')
        
        return {
            "type": "lambda_function_tracing_enabled",
            "resource": function_arn,
            "status": "alarm" if tracing_mode == 'PassThrough' else "ok",
            "reason": f"{function_name} has tracing disabled." if tracing_mode == 'PassThrough'
                     else f"{function_name} has tracing enabled.",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function tracing {function_name}: {str(e)}")
        return None

def get_subnet_az_count(ec2_client, subnet_ids: List[str]) -> int:
    """Get the number of unique availability zones for given subnet IDs"""
    try:
        if not subnet_ids:
            return 0
            
        response = ec2_client.describe_subnets(SubnetIds=subnet_ids)
        unique_azs = {subnet['AvailabilityZoneId'] for subnet in response['Subnets']}
        return len(unique_azs)
    except Exception as e:
        print(f"Error getting subnet AZ information: {str(e)}")
        return 0

def check_lambda_function_multiple_az(lambda_client, ec2_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function is configured with multiple AZs"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        vpc_config = function.get('VpcConfig', {})
        vpc_id = vpc_config.get('VpcId')
        subnet_ids = vpc_config.get('SubnetIds', [])
        
        # If not in VPC, skip the check
        if not vpc_id:
            return {
                "type": "lambda_function_multiple_az_configured",
                "resource": function_arn,
                "status": "skip",
                "reason": f"{function_name} is not in VPC.",
                "region": region,
                "account": account_id
            }
        
        # Count unique AZs
        az_count = get_subnet_az_count(ec2_client, subnet_ids)
        
        return {
            "type": "lambda_function_multiple_az_configured",
            "resource": function_arn,
            "status": "ok" if az_count >= 2 else "alarm",
            "reason": f"{function_name} has {len(subnet_ids)} availability zone(s).",
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function multiple AZ {function_name}: {str(e)}")
        return None

# Update the runtime lists to include python3.10
LAMBDA_LATEST_RUNTIMES = [
    'python3.12%', 'python3.11%', 'python3.10%',  # Python latest
    'nodejs20.x%', 'nodejs18.x%',                 # Node.js latest
    'java21%', 'java17%',                        # Java latest
    'dotnet7%', 'dotnet6%',                      # .NET latest
    'ruby3.2%',                                  # Ruby latest
    'provided.al2023%'                           # Custom runtime latest
]

LAMBDA_DEPRECATED_RUNTIMES = [
    'python3.9%', 'python3.8%', 'python3.7%', 'python3.6%', 'python2.7%',  # Python deprecated
    'nodejs16.x%', 'nodejs14.x%', 'nodejs12.x%', 'nodejs10.x%', 'nodejs8.10%', 'nodejs6.10%', 'nodejs4.3%',  # Node.js deprecated
    'java8%', 'java8.al2%',  # Java deprecated
    'dotnet5%', 'dotnet3.1%', 'dotnet2.1%',  # .NET deprecated
    'ruby2.7%', 'ruby2.5%',  # Ruby deprecated
    'provided%', 'provided.al2%'  # Custom runtime deprecated
]

def check_lambda_function_runtime(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function uses the latest runtime"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        package_type = function.get('PackageType', 'Zip')
        runtime = function.get('Runtime', '')
        
        # Skip check for non-Zip package types
        if package_type != 'Zip':
            return {
                "type": "lambda_function_use_latest_runtime",
                "resource": function_arn,
                "status": "skip",
                "reason": f"{function_name} package type is {package_type}.",
                "region": region,
                "account": account_id
            }
        
        # Check runtime version
        is_latest = any(runtime.startswith(r.replace('%', '')) for r in LAMBDA_LATEST_RUNTIMES)
        is_deprecated = any(runtime.startswith(r.replace('%', '')) for r in LAMBDA_DEPRECATED_RUNTIMES)
        
        if is_latest:
            status = "ok"
            reason = f"{function_name} uses latest runtime - {runtime}."
        elif is_deprecated:
            status = "alarm"
            reason = f"{function_name} uses {runtime} which is not the latest version."
        else:
            status = "info"
            reason = f"{function_name} uses runtime {runtime} which is yet to be released."
            
        return {
            "type": "lambda_function_use_latest_runtime",
            "resource": function_arn,
            "status": status,
            "reason": reason,
            "region": region,
            "account": account_id
        }
    except Exception as e:
        print(f"Error checking Lambda function runtime {function_name}: {str(e)}")
        return None

def check_lambda_function_restrict_public_url(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function restricts public URL access"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        try:
            # Try to get URL configuration using GetFunctionUrlConfig with caching
            url_config = get_cached_function_url_config(lambda_client, function_name)
            if url_config is None:
                return {
                    "type": "lambda_function_restrict_public_url",
                    "resource": function_arn,
                    "status": "info",
                    "reason": f"{function_name} having no URL config.",
                    "region": region,
                    "account": account_id
                }
            
            auth_type = url_config.get('AuthType')
            return {
                "type": "lambda_function_restrict_public_url",
                "resource": function_arn,
                "status": "ok" if auth_type == 'AWS_IAM' else "alarm",
                "reason": (f"{function_name} restricts public function URL." 
                          if auth_type == 'AWS_IAM' 
                          else f"{function_name} public function URL configured."),
                "region": region,
                "account": account_id
            }
            
        except lambda_client.exceptions.ResourceNotFoundException:
            # No URL config exists
            return {
                "type": "lambda_function_restrict_public_url",
                "resource": function_arn,
                "status": "info",
                "reason": f"{function_name} having no URL config.",
                "region": region,
                "account": account_id
            }
        except Exception as e:
            # Handle all other errors including permission issues
            error_message = str(e)
            if 'AccessDenied' in error_message:
                return {
                    "type": "lambda_function_restrict_public_url",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Access denied checking URL config for {function_name}",
                    "region": region,
                    "account": account_id
                }
            else:
                print(f"Error getting URL config for {function_name}: {error_message}")
                return {
                    "type": "lambda_function_restrict_public_url",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Error checking URL config for {function_name}: {error_message}",
                    "region": region,
                    "account": account_id
                }
            
    except Exception as e:
        print(f"Error checking Lambda function public URL {function_name}: {str(e)}")
        return None

def has_sensitive_pattern(text: str) -> bool:
    """Check if text contains sensitive data patterns"""
    # Pattern for password complexity (at least one uppercase, lowercase, number, and special character)
    complex_pattern = r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]'
    
    # Check for common sensitive keywords
    sensitive_keywords = ['pass', 'secret', 'token', 'key']
    
    # Convert to lowercase for case-insensitive keyword check
    text_lower = text.lower()
    
    # Check for keywords
    if any(keyword in text_lower for keyword in sensitive_keywords):
        return True
        
    # Check for complex password pattern
    if re.search(complex_pattern, text):
        return True
        
    return False

def check_lambda_function_variables_no_sensitive_data(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function environment variables contain sensitive data"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Get environment variables
        env_vars = function.get('Environment', {}).get('Variables', {})
        
        # Check both keys and values for sensitive data
        has_sensitive_data = False
        for key, value in env_vars.items():
            if has_sensitive_pattern(key) or has_sensitive_pattern(str(value)):
                has_sensitive_data = True
                break
        
        return {
            "type": "lambda_function_variables_no_sensitive_data",
            "resource": function_arn,
            "status": "alarm" if has_sensitive_data else "ok",
            "reason": f"{function_name} has potential sensitive data." 
                     if has_sensitive_data 
                     else f"{function_name} has no sensitive data.",
            "region": region,
            "account": account_id
        }
            
    except Exception as e:
        print(f"Error checking Lambda function environment variables {function_name}: {str(e)}")
        return None

def check_lambda_function_cloudwatch_insights(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has CloudWatch Insights enabled"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Get layers
        layers = function.get('Layers', [])
        
        # Check for Lambda Insights Extension layer
        has_insights = any(
            'layer:LambdaInsightsExtension:' in layer.get('Arn', '')
            for layer in layers
        )
        
        return {
            "type": "lambda_function_cloudwatch_insights_enabled",
            "resource": function_arn,
            "status": "ok" if has_insights else "alarm",
            "reason": f"{function_name} CloudWatch Insights enabled." 
                     if has_insights 
                     else f"{function_name} CloudWatch Insights disabled.",
            "region": region,
            "account": account_id
        }
            
    except Exception as e:
        print(f"Error checking Lambda function CloudWatch Insights {function_name}: {str(e)}")
        return None

def check_lambda_function_encryption(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has encryption enabled"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        # Check for KMS key ARN
        kms_key_arn = function.get('KMSKeyArn')
        
        return {
            "type": "lambda_function_encryption_enabled",
            "resource": function_arn,
            "status": "ok" if kms_key_arn else "alarm",
            "reason": f"{function_name} encryption is enabled." 
                     if kms_key_arn 
                     else f"{function_name} encryption is disabled.",
            "region": region,
            "account": account_id
        }
            
    except Exception as e:
        print(f"Error checking Lambda function encryption {function_name}: {str(e)}")
        return None

def check_lambda_function_cors_configuration(lambda_client, function: Dict, account_id: str) -> Dict[str, Any]:
    """Check if Lambda function has secure CORS configuration"""
    try:
        function_arn = function['FunctionArn']
        function_name = function['FunctionName']
        region = function_arn.split(':')[3]
        
        try:
            # Try to get URL configuration using GetFunctionUrlConfig with caching
            url_config = get_cached_function_url_config(lambda_client, function_name)
            if url_config is None:
                return {
                    "type": "lambda_function_cors_configuration",
                    "resource": function_arn,
                    "status": "info",
                    "reason": f"{function_name} does not has a URL config.",
                    "region": region,
                    "account": account_id
                }
            
            # Check CORS configuration
            cors_config = url_config.get('Cors', {})
            allow_origins = cors_config.get('AllowOrigins', [])
            
            # Check if all origins are allowed
            allows_all_origins = '*' in allow_origins
            
            return {
                "type": "lambda_function_cors_configuration",
                "resource": function_arn,
                "status": "alarm" if allows_all_origins else "ok",
                "reason": f"{function_name} CORS configuration allows all origins." 
                         if allows_all_origins 
                         else f"{function_name} CORS configuration does not allow all origins.",
                "region": region,
                "account": account_id
            }
            
        except lambda_client.exceptions.ResourceNotFoundException:
            # No URL config exists
            return {
                "type": "lambda_function_cors_configuration",
                "resource": function_arn,
                "status": "info",
                "reason": f"{function_name} does not has a URL config.",
                "region": region,
                "account": account_id
            }
        except Exception as e:
            # Handle all other errors including permission issues
            error_message = str(e)
            if 'AccessDenied' in error_message:
                return {
                    "type": "lambda_function_cors_configuration",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Access denied checking CORS configuration for {function_name}",
                    "region": region,
                    "account": account_id
                }
            else:
                print(f"Error getting URL config for {function_name}: {error_message}")
                return {
                    "type": "lambda_function_cors_configuration",
                    "resource": function_arn,
                    "status": "error",
                    "reason": f"Error checking CORS configuration for {function_name}: {error_message}",
                    "region": region,
                    "account": account_id
                }
            
    except Exception as e:
        print(f"Error checking Lambda function CORS configuration {function_name}: {str(e)}")
        return None

@app.route('/check-lambda')
def process_region(region: str, session: boto3.Session, cloudtrail_info: Dict, account_id: str) -> List[Dict]:
    """Process all Lambda functions in a single region"""
    region_results = []
    try:
        lambda_client = session.client('lambda', region_name=region)
        ec2_client = session.client('ec2', region_name=region)
        
        try:
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    # Run each check
                    checks = [
                        check_lambda_function_dead_letter_queue(lambda_client, function, account_id),
                        check_lambda_function_in_vpc(lambda_client, function, account_id),
                        check_lambda_function_restrict_public_access(lambda_client, function, account_id),
                        check_lambda_function_concurrent_execution_limit(lambda_client, function, account_id),
                        check_lambda_function_cloudtrail_logging(lambda_client, function, cloudtrail_info, account_id),
                        check_lambda_function_tracing(lambda_client, function, account_id),
                        check_lambda_function_multiple_az(lambda_client, ec2_client, function, account_id),
                        check_lambda_function_runtime(lambda_client, function, account_id),
                        check_lambda_function_restrict_public_url(lambda_client, function, account_id),
                        check_lambda_function_variables_no_sensitive_data(lambda_client, function, account_id),
                        check_lambda_function_cloudwatch_insights(lambda_client, function, account_id),
                        check_lambda_function_encryption(lambda_client, function, account_id),
                        check_lambda_function_cors_configuration(lambda_client, function, account_id)
                    ]
                    
                    # Filter out None results and add valid ones
                    region_results.extend([r for r in checks if r])
                    
        except lambda_client.exceptions.ResourceNotFoundException:
            print(f"No Lambda functions found in region {region}")
        except Exception as e:
            print(f"Error processing region {region}: {str(e)}")
            
    except Exception as e:
        print(f"Error setting up clients for region {region}: {str(e)}")
        
    return region_results

def batch_insert_results(cur: psycopg2.extensions.cursor, results: List[Dict]) -> None:
    """Insert multiple results into the database in a single batch"""
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

def get_aws_session():
    """Get a reusable AWS session"""
    return boto3.Session(
        aws_access_key_id=config['AWS']['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=config['AWS']['AWS_SECRET_ACCESS_KEY']
    )

def get_aws_regions(session: boto3.Session) -> List[str]:
    """Get list of AWS regions"""
    ec2_client = session.client('ec2', region_name='us-east-1')
    return [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

def check_lambda():
    try:
        # Create a single session for reuse
        session = get_aws_session()
        
        # Get AWS account ID once
        sts_client = session.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
        
        # Get CloudTrail logging information once
        cloudtrail_client = session.client('cloudtrail', region_name='us-east-1')
        cloudtrail_info = get_lambda_logging_cloudtrails(cloudtrail_client)
        
        # Get all regions once
        regions = get_aws_regions(session)
        
        all_results = []
        conn = get_db_connection()
        cur = conn.cursor()

        try:
            # Process regions in parallel using ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                # Create a partial function with the common arguments
                process_region_partial = partial(
                    process_region,
                    session=session,
                    cloudtrail_info=cloudtrail_info,
                    account_id=account_id
                )
                
                # Submit all regions for processing
                future_to_region = {
                    executor.submit(process_region_partial, region): region
                    for region in regions
                }
                
                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_region):
                    region = future_to_region[future]
                    try:
                        region_results = future.result()
                        if region_results:
                            # Batch insert results for this region
                            batch_insert_results(cur, region_results)
                            all_results.extend(region_results)
                    except Exception as e:
                        print(f"Error processing region {region}: {str(e)}")

            conn.commit()
            return jsonify({
                "status": "success",
                "data": all_results,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_checks": len(all_results),
                    "ok": len([r for r in all_results if r['status'] == 'ok']),
                    "alarm": len([r for r in all_results if r['status'] == 'alarm']),
                    "error": len([r for r in all_results if r['status'] == 'error'])
                }
            })

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
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 500

if __name__ == '__main__':
    app.run(debug=True, port=5003)
