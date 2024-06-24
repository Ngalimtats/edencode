import boto3
import os
import logging
import csv
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def lambda_handler(event, context):
    session = boto3.Session()
    account_id = context.invoked_function_arn.split(":")[4]
    account_name = get_account_name(account_id)
    logger.info(f"Checking account {account_name} ({account_id})")

    required_tags = ['map-migrated', 'map-dba']
    
    try:
        untagged_resources = get_untagged_resources(session, required_tags)
        untagged_resources_report = {
            'AccountID': account_id,
            'AccountName': account_name,
            'Resources': untagged_resources
        } if untagged_resources else {}
    except Exception as e:
        logger.error(f"Error checking resources in account {account_name} ({account_id}): {str(e)}")
        return {"error": f"Error checking resources in account {account_name} ({account_id}): {str(e)}"}

    if untagged_resources_report:
        csv_file = write_report_to_csv(untagged_resources_report)
        s3_bucket = os.environ.get('S3_BUCKET')
        if s3_bucket:
            s3_object_name = 'untagged_resource_report.csv'
            upload_file_to_s3(csv_file, s3_bucket, s3_object_name)
            s3_url = f"https://{s3_bucket}.s3.amazonaws.com/{s3_object_name}"

            final_report = f"The following resources have been found not tagged with pps mandatory tags; map-migrated or map-dba:\n"
            final_report += f"Account ID: {untagged_resources_report['AccountID']}, Account Name: {untagged_resources_report['AccountName']}\n"
            for resource in untagged_resources_report['Resources']:
                final_report += f"ResourceARN : {resource['ResourceARN']}, Tags : {resource['Tags']}, Created By: {resource['CreatedBy']}\n"
            logger.info("Untagged Resources Report : %s", final_report)

            notification_message = (
                f"Untagged Resources Report: The Following resources have been found not tagged with any of the pps mandatory tags; "
                f"map-migrated and map-dba: {untagged_resources_report}. PLEASE TAKE ACTIONS ACCORDINGLY !!!\n\n"
                f"Report CSV file: {s3_url}"
            )
            sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
            if sns_topic_arn:
                sns_client = boto3.client('sns')
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Message=notification_message,
                    Subject="Untagged Resources Report"
                )

    logger.info("Untagged Resources Report: %s", untagged_resources_report)
    return untagged_resources_report

# def assume_role(account_id, role_name ="OrganizationalAccountAccessRole"):
#     sts_client = boto3.client('sts')
#     role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
#     try:
#         assumed_role = sts_client.assume_role(
#             RoleArn=role_arn,
#             RoleSessionName="AssumeRoleSession1"
#         )
#         credentials = assumed_role['Credentials']
#         return boto3.Session(
#             aws_access_key_id=credentials['AccessKeyId'],
#             aws_secret_access_key=credentials['SecretAccessKey'],
#             aws_session_token=credentials['SessionToken'],
#         )
#     except Exception as e:
#         logger.error(f"Error assuming role for account {account_id}: {str(e)}")
#         return None


# def get_all_accounts():
#     org_client = boto3.client('organizations')
#     paginator = org_client.get_paginator('list_accounts')
#     accounts = [account for page in paginator.paginate() for account in page ['Accounts']]
#     return accounts


def get_untagged_resources(session, required_tags):
    tagging_client = session.client('resourcegroupstaggingapi')
    paginator = tagging_client.get_paginator('get_resources')
    untagged_resources = []

    for page in paginator.paginate(ResourcesPerPage=100):
        for resource in page['ResourceTagMappingList']:
            tags = {tag['Key']: tag['Value'] for tag in resource.get('Tags', [])}
            resource_arn = resource['ResourceARN']
            if not all(tag in tags for tag in required_tags):
                created_by = determine_creation_source(tags)
                resource_report = {
                    'ResourceARN': resource_arn,
                    'Tags': {
                        'Name': tags.get('name', 'Not Tagged'),
                        'map-migrated': tags.get('map-migrated', 'Not Tagged'),
                        'map-dba': tags.get('map-dba', 'Not Tagged')
                    },
                    'CreatedBy': created_by
                }
                untagged_resources.append(resource_report)
    return untagged_resources

def determine_creation_source(tags):
    # Heuristic to determine the creation source
    if 'terraform' in tags.values():
        return 'Terraform'
    if 'created-by' in tags and tags['created-by'] == 'terraform':
        return 'Terraform'
    if 'managed-by' in tags and tags['managed-by'] == 'terraform':
        return 'Terraform'
    return 'Console'

def write_report_to_csv(report):
    with tempfile.NamedTemporaryFile(mode='w', newline='', delete=False) as csvfile:
        fieldnames = ['AccountID', 'AccountName', 'ResourceARN', 'Name', 'map-migrated', 'map-dba', 'CreatedBy']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for resource in report['Resources']:
            writer.writerow({
                'AccountID': report['AccountID'],
                'AccountName': report['AccountName'],
                'ResourceARN': resource['ResourceARN'],
                'Name': resource['Tags']['Name'],
                'map-migrated': resource['Tags']['map-migrated'],
                'map-dba': resource['Tags']['map-dba'],
                'CreatedBy': resource['CreatedBy']
            })
        return csvfile.name
    
def upload_file_to_s3(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = os.path.basename(file_name)
    
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(file_name, bucket, object_name)
        logger.info(f"File uploaded to s3: s3://{bucket}/{object_name}")
    except Exception as e:
        logger.error(f"Failed to upload file to s3: {str(e)}")

def get_account_name(account_id):
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(AccountId=account_id)
        return response['Account']['Name']
    except Exception as e:
        logger.error(f"Error describing account {account_id}: {str(e)}")
        return "Unknown Account Name"









#Using AWS Resources for a single region
import boto3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def lambda_handler(event, context):
    session = boto3.Session()
    account_id = context.invoked_function_arn.split(":")[4]
    account_name = get_account_name(account_id)
    
    logger.info("Checking account {account_name} ({account_id})")

    required_tags = ['map-migrated', 'map-dba']
    try:
        untagged_resources = get_untagged_resources(session, required_tags)
        untagged_resources_report = {
            'AcountID': account_id,
            'AccountName': account_name,
            'Resources' : untagged_resources
        } if untagged_resources else {}
    except Exception as e:
        logger.error(f"Error checking resources in account {account_name} ({account_id}): {str(e)}")
        return{"error": f"Error checking resources in account {account_name} ({account_id}): {str(e)}"}
    
    logger.info("Untagged Resources Report: %s", untagged_resources_report)

    notification_message = f"Untagged Resources Report: The Following resources have been found not tagged with any of the pps mandatory tags;  map-migrated and map-dba: {untagged_resources_report}. PLEASE TAKE ACTIONS ACCORDINGLY !!!"
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if sns_topic_arn and untagged_resources_report:
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=notification_message,
            Subject="Untagged Resources Report"
        )
    
    return untagged_resources_report

def get_untagged_resources(session, required_tags):     
    explorer_client = session.client('resource-explorer-2')
    query = "tags.map-migrated:false AND tags.map-dba:false"
    untagged_resources = []

    try:
        response = explorer_client.search(QueryString=query,MaxResults=100)
        for resource in response['Results']:
            resource_arn = resource['Arn']
            tags = {tag['key']: tag['value'] for tag in resource.get('Tags', [])}
            resource_report = {
               'ResourceARN': resource_arn,
                    'Tags': {
                        'Name': tags.get('name', 'Not Tagged'),
                        'map-migrated': tags.get('map-migrated', 'Not Tagged'),
                        'map-dba': tags.get('map-dba', 'Not Tagged')
                    } 
            }
            untagged_resources.append(resource_report)
    except Exception as e:
        logger.error(f"Failed to search for untagged resources: {str(e)}")
    return untagged_resources

  
def get_account_name(account_id):
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(AccountId=account_id)
        return response['Account']['Name']
    except Exception as e:
        logger.error(f"Failed to retrieve account name for account {account_id}: {str(e)}")
        return "Unknown Account Name"
    
   





  
#Using AWS Resource Explorer for all regions
import boto3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def lambda_handler(event, context):
    session = boto3.Session()
    account_id = context.invoked_function_arn.split(":")[4]
    account_name = get_account_name(account_id)
    
    logger.info("Checking account {account_name} ({account_id})")

    required_tags = ['map-migrated', 'map-dba']
    try:
        untagged_resources = get_untagged_resources(session, required_tags)
        untagged_resources_report = {
            'AcountID': account_id,
            'AccountName': account_name,
            'Resources' : untagged_resources
        } if untagged_resources else {}
    except Exception as e:
        logger.error(f"Error checking resources in account {account_name} ({account_id}): {str(e)}")
        return{"error": f"Error checking resources in account {account_name} ({account_id}): {str(e)}"}
    
    logger.info("Untagged Resources Report: %s", untagged_resources_report)

    notification_message = f"Untagged Resources Report: The Following resources have been found not tagged with any of the pps mandatory tags;  map-migrated and map-dba: {untagged_resources_report}. PLEASE TAKE ACTIONS ACCORDINGLY !!!"
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if sns_topic_arn and untagged_resources_report:
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=notification_message,
            Subject="Untagged Resources Report"
        )
    
    return untagged_resources_report

def get_untagged_resources_in_region(session, region, required_tags):     
    explorer_client = session.client('resource-explorer-2', region)
    query = "tags.map-migrated:false AND tags.map-dba:false"
    untagged_resources = []

    try:
        response = explorer_client.search(QueryString=query,MaxResults=100)
        for resource in response['Results']:
            resource_arn = resource['Arn']
            tags = {tag['key']: tag['value'] for tag in resource.get('Tags', [])}
            resource_report = {
               'ResourceARN': resource_arn,
                    'Tags': {
                        'Name': tags.get('name', 'Not Tagged'),
                        'map-migrated': tags.get('map-migrated', 'Not Tagged'),
                        'map-dba': tags.get('map-dba', 'Not Tagged')
                    } 
            }
            untagged_resources.append(resource_report)
    except Exception as e:
        logger.error(f"Failed to search for untagged resources in region {region}: {str(e)}")
    return untagged_resources


def get_untagged_resources(session, required_tags):
    all_regions = get_all_regions()
    all_untagged_resources = []

    for region in all_regions:
        logger.info(f"Checking region {region}")
        untagged_resources = get_untagged_resources_in_region(session, region, required_tags)
        all_untagged_resources.extend(untagged_resources)
    return all_untagged_resources

  

def get_all_regions():
    ec2_client = boto3.client('ec2')
    regions = ec2_client.describe_regions()
    return [region['RegionName'] for region in regions['Regions']]


def get_account_name(account_id):
    org_client = boto3.client('organizations')
    try:
        response = org_client.describe_account(AccountId=account_id)
        return response['Account']['Name']
    except Exception as e:
        logger.error(f"Failed to retrieve account name for account {account_id}: {str(e)}")
        return "Unknown Account Name"