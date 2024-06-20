import boto3
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def assume_role(account_id, role_name="AWSReservedSSO_AWSOrganizationFullAccess"):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CrossAccountSession",
            DurationSeconds=3600  # Optional: specify session duration
        )
        credentials = assumed_role['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
    except Exception as e:
        logger.error(f"Failed to assume role for account {account_id}: {str(e)}")
        return None

def get_all_accounts():
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator('list_accounts')
    accounts = [account for page in paginator.paginate() for account in page['Accounts']]
    return accounts

def get_untagged_ec2_instances(session):
    ec2_client = session.client('ec2')
    instances = ec2_client.describe_instances()
    untagged_instances = [
        instance['InstanceId']
        for reservation in instances['Reservations']
        for instance in reservation['Instances']
        if 'map-migrated' not in {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])} or
           'map-dba' not in {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
    ]
    return untagged_instances

def get_untagged_s3_buckets(session):
    s3_client = session.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    untagged_buckets = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            tags = s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
        except s3_client.exceptions.NoSuchTagSet:
            tags = []
        tag_keys = {tag['Key'] for tag in tags}
        if 'map-migrated' not in tag_keys or 'map-dba' not in tag_keys:
            untagged_buckets.append(bucket_name)

    return untagged_buckets

def get_untagged_rds_instances(session):
    rds_client = session.client('rds')
    instances = rds_client.describe_db_instances()['DBInstances']
    untagged_instances = [
        instance['DBInstanceIdentifier']
        for instance in instances
        if 'map-migrated' not in {tag['Key'] for tag in rds_client.list_tags_for_resource(ResourceName=instance['DBInstanceArn']).get('TagList', [])} or
           'map-dba' not in {tag['Key'] for tag in rds_client.list_tags_for_resource(ResourceName=instance['DBInstanceArn']).get('TagList', [])}
    ]
    return untagged_instances

def check_resources(session):
    return {
        'ec2_instances': get_untagged_ec2_instances(session),
        's3_buckets': get_untagged_s3_buckets(session),
        'rds_instances': get_untagged_rds_instances(session),
    }

def lambda_handler(event, context):
    accounts = get_all_accounts()
    untagged_resources_report = {}

    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']
        logger.info(f"Checking account {account_name} ({account_id})")
        
        session = assume_role(account_id)
        if session is None:
            continue
        
        try:
            untagged_resources = check_resources(session)
            if any(untagged_resources.values()):
                untagged_resources_report[account_name] = untagged_resources
        except Exception as e:
            logger.error(f"Error checking resources in account {account_name} ({account_id}): {str(e)}")
    
    logger.info("Untagged Resources Report: %s", untagged_resources_report)

    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if sns_topic_arn:
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=str(untagged_resources_report),
            Subject="Untagged Resources Report"
        )

    return untagged_resources_report
