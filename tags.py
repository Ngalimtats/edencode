import boto3
import os

def assume_role(account_id, role_name="OrganizationAccountAccessRole"):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="CrossAccountSession"
    )
    
    credentials = assumed_role['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
    )

def get_all_accounts():
    org_client = boto3.client('organizations')
    paginator = org_client.get_paginator('list_accounts')
    accounts = []
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def check_ec2_instances(session):
    ec2_client = session.client('ec2')
    instances = ec2_client.describe_instances()
    untagged_resources = []

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            if 'map-migrated' not in tags or 'map-dba' not in tags:
                untagged_resources.append(instance['InstanceId'])

    return untagged_resources

def check_s3_buckets(session):
    s3_client = session.client('s3')
    buckets = s3_client.list_buckets()['Buckets']
    untagged_resources = []

    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            tags = s3_client.get_bucket_tagging(Bucket=bucket_name).get('TagSet', [])
        except s3_client.exceptions.NoSuchTagSet:
            tags = []
        tag_keys = {tag['Key'] for tag in tags}
        if 'map-migrated' not in tag_keys or 'map-dba' not in tag_keys:
            untagged_resources.append(bucket_name)

    return untagged_resources

def check_rds_instances(session):
    rds_client = session.client('rds')
    instances = rds_client.describe_db_instances()
    untagged_resources = []

    for instance in instances['DBInstances']:
        resource_arn = instance['DBInstanceArn']
        tags = rds_client.list_tags_for_resource(ResourceName=resource_arn).get('TagList', [])
        tag_keys = {tag['Key'] for tag in tags}
        if 'map-migrated' not in tag_keys or 'map-dba' not in tag_keys:
            untagged_resources.append(instance['DBInstanceIdentifier'])

    return untagged_resources

def check_resources(session):
    return {
        'ec2_instances': check_ec2_instances(session),
        's3_buckets': check_s3_buckets(session),
        'rds_instances': check_rds_instances(session),
        #'lambda_functions': check_lambda_functions(session)
    }

def lambda_handler(event, context):
    accounts = get_all_accounts()
    untagged_resources_report = {}

    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']
        try:
            session = assume_role(account_id)
            untagged_resources = check_resources(session)
            if any(untagged_resources.values()):
                untagged_resources_report[account_name] = untagged_resources
        except Exception as e:
            print(f"Error accessing account {account_name} ({account_id}): {str(e)}")
    
    # Output the report, send it via SNS or any preferred method
    print("Untagged Resources Report:", untagged_resources_report)

    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    if sns_topic_arn:
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=str(untagged_resources_report),
            Subject="Untagged Resources Report"
        )

    return untagged_resources_report
