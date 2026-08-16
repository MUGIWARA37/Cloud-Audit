#!/usr/bin/env python3
"""
Seeds a deliberately vulnerable AWS environment inside LocalStack.
Used to generate real, catchable findings for the CSPM audit pipeline.
Safe to run multiple times — idempotent (won't crash if resources already exist).

Run against LocalStack ONLY. Never point this at a real AWS account.
"""

import json
import os
import sys
import boto3
from botocore.exceptions import ClientError


def get_client(service_name):
    """
    Returns a boto3 client configured from environment variables.
    Requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_DEFAULT_REGION.
    Optionally uses AWS_ENDPOINT_URL for LocalStack.
    """
    required_vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_DEFAULT_REGION"]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        print(f"[ERROR] Missing environment variables: {', '.join(missing)}", file=sys.stderr)
        print("[ERROR] Set them before running (see .env.example).", file=sys.stderr)
        sys.exit(1)

    kwargs = {
        "aws_access_key_id": os.environ["AWS_ACCESS_KEY_ID"],
        "aws_secret_access_key": os.environ["AWS_SECRET_ACCESS_KEY"],
        "region_name": os.environ["AWS_DEFAULT_REGION"],
    }

    endpoint = os.environ.get("AWS_ENDPOINT_URL")
    if endpoint:
        kwargs["endpoint_url"] = endpoint

    return boto3.client(service_name, **kwargs)


def seed_public_s3_buckets():
    """
    Creates multiple buckets and attaches public-read policies.
    Simulates CIS 2.1.1 — publicly accessible storage.
    Idempotent: safe to re-run even if buckets already exist.
    """
    s3 = get_client("s3")
    buckets = [
        "corporate-data-backup",
        "hr-public-records",
        "finance-reports-2026",
        "legacy-web-assets",
        "dev-test-data-bucket",
    ]

    for bucket_name in buckets:
        try:
            print(f"[SEED] Creating bucket: {bucket_name}")
            s3.create_bucket(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                print(f"[SEED] Bucket {bucket_name} already exists, continuing...")
            else:
                raise

        public_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadAccess",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }
            ],
        }

        # put_bucket_policy is naturally idempotent
        print(f"[SEED] Attaching public-read policy to {bucket_name}")
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
        print(f"[SEED] Done — {bucket_name} is now publicly readable (CIS 2.1.1 violation)")


def seed_overprivileged_iam_users():
    """
    Creates multiple IAM users with AdministratorAccess and active access keys.
    Simulates CIS 1.14 — root-equivalent, unrestricted long-lived credentials.
    Idempotent: safe to re-run even if the users already exist.
    """
    iam = get_client("iam")
    users = [
        "legacy-automation-user",
        "dev-admin-temp",
        "ci-cd-pipeline-root",
        "external-contractor-admin",
        "test-runner-service",
    ]

    for user_name in users:
        try:
            print(f"[SEED] Creating IAM user: {user_name}")
            iam.create_user(UserName=user_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists":
                print(f"[SEED] User {user_name} already exists, continuing...")
            else:
                raise

        # attach_user_policy is naturally idempotent
        print(f"[SEED] Attaching AdministratorAccess policy to {user_name}")
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )

        existing_keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
        if existing_keys:
            print(f"[SEED] {user_name} already has an access key, skipping creation")
        else:
            print(f"[SEED] Creating long-lived access key for {user_name}")
            response = iam.create_access_key(UserName=user_name)
            access_key_id = response["AccessKey"]["AccessKeyId"]
            print(f"[SEED] Created key {access_key_id}")

        print(f"[SEED] Done — {user_name} has AdministratorAccess + active key (CIS 1.14-equivalent violation)")


def verify_no_password_policy():
    """
    Confirms no IAM account password policy is configured.
    Simulates CIS 1.9 — password policy does not enforce strong passwords.
    """
    iam = get_client("iam")

    print("[SEED] Checking IAM account password policy (expecting none)...")
    try:
        iam.get_account_password_policy()
        print("[SEED] WARNING — a password policy already exists. Environment not clean.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print("[SEED] Confirmed — no IAM password policy configured (CIS 1.9 violation)")
        else:
            raise

def seed_open_ssh_security_groups():
    """
    Creates multiple EC2 security groups with SSH open to the world.
    Simulates CIS 4.1.
    """
    ec2 = get_client("ec2")
    groups = [
        "default-ssh-open",
        "web-tier-ssh",
        "legacy-jump-box",
    ]

    for sg_name in groups:
        try:
            print(f"[SEED] Creating security group: {sg_name}")
            response = ec2.create_security_group(
                GroupName=sg_name,
                Description="Vulnerable SG created by Cloud Audit seed script"
            )
            sg_id = response['GroupId']
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
                print(f"[SEED] Security group {sg_name} already exists, continuing...")
                response = ec2.describe_security_groups(GroupNames=[sg_name])
                sg_id = response['SecurityGroups'][0]['GroupId']
            else:
                raise

        try:
            print(f"[SEED] Authorizing ingress 0.0.0.0/0 on port 22 for {sg_name}")
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
            print(f"[SEED] Done — {sg_name} has unrestricted SSH (CIS 4.1 violation)")
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidPermission.Duplicate":
                print(f"[SEED] Ingress rule already exists on {sg_name}, skipping...")
            else:
                raise

if __name__ == "__main__":
    seed_public_s3_buckets()
    seed_overprivileged_iam_users()
    seed_open_ssh_security_groups()
    verify_no_password_policy()