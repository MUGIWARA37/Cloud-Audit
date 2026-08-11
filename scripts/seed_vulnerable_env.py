#!/usr/bin/env python3
"""
Seeds a deliberately vulnerable AWS environment inside LocalStack.
Used to generate real, catchable findings for the CSPM audit pipeline.
Safe to run multiple times — idempotent (won't crash if resources already exist).

Run against LocalStack ONLY. Never point this at a real AWS account.
"""

import json
import boto3
from botocore.exceptions import ClientError

LOCALSTACK_ENDPOINT = "http://localhost:4566"

FAKE_CREDS = {
    "aws_access_key_id": "test",
    "aws_secret_access_key": "test",
    "region_name": "us-east-1",
}


def get_client(service_name):
    """Returns a boto3 client pointed at LocalStack instead of real AWS."""
    return boto3.client(
        service_name,
        endpoint_url=LOCALSTACK_ENDPOINT,
        **FAKE_CREDS,
    )


def seed_public_s3_bucket():
    """
    Creates a bucket and attaches a public-read policy.
    Simulates CIS 2.1.1 — publicly accessible storage.
    Idempotent: safe to re-run even if the bucket already exists.
    """
    s3 = get_client("s3")
    bucket_name = "corporate-data-backup"

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

    # put_bucket_policy is naturally idempotent — re-applying the same
    # policy is always safe, no try/except needed here
    print(f"[SEED] Attaching public-read policy to {bucket_name}")
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))

    print(f"[SEED] Done — {bucket_name} is now publicly readable (CIS 2.1.1 violation)")


def seed_overprivileged_iam_user():
    """
    Creates an IAM user with AdministratorAccess and an active access key.
    Simulates CIS 1.14 — root-equivalent, unrestricted long-lived credentials.
    Idempotent: safe to re-run even if the user already exists.
    """
    iam = get_client("iam")
    user_name = "legacy-automation-user"

    try:
        print(f"[SEED] Creating IAM user: {user_name}")
        iam.create_user(UserName=user_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            print(f"[SEED] User {user_name} already exists, continuing...")
        else:
            raise

    # attach_user_policy is naturally idempotent — attaching an already-attached
    # policy is a safe no-op, no try/except needed
    print(f"[SEED] Attaching AdministratorAccess policy to {user_name}")
    iam.attach_user_policy(
        UserName=user_name,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    # Access keys are trickier: AWS allows max 2 per user, and create_access_key
    # is NOT idempotent (calling it twice creates two different keys).
    # So we check first before creating.
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

if __name__ == "__main__":
    seed_public_s3_bucket()
    seed_overprivileged_iam_user()
    verify_no_password_policy()