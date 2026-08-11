#!/usr/bin/env python3
"""
Seeds a deliberately vulnerable AWS environment inside LocalStack.
Used to generate real, catchable findings for the CSPM audit pipeline.

Run against LocalStack ONLY. Never point this at a real AWS account.
"""

import json
import boto3

# LocalStack always listens here by default
LOCALSTACK_ENDPOINT = "http://localhost:4566"

# Fake credentials — LocalStack doesn't validate these, but boto3 requires *something*
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
    """
    s3 = get_client("s3")
    bucket_name = "corporate-data-backup"

    print(f"[SEED] Creating bucket: {bucket_name}")
    s3.create_bucket(Bucket=bucket_name)

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

    print(f"[SEED] Attaching public-read policy to {bucket_name}")
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))

    print(f"[SEED] Done — {bucket_name} is now publicly readable (CIS 2.1.1 violation)")


def seed_overprivileged_iam_user():
    """
    Creates an IAM user with AdministratorAccess and an active access key.
    Simulates CIS 1.14 — root-equivalent, unrestricted long-lived credentials.
    """
    iam = get_client("iam")
    user_name = "legacy-automation-user"

    print(f"[SEED] Creating IAM user: {user_name}")
    iam.create_user(UserName=user_name)

    print(f"[SEED] Attaching AdministratorAccess policy to {user_name}")
    iam.attach_user_policy(
        UserName=user_name,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    print(f"[SEED] Creating long-lived access key for {user_name}")
    response = iam.create_access_key(UserName=user_name)
    access_key_id = response["AccessKey"]["AccessKeyId"]

    print(f"[SEED] Done — {user_name} has AdministratorAccess + active key {access_key_id}")
    print(f"[SEED]   (CIS 1.14-equivalent violation: unrestricted, non-rotated credentials)")


if __name__ == "__main__":
    seed_public_s3_bucket()
    seed_overprivileged_iam_user()