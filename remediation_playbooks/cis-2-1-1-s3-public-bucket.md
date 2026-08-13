# Remediation: CIS 2.1.1 — S3 Bucket Publicly Accessible

## Finding

**Severity:** CRITICAL
**Resource:** `corporate-data-backup`
**Issue:** The bucket has a policy granting `s3:GetObject` to `Principal: "*"`, meaning
anyone on the internet can read its contents without authentication.

## Why This Is Dangerous

A publicly readable bucket exposes all stored objects (documents, backups, credentials,
PII) to the entire internet. Attackers routinely scan for open buckets. This is one of
the most common causes of large-scale data breaches in cloud environments.

## Remediation — AWS CLI

```bash
# Step 1: Remove the public bucket policy entirely
aws s3api delete-bucket-policy --bucket corporate-data-backup

# Step 2: Block ALL public access at the bucket level (belt and suspenders)
aws s3api put-public-access-block --bucket corporate-data-backup \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Step 3: Enable server-side encryption (AES-256 by default)
aws s3api put-bucket-encryption --bucket corporate-data-backup \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
```

## Remediation — Terraform

```hcl
resource "aws_s3_bucket_public_access_block" "corporate_data_backup" {
  bucket = "corporate-data-backup"

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "corporate_data_backup" {
  bucket = "corporate-data-backup"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Remove any existing public bucket policy by not defining one,
# or explicitly set an empty/restricted policy.
```

## Verification

```bash
# Confirm the public policy is gone
aws s3api get-bucket-policy --bucket corporate-data-backup
# Expected: "The bucket policy does not exist" error

# Confirm public access block is active
aws s3api get-public-access-block --bucket corporate-data-backup
# Expected: all four settings = true

# Confirm encryption is enabled
aws s3api get-bucket-encryption --bucket corporate-data-backup
# Expected: SSEAlgorithm = AES256
```

## Deployment Impact

- **Removing the public policy** will immediately cut off any external system or user
  relying on unauthenticated reads. Before deploying, confirm no legitimate service
  depends on public access to this bucket.
- **Enabling encryption** is transparent to existing authenticated consumers — no
  downtime expected. Objects already stored will be encrypted on next write/copy.
- **Recommended approach:** apply during a maintenance window, notify stakeholders,
  and monitor CloudWatch/CloudTrail for `AccessDenied` errors in the hours after.
