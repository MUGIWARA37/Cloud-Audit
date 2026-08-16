# CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22

## 1. Finding Overview
A security group in your environment is allowing unrestricted inbound access (0.0.0.0/0) on port 22 (SSH).
This exposes the attached compute instances to brute-force attacks and zero-day vulnerabilities from anywhere on the internet.

## 2. Remediation (AWS CLI)
To remove the insecure rule from the security group:
```bash
aws ec2 revoke-security-group-ingress \
  --group-id <SECURITY_GROUP_ID> \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
```
*Note: Replace `<SECURITY_GROUP_ID>` with the ID found in the Cloud Audit report (e.g., sg-9bd597...)*

## 3. Remediation (Terraform)
If this security group is managed via Infrastructure as Code, locate the `aws_security_group_rule` or inline `ingress` block and remove or update the CIDR blocks:
```hcl
# BAD
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

# GOOD (Restrict to your corporate VPN IP or bastion host)
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["203.0.113.0/24"] # Example IP
}
```

## 4. Verification
Run the following command to verify the rule was successfully removed:
```bash
aws ec2 describe-security-groups \
  --group-ids <SECURITY_GROUP_ID> \
  --query 'SecurityGroups[*].IpPermissions'
```
*Ensure no rules return with a CidrIp of 0.0.0.0/0 on port 22.*

## 5. Deployment Impact
Removing SSH access will immediately disconnect any active SSH sessions using that rule. Ensure you have alternative secure access (such as AWS Systems Manager Session Manager or a restricted corporate VPN block) before applying this change to avoid locking yourself out of critical instances.
