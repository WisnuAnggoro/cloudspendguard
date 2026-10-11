# CloudSpendGuard Report

Generated 2026-10-09 20:17 UTC by csg 0.6.0-beta.

Input: 392 CUR line items, 8 CloudTrail events, 22 Terraform resources.

Profile `devops`: score = 0.40 x savings + 0.50 x risk - 0.30 x blast radius (each normalized 0 to 1).

## Summary

- Findings: 20 (12 security, 8 cost)
- Projected savings: USD 768.93 per month
- Critical: 3
- High: 4
- Medium: 8
- Low: 3
- Info: 2

## Prioritized backlog

| # | Score | S / R / B | Kind | Severity | Rule | Resource | Savings per month | Controls |
|---|---|---|---|---|---|---|---|---|
| 1 | 0.476 | 0.85 / 0.30 / 0.05 | cost | high | `COST-ANOMALY-001` | `AmazonEC2/booking` | USD 146.88 | - |
| 2 | 0.360 | 0.00 / 0.90 / 0.30 | security | critical | `SEC-S3-PUBLIC-001` | `tui-demo-booking-exports` | USD 0.00 | CIS 2.1.4 |
| 3 | 0.320 | 0.00 / 0.85 / 0.35 | security | critical | `SEC-RDS-PUBLIC-001` | `analytics-staging` | USD 0.00 | CIS 2.3.3 |
| 4 | 0.310 | 0.00 / 0.80 / 0.30 | security | critical | `SEC-SG-ADMIN-IPV4-001` | `sg-0a1b2c3d4e5f60022` | USD 0.00 | CIS 5.2 |
| 5 | 0.295 | 1.00 / 0.00 / 0.35 | cost | medium | `COST-RDS-NONPROD-SIZE-001` | `analytics-staging` | USD 350.40 | - |
| 6 | 0.293 | 0.88 / 0.00 / 0.20 | cost | low | `COST-RDS-NONPROD-MULTIAZ-001` | `analytics-staging` | USD 175.20 | - |
| 7 | 0.265 | 0.00 / 0.65 / 0.20 | security | high | `SEC-EC2-IMDSV2-001` | `i-0a1b2c3d4e5f60042` | USD 0.00 | CIS 5.6 |
| 8 | 0.245 | 0.00 / 0.85 / 0.60 | security | high | `SEC-IAM-ADMIN-001` | `arn:aws:iam::111122223333:policy/break-glass-admin` | USD 0.00 | CIS 1.16 |
| 9 | 0.245 | 0.00 / 0.85 / 0.60 | security | high | `SEC-IAM-ADMIN-001` | `legacy-ci-deployer` | USD 0.00 | CIS 1.16 |
| 10 | 0.244 | 0.64 / 0.10 / 0.20 | cost | low | `COST-EBS-IDLE-001` | `vol-0a1b2c3d4e5f60099` | USD 40.55 | - |
| 11 | 0.210 | 0.00 / 0.45 / 0.05 | security | medium | `SEC-VPC-FLOWLOGS-001` | `vpc-0a1b2c3d4e5f60100` | USD 0.00 | CIS 3.7 |
| 12 | 0.185 | 0.00 / 0.40 / 0.05 | security | medium | `SEC-CT-VALIDATION-001` | `org-trail` | USD 0.00 | CIS 3.2 |
| 13 | 0.160 | 0.00 / 0.35 / 0.05 | security | medium | `SEC-KMS-ROTATION-001` | `1234abcd-12ab-34cd-56ef-1234567890ab` | USD 0.00 | CIS 3.6 |
| 14 | 0.155 | 0.00 / 0.40 / 0.15 | security | medium | `SEC-S3-TLS-001` | `tui-demo-access-logs` | USD 0.00 | CIS 2.1.1 |
| 15 | 0.155 | 0.00 / 0.40 / 0.15 | security | medium | `SEC-S3-TLS-001` | `tui-demo-booking-exports` | USD 0.00 | CIS 2.1.1 |
| 16 | 0.130 | 0.00 / 0.35 / 0.15 | security | medium | `SEC-CT-KMS-001` | `org-trail` | USD 0.00 | CIS 3.5 |
| 17 | 0.115 | 0.60 / 0.05 / 0.50 | cost | medium | `COST-NAT-IDLE-001` | `nat-0a1b2c3d4e5f60020` | USD 32.85 | - |
| 18 | 0.099 | 0.49 / 0.05 / 0.40 | cost | low | `COST-EC2-PREVGEN-001` | `i-0a1b2c3d4e5f60042` | USD 16.21 | - |
| 19 | 0.055 | 0.26 / 0.05 / 0.25 | cost | info | `COST-EIP-UNATTACHED-001` | `eipalloc-0a1b2c3d4e5f60077` | USD 3.65 | - |
| 20 | 0.048 | 0.24 / 0.05 / 0.25 | cost | info | `COST-S3-NO-LIFECYCLE-001` | `tui-demo-booking-exports` | USD 3.19 | - |

## Cost anomalies

- `AmazonEC2/booking`: 2026-09-19, 2026-09-20

## Findings

### 1. Cost anomaly in AmazonEC2 (team booking)

- Resource: `AmazonEC2/booking`
- Rule: `COST-ANOMALY-001`; controls: -
- Evidence: Spend on 2026-09-19 to 2026-09-20 was USD 152.26 against an STL expectation of USD 5.38 (USD 146.88 above normal; robust z = 12.0, isolation score = 0.79). Both the statistical and the machine-learning signal agree.
- Fix (investigate): Investigate 2026-09-19 to 2026-09-20: csg query "SELECT usage_type, resource_id, ROUND(SUM(cost),2) FROM cur WHERE service = 'AmazonEC2' AND usage_start >= '2026-09-19' GROUP BY 1, 2 ORDER BY 3 DESC" and check CloudTrail for the same window.

### 2. S3 bucket is publicly accessible

- Resource: `tui-demo-booking-exports` (`aws_s3_bucket_public_access_block.exports`)
- Rule: `SEC-S3-PUBLIC-001`; controls: CIS 2.1.4
- Evidence: Terraform aws_s3_bucket_acl.exports sets acl = "public-read"; Terraform aws_s3_bucket_public_access_block.exports disables block_public_acls, ignore_public_acls; CloudTrail DeleteBucketPublicAccessBlock at 2026-09-09 14:40Z by arn:aws:iam::111122223333:user/bob removed Block Public Access; CloudTrail PutBucketAcl at 2026-09-09 14:41Z by arn:aws:iam::111122223333:user/bob granted public access.
- Fix (modify): Set all four aws_s3_bucket_public_access_block arguments to true and remove public ACL grants; serve public content through CloudFront with origin access control.

### 3. RDS instance is publicly accessible

- Resource: `analytics-staging` (`aws_db_instance.analytics_staging`)
- Rule: `SEC-RDS-PUBLIC-001`; controls: CIS 2.3.3
- Evidence: Terraform aws_db_instance.analytics_staging sets publicly_accessible = true.
- Fix (modify): Set publicly_accessible = false and reach the database through a bastion, VPN, or RDS Proxy.

### 4. Security group allows SSH or RDP from 0.0.0.0/0

- Resource: `sg-0a1b2c3d4e5f60022` (`aws_security_group.bastion`)
- Rule: `SEC-SG-ADMIN-IPV4-001`; controls: CIS 5.2
- Evidence: Terraform aws_security_group.bastion allows ports 22-22 from 0.0.0.0/0.
- Fix (modify): Restrict the ingress rule to a corporate CIDR or remove it and use SSM Session Manager.

### 5. Large RDS instance class in a non-production environment

- Resource: `analytics-staging` (`aws_db_instance.analytics_staging`)
- Rule: `COST-RDS-NONPROD-SIZE-001`; controls: -
- Evidence: analytics-staging (aws_db_instance.analytics_staging): class db.r5.2xlarge is oversized for env=staging. Fixing it saves USD 350.40/month (50% of the cost observed in CUR).
- Fix (modify): Downsize instance_class on aws_db_instance.analytics_staging one or two sizes (for example db.t4g.medium) and watch CPU and memory for a week

### 6. Multi-AZ RDS in a non-production environment

- Resource: `analytics-staging` (`aws_db_instance.analytics_staging`)
- Rule: `COST-RDS-NONPROD-MULTIAZ-001`; controls: -
- Evidence: analytics-staging (aws_db_instance.analytics_staging): multi_az doubles instance cost and is rarely needed outside production (env=staging). Fixing it saves USD 175.20/month after COST-RDS-NONPROD-SIZE-001 is applied to the same resource (USD 350.40 on its own).
- Fix (modify): Set multi_az = false on aws_db_instance.analytics_staging

### 7. EC2 instance allows IMDSv1

- Resource: `i-0a1b2c3d4e5f60042` (`aws_instance.legacy_reporting`)
- Rule: `SEC-EC2-IMDSV2-001`; controls: CIS 5.6
- Evidence: Terraform aws_instance.legacy_reporting does not set metadata_options.http_tokens = "required".
- Fix (modify): Set metadata_options { http_tokens = "required" } so credentials cannot be stolen through SSRF against IMDSv1.

### 8. IAM policy grants full administrative access (*:*)

- Resource: `arn:aws:iam::111122223333:policy/break-glass-admin` (`aws_iam_policy.break_glass`)
- Rule: `SEC-IAM-ADMIN-001`; controls: CIS 1.16
- Evidence: Terraform aws_iam_policy.break_glass allows Action "*" on Resource "*".
- Fix (modify): Replace the wildcard statement with the actions the principal actually uses (IAM Access Analyzer policy generation from CloudTrail helps), and require MFA for any remaining break-glass admin role.

### 9. IAM policy grants full administrative access (*:*)

- Resource: `legacy-ci-deployer`
- Rule: `SEC-IAM-ADMIN-001`; controls: CIS 1.16
- Evidence: CloudTrail PutRolePolicy at 2026-09-15 22:03Z by arn:aws:iam::111122223333:user/legacy-ci attached a "*:*" policy.
- Fix (modify): Replace the wildcard statement with the actions the principal actually uses (IAM Access Analyzer policy generation from CloudTrail helps), and require MFA for any remaining break-glass admin role.

### 10. Unattached EBS volume

- Resource: `vol-0a1b2c3d4e5f60099`
- Rule: `COST-EBS-IDLE-001`; controls: -
- Evidence: vol-0a1b2c3d4e5f60099 (gp3, aws_ebs_volume.etl_scratch) has no aws_volume_attachment and costs USD 40.55/month observed in CUR. Snapshot it if the data is needed, then delete the volume.
- Fix (-): aws ec2 create-snapshot --volume-id vol-0a1b2c3d4e5f60099, then remove aws_ebs_volume.etl_scratch from Terraform

### 11. VPC has no flow logs

- Resource: `vpc-0a1b2c3d4e5f60100` (`aws_vpc.main`)
- Rule: `SEC-VPC-FLOWLOGS-001`; controls: CIS 3.7
- Evidence: Terraform aws_vpc.main has no aws_flow_log attached.
- Fix (investigate): Add an aws_flow_log for the VPC with traffic_type = "REJECT" (or ALL) to CloudWatch Logs or S3.

### 12. CloudTrail log file validation is disabled

- Resource: `org-trail` (`aws_cloudtrail.main`)
- Rule: `SEC-CT-VALIDATION-001`; controls: CIS 3.2
- Evidence: Terraform aws_cloudtrail.main sets enable_log_file_validation = false.
- Fix (modify): Set enable_log_file_validation = true so tampering with log files is detectable.

### 13. KMS key rotation is disabled

- Resource: `1234abcd-12ab-34cd-56ef-1234567890ab` (`aws_kms_key.exports`)
- Rule: `SEC-KMS-ROTATION-001`; controls: CIS 3.6
- Evidence: Terraform aws_kms_key.exports sets enable_key_rotation = false on a symmetric key.
- Fix (modify): Set enable_key_rotation = true.

### 14. S3 bucket accepts unencrypted (HTTP) requests

- Resource: `tui-demo-access-logs` (`aws_s3_bucket.logs`)
- Rule: `SEC-S3-TLS-001`; controls: CIS 2.1.1
- Evidence: Terraform aws_s3_bucket.logs has no bucket policy denying aws:SecureTransport = false.
- Fix (modify): Add a Deny statement for all principals when aws:SecureTransport is false to the bucket policy.

### 15. S3 bucket accepts unencrypted (HTTP) requests

- Resource: `tui-demo-booking-exports` (`aws_s3_bucket.exports`)
- Rule: `SEC-S3-TLS-001`; controls: CIS 2.1.1
- Evidence: Terraform aws_s3_bucket.exports has no bucket policy denying aws:SecureTransport = false.
- Fix (modify): Add a Deny statement for all principals when aws:SecureTransport is false to the bucket policy.

### 16. CloudTrail logs are not encrypted with a KMS key

- Resource: `org-trail` (`aws_cloudtrail.main`)
- Rule: `SEC-CT-KMS-001`; controls: CIS 3.5
- Evidence: Terraform aws_cloudtrail.main has no kms_key_id.
- Fix (modify): Set kms_key_id to a customer-managed KMS key whose policy allows CloudTrail to encrypt.

### 17. Idle NAT gateway

- Resource: `nat-0a1b2c3d4e5f60020`
- Rule: `COST-NAT-IDLE-001`; controls: -
- Evidence: nat-0a1b2c3d4e5f60020 bills NAT gateway hours but processed almost no data (USD 0.00 data charge in the window). Removing it saves USD 32.85/month observed in CUR.
- Fix (delete): Confirm no private subnet route needs outbound internet (check VPC Flow Logs), then delete the NAT gateway or replace it with VPC endpoints

### 18. EC2 instance uses a previous-generation type

- Resource: `i-0a1b2c3d4e5f60042` (`aws_instance.legacy_reporting`)
- Rule: `COST-EC2-PREVGEN-001`; controls: -
- Evidence: i-0a1b2c3d4e5f60042 (aws_instance.legacy_reporting): instance type m4.xlarge is previous generation; m5.xlarge is cheaper and faster. Fixing it saves USD 16.21/month (10% of the cost observed in CUR).
- Fix (modify): Change instance_type to m5.xlarge in a maintenance window (requires stop/start)

### 19. Unattached Elastic IP

- Resource: `eipalloc-0a1b2c3d4e5f60077`
- Rule: `COST-EIP-UNATTACHED-001`; controls: -
- Evidence: eipalloc-0a1b2c3d4e5f60077 (aws_eip.legacy_bastion) is allocated but idle (no association in Terraform state; billed as EUW1-PublicIPv4:IdleAddress) and costs USD 3.65/month observed in CUR. Check DNS records before releasing it to avoid a dangling record.
- Fix (-): aws ec2 release-address --allocation-id eipalloc-0a1b2c3d4e5f60077

### 20. S3 bucket has no lifecycle policy

- Resource: `tui-demo-booking-exports` (`aws_s3_bucket.exports`)
- Rule: `COST-S3-NO-LIFECYCLE-001`; controls: -
- Evidence: tui-demo-booking-exports (aws_s3_bucket.exports): no lifecycle configuration, so objects never move to cheaper storage classes or expire. Fixing it saves USD 3.19/month (30% of the cost observed in CUR).
- Fix (investigate): Add aws_s3_bucket_lifecycle_configuration for aws_s3_bucket.exports (Intelligent-Tiering after 30 days, expire noncurrent versions)

CloudSpendGuard never applies a change. Patches from `csg remediate` are shown for review only.
