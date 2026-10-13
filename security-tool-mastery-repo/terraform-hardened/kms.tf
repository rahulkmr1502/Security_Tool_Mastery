############################################
# One customer-managed key (CMK) shared by S3, CloudTrail, CloudWatch Logs,
# SNS and the EC2 root volume. Rotation is on; the key policy lists exactly
# which AWS services may use it.
############################################

data "aws_iam_policy_document" "lab_key" {
  # checkov:skip=CKV_AWS_109:KMS key policy - Resource "*" means "this key"; root statement is the standard way to delegate to IAM
  # checkov:skip=CKV_AWS_111:KMS key policy - Resource "*" means "this key"; write actions are limited to named AWS service principals
  # checkov:skip=CKV_AWS_356:KMS key policy - Resource "*" means "this key", not all resources

  statement {
    sid       = "EnableIAMDelegationFromAccountRoot"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AllowCloudWatchLogsToUseKey"
    effect    = "Allow"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:*"]
    }
  }

  statement {
    sid       = "AllowAlarmsAndS3ToPublishToEncryptedTopic"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "s3.amazonaws.com", "cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "lab" {
  description             = "Cloud security lab CMK (S3, CloudTrail, Logs, SNS, EBS)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.lab_key.json
}

resource "aws_kms_alias" "lab" {
  name          = "alias/cloud-security-lab"
  target_key_id = aws_kms_key.lab.key_id
}
