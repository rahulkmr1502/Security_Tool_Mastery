############################################
# IAM: admin via group (not user-attached), analyst via MFA-gated role
############################################

resource "aws_iam_user" "lab_admin" {
  # checkov:skip=CKV_AWS_273:Task requires demonstrating IAM users; production would federate through IAM Identity Center (SSO)
  name = "lab-admin"
  tags = { Purpose = "Administrative setup only - MFA enforced" }
}

# Fix for CKV_AWS_40: policies attach to a GROUP, the user just joins it.
resource "aws_iam_group" "lab_admins" {
  name = "lab-admins"
}

resource "aws_iam_group_membership" "lab_admins" {
  name  = "lab-admins-membership"
  group = aws_iam_group.lab_admins.name
  users = [aws_iam_user.lab_admin.name]
}

resource "aws_iam_group_policy_attachment" "admin_access" {
  # checkov:skip=CKV_AWS_274:Bootstrap admin for lab setup; gated by the ForceMFA deny below. Production: time-boxed break-glass role instead
  group      = aws_iam_group.lab_admins.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Deny everything except MFA self-management until the session is MFA-authenticated
resource "aws_iam_group_policy" "force_mfa" {
  name  = "ForceMFA"
  group = aws_iam_group.lab_admins.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowViewAccountInfo"
        Effect    = "Allow"
        Action    = ["iam:GetAccountSummary", "iam:ListVirtualMFADevices"]
        Resource  = "*"
      },
      {
        Sid       = "DenyAllExceptMFAManagementUnlessMFAd"
        Effect    = "Deny"
        NotAction = ["iam:*MFADevice*", "iam:ChangePassword", "iam:GetUser"]
        Resource  = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      }
    ]
  })
}

############################################
# Least-privilege analyst
############################################

resource "aws_iam_user" "lab_analyst" {
  # checkov:skip=CKV_AWS_273:Same reason as lab-admin - IAM users are the point of the exercise
  name = "lab-analyst"
}

data "aws_iam_policy_document" "lab_analyst_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_user.lab_analyst.arn]
    }
    # Hardening vs baseline: role can only be assumed with MFA
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "lab_readonly" {
  name               = "lab-readonly"
  assume_role_policy = data.aws_iam_policy_document.lab_analyst_assume.json
}

data "aws_iam_policy_document" "lab_readonly_permissions" {
  # checkov:skip=CKV_AWS_356:ec2:Describe* does not support resource-level permissions, "*" is the only valid value (checkov false positive)

  statement {
    sid       = "ScopedS3Access"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.lab_bucket.arn}/*"]
  }

  # Needed because the bucket now uses SSE-KMS with our CMK (functional fix:
  # the baseline policy would have been denied on every object read/write).
  statement {
    sid       = "UseBucketKeyOnly"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.lab.arn]
  }

  statement {
    sid       = "ReadOnlyEC2Describe"
    effect    = "Allow"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "lab_readonly_policy" {
  name   = "lab-readonly-least-privilege"
  role   = aws_iam_role.lab_readonly.id
  policy = data.aws_iam_policy_document.lab_readonly_permissions.json
}
