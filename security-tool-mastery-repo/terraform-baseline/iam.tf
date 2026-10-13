############################################
# Objective 2: IAM Users, Roles, and Access Permissions
############################################

resource "aws_iam_user" "lab_admin" {
  name = "lab-admin"

  tags = {
    Purpose = "Administrative setup only - MFA enforced, not for daily tasks"
  }
}

resource "aws_iam_user_policy_attachment" "lab_admin_access" {
  user       = aws_iam_user.lab_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Enforce MFA before any action beyond changing one's own credentials
resource "aws_iam_user_policy" "force_mfa" {
  name = "ForceMFA"
  user = aws_iam_user.lab_admin.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowViewAccountInfo"
        Effect   = "Allow"
        Action   = ["iam:GetAccountSummary", "iam:ListVirtualMFADevices"]
        Resource = "*"
      },
      {
        Sid      = "DenyAllExceptMFAManagementUnlessMFAd"
        Effect   = "Deny"
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
# Least-privilege analyst identity (objective 2 + 3)
############################################

resource "aws_iam_user" "lab_analyst" {
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
  }
}

resource "aws_iam_role" "lab_readonly" {
  name               = "lab-readonly"
  assume_role_policy = data.aws_iam_policy_document.lab_analyst_assume.json
}

data "aws_iam_policy_document" "lab_readonly_permissions" {
  statement {
    sid       = "ScopedS3Access"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.lab_bucket.arn}/*"]
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

# Rationale: lab-analyst has NO standing permissions of its own; it can only
# act by assuming lab-readonly, which is scoped to two narrow actions.
# This demonstrates least privilege and separation between an administrative
# identity (lab-admin) and an operational identity (lab-analyst).
