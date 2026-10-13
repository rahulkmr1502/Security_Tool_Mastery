############################################
# Alerts topic (encrypted - fix for CKV_AWS_26)
############################################

resource "aws_sns_topic" "lab_alerts" {
  name              = "lab-security-alerts"
  kms_master_key_id = aws_kms_key.lab.arn
}

resource "aws_sns_topic_subscription" "lab_alerts_email" {
  topic_arn = aws_sns_topic.lab_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "aws_iam_policy_document" "lab_alerts" {
  statement {
    sid       = "AccountOwnerFullAccess"
    effect    = "Allow"
    actions   = ["SNS:GetTopicAttributes", "SNS:SetTopicAttributes", "SNS:Subscribe", "SNS:ListSubscriptionsByTopic", "SNS:Publish"]
    resources = [aws_sns_topic.lab_alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AllowAwsServicesToPublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.lab_alerts.arn]
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

resource "aws_sns_topic_policy" "lab_alerts" {
  arn    = aws_sns_topic.lab_alerts.arn
  policy = data.aws_iam_policy_document.lab_alerts.json
}

############################################
# CloudTrail: KMS-encrypted, SNS-notified, streamed to CloudWatch Logs
# (fixes CKV_AWS_35, CKV_AWS_252, CKV2_AWS_10), plus S3 DATA events on the lab
# bucket - the event type that would have exposed the Capital One exfiltration.
############################################

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/lab/cloudtrail"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lab.arn
}

data "aws_iam_policy_document" "trail_cw_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "trail_cw_permissions" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:*"]
  }
}

resource "aws_iam_role" "trail_cw" {
  name               = "lab-cloudtrail-to-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.trail_cw_assume.json
}

resource "aws_iam_role_policy" "trail_cw" {
  name   = "write-cloudtrail-logs"
  role   = aws_iam_role.trail_cw.id
  policy = data.aws_iam_policy_document.trail_cw_permissions.json
}

resource "aws_cloudtrail" "lab_trail" {
  name                          = "lab-management-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.lab.arn
  sns_topic_name                = aws_sns_topic.lab_alerts.name
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_cw.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.lab_bucket.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.trail_bucket, aws_sns_topic_policy.lab_alerts]
}

############################################
# Detections (CIS AWS Foundations style): metric filter -> alarm -> SNS
############################################

locals {
  detections = {
    root-account-usage = {
      pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
      desc    = "Root account used"
    }
    unauthorized-api-calls = {
      pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
      desc    = "API call denied (possible probing / stolen credential)"
    }
    console-login-without-mfa = {
      pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }"
      desc    = "Console login without MFA"
    }
    iam-policy-changes = {
      pattern = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = AttachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = AttachGroupPolicy) }"
      desc    = "IAM policy changed"
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each       = local.detections
  name           = each.key
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value.pattern

  metric_transformation {
    name      = each.key
    namespace = "LabSecurity"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each            = local.detections
  alarm_name          = "lab-${each.key}"
  alarm_description   = each.value.desc
  namespace           = "LabSecurity"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.lab_alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}

# Baseline's CPU alarm had no InstanceId dimension, so it watched nothing.
resource "aws_cloudwatch_metric_alarm" "cpu_alarm" {
  alarm_name          = "lab-ec2-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = [aws_sns_topic.lab_alerts.arn]
  dimensions          = { InstanceId = aws_instance.lab.id }
}

# Baseline used a CloudWatch EstimatedCharges alarm, but that metric only exists
# in us-east-1 while the provider region is ap-south-1, so it could never fire.
# AWS Budgets is global and emails directly.
resource "aws_budgets_budget" "lab" {
  name         = "lab-monthly-budget"
  budget_type  = "COST"
  limit_amount = "1"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}
