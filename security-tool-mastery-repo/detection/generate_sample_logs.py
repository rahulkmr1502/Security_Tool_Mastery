#!/usr/bin/env python3
"""
Generate SYNTHETIC CloudTrail-format events for testing detection logic.

NOT real telemetry: no AWS account was available for this project, so the
events below are fabricated to follow CloudTrail's JSON schema. Account ID,
IPs and instance IDs are documentation/example values (AWS docs account
111122223333, RFC 5737 test-net IPs).

The scenario mirrors the 2019 Capital One breach pattern:
  benign admin/analyst traffic + one EC2 role whose credentials get used from
  an unknown IP to enumerate and bulk-read an S3 bucket, followed by
  privilege escalation and log tampering.
"""
import json, random
from datetime import datetime, timedelta, timezone

random.seed(42)
ACCOUNT = "111122223333"
BUCKET = "cloud-security-lab-rahul-2026"
INSTANCE_ID = "i-0abc1234def567890"
INSTANCE_IP = "203.0.113.10"      # the instance's Elastic IP
ADMIN_IP = "203.0.113.50"         # administrator's home IP (admin_ip_cidr)
ATTACKER_IP = "198.51.100.77"     # unknown external IP
DAY = datetime(2026, 10, 10, tzinfo=timezone.utc)

records = []

def ts(h, m, s=0):
    return (DAY + timedelta(hours=h, minutes=m, seconds=s)).strftime("%Y-%m-%dT%H:%M:%SZ")

def instance_identity():
    return {
        "type": "AssumedRole",
        "principalId": f"AROAEXAMPLEINSTROLE:{INSTANCE_ID}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/lab-instance-role/{INSTANCE_ID}",
        "accountId": ACCOUNT,
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "userName": "lab-instance-role",
                              "arn": f"arn:aws:iam::{ACCOUNT}:role/lab-instance-role"},
            "attributes": {"mfaAuthenticated": "false"},
        },
    }

def analyst_identity():
    return {
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLEREADONLY:lab-analyst",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/lab-readonly/lab-analyst",
        "accountId": ACCOUNT,
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "userName": "lab-readonly",
                              "arn": f"arn:aws:iam::{ACCOUNT}:role/lab-readonly"},
            "attributes": {"mfaAuthenticated": "true"},
        },
    }

def iam_user(name):
    return {"type": "IAMUser", "userName": name, "accountId": ACCOUNT,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}"}

def add(when, identity, source, name, ip, ro=True, error=None, extra=None):
    rec = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": when,
        "eventSource": source,
        "eventName": name,
        "awsRegion": "ap-south-1",
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.15.0",
        "eventType": "AwsApiCall",
        "readOnly": ro,
        "recipientAccountId": ACCOUNT,
    }
    if error:
        rec["errorCode"] = error
    if extra:
        rec.update(extra)
    records.append(rec)

# ---------------- benign background noise ----------------
# instance role talking to Systems Manager from its own IP, all day
for h in range(0, 24):
    for k in range(5):
        add(ts(h, random.randint(0, 59), random.randint(0, 59)), instance_identity(),
            "ssm.amazonaws.com", "UpdateInstanceInformation", INSTANCE_IP, ro=False)

# analyst (MFA'd) reads a handful of objects in working hours
for _ in range(14):
    add(ts(random.randint(9, 17), random.randint(0, 59), random.randint(0, 59)), analyst_identity(),
        "s3.amazonaws.com", "GetObject", ADMIN_IP,
        extra={"requestParameters": {"bucketName": BUCKET, "key": f"reports/file{random.randint(1,9)}.csv"},
               "eventCategory": "Data"})
for _ in range(4):
    add(ts(random.randint(9, 17), random.randint(0, 59)), analyst_identity(),
        "ec2.amazonaws.com", "DescribeInstances", ADMIN_IP)
# the analyst hits one AccessDenied while trying something out of scope (normal human behaviour)
add(ts(11, 20), analyst_identity(), "iam.amazonaws.com", "ListUsers", ADMIN_IP, error="AccessDenied")

# admin logs in with MFA in the morning
add(ts(8, 55), iam_user("lab-admin"), "signin.amazonaws.com", "ConsoleLogin", ADMIN_IP, ro=False,
    extra={"additionalEventData": {"MFAUsed": "Yes"}, "responseElements": {"ConsoleLogin": "Success"},
           "eventType": "AwsConsoleSignIn"})

# ---------------- attack timeline (Capital One pattern) ----------------
# 02:10 - instance-role credentials appear from an external IP, start enumerating
add(ts(2, 10, 5), instance_identity(), "s3.amazonaws.com", "ListBuckets", ATTACKER_IP)
for i, (src, name) in enumerate([("iam.amazonaws.com", "ListUsers"), ("iam.amazonaws.com", "ListRoles"),
                                 ("ec2.amazonaws.com", "DescribeInstances"), ("s3.amazonaws.com", "ListObjects"),
                                 ("kms.amazonaws.com", "ListKeys"), ("iam.amazonaws.com", "GetAccountAuthorizationDetails"),
                                 ("secretsmanager.amazonaws.com", "ListSecrets")]):
    add(ts(2, 11, i * 4), instance_identity(), src, name, ATTACKER_IP, error="AccessDenied")
# 02:14-02:29 - bulk read of the lab bucket (S3 data events)
for i in range(260):
    add(ts(2, 14 + i // 18, (i * 3) % 60), instance_identity(), "s3.amazonaws.com", "GetObject", ATTACKER_IP,
        extra={"requestParameters": {"bucketName": BUCKET, "key": f"customers/part-{i:04d}.parquet"},
               "eventCategory": "Data"})
# 02:41 - console login without MFA as the analyst user, from the attacker IP
add(ts(2, 41), iam_user("lab-analyst"), "signin.amazonaws.com", "ConsoleLogin", ATTACKER_IP, ro=False,
    extra={"additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"},
           "eventType": "AwsConsoleSignIn"})
# 02:43 - root console login
add(ts(2, 43), {"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root", "accountId": ACCOUNT},
    "signin.amazonaws.com", "ConsoleLogin", ATTACKER_IP, ro=False,
    extra={"additionalEventData": {"MFAUsed": "No"}, "responseElements": {"ConsoleLogin": "Success"},
           "eventType": "AwsConsoleSignIn"})
# 02:50 - privilege escalation
add(ts(2, 50), iam_user("lab-analyst"), "iam.amazonaws.com", "AttachRolePolicy", ATTACKER_IP, ro=False,
    extra={"requestParameters": {"roleName": "lab-readonly",
                                 "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}})
# 02:55 - cover tracks
add(ts(2, 55), iam_user("lab-analyst"), "cloudtrail.amazonaws.com", "StopLogging", ATTACKER_IP, ro=False,
    extra={"requestParameters": {"name": "lab-management-trail"}})

records.sort(key=lambda r: r["eventTime"])
with open("sample_cloudtrail.json", "w") as f:
    json.dump({"_note": "SYNTHETIC test data - not real AWS telemetry", "Records": records}, f, indent=1)
print(f"wrote {len(records)} synthetic events to sample_cloudtrail.json")
