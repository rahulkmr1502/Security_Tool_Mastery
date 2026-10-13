#!/usr/bin/env python3
"""
Rule-based CloudTrail detector. Reads a CloudTrail JSON export ({"Records": [...]})
and prints/saves findings. Rules mirror the CloudWatch metric filters in
terraform-hardened/monitoring.tf, plus two behavioural rules (credential use
from an unexpected IP, bulk S3 reads) that metric filters cannot express.

usage: python3 detect.py sample_cloudtrail.json [--known-ips 203.0.113.10,203.0.113.50]
"""
import argparse, collections, json
from datetime import datetime, timedelta

BULK_READ_THRESHOLD = 50     # GetObject calls by one principal inside WINDOW_MIN
WINDOW_MIN = 10
DENIED_THRESHOLD = 5         # AccessDenied/Unauthorized by one principal inside DENIED_WINDOW_MIN
DENIED_WINDOW_MIN = 15

def parse(t):
    return datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")

def principal(r):
    u = r["userIdentity"]
    return u.get("arn") or u.get("userName") or u.get("type")

def issuer(r):
    return r["userIdentity"].get("sessionContext", {}).get("sessionIssuer", {}).get("userName")

def sliding_max(times, window):
    """largest number of timestamps falling inside any `window` span, plus the first/last of that span"""
    times = sorted(times)
    best, lo, span = 0, 0, (None, None)
    for hi in range(len(times)):
        while times[hi] - times[lo] > window:
            lo += 1
        if hi - lo + 1 > best:
            best, span = hi - lo + 1, (times[lo], times[hi])
    return best, span

def run(records, known_ips):
    findings = []
    def add(sev, rule, when, who, detail, mitre=""):
        findings.append({"severity": sev, "rule": rule, "time": when, "principal": who,
                         "detail": detail, "mitre": mitre})

    # --- single-event rules ---
    for r in records:
        u, name, when = r["userIdentity"], r["eventName"], r["eventTime"]
        if u.get("type") == "Root" and r.get("eventType") != "AwsServiceEvent":
            add("CRITICAL", "root-account-usage", when, principal(r),
                f"{name} from {r['sourceIPAddress']}", "T1078.004 Valid Accounts: Cloud")
        if (name == "ConsoleLogin" and r.get("responseElements", {}).get("ConsoleLogin") == "Success"
                and r.get("additionalEventData", {}).get("MFAUsed") != "Yes" and u.get("type") == "IAMUser"):
            add("HIGH", "console-login-without-mfa", when, principal(r),
                f"from {r['sourceIPAddress']}", "T1078.004")
        if name in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"):
            add("CRITICAL", "cloudtrail-tampering", when, principal(r),
                f"{name} on {r.get('requestParameters', {}).get('name')}", "T1562.008 Disable Cloud Logs")
        if name in ("AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy", "PutRolePolicy", "PutUserPolicy",
                    "PutGroupPolicy", "CreatePolicy"):
            arn = r.get("requestParameters", {}).get("policyArn", "")
            sev = "CRITICAL" if arn.endswith("AdministratorAccess") else "MEDIUM"
            add(sev, "iam-policy-change", when, principal(r), f"{name} {arn or ''}".strip(),
                "T1098 Account Manipulation")
        # Capital One signature: an EC2 role's temporary credentials used away from the instance
        if (u.get("type") == "AssumedRole" and issuer(r) == "lab-instance-role"
                and r["sourceIPAddress"] not in known_ips):
            pass  # aggregated below to avoid one finding per call

    # --- aggregated rules ---
    foreign = collections.defaultdict(list)
    for r in records:
        if (r["userIdentity"].get("type") == "AssumedRole" and issuer(r) == "lab-instance-role"
                and r["sourceIPAddress"] not in known_ips):
            foreign[(principal(r), r["sourceIPAddress"])].append(r)
    for (who, ip), evs in foreign.items():
        evs.sort(key=lambda e: e["eventTime"])
        add("CRITICAL", "instance-credentials-used-from-unknown-ip", evs[0]["eventTime"], who,
            f"{len(evs)} API calls from {ip} (not the instance's EIP) between {evs[0]['eventTime']} and "
            f"{evs[-1]['eventTime']} - matches stolen-IMDS-credential pattern", "T1552.005 Cloud Instance Metadata API")

    reads = collections.defaultdict(list)
    denied = collections.defaultdict(list)
    for r in records:
        if r["eventName"] == "GetObject" and r["eventSource"] == "s3.amazonaws.com":
            reads[principal(r)].append(parse(r["eventTime"]))
        ec = r.get("errorCode", "")
        if ec.endswith("UnauthorizedOperation") or ec.startswith("AccessDenied"):
            denied[principal(r)].append(parse(r["eventTime"]))
    for who, times in reads.items():
        n, (a, b) = sliding_max(times, timedelta(minutes=WINDOW_MIN))
        if n >= BULK_READ_THRESHOLD:
            add("HIGH", "s3-bulk-read", a.strftime("%Y-%m-%dT%H:%M:%SZ"), who,
                f"{n} GetObject calls within {WINDOW_MIN} min (threshold {BULK_READ_THRESHOLD})",
                "T1530 Data from Cloud Storage")
    for who, times in denied.items():
        n, (a, b) = sliding_max(times, timedelta(minutes=DENIED_WINDOW_MIN))
        if n >= DENIED_THRESHOLD:
            add("MEDIUM", "access-denied-burst", a.strftime("%Y-%m-%dT%H:%M:%SZ"), who,
                f"{n} denied calls within {DENIED_WINDOW_MIN} min (threshold {DENIED_THRESHOLD}) - enumeration / probing",
                "T1087.004 Account Discovery: Cloud")

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (f["time"], order[f["severity"]]))
    return findings

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--known-ips", default="203.0.113.10,203.0.113.50")
    ap.add_argument("--out", default="findings.json")
    args = ap.parse_args()
    data = json.load(open(args.logfile))
    recs = data["Records"]
    f = run(recs, set(args.known_ips.split(",")))
    json.dump(f, open(args.out, "w"), indent=1)
    sev = collections.Counter(x["severity"] for x in f)
    print(f"events analysed: {len(recs)}   findings: {len(f)}   {dict(sev)}")
    for x in f:
        print(f"[{x['severity']:8}] {x['time']}  {x['rule']:42} {x['detail']}")
