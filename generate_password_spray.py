"""Generate synthetic password spray activity (Day -3 and Day -2).

Scenario: hundreds of failed sign-ins across many accounts, between 1 AM and 4 AM,
from a small pool of rotating attacker IPs in Lagos. Logs are pushed to the
workspace through the HTTP Data Collector API.

Usage:
    export LA_WORKSPACE_ID=...    # PowerShell: $env:LA_WORKSPACE_ID="..."
    export LA_PRIMARY_KEY=...
    python generate_password_spray.py
"""

import datetime
import json
import random

from common import load_credentials, post_logs

LOG_TYPE = "SigninLogs"  # same SigninLogs_CL table as the CEO sign-in

# Attack configuration
ATTACKER_IPS = ["154.1.1.23", "154.1.1.45", "154.1.1.67"]  # rotating IPs in one Lagos range
NUM_TARGET_ACCOUNTS = 40          # accounts targeted per night
FAILED_ATTEMPTS_PER_NIGHT = 300   # failed sign-ins per night
RESULT_TYPE_FAILED = "50126"      # Entra ID error: invalid username or password


def generate_target_accounts(n):
    return [f"user{i}@company.com" for i in range(1, n + 1)]


def generate_night_logs(days_ago, num_attempts, target_accounts):
    """Failed sign-ins scattered between 1 AM and 4 AM, typical of automated spraying."""
    base_date = (datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    logs = []
    for _ in range(num_attempts):
        timestamp = base_date + datetime.timedelta(seconds=random.randint(1 * 3600, 4 * 3600))
        logs.append(
            {
                "TimeGenerated": timestamp.isoformat() + "Z",
                "UserPrincipalName": random.choice(target_accounts),
                "IPAddress": random.choice(ATTACKER_IPS),
                "Location": "Lagos, Nigeria",
                "ResultType": RESULT_TYPE_FAILED,
                "AppDisplayName": "Office 365",
            }
        )
    return logs


def send_in_batches(workspace_id, primary_key, logs, batch_size=100):
    total_sent = 0
    for i in range(0, len(logs), batch_size):
        batch = logs[i : i + batch_size]
        status, text = post_logs(workspace_id, primary_key, json.dumps(batch), LOG_TYPE)
        if status == 200:
            total_sent += len(batch)
            print(f"  Batch {i // batch_size + 1}: sent {len(batch)} logs")
        else:
            print(f"  Batch {i // batch_size + 1}: error {status} - {text}")
    return total_sent


if __name__ == "__main__":
    workspace_id, primary_key = load_credentials()
    targets = generate_target_accounts(NUM_TARGET_ACCOUNTS)
    print(f"Created {NUM_TARGET_ACCOUNTS} simulated target accounts.\n")

    total = 0
    for days_ago in (3, 2):
        print(f"=== Day -{days_ago}: generating failed sign-ins ===")
        logs = generate_night_logs(days_ago, FAILED_ATTEMPTS_PER_NIGHT, targets)
        sent = send_in_batches(workspace_id, primary_key, logs)
        print(f"Day -{days_ago}: {sent}/{len(logs)} logs sent.\n")
        total += sent

    print(f"Done. Total failed sign-ins sent: {total}")
    print("Wait 2-15 minutes, then query SigninLogs_CL in Sentinel > Logs.")
