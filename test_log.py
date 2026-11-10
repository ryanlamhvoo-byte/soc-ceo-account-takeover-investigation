"""Send one simulated sign-in: the CEO account logging in successfully at 3 AM from Lagos.

Usage:
    export LA_WORKSPACE_ID=...    # PowerShell: $env:LA_WORKSPACE_ID="..."
    export LA_PRIMARY_KEY=...
    python test_log.py
"""

import datetime
import json

from common import load_credentials, post_logs

LOG_TYPE = "SigninLogs"  # lands in the custom table SigninLogs_CL


if __name__ == "__main__":
    workspace_id, primary_key = load_credentials()

    sample_log = [
        {
            "TimeGenerated": datetime.datetime.utcnow().isoformat() + "Z",
            "UserPrincipalName": "ceo@company.com",
            "IPAddress": "154.1.1.23",
            "Location": "Lagos, Nigeria",
            "ResultType": "0",  # 0 = successful sign-in
            "AppDisplayName": "Office 365",
        }
    ]

    status, text = post_logs(workspace_id, primary_key, json.dumps(sample_log), LOG_TYPE)
    print("Status code:", status)
    print("Accepted." if status == 200 else f"Error: {text}")
