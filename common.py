"""Shared helper: send JSON logs to a Log Analytics workspace (HTTP Data Collector API).

Credentials are read from environment variables, never hard-coded:
    LA_WORKSPACE_ID   - Log Analytics workspace ID
    LA_PRIMARY_KEY    - workspace primary (shared) key
"""

import base64
import datetime
import hashlib
import hmac
import os
import sys

import requests


def load_credentials():
    workspace_id = os.environ.get("LA_WORKSPACE_ID")
    primary_key = os.environ.get("LA_PRIMARY_KEY")
    if not workspace_id or not primary_key:
        sys.exit("Set LA_WORKSPACE_ID and LA_PRIMARY_KEY environment variables first.")
    return workspace_id, primary_key


def build_signature(workspace_id, primary_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(primary_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


def post_logs(workspace_id, primary_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")

    signature = build_signature(
        workspace_id, primary_key, rfc1123date, len(body), method, content_type, resource
    )
    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }
    response = requests.post(uri, data=body, headers=headers, timeout=30)
    return response.status_code, response.text
