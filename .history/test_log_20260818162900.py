import base64
import hashlib
import hmac
import json
import datetime
import requests

# ============ ĐIỀN THÔNG TIN CỦA BẠN VÀO ĐÂY ============
WORKSPACE_ID = ""YOUR_WORKSPACE_ID_HERE""
PRIMARY_KEY = "Kcl/eAOA5Hq/KYaPbygW/21fjWs4pLUT3BVfYppE8D1Ss6kFaAtclQV4JowMYNnvGLHuJEjAGKJIYr3C5aWvIA=="
LOG_TYPE = "SigninLogs"  # sẽ tự thành bảng "SigninLogs_CL" trong Sentinel
# ==========================================================

def build_signature(workspace_id, primary_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(primary_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"

def post_log(workspace_id, primary_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    signature = build_signature(
        workspace_id, primary_key, rfc1123date, content_length, method, content_type, resource
    )

    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }

    response = requests.post(uri, data=body, headers=headers)
    print("Status code:", response.status_code)
    if response.status_code == 200:
        print("✅ Log đã được server chấp nhận thành công!")
    else:
        print("❌ Có lỗi xảy ra. Response:", response.text)
    return response.status_code

if __name__ == "__main__":
    # 1 dòng log giả: đăng nhập CEO lúc 3AM từ Lagos (theo đúng scenario project)
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

    body = json.dumps(sample_log)
    post_log(WORKSPACE_ID, PRIMARY_KEY, body, LOG_TYPE)