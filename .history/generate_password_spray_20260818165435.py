"""
Generate dữ liệu synthetic: Password Spray Attack (Day -3 và Day -2)
Theo đúng scenario: hàng trăm failed sign-in trên nhiều tài khoản, từ IP tấn công (Lagos).
Đẩy thẳng vào Sentinel qua HTTP Data Collector API.
"""

import base64
import hashlib
import hmac
import json
import datetime
import random
import requests

# ============ ĐIỀN THÔNG TIN CỦA BẠN VÀO ĐÂY ============
WORKSPACE_ID = "********************"
PRIMARY_KEY = "*********************"
LOG_TYPE = "SigninLogs"  # cùng bảng SigninLogs_CL với log CEO trước đó
# ==========================================================

# Cấu hình cuộc tấn công password spray
ATTACKER_IPS = ["154.1.1.23", "154.1.1.45", "154.1.1.67"]  # vài IP trong cùng dải Lagos, giả lập botnet/proxy xoay IP
NUM_TARGET_ACCOUNTS = 40          # số tài khoản bị tấn công mỗi đêm
FAILED_ATTEMPTS_PER_NIGHT = 300   # tổng số failed sign-in mỗi đêm
RESULT_TYPE_FAILED = "50126"      # mã lỗi Azure AD: sai username hoặc password


def build_signature(workspace_id, primary_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(primary_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


def post_logs(workspace_id, primary_key, body, log_type):
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
    return response.status_code, response.text


def generate_target_accounts(n):
    """Tạo danh sách tài khoản giả bị tấn công, ví dụ user1@company.com ... userN@company.com"""
    return [f"user{i}@company.com" for i in range(1, n + 1)]


def generate_night_logs(days_ago, num_attempts, target_accounts):
    """
    Generate các dòng log failed sign-in cho 1 đêm, rải rác trong khung giờ 1AM-4AM
    (khung giờ điển hình của tấn công password spray tự động).
    """
    logs = []
    base_date = datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)
    # đặt về đầu ngày, rồi cộng thêm giờ ngẫu nhiên trong khung 1AM-4AM
    base_date = base_date.replace(hour=0, minute=0, second=0, microsecond=0)

    for _ in range(num_attempts):
        random_offset_seconds = random.randint(1 * 3600, 4 * 3600)  # 1AM - 4AM
        timestamp = base_date + datetime.timedelta(seconds=random_offset_seconds)

        log_entry = {
            "TimeGenerated": timestamp.isoformat() + "Z",
            "UserPrincipalName": random.choice(target_accounts),
            "IPAddress": random.choice(ATTACKER_IPS),
            "Location": "Lagos, Nigeria",
            "ResultType": RESULT_TYPE_FAILED,
            "AppDisplayName": "Office 365",
        }
        logs.append(log_entry)

    return logs


def send_in_batches(logs, batch_size=100):
    """Gửi log theo từng batch để tránh request quá lớn."""
    total_sent = 0
    for i in range(0, len(logs), batch_size):
        batch = logs[i : i + batch_size]
        body = json.dumps(batch)
        status_code, response_text = post_logs(WORKSPACE_ID, PRIMARY_KEY, body, LOG_TYPE)

        if status_code == 200:
            total_sent += len(batch)
            print(f"  ✅ Batch {i // batch_size + 1}: gửi thành công {len(batch)} logs (status {status_code})")
        else:
            print(f"  ❌ Batch {i // batch_size + 1}: LỖI (status {status_code}) - {response_text}")

    return total_sent


if __name__ == "__main__":
    target_accounts = generate_target_accounts(NUM_TARGET_ACCOUNTS)

    print(f"Đã tạo {NUM_TARGET_ACCOUNTS} tài khoản mục tiêu giả lập.\n")

    # ---- Day -3 ----
    print("=== Generating Day -3: Hundreds of failed sign-ins ===")
    day3_logs = generate_night_logs(days_ago=3, num_attempts=FAILED_ATTEMPTS_PER_NIGHT, target_accounts=target_accounts)
    sent_day3 = send_in_batches(day3_logs)
    print(f"Tổng cộng Day -3: {sent_day3}/{len(day3_logs)} logs đã gửi thành công.\n")

    # ---- Day -2 ----
    print("=== Generating Day -2: Hundreds of failed sign-ins ===")
    day2_logs = generate_night_logs(days_ago=2, num_attempts=FAILED_ATTEMPTS_PER_NIGHT, target_accounts=target_accounts)
    sent_day2 = send_in_batches(day2_logs)
    print(f"Tổng cộng Day -2: {sent_day2}/{len(day2_logs)} logs đã gửi thành công.\n")

    print("=== HOÀN TẤT ===")
    print(f"Tổng số failed sign-in đã đẩy vào Sentinel: {sent_day3 + sent_day2}")
    print("Đợi 2-15 phút rồi vào Sentinel → Logs, chạy query KQL để kiểm tra kết quả.")