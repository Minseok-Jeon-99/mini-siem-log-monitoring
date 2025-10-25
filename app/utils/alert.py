# fastapi_app/utils/alert.py
import requests, os

def send_slack_alert(message: str):
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        print("[WARN] Slack webhook not set.")
        return
    payload = {"text": message}
    requests.post(webhook, json=payload)
