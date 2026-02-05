import requests
import json

# Your Render URL
API_URL = "https://your-app-name.onrender.com/honeypot"
API_KEY = "your-secret-honeypot-key-123"  # Same as in .env

headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

# Test payload
payload = {
    "sessionId": "test-001",
    "message": {
        "sender": "scammer",
        "text": "Your bank account will be blocked in 2 hours. Click http://fake-bank-verify.com to verify immediately.",
        "timestamp": "2026-01-21T10:15:30Z"
    },
    "conversationHistory": [],
    "metadata": {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
}

try:
    response = requests.post(API_URL, headers=headers, json=payload, timeout=10)
    print("Status Code:", response.status_code)
    print("Response:", json.dumps(response.json(), indent=2))
except Exception as e:
    print("Error:", e)