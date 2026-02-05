import requests
import json
import uuid
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path="backend/.env")

# BASE_URL = "http://127.0.0.1:8000"
BASE_URL = "https://honeypot-scam-detection-theta.vercel.app" # Vercel Deployment
API_KEY = os.getenv("API_KEY")

def run_step(step_num, title, message, session_id, headers):
    print(f"\n[Step {step_num}] {title}")
    payload = {
        "sessionId": session_id,
        "message": message,
        "conversationHistory": [] 
    }
    try:
        resp = requests.post(f"{BASE_URL}/chat", headers=headers, json=payload)
        resp.raise_for_status()
        print(f"Response: {resp.json()}")
    except Exception as e:
        print(f"Error in Step {step_num}: {e}")

def test_chat():
    session_id = str(uuid.uuid4())
    print(f"--- Starting Test Session: {session_id} ---")
    
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }

    # 1. Normal Greeting
    run_step(1, "Sending Hello...", "Hello, I am calling from the bank.", session_id, headers)

    # 2. Scam Trigger
    run_step(2, "Sending Scam Keyword...", "Your account is blocked. Verification required.", session_id, headers)

    # 3. Intel Extraction (UPI)
    run_step(3, "Sending UPI ID...", "Here is my ID: verify-me@upi. Please pay immediately.", session_id, headers)
    
    # 4. Intel Extraction (Bank Details)
    run_step(4, "Sending Bank Details...", "Or transfer to Account 987654321012, IFSC HDFC0005678 to avoid legal action.", session_id, headers)

    # 5. Compatibility Test (snake_case)
    print("\n[Step 5] Compatibility Test (session_id/text field)...")
    payload_compat = {
        "session_id": session_id,
        "text": "Just checking if this works.",
        "history": []
    }
    try:
        resp = requests.post(f"{BASE_URL}/chat", headers=headers, json=payload_compat)
        resp.raise_for_status()
        print(f"Response: {resp.json()}")
    except Exception as e:
        print(f"Error in Step 5: {e}")

    print("\n--- Test Complete. Check server logs for [ALERT] and [INTEL] messages. ---")

if __name__ == "__main__":
    test_chat()
