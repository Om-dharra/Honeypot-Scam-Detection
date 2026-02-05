import os
import json
import re
import requests
from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from dotenv import load_dotenv
import google.generativeai as genai
from groq import Groq
import redis

load_dotenv()

app = FastAPI(title="Honeypot Scam Detector")

API_KEY = os.getenv("API_KEY", "secret-api-key-123")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
MAX_HISTORY_CONTEXT = 15 # Sliding window size
GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL")

try:
    r = redis.Redis(
        host=REDIS_HOST, 
        port=REDIS_PORT, 
        password=REDIS_PASSWORD, 
        decode_responses=True,
        socket_connect_timeout=5
    )
    r.ping()
    print("Connected to Redis")
except Exception as e:
    print(f"Warning: Redis connection failed: {e}")
    r = None

class ChatRequest(BaseModel):
    sessionId: Optional[str] = None
    session_id: Optional[str] = None  # Compatibility alias
    message: Optional[str] = None
    text: Optional[str] = None        # Compatibility alias
    query: Optional[str] = None       # Compatibility alias
    input: Optional[str] = None       # Compatibility alias
    content: Optional[str] = None     # Compatibility alias
    conversationHistory: Optional[List[dict]] = []
    history: Optional[List[dict]] = [] # Compatibility alias

class ChatResponse(BaseModel):
    status: str
    reply: str

def get_session(session_id: str) -> dict:
    if r:
        data = r.get(f"session:{session_id}")
        if data:
            return json.loads(data)
    
   
    return {
        "scamDetected": False,
        "intelligence": {
            "upi_ids": [],
            "urls": [],
            "phone_numbers": []
        },
        "message_count": 0,
        "history": [] 
    }

def save_session(session_id: str, data: dict):
    if r:
        r.set(f"session:{session_id}", json.dumps(data))


def extract_intelligence_regex(message: str) -> dict:
    """
    Regex-based extraction to aid the LLM.
    """
    extracted = {
        "upi_ids": [],
        "urls": [],
        "phone_numbers": [],
        "bank_details": [] 
    }
    
     # regex patterns
    upi_pattern = r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}"
    url_pattern = r"https?://[^\s]+"
    phone_pattern = r"(\+91[\-\s]?)?[6-9]\d{9}"
    
    ifsc_pattern = r"[A-Z]{4}0[A-Z0-9]{6}"
    account_pattern = r"\b\d{9,18}\b"
    
    extracted["upi_ids"] = re.findall(upi_pattern, message)
    extracted["urls"] = re.findall(url_pattern, message)
    extracted["phone_numbers"] = re.findall(phone_pattern, message)
    
    # Bank Details
    ifscs = re.findall(ifsc_pattern, message)
    accounts = re.findall(account_pattern, message)
    
    for code in ifscs: extracted["bank_details"].append(f"IFSC: {code}")
    for acc in accounts: extracted["bank_details"].append(f"Account: {acc}")
    
    return extracted

SYSTEM_PROMPT = """
You are acting as a dual-system agent.
1. ANALYST: Analyze the user's message for scam intent (urgency, threats, financial requests, KYC, etc.). Extract any UPI IDs, URLs, Phone numbers, or BANK DETAILS (Account Numbers, IFSC Codes).
2. PERSONA: You are an elderly, non-tech-savvy Indian citizen. You are confused and worried. You want to comply but don't understand technology. Keep the scammer engaged. Never admit you know it's a scam.

INPUT CONTEXT:
- You will receive the conversation history and regex-extracted tokens.

OUTPUT FORMAT:
You must respond in VALID JSON format ONLY. Do not add markdown blocks.
{
    "is_scam": boolean,
    "scam_reason": "short explanation",
    "extracted_intelligence": {
        "upi_ids": ["list", "of", "ids"],
        "urls": ["list", "of", "urls"],
        "phone_numbers": ["list", "of", "numbers"],
        "bank_details": ["list", "of", "account_numbers", "or", "IFSC_codes"]
    },
    "persona_response": "The confused reply text"
}
"""

def process_turn(session_id: str, user_message: str, history: List[dict], regex_intel: dict) -> dict:
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    
    context_message = f"""
    User Message: "{user_message}"
    Regex Hints: {json.dumps(regex_intel)}
    """
    
    try:
        response_text = "{}"
        
        if provider == "groq":
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key: return {"error": "GROQ_API_KEY missing"}
            
            client = Groq(api_key=api_key)
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            
            recent_history = history[-MAX_HISTORY_CONTEXT:]
            
            for msg in recent_history:
                role = "user" if msg.get("sender") == "scammer" else "assistant"
                
                content = msg.get("text", "")
                if content: messages.append({"role": role, "content": content})
            
            messages.append({"role": "user", "content": context_message})
            
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile", 
                messages=messages,
                temperature=0.7,
                max_tokens=300,
                response_format={"type": "json_object"}
            )
            response_text = completion.choices[0].message.content

        elif provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key: return {"error": "GEMINI_API_KEY missing"}
            
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash", generation_config={"response_mime_type": "application/json"})
            
            recent_history = history[-MAX_HISTORY_CONTEXT:]
            
            chat_history = []
            for msg in recent_history:
                role = "user" if msg.get("sender") == "scammer" else "model"
                chat_history.append({"role": role, "parts": [msg.get("text", "")]})
                
            chat = model.start_chat(history=chat_history)
            
            full_prompt = f"{SYSTEM_PROMPT}\n\n{context_message}"
            response = chat.send_message(full_prompt)
            response_text = response.text
            
        else:
            return {"error": f"Unsupported provider {provider}"}

        if "```json" in response_text:
            response_text = response_text.replace("```json", "").replace("```", "")
        elif "```" in response_text:
            response_text = response_text.replace("```", "")
            

        return json.loads(response_text.strip())

    except Exception as e:
        with open("backend/error.log", "a") as f:
            f.write(f"LLM Logic Error: {e}\nResponse Text: {response_text}\n")
        print(f"LLM Logic Error: {e}")
        # Fallback safe response
        return {
            "is_scam": True,
            "scam_reason": "LLM Error Fallback",
            "extracted_intelligence": regex_intel,
            "persona_response": "I... I am having trouble with my phone. Can you say that again?"
        }


def send_callback(session_id: str, session_data: dict):
    """
    Sends the session data to the GUVI callback URL.
    Payload: sessionId, scamDetected, totalMessagesExchanged, extractedIntelligence, agentNotes
    """
    if not GUVI_CALLBACK_URL:
        print("Warning: GUVI_CALLBACK_URL not set. Callback skipped.")
        return

    payload = {
        "sessionId": session_id,
        "scamDetected": session_data["scamDetected"],
        "totalMessagesExchanged": session_data["message_count"],
        "extractedIntelligence": session_data["intelligence"],
        "agentNotes": "Automated report from Honeypot System.",
        "conversationHistory": session_data.get("history", [])
    }

    try:
        response = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        print(f"Callback sent for {session_id}: Status {response.status_code}")
    except Exception as e:
        print(f"Callback failed for {session_id}: {e}")

# --- Routes ---
@app.get("/")
def read_root():
    return {"message": "Honeypot Scam Detector API is running."}

@app.post("/chat", response_model=ChatResponse)
async def chat_endpoint(request: ChatRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    """
    Main chat endpoint.
    1. Validates API Key.
    2. Runs Regex (Helper).
    3. Calls LLM (Analysis + Response).
    4. Updates Session & Triggers Callback.
    """
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Normalize Input (Handle aliases)
    # Normalize Input (Handle aliases)
    session_id = request.sessionId or request.session_id or "default-session"
    user_message = (
        request.message or 
        request.text or 
        request.query or 
        request.input or 
        request.content or 
        "Hello" # Fallback to prevent 422
    )
    
    session = get_session(session_id)
    session["message_count"] += 1
    
    if "history" not in session: session["history"] = []
    session["history"].append({"sender": "scammer", "text": user_message})

    should_trigger_callback = False

   
    regex_intel = extract_intelligence_regex(user_message)

    # 3. LLM Processing (The Brain)
    # We pass the accumulated history from the request (client-side) OR our redis history.
    # The prompt expects list of dicts.
    history_context = request.conversationHistory or request.history or []
    
    llm_result = process_turn(session_id, user_message, history_context, regex_intel)
    
  
    is_scam = llm_result.get("is_scam", False)
    scam_reason = llm_result.get("scam_reason", "Unknown")
    extracted_intel = llm_result.get("extracted_intelligence", {})
    ai_reply = llm_result.get("persona_response", "I am confused.")

  
    
    # Scam Status
    if is_scam and not session["scamDetected"]:
        session["scamDetected"] = True
        should_trigger_callback = True
        print(f"[ALERT] LLM Detected Scam: {scam_reason}")

    for category in ["upi_ids", "urls", "phone_numbers", "bank_details"]:
        found_items = extracted_intel.get(category, [])
        for item in found_items:
            if category not in session["intelligence"]:
                session["intelligence"][category] = []
                
            if item not in session["intelligence"][category]:
                session["intelligence"][category].append(item)
                should_trigger_callback = True
                print(f"[INTEL] Extracted {category}: {item}")

    session["history"].append({"sender": "victim", "text": ai_reply})

    save_session(session_id, session)

    if should_trigger_callback or (session["message_count"] % 10 == 0):
        background_tasks.add_task(send_callback, session_id, session)
    
    return ChatResponse(status="active", reply=ai_reply)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
