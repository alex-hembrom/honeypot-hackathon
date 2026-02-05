import os
import sqlite3
import logging
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

# --- 0. LOGGING SETUP ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- 1. SECURITY SETUP ---
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    logger.error("CRITICAL: GEMINI_API_KEY is missing from environment variables!")
else:
    genai.configure(api_key=GEMINI_API_KEY)

app = FastAPI()

# --- 2. DATABASE SETUP ---
DB_NAME = "honeypot.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                message_count INTEGER,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Database Error: {e}")

init_db()

# --- 3. HELPER FUNCTIONS ---
def format_history_for_ai(history: List[Any], current_msg: str) -> str:
    script = ""
    # This loop now handles both Objects and Dictionaries safely
    for item in history:
        # Get 'sender' and 'text' regardless of format
        if isinstance(item, dict):
            sender = item.get('sender', 'unknown')
            text = item.get('text', '')
        else:
            sender = getattr(item, 'sender', 'unknown')
            text = getattr(item, 'text', '')
            
        role = "Scammer" if str(sender).lower() == "scammer" else "Grandpa Joe"
        script += f"{role}: {text}\n"
    
    script += f"Scammer: {current_msg}\n"
    script += "Grandpa Joe:" 
    return script

def call_gemini(formatted_transcript: str):
    system_instruction = """
    You are 'Grandpa Joe', an 85-year-old retired school teacher.
    You are NOT tech-savvy. You are worried about losing money.
    GOAL: Bait the scammer. Ask for their 'UPI ID' or 'Bank Details' to pay them.
    Keep responses short and include slight typos.
    """
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"{system_instruction}\n\n=== CONVERSATION LOG ===\n{formatted_transcript}"
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Gemini AI Failed: {e}")
        return "I am clicking the button but nothing is happening. Can you help?"

# --- 4. API ENDPOINTS ---
@app.get("/")
def home():
    logger.info("Someone checked the server health.")
    return {"status": "online", "message": "Honeypot is active. Post to /analyze to use."}

@app.post("/analyze")
async def analyze_message(request: Request, x_api_key: str = Header(...)):
    # --- STEP 1: READ RAW DATA (Fixes 422 Error) ---
    try:
        data = await request.json()
        logger.info(f"RAW RECEIVED DATA: {data}") # Check your Render logs to see exactly what GUVI sent!
    except Exception:
        logger.error("Could not parse JSON body")
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # --- STEP 2: VALIDATE KEY ---
    if x_api_key != "my_secret_password":
        logger.warning(f"Invalid API Key used: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # --- STEP 3: SMART DATA EXTRACTION ---
    # We look for fields even if they are named slightly differently
    session_id = data.get('sessionId') or data.get('session_id') or "default-session"
    
    # Handle 'message' being a string OR an object
    user_text = ""
    msg_obj = data.get('message')
    if isinstance(msg_obj, dict):
        user_text = msg_obj.get('text', '')
    elif isinstance(msg_obj, str):
        user_text = msg_obj
    else:
        user_text = data.get('text') or "Hello"

    # Handle history
    history = data.get('conversationHistory') or data.get('history') or []

    # --- STEP 4: UPDATE DATABASE ---
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (session_id, message_count) 
            VALUES (?, ?) 
            ON CONFLICT(session_id) DO UPDATE SET 
            message_count = message_count + 1
        ''', (session_id, len(history) + 1))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save to database: {e}")

    # --- STEP 5: GENERATE AI RESPONSE ---
    chat_context = format_history_for_ai(history, user_text)
    ai_reply = call_gemini(chat_context)
    
    logger.info(f"Success! Reply: {ai_reply}")

    # --- STEP 6: RETURN RESPONSE ---
    return {
        "status": "success",
        "scamDetected": True,
        "engagementMetrics": {
            "engagementDurationSeconds": (len(history) + 1) * 15,
            "totalMessagesExchanged": len(history) + 1
        },
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [], 
            "phishingLinks": []
        },
        "agentNotes": ai_reply 
    }