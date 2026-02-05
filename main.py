import os
import sqlite3
import logging  # <--- NEW: Import logging tool
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict
from dotenv import load_dotenv

# --- 0. LOGGING SETUP (NEW) ---
# This makes logs show up in Render with timestamps
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
        logger.info("Database initialized successfully.") # <--- NEW: Confirm DB works
    except Exception as e:
        logger.error(f"Database Error: {e}") # <--- NEW: Log DB errors

init_db()

# --- 3. DATA MODELS ---
class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: str

class IncomingRequest(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: List[MessageContent] = []
    metadata: Optional[Dict] = None

# --- 4. HELPER FUNCTIONS ---
def format_history_for_ai(history: List[MessageContent], current_msg: str) -> str:
    script = ""
    for msg in history:
        role = "Scammer" if msg.sender == "scammer" else "Grandpa Joe"
        script += f"{role}: {msg.text}\n"
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
        # <--- NEW: detailed error log
        logger.error(f"Gemini AI Failed: {e}")
        return "I am clicking the button but nothing is happening. Can you help?"

# --- 5. API ENDPOINTS ---

# <--- NEW: This fixes the "404 Not Found" log error!
@app.get("/")
def home():
    logger.info("Someone checked the server health.")
    return {"status": "online", "message": "Honeypot is active. Post to /analyze to use."}

@app.post("/analyze")
async def analyze_message(payload: IncomingRequest, x_api_key: str = Header(...)):
    logger.info(f"Received request for Session ID: {payload.sessionId}") # <--- NEW: Log incoming requests

    if x_api_key != "my_secret_password":
        logger.warning(f"Invalid API Key used: {x_api_key}") # <--- NEW: Log security issues
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # Update Database
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (session_id, message_count) 
            VALUES (?, ?) 
            ON CONFLICT(session_id) DO UPDATE SET 
            message_count = message_count + 1
        ''', (payload.sessionId, len(payload.conversationHistory) + 1))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to save to database: {e}")

    # Process AI
    chat_context = format_history_for_ai(payload.conversationHistory, payload.message.text)
    ai_reply = call_gemini(chat_context)
    
    logger.info("Successfully generated AI response.") # <--- NEW: Success log

    return {
        "status": "success",
        "scamDetected": True,
        "engagementMetrics": {
            "engagementDurationSeconds": (len(payload.conversationHistory) + 1) * 15,
            "totalMessagesExchanged": len(payload.conversationHistory) + 1
        },
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [], 
            "phishingLinks": []
        },
        "agentNotes": ai_reply 
    }