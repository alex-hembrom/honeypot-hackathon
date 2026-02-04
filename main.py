import os
import sqlite3
import google.generativeai as genai
from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict
from dotenv import load_dotenv

# --- 1. SECURITY SETUP ---
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("CRITICAL WARNING: GEMINI_API_KEY not found in .env file!")
else:
    genai.configure(api_key=GEMINI_API_KEY)

app = FastAPI()

# --- 2. DATABASE SETUP (SQLite) ---
DB_NAME = "honeypot.db"

def init_db():
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

# --- 4. MEMORY LOGIC ---
def format_history_for_ai(history: List[MessageContent], current_msg: str) -> str:
    script = ""
    for msg in history:
        role = "Scammer" if msg.sender == "scammer" else "Grandpa Joe"
        script += f"{role}: {msg.text}\n"
    
    script += f"Scammer: {current_msg}\n"
    script += "Grandpa Joe:" 
    return script

# --- 5. THE BRAIN (PHASE 3: Updated Persona) ---
def call_gemini(formatted_transcript: str):
    # This is the "Persona". We tell the AI exactly who to be.
    system_instruction = """
    You are 'Grandpa Joe', an 85-year-old retired school teacher.
    You are not tech-savvy and get easily confused by modern apps.
    
    YOUR GOAL:
    You currently have money in your account and you are WORRIED about losing it.
    You WANT to comply with the scammer, but you don't know how.
    
    STRATEGY:
    1. Act panicked and eager to resolve the issue.
    2. Bait the scammer: Tell them you are ready to pay.
    3. THE TRAP: Ask them clearly for their 'UPI ID', 'Bank Account Number', or 'QR Code' so you can transfer the money.
    4. Do NOT reveal you are an AI.
    5. Keep responses short (under 30 words) and use slight typos (to look real).
    """
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        
        # We combine the Persona + The Chat History
        prompt = f"{system_instruction}\n\n=== CONVERSATION LOG ===\n{formatted_transcript}"
        
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        # Fallback if AI fails (e.g. internet issue)
        return "I am clicking the button but nothing is happening. Can you help?"

# --- 6. API ENDPOINT ---
@app.post("/analyze")
async def analyze_message(
    payload: IncomingRequest, 
    x_api_key: str = Header(...)
):
    # Auth Check
    if x_api_key != "my_secret_password":
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # A. Update Database
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

    # B. Process Memory
    chat_context = format_history_for_ai(
        payload.conversationHistory, 
        payload.message.text
    )

    # C. Generate Reply
    ai_reply = call_gemini(chat_context)

    # D. Return Response
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