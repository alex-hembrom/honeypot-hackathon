import os
import json
import re
import asyncio
import requests
from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import logging
import google.generativeai as genai

# ========== SETUP ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Keys
GOOGLE_AI_API_KEY = os.getenv("GOOGLE_AI_API_KEY", "")
API_KEY = os.getenv("API_KEY", "hackathon-secret-key-2024")

# Initialize AI
if GOOGLE_AI_API_KEY:
    genai.configure(api_key=GOOGLE_AI_API_KEY)
    AI_MODEL = genai.GenerativeModel('gemini-pro')
else:
    AI_MODEL = None
    logger.warning("Google AI not available - using rule-based responses")

# In-memory storage (simple for hackathon)
sessions = {}

# ========== MODELS ==========
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class RequestPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Dict] = None

class Intelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class ResponsePayload(BaseModel):
    status: str = "success"
    scamDetected: bool = False
    engagementMetrics: Optional[Dict] = None
    extractedIntelligence: Optional[Intelligence] = None
    agentNotes: Optional[str] = None

# ========== APP ==========
app = FastAPI(title="Agentic Honey-Pot", version="1.0")

# ========== AUTH ==========
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if not api_key or api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True

# ========== SCAM DETECTION ==========
def detect_scam(text: str) -> bool:
    scam_indicators = [
        "urgent", "verify", "immediately", "blocked", "suspend",
        "account", "bank", "password", "otp", "click", "link",
        "upi", "payment", "win", "prize", "lottery", "free",
        "congratulations", "winner", "offer", "limited"
    ]
    
    text_lower = text.lower()
    score = sum(1 for word in scam_indicators if word in text_lower)
    
    # Check for URL patterns
    if re.search(r'http[s]?://', text_lower):
        score += 2
    
    return score >= 2

# ========== INTELLIGENCE EXTRACTION ==========
def extract_intel(text: str) -> Intelligence:
    intel = Intelligence()
    
    # UPI IDs
    upi_matches = re.findall(r'[\w\.-]+@[\w\.-]+', text)
    intel.upiIds = list(set(upi_matches))
    
    # Phone numbers
    phone_matches = re.findall(r'[\+\d\s\-\(\)]{10,}', text)
    intel.phoneNumbers = [p.strip() for p in phone_matches if len(re.sub(r'\D', '', p)) >= 10]
    
    # Links
    link_matches = re.findall(r'https?://[^\s]+', text)
    intel.phishingLinks = link_matches
    
    # Bank accounts (simplified)
    account_matches = re.findall(r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}', text)
    intel.bankAccounts = account_matches
    
    # Keywords
    scam_words = ["urgent", "verify", "blocked", "password", "otp", "upi", "win", "free"]
    found = [w for w in scam_words if w in text.lower()]
    intel.suspiciousKeywords = list(set(found))
    
    return intel

# ========== AI AGENT ==========
def generate_response(text: str, session_id: str) -> str:
    if AI_MODEL:
        try:
            prompt = f"""You're a regular person chatting. Someone sent you this message: "{text}"
            You suspect nothing. Respond naturally, casually. Keep it short (1 sentence)."""
            
            response = AI_MODEL.generate_content(prompt)
            return response.text.strip()
        except:
            pass
    
    # Fallback responses
    fallbacks = [
        "Oh really? What happened?",
        "I'm not sure I understand. Can you explain?",
        "Why would that happen?",
        "What should I do about it?",
        "Can you send more details?",
        "Let me check and get back to you."
    ]
    
    import random
    return random.choice(fallbacks)

# ========== CALLBACK ==========
async def send_callback(session_id: str, intel: Intelligence, message_count: int):
    if not session_id.startswith("test-"):
        try:
            payload = {
                "sessionId": session_id,
                "scamDetected": True,
                "totalMessagesExchanged": message_count,
                "extractedIntelligence": intel.dict(),
                "agentNotes": f"Extracted {len(intel.upiIds)} UPI IDs, {len(intel.phoneNumbers)} phone numbers"
            }
            
            requests.post(
                "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
                json=payload,
                timeout=5
            )
        except:
            pass

# ========== MAIN ENDPOINT ==========
@app.post("/honeypot")
async def honeypot(
    data: RequestPayload,
    auth: bool = Depends(verify_api_key)
):
    session_id = data.sessionId
    
    # Initialize session if new
    if session_id not in sessions:
        sessions[session_id] = {
            "messages": [],
            "intel": Intelligence(),
            "start_time": datetime.now(),
            "scam_detected": False
        }
    
    session = sessions[session_id]
    
    # Add message
    session["messages"].append({
        "sender": data.message.sender,
        "text": data.message.text,
        "timestamp": data.message.timestamp
    })
    
    # Detect scam
    scam_detected = detect_scam(data.message.text)
    if scam_detected:
        session["scam_detected"] = True
        
        # Extract intelligence
        new_intel = extract_intel(data.message.text)
        
        # Merge intelligence
        for field in ["bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"]:
            existing = getattr(session["intel"], field)
            new = getattr(new_intel, field)
            setattr(session["intel"], field, list(set(existing + new)))
    
    # Generate response if scam
    agent_response = ""
    if scam_detected:
        agent_response = generate_response(data.message.text, session_id)
    
    # Calculate metrics
    duration = int((datetime.now() - session["start_time"]).total_seconds())
    
    # Send callback if enough messages
    if scam_detected and len(session["messages"]) >= 3:
        asyncio.create_task(
            send_callback(session_id, session["intel"], len(session["messages"]))
        )
    
    # Prepare response
    response = {
        "status": "success",
        "scamDetected": scam_detected,
        "engagementMetrics": {
            "engagementDurationSeconds": duration,
            "totalMessagesExchanged": len(session["messages"])
        },
        "extractedIntelligence": session["intel"].dict() if scam_detected else None,
        "agentNotes": agent_response if scam_detected else None
    }
    
    return response

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "sessions": len(sessions)
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)