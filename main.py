import os
import json
import re
import sqlite3
import asyncio
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Security, Depends, Header
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
import logging
from contextlib import asynccontextmanager
import google.generativeai as genai

# ========== CONFIGURATION ==========
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get API key from environment
GOOGLE_AI_API_KEY = os.getenv("GOOGLE_AI_API_KEY", "")
HONEYPOT_API_KEY = os.getenv("HONEYPOT_API_KEY", "default-secret-key-123")
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Configure Google AI
if GOOGLE_AI_API_KEY:
    genai.configure(api_key=GOOGLE_AI_API_KEY)
    AI_MODEL = "models/gemini-pro"
else:
    AI_MODEL = None
    logger.warning("Google AI API key not found. Using rule-based responses.")

# ========== DATABASE SETUP ==========
def init_db():
    conn = sqlite3.connect('honeypot.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        scam_detected BOOLEAN DEFAULT 0,
        messages TEXT,
        start_time TIMESTAMP,
        intelligence TEXT,
        agent_persona TEXT,
        conversation_phase TEXT DEFAULT 'initial',
        callback_sent BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# ========== LIFECYCLE MANAGEMENT ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Agentic Honey-Pot API")
    yield
    # Shutdown
    logger.info("Shutting down Agentic Honey-Pot API")

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Agentic Honey-Pot API",
    description="AI-powered scam detection and intelligence extraction system",
    version="2.0.0",
    lifespan=lifespan
)

# ========== SECURITY ==========
API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

async def verify_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key missing")
    if api_key != HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return api_key

# ========== DATA MODELS ==========
class Message(BaseModel):
    sender: str
    text: str
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str] = None
    language: Optional[str] = None
    locale: Optional[str] = None

class RequestPayload(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

class Intelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int = 0
    totalMessagesExchanged: int = 0

class ResponsePayload(BaseModel):
    status: str = "success"
    scamDetected: bool = False
    engagementMetrics: Optional[EngagementMetrics] = None
    extractedIntelligence: Optional[Intelligence] = None
    agentNotes: Optional[str] = None

class SessionState(BaseModel):
    session_id: str
    scam_detected: bool = False
    messages: List[Dict] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)
    intelligence: Intelligence = Field(default_factory=Intelligence)
    agent_persona: Dict = Field(default_factory=dict)
    conversation_phase: str = "initial"
    callback_sent: bool = False

# ========== DATABASE HELPERS ==========
def get_db_connection():
    conn = sqlite3.connect('honeypot.db')
    conn.row_factory = sqlite3.Row
    return conn

def save_session(session: SessionState):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    INSERT OR REPLACE INTO sessions 
    (session_id, scam_detected, messages, start_time, intelligence, 
     agent_persona, conversation_phase, callback_sent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        session.session_id,
        session.scam_detected,
        json.dumps(session.messages),
        session.start_time.isoformat(),
        json.dumps(session.intelligence.dict()),
        json.dumps(session.agent_persona),
        session.conversation_phase,
        session.callback_sent
    ))
    
    conn.commit()
    conn.close()

def load_session(session_id: str) -> Optional[SessionState]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
    
    try:
        return SessionState(
            session_id=row['session_id'],
            scam_detected=bool(row['scam_detected']),
            messages=json.loads(row['messages']),
            start_time=datetime.fromisoformat(row['start_time']),
            intelligence=Intelligence(**json.loads(row['intelligence'])),
            agent_persona=json.loads(row['agent_persona']),
            conversation_phase=row['conversation_phase'],
            callback_sent=bool(row['callback_sent'])
        )
    except:
        return None

# ========== SCAM DETECTION ==========
def detect_scam_intent(text: str) -> Dict[str, Any]:
    """Advanced scam detection with scoring"""
    
    scam_patterns = {
        "urgency": [
            r"urgent", r"immediately", r"right now", r"asap",
            r"within.*hour", r"today.*only", r"last chance"
        ],
        "threat": [
            r"account.*block", r"suspend", r"terminate", r"close",
            r"legal.*action", r"police", r"court", r"fine"
        ],
        "financial": [
            r"upi", r"bank.*account", r"card.*details",
            r"password", r"otp", r"pin", r"cvv"
        ],
        "reward": [
            r"win.*prize", r"congratulation", r"lottery",
            r"free.*gift", r"cashback", r"offer"
        ],
        "verification": [
            r"verify.*account", r"confirm.*details",
            r"update.*information", r"click.*link"
        ]
    }
    
    text_lower = text.lower()
    scores = {}
    detected_patterns = []
    
    for category, patterns in scam_patterns.items():
        category_score = 0
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                category_score += 1
                detected_patterns.append(f"{category}:{pattern}")
        
        scores[category] = category_score
    
    total_score = sum(scores.values())
    is_scam = total_score >= 2  # Threshold
    
    return {
        "is_scam": is_scam,
        "score": total_score,
        "category_scores": scores,
        "patterns": detected_patterns
    }

# ========== INTELLIGENCE EXTRACTION ==========
def extract_intelligence(text: str) -> Intelligence:
    """Extract structured intelligence from message"""
    
    intel = Intelligence()
    
    # UPI IDs (Indian formats)
    upi_patterns = [
        r'[\w\.\-]+@(okaxis|oksbi|okhdfcbank|okicici|paytm|phonepe|gpay|ybl|axl)',
        r'[\w\.\-]+\s*@\s*[\w\.\-]+'
    ]
    
    for pattern in upi_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if '@' in match and len(match) > 5:
                intel.upiIds.append(match.strip())
    
    # Phone numbers (Indian and international)
    phone_patterns = [
        r'\+91[6-9]\d{9}',
        r'[6-9]\d{9}',
        r'\+\d{10,15}',
        r'\(\d{3}\)\s*\d{3}[\s\-]?\d{4}'
    ]
    
    for pattern in phone_patterns:
        matches = re.findall(pattern, text)
        intel.phoneNumbers.extend([m.strip() for m in matches])
    
    # URLs/links
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    links = re.findall(url_pattern, text)
    intel.phishingLinks.extend(links)
    
    # Bank accounts (common patterns)
    account_patterns = [
        r'\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{0,4}',
        r'account\s*(?:no|number|#)?\s*[:=]?\s*[\d\s\-]+',
        r'card\s*(?:no|number|#)?\s*[:=]?\s*[\d\s\-]+'
    ]
    
    for pattern in account_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            # Extract only digits
            digits = re.sub(r'\D', '', match)
            if 10 <= len(digits) <= 20:
                intel.bankAccounts.append(digits)
    
    # Suspicious keywords
    scam_keywords = [
        "urgent", "verify", "immediately", "blocked", "suspend",
        "password", "otp", "click", "link", "bank", "account",
        "upi", "payment", "win", "prize", "lottery", "free",
        "limited time", "offer", "congratulations", "winner"
    ]
    
    text_words = set(re.findall(r'\w+', text.lower()))
    found_keywords = [kw for kw in scam_keywords if kw in text_words]
    intel.suspiciousKeywords = list(set(found_keywords))
    
    return intel

# ========== AI AGENT ==========
def generate_ai_response(user_message: str, session: SessionState) -> str:
    """Generate human-like response using Google AI"""
    
    if not AI_MODEL or not GOOGLE_AI_API_KEY:
        # Fallback to rule-based responses
        return generate_fallback_response(session)
    
    try:
        # Create conversation context
        conversation_history = "\n".join([
            f"{msg['sender']}: {msg['text']}" 
            for msg in session.messages[-5:]  # Last 5 messages
        ])
        
        # Define agent persona
        persona = session.agent_persona or {
            "name": "Raj",
            "age": "28",
            "occupation": "software engineer",
            "traits": ["curious", "cautious", "helpful", "a bit naive"]
        }
        
        session.agent_persona = persona
        
        # Prepare prompt
        prompt = f"""You are {persona['name']}, a {persona['age']}-year-old {persona['occupation']}. 
        You are talking to someone who might be a scammer, but you don't know that.
        
        Your traits: {', '.join(persona['traits'])}
        
        Conversation so far:
        {conversation_history}
        
        Latest message from them: {user_message}
        
        Respond naturally as {persona['name']}. Be helpful but cautious. Ask questions. Don't reveal suspicion.
        Keep response short (1-2 sentences)."""
        
        # Generate response
        model = genai.GenerativeModel(AI_MODEL)
        response = model.generate_content(prompt)
        
        return response.text.strip()
        
    except Exception as e:
        logger.error(f"AI generation failed: {e}")
        return generate_fallback_response(session)

def generate_fallback_response(session: SessionState) -> str:
    """Rule-based fallback responses"""
    
    response_templates = {
        "initial": [
            "Oh, really? What happened?",
            "I'm not sure I understand. Can you explain?",
            "Why would that happen to my account?",
            "Can you tell me more about this?"
        ],
        "middle": [
            "What do I need to do exactly?",
            "Is there any other way to fix this?",
            "Can you send me the details again?",
            "I'm a bit busy right now. Can this wait?"
        ],
        "final": [
            "Let me check and get back to you.",
            "I need to ask someone about this first.",
            "Can you give me some time to think?",
            "I'll do it in a few minutes."
        ]
    }
    
    phase = session.conversation_phase
    msg_count = len(session.messages)
    
    # Update phase based on conversation length
    if msg_count < 3:
        phase = "initial"
    elif msg_count < 8:
        phase = "middle"
    else:
        phase = "final"
    
    session.conversation_phase = phase
    
    import random
    return random.choice(response_templates[phase])

# ========== CALLBACK HANDLER ==========
async def send_callback_to_guvi(session: SessionState):
    """Send final intelligence to GUVI"""
    
    if session.callback_sent or not session.scam_detected:
        return
    
    # Only send after sufficient engagement
    if len(session.messages) < 3:
        return
    
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": len(session.messages),
        "extractedIntelligence": session.intelligence.dict(),
        "agentNotes": f"Scammer engaged in {len(session.messages)} messages. "
                     f"Detected patterns: {', '.join(set(session.intelligence.suspiciousKeywords))}"
    }
    
    try:
        response = requests.post(
            CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            session.callback_sent = True
            save_session(session)
            logger.info(f"Callback successful for session {session.session_id}")
        else:
            logger.error(f"Callback failed: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Callback error: {e}")

# ========== MAIN ENDPOINT ==========
@app.post("/honeypot", response_model=ResponsePayload)
async def honeypot_endpoint(
    request_data: RequestPayload,
    api_key: str = Depends(verify_api_key)
):
    """Main endpoint for scam detection and engagement"""
    
    logger.info(f"Request received: {request_data.sessionId}")
    
    # Load or create session
    session = load_session(request_data.sessionId)
    if not session:
        session = SessionState(session_id=request_data.sessionId)
    
    # Add new message to session
    session.messages.append({
        "sender": request_data.message.sender,
        "text": request_data.message.text,
        "timestamp": request_data.message.timestamp
    })
    
    # Detect scam intent
    detection_result = detect_scam_intent(request_data.message.text)
    scam_detected = detection_result["is_scam"] or session.scam_detected
    
    if scam_detected:
        session.scam_detected = True
        
        # Extract intelligence
        new_intel = extract_intelligence(request_data.message.text)
        
        # Merge intelligence
        session.intelligence.bankAccounts = list(set(
            session.intelligence.bankAccounts + new_intel.bankAccounts
        ))
        session.intelligence.upiIds = list(set(
            session.intelligence.upiIds + new_intel.upiIds
        ))
        session.intelligence.phishingLinks = list(set(
            session.intelligence.phishingLinks + new_intel.phishingLinks
        ))
        session.intelligence.phoneNumbers = list(set(
            session.intelligence.phoneNumbers + new_intel.phoneNumbers
        ))
        session.intelligence.suspiciousKeywords = list(set(
            session.intelligence.suspiciousKeywords + new_intel.suspiciousKeywords
        ))
    
    # Generate agent response
    agent_response = ""
    if scam_detected:
        agent_response = generate_ai_response(
            request_data.message.text,
            session
        )
    
    # Calculate metrics
    engagement_seconds = 0
    if session.start_time:
        engagement_seconds = int((datetime.now() - session.start_time).total_seconds())
    
    # Save session
    save_session(session)
    
    # Schedule callback if conditions met
    if (scam_detected and 
        len(session.messages) >= 3 and 
        not session.callback_sent):
        asyncio.create_task(send_callback_to_guvi(session))
    
    # Prepare response
    response = ResponsePayload(
        status="success",
        scamDetected=scam_detected,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=engagement_seconds,
            totalMessagesExchanged=len(session.messages)
        ),
        extractedIntelligence=session.intelligence if scam_detected else None,
        agentNotes=agent_response if scam_detected else None
    )
    
    logger.info(f"Response sent: scam_detected={scam_detected}, messages={len(session.messages)}")
    return response

# ========== ADDITIONAL ENDPOINTS ==========
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "ai_available": bool(GOOGLE_AI_API_KEY)
    }

@app.get("/session/{session_id}")
async def get_session_info(session_id: str):
    """Debug endpoint to check session data"""
    session = load_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "session_id": session.session_id,
        "scam_detected": session.scam_detected,
        "message_count": len(session.messages),
        "intelligence": session.intelligence.dict(),
        "phase": session.conversation_phase,
        "callback_sent": session.callback_sent
    }

@app.get("/stats")
async def get_stats():
    """Get system statistics"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total_sessions FROM sessions")
    total_sessions = cursor.fetchone()['total_sessions']
    
    cursor.execute("SELECT COUNT(*) as scam_sessions FROM sessions WHERE scam_detected = 1")
    scam_sessions = cursor.fetchone()['scam_sessions']
    
    conn.close()
    
    return {
        "total_sessions": total_sessions,
        "scam_sessions": scam_sessions,
        "uptime": "running",
        "ai_enabled": bool(GOOGLE_AI_API_KEY)
    }

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    
    # Get port from environment (Render sets this)
    port = int(os.getenv("PORT", 8000))
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )