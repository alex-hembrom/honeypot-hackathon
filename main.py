from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict

# Initialize the App
app = FastAPI()

# --- A. DATA MODELS (Defining the structure of incoming data) ---
# This matches Section 6 of your problem statement exactly.

class MessageContent(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str

class IncomingRequest(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: List[MessageContent] = []  # Can be empty for first message
    metadata: Optional[Dict] = None

# --- B. DUMMY PROCESSING LOGIC ---
# This is where your "Brain" will go later. For now, it's just a placeholder.

def analyze_and_generate_response(data: IncomingRequest):
    # TODO: Connect LLM here later to generate real replies
    return {
        "is_scam": True,
        "reply": "Oh my god, I am so worried. How do I verify?", # Fake Agent Reply
        "extracted_data": {}
    }

# --- C. THE MAIN API ENDPOINT ---
# This is the door the Hackathon platform knocks on.

@app.post("/analyze")
async def analyze_message(
    payload: IncomingRequest, 
    x_api_key: str = Header(...) # This enforces the API Key check (Section 4)
):
    # 1. Check Authentication
    MY_SECRET_KEY = "my_secret_password" # You will change this later
    if x_api_key != MY_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    print(f"Received message from session: {payload.sessionId}")
    print(f"Message text: {payload.message.text}")

    # 2. Process the message (The "Brain")
    result = analyze_and_generate_response(payload)

    # 3. Construct the Response (Matching Section 8)
    response_data = {
        "status": "success",
        "scamDetected": result["is_scam"],
        "engagementMetrics": {
            "engagementDurationSeconds": 10, # Dummy value
            "totalMessagesExchanged": len(payload.conversationHistory) + 1
        },
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": []
        },
        "agentNotes": "Simulation mode. Response generated."
    }
    
    return response_data

# --- D. START INSTRUCTION ---
# To run this, use the command: uvicorn main:app --reload