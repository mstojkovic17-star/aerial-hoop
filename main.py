import os
import time
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import jwt
from bson import ObjectId
from typing import List, Optional

# Env vars
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
TRAINER_PIN = os.getenv("TRAINER_PIN", "5555")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-in-prod")

app = FastAPI()
client = AsyncIOMotorClient(MONGO_URI)
db = client.aerial_hoop

# Rate limiting for PIN
login_attempts = {}

class SignupModel(BaseModel):
    name: str
    month: str
    group: int
    plan: str
    half: Optional[str] = None
    note: Optional[str] = None
    dont_know: bool = False

class PinModel(BaseModel):
    pin: str

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("role") == "trainer"
    except:
        return None

def verify_trainer(is_trainer: bool = Depends(get_current_user)):
    if not is_trainer:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

@app.post("/api/auth/pin")
async def login(data: PinModel, request: Request):
    ip = request.client.host
    now = time.time()
    
    # Rate limit check (5 attempts per 5 mins)
    if ip in login_attempts:
        attempts = [t for t in login_attempts[ip] if now - t < 300]
        login_attempts[ip] = attempts
        if len(attempts) >= 5:
            raise HTTPException(status_code=429, detail="Too many attempts")

    if data.pin == TRAINER_PIN:
        if ip in login_attempts:
            del login_attempts[ip]
        token = jwt.encode({"role": "trainer", "exp": datetime.utcnow() + timedelta(days=30)}, JWT_SECRET, algorithm="HS256")
        return {"token": token}
    
    login_attempts.setdefault(ip, []).append(now)
    raise HTTPException(status_code=401, detail="Invalid PIN")

@app.get("/api/signups")
async def get_signups(month: str, is_trainer: bool = Depends(get_current_user)):
    cursor = db.signups.find({"month": month})
    signups = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        # Hide private fields if not trainer
        if not is_trainer:
            doc.pop("note", None)
            doc.pop("attended_dates", None)
        signups.append(doc)
    return signups

@app.post("/api/signups")
async def create_signup(signup: SignupModel):
    doc = signup.dict()
    doc.update({
        "assigned_dates": [],
        "excluded_dates": [],
        "attended_dates": [],
        "created_at": datetime.utcnow()
    })
    result = await db.signups.insert_one(doc)
    return {"id": str(result.inserted_id)}

@app.delete("/api/signups/{id}")
async def delete_signup(id: str, _: bool = Depends(verify_trainer)):
    await db.signups.delete_one({"_id": ObjectId(id)})
    return {"status": "ok"}

class DateActionModel(BaseModel):
    date: str
    action: str # "add" or "remove"

@app.post("/api/signups/{id}/dates")
async def modify_signup_dates(id: str, data: DateActionModel, _: bool = Depends(verify_trainer)):
    field = "assigned_dates" if data.action == "add" else "excluded_dates"
    await db.signups.update_one({"_id": ObjectId(id)}, {"$addToSet": {field: data.date}})
    return {"status": "ok"}

class AttendanceModel(BaseModel):
    date: str
    attended: bool

@app.post("/api/signups/{id}/attendance")
async def modify_attendance(id: str, data: AttendanceModel, _: bool = Depends(verify_trainer)):
    update_op = {"$addToSet": {"attended_dates": data.date}} if data.attended else {"$pull": {"attended_dates": data.date}}
    await db.signups.update_one({"_id": ObjectId(id)}, update_op)
    return {"status": "ok"}

# Mount frontend
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/{catchall:path}")
async def serve_index():
    return FileResponse("static/index.html")
