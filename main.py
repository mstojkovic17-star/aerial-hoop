import calendar
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

load_dotenv()

MONGO_URL = os.environ.get("MONGO_URL", "")
DB_NAME = os.environ.get("DB_NAME", "aerial_hoop")
TRAINER_PIN = os.environ.get("TRAINER_PIN", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_DAYS = 30

client = AsyncIOMotorClient(MONGO_URL or "mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = client[DB_NAME]

app = FastAPI(title="Aerial Hoop")
api = APIRouter(prefix="/api")

TRAINING_WEEKDAYS = (1, 3)  # Tuesday, Thursday


def training_days(month: str) -> list[str]:
    y, m = map(int, month.split("-"))
    days = []
    for d in range(1, calendar.monthrange(y, m)[1] + 1):
        if date(y, m, d).weekday() in TRAINING_WEEKDAYS:
            days.append(date(y, m, d).isoformat())
    return days


def valid_month(month: str) -> str:
    try:
        datetime.strptime(month, "%Y-%m")
    except ValueError:
        raise HTTPException(400, "Neispravan mesec")
    return month


def valid_date(d: str) -> str:
    try:
        datetime.strptime(d, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Neispravan datum")
    return d


def make_token() -> str:
    if not JWT_SECRET:
        raise HTTPException(500, "Server nije podešen: nedostaje JWT_SECRET")
    exp = datetime.now(timezone.utc) + timedelta(days=JWT_DAYS)
    return jwt.encode({"role": "trainer", "exp": exp}, JWT_SECRET, algorithm="HS256")


def is_trainer_token(token: Optional[str]) -> bool:
    if not token or not JWT_SECRET:
        return False
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return data.get("role") == "trainer"
    except jwt.PyJWTError:
        return False


def bearer(authorization: Optional[str]) -> Optional[str]:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


async def optional_trainer(authorization: Optional[str] = Header(None)) -> bool:
    return is_trainer_token(bearer(authorization))


async def require_trainer(authorization: Optional[str] = Header(None)) -> bool:
    if not is_trainer_token(bearer(authorization)):
        raise HTTPException(401, "Potrebna je prijava trenerice")
    return True


def public_view(doc: dict, trainer: bool) -> dict:
    doc = {k: v for k, v in doc.items() if k != "_id"}
    if not trainer:
        doc["note"] = ""
        doc["attended_dates"] = []
        doc["dont_know"] = False
    return doc


_fails: dict[str, deque] = defaultdict(deque)
WINDOW = 300
MAX_FAILS = 5


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class PinIn(BaseModel):
    pin: str


class SignupIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    month: str
    group: Literal[1, 2]
    plan: Literal["full", "half"]
    half: Optional[Literal["first", "second", "other"]] = None
    note: str = Field(default="", max_length=1000)
    dont_know: bool = False


class DateAction(BaseModel):
    date: str
    action: Literal["add", "remove"]


class AttendanceIn(BaseModel):
    date: str
    attended: bool


@api.get("/health")
async def health():
    info = {
        "MONGO_URL": bool(MONGO_URL),
        "TRAINER_PIN": bool(TRAINER_PIN),
        "JWT_SECRET": bool(JWT_SECRET),
        "mongo_connected": False,
    }
    try:
        await client.admin.command("ping")
        info["mongo_connected"] = True
    except Exception as e:  # noqa: BLE001
        info["mongo_error"] = type(e).__name__
    return info


@api.post("/auth/pin")
async def auth_pin(body: PinIn, request: Request):
    if not TRAINER_PIN:
        raise HTTPException(500, "Server nije podešen: nedostaje TRAINER_PIN")
    ip = client_ip(request)
    now = time.time()
    q = _fails[ip]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= MAX_FAILS:
        raise HTTPException(429,
