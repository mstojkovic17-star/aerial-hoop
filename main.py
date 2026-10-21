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
TRAINER_PIN = os.environ.get("TRAINER_PIN", "")  # lives ONLY in env / .env
JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_DAYS = 30

# Never crash on import if env vars are missing; /api/health shows what is missing.
client = AsyncIOMotorClient(MONGO_URL or "mongodb://localhost:27017", serverSelectionTimeoutMS=8000)
db = client[DB_NAME]

app = FastAPI(title="Aerial Hoop")
api = APIRouter(prefix="/api")

# ---------- helpers ----------

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
        # Non-trainers never receive notes or attendance
        doc["note"] = ""
        doc["attended_dates"] = []
        doc["dont_know"] = False
    return doc


# ---------- PIN rate limiting (5 wrong attempts / 5 minutes / IP) ----------

_fails: dict[str, deque] = defaultdict(deque)
WINDOW = 300
MAX_FAILS = 5


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------- models ----------


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


# ---------- routes ----------


@api.get("/health")
async def health():
    """Shows which settings are present (never their values) and whether MongoDB answers."""
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
        raise HTTPException(429, "Previše pokušaja. Pokušaj ponovo za nekoliko minuta.")
    if body.pin != TRAINER_PIN:
        q.append(now)
        raise HTTPException(401, "Pogrešan PIN")
    q.clear()
    return {"token": make_token()}


@api.get("/signups")
async def list_signups(month: str, trainer: bool = Depends(optional_trainer)):
    valid_month(month)
    docs = await db.signups.find({"month": month}).sort("created_at", 1).to_list(1000)
    return [public_view(d, trainer) for d in docs]


@api.get("/cancelled")
async def list_cancelled(month: str):
    valid_month(month)
    docs = await db.cancelled.find({"date": {"$regex": f"^{month}"}}).to_list(100)
    return [d["date"] for d in docs]


@api.post("/signups")
async def create_signup(body: SignupIn):
    valid_month(body.month)
    days = training_days(body.month)
    half = body.half if body.plan == "half" else None
    if body.plan == "half" and half is None:
        raise HTTPException(400, "Izaberi koji deo meseca")
    assigned: list[str] = []
    if body.plan == "full":
        assigned = days
    elif half == "first":
        assigned = days[:4]
    elif half == "second":
        assigned = days[-4:]
    doc = {
        "id": str(uuid.uuid4()),
        "name": body.name.strip(),
        "month": body.month,
        "group": body.group,
        "plan": body.plan,
        "half": half,
        "note": body.note.strip(),
        "dont_know": body.dont_know,
        "assigned_dates": assigned,
        "excluded_dates": [],
        "attended_dates": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.signups.insert_one(dict(doc))
    return public_view(doc, False)


@api.delete("/signups/{signup_id}")
async def delete_signup(signup_id: str, _: bool = Depends(require_trainer)):
    res = await db.signups.delete_one({"id": signup_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Prijava nije pronađena")
    return {"ok": True}


@api.post("/signups/{signup_id}/dates")
async def edit_dates(signup_id: str, body: DateAction, _: bool = Depends(require_trainer)):
    valid_date(body.date)
    if body.action == "add":
        upd = {"$addToSet": {"assigned_dates": body.date}, "$pull": {"excluded_dates": body.date}}
    else:
        upd = {"$addToSet": {"excluded_dates": body.date}, "$pull": {"assigned_dates": body.date}}
    res = await db.signups.update_one({"id": signup_id}, upd)
    if res.matched_count == 0:
        raise HTTPException(404, "Prijava nije pronađena")
    doc = await db.signups.find_one({"id": signup_id})
    return public_view(doc, True)


@api.post("/signups/{signup_id}/attendance")
async def set_attendance(signup_id: str, body: AttendanceIn, _: bool = Depends(require_trainer)):
    valid_date(body.date)
    op = "$addToSet" if body.attended else "$pull"
    res = await db.signups.update_one({"id": signup_id}, {op: {"attended_dates": body.date}})
    if res.matched_count == 0:
        raise HTTPException(404, "Prijava nije pronađena")
    doc = await db.signups.find_one({"id": signup_id})
    return public_view(doc, True)


@api.post("/cancelled")
async def cancel_class(body: DateAction, _: bool = Depends(require_trainer)):
    """action=add cancels the class on that date; action=remove restores it."""
    valid_date(body.date)
    if body.action == "add":
        await db.cancelled.update_one({"date": body.date}, {"$set": {"date": body.date}}, upsert=True)
    else:
        await db.cancelled.delete_one({"date": body.date})
    return {"ok": True}


app.include_router(api)

# ---------- frontend ----------

 PUBLIC = Path(__file__).resolve().parent / "static" / "public"


@app.get("/")
async def index():
    return FileResponse(PUBLIC / "index.html")
