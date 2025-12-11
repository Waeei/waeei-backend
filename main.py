import os
import urllib.request
from pathlib import Path
from datetime import datetime
import httpx
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from typing import Optional
from urllib.parse import urlparse
from openai import OpenAI

load_dotenv()

# ========= API KEYS =========
GSB_KEY = os.getenv("GSB_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_KEY)

# ========= FASTAPI APP =========
app = FastAPI(title="Waaei Link Scanner")

# ========= DATABASE =========
db_path = os.getenv("DB_PATH", "WaaeiDB.db")
DATABASE_URL = f"sqlite:///{db_path}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class URLCheck(Base):
    __tablename__ = "url_checks"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    verdict = Column(String, nullable=False)
    explanation = Column(String, nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ========= CORS =========
origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://waeei.github.io",
    "https://waeei.github.io/waeei-website",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= MALICIOUS LIST =========
GITHUB_RAW = os.getenv("MALICIOUS_LIST_URL", "").strip()
LOCAL_DATA_DIR = Path(__file__).parent / "data"
LOCAL_DATA_DIR.mkdir(exist_ok=True)
MALICIOUS_FILE = LOCAL_DATA_DIR / "malicious_urls.txt"
MALICIOUS_SET = set()

def try_download_from_github():
    if not GITHUB_RAW:
        return False
    try:
        with urllib.request.urlopen(GITHUB_RAW, timeout=20) as r:
            raw = r.read().decode("utf-8", errors="ignore")
        MALICIOUS_FILE.write_text(raw, encoding="utf-8")
        return True
    except:
        return False

def load_malicious_set():
    global MALICIOUS_SET
    MALICIOUS_SET = set()

    if MALICIOUS_FILE.exists():
        try:
            text = MALICIOUS_FILE.read_text(encoding="utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                MALICIOUS_SET.add(line.lower().rstrip("/"))
            return
        except:
            pass

    if GITHUB_RAW:
        if try_download_from_github() and MALICIOUS_FILE.exists():
            load_malicious_set()

def normalize_url_and_domain(u: str):
    u = (u or "").strip()
    if not u:
        return "", ""
    if not (u.startswith("http://") or u.startswith("https://")):
        u = "http://" + u
    try:
        p = urlparse(u)
        domain = (p.netloc or "").lower().split(":")[0]
        return (p.geturl().lower().rstrip("/"), domain)
    except:
        return u.lower().rstrip("/"), u.lower().rstrip("/")

def is_in_malicious_list(url: str) -> bool:
    url_norm, domain = normalize_url_and_domain(url)
    return (
        url_norm in MALICIOUS_SET or
        domain in MALICIOUS_SET or
        (domain.startswith("www.") and domain[4:] in MALICIOUS_SET)
    )


# ========= GOOGLE SAFE BROWSING =========
async def check_gsb(url: str):
    if not GSB_KEY:
        return {"provider": "gsb", "status": "skipped", "raw": None}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    payload = {
        "client": {"clientId": "waaei", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(endpoint, json=payload)
            data = r.json() if r.content else {}
            return {"provider": "gsb", "status": "malicious" if data else "clean", "raw": data}
    except:
        return {"provider": "gsb", "status": "error", "raw": None}


# ========= URLSCAN.IO =========
async def check_urlscan(url: str):
    if not URLSCAN_KEY:
        return {"provider": "urlscan", "status": "skipped"}

    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url})
            if r.status_code in (200, 201):
                return {"provider": "urlscan", "status": "submitted", "raw": r.json()}
            return {"provider": "urlscan", "status": "error", "raw": r.text}
    except:
        return {"provider": "urlscan", "status": "error"}


# ========= GPT EXPLANATION =========
async def gpt_explain(verdict: str, url: str) -> str:
    if not OPENAI_KEY:
        return "تعذر الاتصال بخدمة OpenAI."

    prompt = f"""
    اشرح للمستخدم نتيجة فحص الرابط ({url}) وسبب تصنيفه كـ {verdict}.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except:
        return "تعذر إنشاء شرح."


# ========= REQUEST MODELS =========
class AnalyzeBody(BaseModel):
    url: HttpUrl

# ========= ENDPOINTS =========

@app.get("/")
def root():
    return {"ok": True, "service": "Waaei Backend"}


@app.post("/analyze-link")
async def analyze_link_post(body: AnalyzeBody, db: Session = Depends(get_db)):
    return await _analyze_and_store(str(body.url), db)


@app.get("/analyze-link")
async def analyze_link_get(url: str, db: Session = Depends(get_db)):
    if not url:
        raise HTTPException(400, "missing url parameter")
    return await _analyze_and_store(url, db)


async def _analyze_and_store(url: str, db: Session):
    if is_in_malicious_list(url):
        final_verdict = "MALICIOUS"
        gsb_result = {"provider": "local", "status": "malicious"}
        urlscan_result = {"provider": "urlscan", "status": "skipped"}
    else:
        gsb_result = await check_gsb(url)
        urlscan_result = await check_urlscan(url)
        final_verdict = "MALICIOUS" if gsb_result["status"] == "malicious" else "SAFE"

    explanation = await gpt_explain(final_verdict, url)

    record = URLCheck(url=url, verdict=final_verdict, explanation=explanation)
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "url": url,
        "final_verdict": final_verdict,
        "gsb": gsb_result,
        "urlscan": urlscan_result,
        "explanation": explanation
    }




@app.post("/analyze-text")
async def analyze_text(data: dict):
    text = data.get("text", "")

    if not text:
        raise HTTPException(400, "text field is required")

    prompt = f"""
    You are a security text-classification AI.
    Analyze the following message and classify it as Fraud or Not Fraud.

    Text:
    {text}

    Include in your response:
    - Classification
    - Risk score (0–100)
    - Explanation in Arabic
    - Red flags
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}]
        )

        content = response.choices[0].message.content
        return {"analysis": content}

    except Exception as e:
        raise HTTPException(500, f"GPT Error: {e}")


# ========= HISTORY =========

@app.get("/history-json")
def history_json(db: Session = Depends(get_db)):
    rows = db.query(URLCheck).order_by(desc(URLCheck.checked_at)).all()
    return rows


# ========= STARTUP =========
@app.on_event("startup")
def on_startup():
    load_malicious_set()
