import os
import urllib.request
from pathlib import Path
from datetime import datetime
import httpx
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from urllib.parse import urlparse
import re
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ========= API KEYS =========
GSB_KEY = os.getenv("GSB_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
OPENAI_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_KEY)

# ========= APP =========
app = FastAPI(title="Waaei Unified Analyzer")

# ========= CORS =========
origins = [
    "https://waeei.github.io",
    "https://waeei.github.io/waeei-website",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:3000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= DATABASE =========
db_path = os.getenv("DB_PATH", "WaaeiDB.db")
DATABASE_URL = f"sqlite:///{db_path}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class URLCheck(Base):
    __tablename__ = "url_checks"
    id = Column(Integer, primary_key=True)
    url = Column(String)
    verdict = Column(String)
    explanation = Column(String)
    checked_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ========= LOAD FRAUD / SAFE TEXTS =========
DATA_FILE = Path(__file__).parent / "data""test_texts.txt"
FRAUD_LIST = []
SAFE_LIST = []

if DATA_FILE.exists():
    raw = DATA_FILE.read_text(encoding="utf-8", errors="ignore")
    entries = raw.split("----------------------------------------")
    for e in entries:
        e = e.strip()
        if "[FRAUD_" in e:
            msg = e.split("MESSAGE:")[1].split("REASON:")[0].strip().lower()
            FRAUD_LIST.append(msg[:25])
        if "[SAFE_" in e:
            msg = e.split("MESSAGE:")[1].split("REASON:")[0].strip().lower()
            SAFE_LIST.append(msg[:25])

# ========= MALICIOUS URL LIST =========
MALICIOUS_URLS = [
    "armx.me",
    "bit.do",
    "mobily.im",
    "smsaexpress.com",
    "mudad.com.sa/login",
]


# ========= HELPER FUNCTIONS =========

def extract_url(text):
    urls = re.findall(r"(https?://[^\s]+)", text)
    return urls[0] if urls else None

def normalize(url):
    if not url.startswith("http"):
        url = "http://" + url
    try:
        p = urlparse(url)
        return p.geturl().lower(), p.netloc.lower()
    except:
        return url.lower(), url.lower()

def url_is_malicious(url):
    full, domain = normalize(url)
    for bad in MALICIOUS_URLS:
        if bad in full or bad in domain:
            return True
    return False


# ========= IMPROVED TEXT FRAUD DETECTOR =========

SUSPICIOUS_KEYWORDS = [
    "تحديث بياناتك",
    "تم حظر",
    "عدم كفاية الرصيد",
    "يرجى الدفع",
    "فاتورة",
    "سداد",
    "اضغط الرابط",
    "اضغط على الرابط",
    "تم إيقاف حسابك",
    "تم تعليق الحساب",
    "بياناتك غير محدثة",
    "تفعيل البطاقة",
    "اتصل فوراً",
    "الرقم التالي",
    "شحنة بانتظارك",
    "دفع الرسوم",
    "تم استلام شحنتك",
    "المسير رقم",
    "مطلوب تحديث",
    "حسابك موقوف",
    "تجاوز الحد الائتماني",
    "تم تجميد الحساب"
]

def text_is_suspicious(text: str) -> bool:
    t = text.replace(" ", "")
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.replace(" ", "") in t:
            return True
    return False


def text_is_fraud(text):
    text_low = text.lower().replace(" ", "")

    # 1) كلمات احتيالية
    if text_is_suspicious(text):
        return True

    # 2) FRAUD_LIST التدريبية
    for f in FRAUD_LIST:
        if f and f in text_low:
            return True

    # 3) وجود رابط احتيالي
    url = extract_url(text)
    if url and url_is_malicious(url):
        return True

    return False


def text_is_safe(text):
    text_low = text.lower().replace(" ", "")
    for s in SAFE_LIST:
        if s and s in text_low:
            return True
    return False


# ========= GPT EXPLANATION =========
async def gpt_explain(verdict, text_or_url):
    try:
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{
                "role": "user",
                "content": f"فسّر للمستخدم لماذا تم تصنيف هذا الإدخال ({text_or_url}) على أنه {verdict}."
            }]
        )
        return resp.choices[0].message.content
    except:
        return "تعذر إنشاء شرح."


# ========= MAIN UNIFIED ENDPOINT =========

class AnalyzeBody(BaseModel):
    input: str

@app.post("/analyze")
async def analyze(body: AnalyzeBody, db: Session = Depends(get_db)):
    text = body.input.strip()

    # ========== 1) إدخال URL مباشر ==========
    if text.startswith("http://") or text.startswith("https://"):
        verdict = "malicious" if url_is_malicious(text) else "safe"
        explanation = await gpt_explain(verdict, text)
        return {"type": "url", "verdict": verdict, "explanation": explanation}

    # ========== 2) نص داخله URL ==========
    url = extract_url(text)
    if url:
        url_verdict = "malicious" if url_is_malicious(url) else "safe"
        text_verdict = "malicious" if text_is_fraud(text) else "safe"

        final = "malicious" if (url_verdict == "malicious" or text_verdict == "malicious") else "safe"
        explanation = await gpt_explain(final, text)
        return {"type": "mixed", "verdict": final, "explanation": explanation}

    # ========== 3) نص فقط ==========
    if text_is_fraud(text):
        verdict = "malicious"
    elif text_is_safe(text):
        verdict = "safe"
    else:
        verdict = "safe"   # النص غامض → اعتبره آمن

    explanation = await gpt_explain(verdict, text)
    return {"type": "text", "verdict": verdict, "explanation": explanation}


@app.get("/")
def root():
    return {"ok": True}
