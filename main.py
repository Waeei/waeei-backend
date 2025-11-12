import os
import urllib.request
from pathlib import Path
from datetime import datetime
import logging

import httpx
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi import Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, DateTime, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("waaei")

load_dotenv()

GSB_KEY = os.getenv("GSB_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

app = FastAPI(title="Waaei Link Scanner")
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse

app.mount("/app", StaticFiles(directory="frontend", html=True), name="app")

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/app/")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = "sqlite:///./WaaeiDB.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class URLCheck(Base):
    __tablename__ = "url_checks"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    verdict = Column(String)
    checked_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

GITHUB_RAW = "https://raw.githubusercontent.com/alaaelkhashap/Malicious-URLs-dataset/main/malicious_urls.txt"
MALICIOUS_FILE = Path("malicious_urls.txt")
MALICIOUS_SET = set()

def download_malicious_file():
    if not MALICIOUS_FILE.exists():
        try:
            logger.info("Downloading malicious_urls.txt from GitHub...")
            urllib.request.urlretrieve(GITHUB_RAW, MALICIOUS_FILE)
            logger.info("Downloaded malicious_urls.txt")
        except Exception as e:
            logger.warning("Could not download malicious list: %s", e)

def load_malicious_set():
    global MALICIOUS_SET
    MALICIOUS_SET = set()
    if MALICIOUS_FILE.exists():
        with MALICIOUS_FILE.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                MALICIOUS_SET.add(line)
    logger.info("Loaded malicious entries: %d", len(MALICIOUS_SET))

def is_in_malicious_list(url: str) -> bool:
    if not url:
        return False
    if url in MALICIOUS_SET:
        return True
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        domain = p.netloc or url
        if domain in MALICIOUS_SET:
            return True
        if domain.startswith("www.") and domain[4:] in MALICIOUS_SET:
            return True
    except Exception:
        pass
    return False

async def check_gsb(url: str):
    if not GSB_KEY:
        return {"provider": "gsb", "status": "skipped", "raw": None, "reason": "GSB_API_KEY missing"}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    payload = {
        "client": {"clientId": "waaie", "clientVersion": "0.1"},
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
    except Exception as e:
        logger.warning("check_gsb error: %s", e)
        return {"provider": "gsb", "status": "error", "raw": None, "reason": str(e)}

async def check_urlscan(url: str):
    if not URLSCAN_KEY:
        return {"provider": "urlscan", "status": "skipped", "raw": None, "reason": "URLSCAN_API_KEY missing"}
    headers = {"API-Key": URLSCAN_KEY, "Content-Type": "application/json"}
    payload = {"url": url}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post("https://urlscan.io/api/v1/scan/", headers=headers, json=payload)
            if r.status_code in (200, 201):
                return {"provider": "urlscan", "status": "submitted", "raw": r.json()}
            else:
                return {"provider": "urlscan", "status": "error", "raw": r.text, "code": r.status_code}
    except Exception as e:
        logger.warning("check_urlscan error: %s", e)
        return {"provider": "urlscan", "status": "error", "raw": None, "reason": str(e)}

@app.get("/test-gsb")
async def test_gsb():
    test_url = "http://testsafebrowsing.appspot.com/s/malware.html"
    return await check_gsb(test_url)

@app.get("/test-urlscan")
async def test_urlscan():
    return await check_urlscan("http://example.com")


@app.get("/analyze-link")
async def analyze_link(url: str, db: Session = Depends(get_db)):
    if not url:
        raise HTTPException(status_code=400, detail="missing url parameter")

    if is_in_malicious_list(url):
        final_verdict = "MALICIOUS"
        gsb_result = {"provider": "local_list", "status": "malicious", "raw": None}
        urlscan_result = {"provider": "urlscan", "status": "skipped", "raw": None, "reason": "local list matched"}
    else:
        gsb_result = await check_gsb(url)
        urlscan_result = await check_urlscan(url)
        final_verdict = "MALICIOUS" if gsb_result.get("status") == "malicious" else "SAFE"

    try:
        record = URLCheck(url=url, verdict=final_verdict)
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as e:
        logger.warning("DB save error: %s", e)

    return JSONResponse({
        "url": url,
        "verdict": final_verdict,
        "checked_at": datetime.utcnow().isoformat(),
        "gsb": gsb_result,
        "urlscan": urlscan_result,
    })

class LinkRequest(BaseModel):
    url: str

@app.post("/analyze-link")
async def analyze_link_post(body: LinkRequest, db: Session = Depends(get_db)):
    url = body.url
    if not url:
        raise HTTPException(status_code=400, detail="missing url parameter")

    if is_in_malicious_list(url):
        final_verdict = "MALICIOUS"
        gsb_result = {"provider": "local_list", "status": "malicious", "raw": None}
        urlscan_result = {"provider": "urlscan", "status": "skipped", "raw": None, "reason": "local list matched"}
    else:
        gsb_result = await check_gsb(url)
        urlscan_result = await check_urlscan(url)
        final_verdict = "MALICIOUS" if gsb_result.get("status") == "malicious" else "SAFE"

    try:
        record = URLCheck(url=url, verdict=final_verdict)
        db.add(record)
        db.commit()
        db.refresh(record)
    except Exception as e:
        logger.warning("DB save error: %s", e)

    return JSONResponse({
        "url": url,
        "verdict": final_verdict,
        "checked_at": datetime.utcnow().isoformat(),
        "gsb": gsb_result,
        "urlscan": urlscan_result,
    })

@app.get("/family", response_class=FileResponse)
def serve_family_page():

    base = Path(__file__).parent
    f = base / "family.html"
    if not f.exists():
        raise HTTPException(status_code=404, detail="family.html not found on server. Put it next to main.py")
    return FileResponse(str(f))

@app.get("/history", response_class=HTMLResponse)
def get_history(db: Session = Depends(get_db)):
    records = db.query(URLCheck).order_by(URLCheck.checked_at.desc()).all()

    html = """
    <html lang='ar' dir='rtl'>
    <head>
        <meta charset="utf-8">
        <title>سجل الروابط - واعي</title>
        <style>
            body { font-family: Arial, sans-serif; background-color:#fff5f5; text-align:center; margin:40px; }
            table { border-collapse:collapse; margin:0 auto; width:90%; background:#c7ddde; box-shadow:0 2px 8px rgba(0,0,0,0.1); border-radius:8px; overflow:hidden;}
            th { background:#5a9695; color:#fff; padding:12px; font-size:16px;}
            td { padding:10px; border-bottom:1px solid #ddd; font-size:14px;}
            .safe { color:green; font-weight:bold; }
            .unsafe { color:red; font-weight:bold; }
        </style>
    </head>
    <body>
        <h2>سجل الروابط</h2>
        <table>
            <tr><th>الرابط</th><th>النتيجة</th><th>التاريخ</th></tr>
    """

    for r in records:
        icon = "✅" if r.verdict == "SAFE" else "❌"
        cls = "safe" if r.verdict == "SAFE" else "unsafe"
        html += f"<tr><td>{r.url}</td><td class='{cls}'>{icon} {r.verdict}</td><td>{r.checked_at}</td></tr>"

    html += "</table></body></html>"
    return HTMLResponse(content=html)
@app.post("/analyze-link/form")
async def analyze_link_form(url: str = Form(...)):
    verdict = "SAFE"
    reasons = []

    if "malware" in url or "phish" in url:
        verdict = "MALICIOUS"
        reasons = ["Matched test rule"]

    if verdict.upper() == "MALICIOUS":
        from urllib.parse import urlencode
        q = urlencode({
            "url": url,
            "verdict": verdict,
            "reasons": " | ".join(reasons)
        })
        return RedirectResponse(url=f"/app/warning.html?{q}", status_code=302)

    html = f"""
    <html dir="rtl">
      <body style='font-family:system-ui;padding:24px'>
        <h3>✔ الرابط آمن</h3>
        <div>{url}</div>
        <p><a href="/app/">🔙 العودة للصفحة الرئيسية</a></p>
      </body>
    </html>
    """
    return HTMLResponse(html)

@app.on_event("startup")
def on_startup():
    logger.info("Starting Waaei backend...")
    logger.info("Main file path: %s", __file__)
    download_malicious_file()
    load_malicious_set()
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    logger.info("DB tables: %s", inspector.get_table_names())
    logger.info("Startup complete.")