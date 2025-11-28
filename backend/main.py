# main.py 
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
import asyncio
import httpx
from typing import List, Optional
import logging
from contextlib import asynccontextmanager
from datetime import datetime
import pytz
import threading


from core import gemini, virustotal, whois, urlscan, openphish

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ng-safecheck")
TZ = pytz.timezone("Africa/Lagos")

# Live counter
BLOCKED_TODAY = 0
counter_lock = threading.Lock()

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(
        timeout=20.0,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50)
    )
    logger.info(".ng SafeCheck v2.0 — PROTECTING NIGERIA")
    yield
    await app.state.http_client.aclose()

app = FastAPI(
    title=".ng SafeCheck",
    description="Nigeria's #1 Real-Time Phishing Detector for .ng domains | NiRA-XT 2025",
    version="2.0.0",
    license_info={"name": "MIT"},
    lifespan=lifespan
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Models
class Threat(BaseModel):
    type: str
    source: str
    details: Optional[str] = None
    confidence: Optional[float] = None

class CheckRequest(BaseModel):
    domain: str

    @validator("domain")
    def clean_domain(cls, v):
        v = v.strip().lower().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        if not v.endswith(".ng"):
            raise ValueError("Only .ng domains are allowed")
        return v

class CheckResponse(BaseModel):
    domain: str
    safe: bool
    risk: str
    registered: bool
    threats: List[Threat]
    confidence: float
    scanned_at: str
    recommendation: str
    blocked_today: int = 0

# MAIN ENDPOINT
@app.post("/api/check", response_model=CheckResponse)
async def check_ng_domain(request: Request, req: CheckRequest):
    domain = req.domain
    logger.info(f"Scanning .ng domain: {domain}")
    global BLOCKED_TODAY

    try:
        
        results = await asyncio.gather(
            whois.check(domain),
            openphish.check(domain),
            virustotal.check(domain),
            gemini.analyze(domain),
            urlscan.check(domain),
            return_exceptions=True
        )
        wh_result, op_result, vt_result, ai_result, us_result = results

        threats: List[Threat] = []
        confidence_score = 0.0

        # WHOIS — NiRA-powered
        if isinstance(wh_result, dict):
            if not wh_result.get("registered", True):
                threats.append(Threat(type="UNREGISTERED", source="NiRA WHOIS", details="Domain does not exist", confidence=99))
                confidence_score += 99
            elif wh_result.get("is_new"):
                threats.append(Threat(type="NEW_DOMAIN", source="NiRA WHOIS", details="Registered <90 days ago", confidence=75))
                confidence_score += 75
            if wh_result.get("privacy_enabled"):
                threats.append(Threat(type="HIDDEN_OWNER", source="WHOIS", details="Owner identity hidden", confidence=65))
                confidence_score += 65

        # OpenPhish — Real-time phishing feed
        if op_result is True:
            threats.append(Threat(type="PHISHING", source="OpenPhish", details="Active phishing site detected", confidence=98))
            confidence_score += 98

        # VirusTotal
        if isinstance(vt_result, dict) and vt_result.get("malicious"):
            count = vt_result.get("count", 0)
            threats.append(Threat(type="MALWARE", source="VirusTotal", details=f"{count} engines flagged", confidence=min(count * 15, 99)))
            confidence_score += min(count * 15, 99)

        # Gemini AI — Nigeria-trained
        if isinstance(ai_result, dict) and ai_result.get("phishy"):
            conf = ai_result.get("confidence", 85)
            reason = ai_result.get("reason", "Suspicious impersonation pattern")
            threats.append(Threat(type="AI_SUSPICION", source="Gemini AI", details=reason, confidence=conf))
            confidence_score += conf

        # URLScan.io
        if isinstance(us_result, dict) and us_result.get("malicious"):
            threats.append(Threat(type="MALICIOUS_PAGE", source="URLScan.io", details="Malicious content found", confidence=90))
            confidence_score += 90

        # FINAL SCORING
        total_threats = len(threats)
        is_safe = total_threats == 0

        if is_safe:
            final_confidence = 0.0
            risk_level = "SAFE"
            recommendation = "This .ng domain is safe and legitimate."
        else:
            avg_conf = confidence_score / total_threats
            final_confidence = round(min(avg_conf, 99.9), 2)
            risk_level = "DANGEROUS" if final_confidence >= 75 else "WARNING"
            recommendation = "DO NOT VISIT! High risk of fraud!" if risk_level == "DANGEROUS" else "Proceed with caution."

        # Auto-report high-confidence threats + counter
        if risk_level == "DANGEROUS" and final_confidence >= 80:
            with counter_lock:
                BLOCKED_TODAY += 1
            try:
                await request.app.state.http_client.post(
                    "https://report.nira.ng/api/v1/report",
                    json={"domain": domain, "risk": risk_level, "confidence": final_confidence, "source": "ng-safecheck-v2"},
                    timeout=8.0
                )
            except:
                pass  

        return CheckResponse(
            domain=domain,
            safe=is_safe,
            risk=risk_level,
            registered=bool(isinstance(wh_result, dict) and wh_result.get("registered", False)),
            threats=threats,
            confidence=final_confidence,
            scanned_at=datetime.now(TZ).isoformat(),
            recommendation=recommendation,
            blocked_today=BLOCKED_TODAY
        )

    except Exception as e:
        logger.error(f"Scan failed for {domain}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Scan temporarily unavailable")

# Extra endpoints 
@app.get("/")
async def root():
    return {"message": ".ng SafeCheck is LIVE — Protecting Nigeria", "blocked_today": BLOCKED_TODAY}

@app.get("/health")
async def health():
    return {"status": "healthy", "blocked_today": BLOCKED_TODAY, "time": datetime.now(TZ).isoformat()}

@app.get("/stats")
async def stats():
    return {"blocked_today": BLOCKED_TODAY, "protected": "All of Nigeria"}

@app.post("/report")
async def public_report(request: Request):
    try:
        data = await request.json()
        domain = data.get("domain", "").strip().lower()
        if not domain.endswith(".ng"):
            return {"status": "error", "message": "Only .ng domains"}
        report_url = f"https://nira.org.ng/abuse-report/?domain={domain}"
        logger.info(f"USER REPORTED: {domain}")
        return {"status": "success", "report_url": report_url}
    except:
        return {"status": "error", "message": "Report failed"}