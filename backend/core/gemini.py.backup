# core/gemini.py — FINAL VERSION (0% or 95%+ only)
import re

TRUSTED_DOMAINS = {
    "nic.ng", "nira.org.ng", "gtbank.com.ng", "uba.com.ng", "accessbankplc.com.ng",
    "zenithbank.com.ng", "firstbanknigeria.com.ng", "jamb.gov.ng", "nimc.gov.ng",
    "nigeriapoliceforce.gov.ng", "cbn.gov.ng", "ncc.gov.ng"
}

DANGEROUS_KEYWORDS = [
    "login", "secure", "verify", "alert", "transfer", "update", "account",
    "password", "banking", "dashboard", "confirm", "otp", "session", "reset"
]

async def analyze(domain: str) -> dict:
    domain = domain.lower().strip().replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Official domains = 0% risk
    if any(domain == trusted or domain.endswith("." + trusted) for trusted in TRUSTED_DOMAINS):
        return {"phishy": False, "confidence": 0, "reason": "Official Nigerian domain"}

    if domain.endswith(".gov.ng") or domain.endswith(".edu.ng"):
        return {"phishy": False, "confidence": 0, "reason": "Government/Education domain"}

    # 2. Obvious phishing = 95–98%
    clean = domain.replace(".ng", "").replace(".com.ng", "").replace(".", "")
    found = [word for word in DANGEROUS_KEYWORDS if word in clean]

    if found:
        return {
            "phishy": True,
            "confidence": 96 + min(len(found), 3),  # 96–99%
            "reason": f"Contains phishing keywords: {', '.join(found[:3])}"
        }

    # 3. Suspicious patterns (hyphens, length, etc.)
    if domain.count("-") >= 3 or len(clean) <= 6 or "xn--" in domain:
        return {"phishy": True, "confidence": 92, "reason": "Suspicious domain pattern"}

    # 4. Everything else = low risk
    return {"phishy": False, "confidence": 15, "reason": "No clear red flags"}