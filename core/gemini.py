# core/gemini.py — OFFLINE MODE (WORKS WITHOUT API KEY)
import re

# High-risk keywords that scream "PHISHING"
PHISHY_WORDS = [
    "login", "secure", "verify", "alert", "transfer", "update",
    "account", "password", "banking", "dashboard", "confirm", "otp"
]

OFFICIAL_DOMAINS = {
    "nic.ng", "nira.org.ng", "gtbank.com.ng", "uba.com.ng", "jamb.gov.ng",
    "nimc.gov.ng", "firstbanknigeria.com.ng", "zenithbank.com.ng", "accessbankplc.com.ng"
}

async def analyze(domain: str) -> dict:
    domain = domain.lower().strip()

    # Always trust official domains
    if domain in OFFICIAL_DOMAINS or domain.endswith(".gov.ng"):
        return {"phishy": False, "reason": "Official domain", "confidence": 0}

    # Check for phishy words
    domain_clean = domain.replace(".com.ng", "").replace(".ng", "")
    found_words = [word for word in PHISHY_WORDS if word in domain_clean]

    if len(found_words) >= 1:
        reason = f"Contains suspicious word: {', '.join(found_words[:2])}"
        confidence = min(90 + len(found_words) * 5, 98)
        return {"phishy": True, "reason": reason, "confidence": confidence}

    # New or weird domain
    if len(domain_clean) < 8 or "xn--" in domain or domain.count("-") >= 3:
        return {"phishy": True, "reason": "Unusual domain pattern", "confidence": 82}

    return {"phishy": False, "reason": "No red flags", "confidence": 0}