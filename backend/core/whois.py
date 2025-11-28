# core/whois.py 
import httpx
from datetime import datetime
import re

# OFFICIAL NIGERIAN DOMAINS THAT MUST ALWAYS BE SAFE
OFFICIAL_DOMAINS = {
    "nic.ng", "nira.org.ng", "gtbank.com.ng", "uba.com.ng",
    "jamb.gov.ng", "nimc.gov.ng", "nigeriaportal.gov.ng",
    "firstbanknigeria.com.ng", "zenithbank.com.ng", "accessbankplc.com.ng"
}

async def check(domain: str) -> dict:
    domain = domain.lower().strip()

    # HARD OVERRIDE: Official domains are ALWAYS safe and old
    if domain in OFFICIAL_DOMAINS:
        return {
            "registered": True,
            "is_new": False,
            "age_days": 9999,
            "status": "good",
            "privacy_enabled": False
        }

    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.get(f"https://whois.nic.ng/whois/{domain}", follow_redirects=True)
            text = r.text.lower()

        if "no match" in text or "not found" in text or "available" in text:
            return {
                "registered": False,
                "is_new": True,
                "status": "available",
                "privacy_enabled": False
            }

        # Parse creation date
        is_new = True
        age_days = 0
        match = re.search(r"creation date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
        if match:
            try:
                created_at = datetime.strptime(match.group(1), "%Y-%m-%d").date()
                age_days = (datetime.utcnow().date() - created_at).days
                is_new = age_days < 90
            except:
                pass

        # SMART privacy detection — only trigger if registrant is actually redacted
        privacy_keywords = ["redacted", "privacy protect", "whoisguard", "hidden", "protected by"]
        privacy_enabled = any(k in text for k in privacy_keywords) and "nira" not in text and "nic.ng" not in text

        status_good = any(s in text for s in ["ok", "active"])

        return {
            "registered": True,
            "is_new": is_new,
            "age_days": age_days,
            "status": "good" if status_good else "suspicious",
            "privacy_enabled": privacy_enabled
        }

    except:
        return {
            "registered": True,
            "is_new": True,
            "status": "unknown",
            "privacy_enabled": True
        }