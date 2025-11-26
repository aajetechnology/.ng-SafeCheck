# core/phishtank.py
import httpx
import os
from dotenv import load_dotenv
load_dotenv()

APP_KEY = os.getenv("PHISHTANK_APP_KEY")  # Register at phishtank.com for free key

async def check(domain: str) -> bool:
    if not APP_KEY:
        logger.warning("PhishTank: No API key — skipping check")
        return False

    url = "https://checkurl.phishtank.com/checkurl/"  # HTTPS!
    payload = {
        "url": f"http://{domain}",
        "format": "json",
        "app_key": APP_KEY  # ← Required for auth
    }

    headers = {
        "User-Agent": "ngSafeCheck-NiRA/2.0",  # Required to avoid rate limits
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, data=payload, headers=headers)  # ← POST, not GET!
            if r.status_code == 200:
                data = r.json()
                result = data.get("results", {})
                # True if in DB, verified, and valid
                return result.get("in_database", False) and result.get("verified", False) and result.get("valid", False)
    except Exception as e:
        logger.warning(f"PhishTank error for {domain}: {e}")
    return False