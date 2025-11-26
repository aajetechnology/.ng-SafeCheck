# core/virustotal.py
import httpx
import os
import asyncio
from dotenv import load_dotenv
load_dotenv()

async def check(domain: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"malicious": False, "count": 0}

    await asyncio.sleep(1.1)  # Stay under free tier limit (4/min)

    try:
        headers = {"x-apikey": api_key}
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                return {"malicious": malicious > 0, "count": malicious}
    except:
        pass
    return {"malicious": False, "count": 0}