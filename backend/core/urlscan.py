# core/urlscan.py
import httpx
import os
import asyncio
from dotenv import load_dotenv
load_dotenv()

URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

async def check(domain: str) -> dict | None:
    if not URLSCAN_KEY:
        logger.warning("URLScan: No API key — skipping check")
        return None

    headers = {
        "API-Key": URLSCAN_KEY,  
        "Content-Type": "application/json"
    }
    data = {
        "url": f"https://{domain}",  
        "visibility": "unlisted"  
    }

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
            if r.status_code != 200:
                logger.warning(f"URLScan submit failed: {r.status_code}")
                return None
            result = r.json()
            uuid = result.get("uuid")
            if not uuid:
                return None

            # Wait & poll for verdict (up to 30s)
            for _ in range(6):  # 6 * 5s = 30s max
                await asyncio.sleep(5)
                verdict_r = await client.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers=headers)
                if verdict_r.status_code == 200:
                    v = verdict_r.json()
                    overall = v.get("verdicts", {}).get("overall", {})
                    return {
                        "malicious": overall.get("malicious", 0) > 0,
                        "score": overall.get("score", 0),
                        "verdict": overall
                    }
            logger.warning("URLScan: Scan timeout")
    except Exception as e:
        logger.warning(f"URLScan error for {domain}: {e}")
    return None