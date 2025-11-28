# core/openphish.py
import httpx
import asyncio
from typing import Set

# Cache the list for 5 minutes to avoid hammering
PHISH_CACHE: Set[str] = set()
CACHE_TIME = 0
CACHE_DURATION = 300  # 5 minutes

async def _update_cache():
    global PHISH_CACHE, CACHE_TIME
    now = asyncio.get_event_loop().time()
    if now - CACHE_TIME < CACHE_DURATION:
        return
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get("https://openphish.com/feed.txt")
            if r.status_code == 200:
                PHISH_CACHE = set(line.strip() for line in r.text.splitlines() if line.strip())
                CACHE_TIME = now
                print("OpenPhish cache updated")  # Log for demo
    except Exception as e:
        print(f"OpenPhish update failed: {e}")

async def check(domain: str) -> bool:
    await _update_cache()
    # Check if domain matches any in the list (simple substring for speed)
    test_url = f"http://{domain}"
    return any(domain in phish_url for phish_url in PHISH_CACHE)