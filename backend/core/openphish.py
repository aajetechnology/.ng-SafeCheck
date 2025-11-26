# core/openphish.py — FIXED (follows redirect)
import httpx

async def check(domain: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            r = await client.get("https://openphish.com/feed.txt")
            if r.status_code == 200:
                domains = {line.split("/")[2].split(":")[0].lower() for line in r.text.splitlines() if line.strip()}
                return domain.lower() in domains
    except:
        pass
    return False