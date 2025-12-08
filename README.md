# .ng SafeCheck — Real-Time Phishing Detector for Nigerian Domains
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
**Hackathon Theme:** Cybersecurity  
**Topic:** Malware and Phishing  
**Team Name:** Coders_Elite  
**Date:** 30 November 2025  

### 1. Problem Statement  
Nigeria loses hundreds of millions of naira yearly to phishing attacks using fake .ng domains that impersonate GTBank, UBA, Zenith, Access, FirstBank, JAMB, NIMC, and other trusted institutions.  
Global tools miss Nigeria-specific tricks:  
→ Typosquatting (e.g. gtbank-alert.com.ng)  
→ Brand-new malicious domains (<7 days old)  
→ Local bank impersonation patterns  

**There was no real-time, open, Nigeria-first .ng safety checker — until now.**

### 2. Solution & Implementation  
.ng SafeCheck is a **blazing-fast, AI-powered public API** that instantly returns:  
**SAFE** | **WARNING** | **DANGEROUS**

**5-Layer Real-Time Defense System**  
1. **Gemini 1.5 Flash AI** — Nigeria-tuned + official whitelist  
2. **OpenPhish** — Live global phishing feed  
3. **VirusTotal** — Malicious engine detection  
4. **URLScan.io** — Live webpage scanning  
5. **NiRA WHOIS** — Age, privacy, status checks  
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
**Features**  
- <1 second response  
- Detailed threat list + confidence score  
-reports DANGEROUS domains to NiRA  
- Fully public — no login required  

**Tech Stack**  
- Backend: Python 3.11 + FastAPI  
- AI: Google Gemini 1.5 Flash  
- Threat Intel: OpenPhish, VirusTotal, URLScan.io, NiRA WHOIS  
- Deployment: Render.com (backend) + Render (frontend)  
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
### 3. Future Roadmap  
- Launch **safecheck.ng** public checker  
- Chrome & Firefox extension for all Nigerians  
- Official NiRA partnership + auto-block integration  
- Mobile SDK for Nigerian banks  
- Open-source community + bug bounty  

### 4. Team Member Contributions  
| Name                  | Role                          | Contribution                                      |
|-----------------------|-------------------------------|---------------------------------------------------|
| Emmanuel O. Agbaje    | Lead Developer & AI Engineer  | Full backend, Gemini AI, scoring system           |
| Emmanuel O. Agbaje    | Threat Intel & DevOps         | OpenPhish, VirusTotal, URLScan, WHOIS, deploy     |
| Abdulmuiz Ismail      | Frontend Developer            | Beautiful public web UI                           |
| Jerrie                | UI/UX & Documentation         | Design, README                                    |

### 5. Live Links (Tested 30 Nov 2025)
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
**Backend API (Click to wake)**  
https://ng-safecheck.onrender.com  

**Interactive Docs**  
https://ng-safecheck.onrender.com/docs  

**Public Web Checker**  
https://ng-safecheck.netlify.app  

**GitHub Repository**  
https://github.com/[your-username]/ng-safecheck  

**3-Minute Demo Video**  
https://youtu.be/[your-video-id] (unlisted)

### Judge Testing (30 seconds)

1. Click → https://ng-safecheck.onrender.com → Server wakes up  
2. Test these domains in /docs or frontend:  

| Domain                        | Expected     | Reason                              |
|-------------------------------|--------------|-------------------------------------|
| nic.ng                        | SAFE         | Official NiRA domain                |
| gtbank.com.ng                 | SAFE         | Legitimate bank                     |
| gtbank-alert.com.ng           | DANGEROUS    | AI + WHOIS flags impersonation      |
| login-uba.ng                  | DANGEROUS    | Gemini AI detects phishing pattern  |
| secure-accessbank.ng          | DANGEROUS    | New domain + suspicious keywords    |

**No login · No keys · Works instantly · Live until 6 Dec 2025**
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
Thank you NiRA & NKF for the chance to protect our nation  
This is more than a hackathon project —  
This is **Nigeria’s digital shield**  

— Team Coders_Elite
🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳🇬🇳
