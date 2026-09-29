# Project Description

This is a phishing checker for email inboxes. The checker returns a verdict with the evidence for it based on email auth headers, domain identities, included links, and content semantics. 

## Where the logic lives

**Rule engine** (`backend/phishing_checker/`)

| File | What it does |
| --- | --- |
| [`engine.py`](backend/phishing_checker/engine.py) | `analyze_message`: runs every rule group, sums the score, and picks the verdict |
| [`models.py`](backend/phishing_checker/models.py) | `Finding`, `ParsedEmail`, the severity weights, and the suspicious/phishing thresholds |
| [`parse.py`](backend/phishing_checker/parse.py) | `parse_email`: MIME walk, headers, text and HTML parts, links, forms, and attachments |
| [`auth.py`](backend/phishing_checker/auth.py) | `analyze_auth`: trusted `Authentication-Results`, SPF/DKIM/DMARC,and alignment |
| [`identity.py`](backend/phishing_checker/identity.py) | `analyze_identity`: Reply-To and Return-Path mismatches, staff and vendor impersonation, and lookalike domains |
| [`links.py`](backend/phishing_checker/links.py) | `analyze_links`: userinfo, nested brands, homoglyphs, IPs, shorteners, redirects, and string mismatches |
| [`content.py`](backend/phishing_checker/content.py) | `analyze_content`: credential lures, signature requests, payment changes, BEC pretexts, and government claims |
| [`attachments.py`](backend/phishing_checker/attachments.py) | `analyze_attachments`: dangerous types, double extensions, PDF byte checks, and passworded archives |
| [`domains.py`](backend/phishing_checker/domains.py) | Registrable-domain logic, lookalike and homoglyph detection, and the built-in lists of well-known senders, e-sign providers, notification platforms, and freemail |
| [`context.py`](backend/phishing_checker/context.py) | `load_context`: reads the organization file ([`context/halvorsen.json`](backend/context/halvorsen.json)) |

**Entry points**

| File | What it does |
| --- | --- |
| [`backend/phishing_checker/api.py`](backend/phishing_checker/api.py) | FastAPI routes: `/api/analyze` (4 MB cap), `/api/health` |
| [`frontend/app/components/Checker.tsx`](frontend/app/components/Checker.tsx) | File upload |
| [`frontend/app/components/ReportView.tsx`](frontend/app/components/ReportView.tsx) | Renders the verdict and findings |

## Layout

```
backend/    FastAPI + the rule engine (Python) and the context file.
frontend/   Next.js App Router UI.
vercel.json Both deployed as Vercel Services in one project.
```

## Run locally

```bash
# backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e backend
cd backend && uvicorn main:app --port 8000 --reload

# frontend
cd frontend && npm install
PHISHING_CHECKER_API_ORIGIN=http://127.0.0.1:8000 npm run dev
```

Open at http://localhost:3000
