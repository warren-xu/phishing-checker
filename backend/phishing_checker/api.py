"""HTTP API. The verdict is computed here, not in the browser.

POST /api/analyze takes the raw message as the body. Vercel caps a function
request body at 4.5 MB, so messages are limited to 4 MB.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from phishing_checker.context import DEFAULT_CONTEXT, OrgContext, load_context
from phishing_checker.engine import analyze_message

MAX_BYTES = 4_000_000

app = FastAPI(title="Phishing Checker", version="0.1.0")


@lru_cache(maxsize=1)
def _context() -> OrgContext:
    override = os.environ.get("PHISHING_CHECKER_CONTEXT")
    return load_context(Path(override) if override else DEFAULT_CONTEXT)


async def _analyze(raw: bytes) -> dict:
    if not raw.strip():
        raise HTTPException(status_code=400, detail="The file is empty.")
    return await run_in_threadpool(analyze_message, raw, _context())


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze(request: Request) -> dict:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BYTES:
        raise HTTPException(status_code=413, detail="Message exceeds 4 MB.")
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > MAX_BYTES:
            raise HTTPException(status_code=413, detail="Message exceeds 4 MB.")
    return await _analyze(bytes(raw))
