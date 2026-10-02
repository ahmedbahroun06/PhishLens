"""The website door: FastAPI routes.

Receives an upload (or pasted raw email), calls analyzer.analyze(), returns the
same JSON the CLI produces. No email is stored on disk.

Security choices:
  * request body capped (MAX_EMAIL_BYTES) before parsing
  * CORS left closed by default (same-origin UI); opt in via ALLOWED_ORIGINS
  * generic error messages to the client; details stay server-side
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .. import config
from ..core.analyzer import analyze

_HERE = Path(__file__).resolve().parent
_TEMPLATES = _HERE / "templates"
_STATIC = _HERE / "static"

app = FastAPI(
    title="PhishLens",
    description="On-demand forensic analysis of a single suspicious email.",
    version="1.0.0",
)

# Optional CORS (off unless the operator sets ALLOWED_ORIGINS). Keeps the default
# deployment same-origin and tight.
_origins = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _origins:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

# Serve the bundled test emails so the UI sample chips run through the REAL pipeline.
_SAMPLES = _HERE.parent.parent / "tests" / "samples"
if _SAMPLES.is_dir():
    app.mount("/samples", StaticFiles(directory=str(_SAMPLES)), name="samples")


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES / "index.html").read_text(encoding="utf-8"))


@app.get("/privacy", response_class=HTMLResponse)
def privacy() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES / "privacy.html").read_text(encoding="utf-8"))


@app.get("/terms", response_class=HTMLResponse)
def terms() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES / "terms.html").read_text(encoding="utf-8"))


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "services": {
            "virustotal": config.vt_configured(),
            "groq": config.groq_configured(),
        },
    }


@app.post("/analyze")
async def analyze_route(
    request: Request,
    file: UploadFile | None = File(default=None),
    raw: str | None = Form(default=None),
) -> JSONResponse:
    # Resolve the raw email bytes from either an upload or a pasted string.
    if file is not None:
        data = await file.read()
    elif raw:
        data = raw.encode("utf-8", errors="replace")
    else:
        # Allow a raw text/plain body POST too.
        body = await request.body()
        data = body or b""

    if not data.strip():
        raise HTTPException(status_code=400, detail="No email provided.")
    if len(data) > config.MAX_EMAIL_BYTES:
        raise HTTPException(status_code=413, detail="Email too large.")

    try:
        report = analyze(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        # Don't leak internals to the client.
        raise HTTPException(status_code=500, detail="Analysis failed.")

    return JSONResponse(report)
