"""Central configuration. Reads secret keys from the environment / .env file.

Keys are optional at import time so the app still boots without them:
each step that needs a key checks `is_configured` and degrades gracefully.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load a .env sitting at the project root (one level above app/), if present.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "").strip()
VT_API_KEY: str = os.getenv("VT_API_KEY", "").strip()

# Model + endpoints (overridable via env, with sane defaults from the guide).
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip()
GROQ_BASE_URL: str = os.getenv(
    "GROQ_BASE_URL", "https://api.groq.com/openai/v1"
).strip()
VT_BASE_URL: str = "https://www.virustotal.com/api/v3"

# Where the VirusTotal SQLite cache lives. In Docker this is a mounted volume.
CACHE_PATH: str = os.getenv("CACHE_PATH", str(_PROJECT_ROOT / "cache.db")).strip()

# Safety limit for uploads (bytes). 10 MB is plenty for a single .eml.
MAX_EMAIL_BYTES: int = int(os.getenv("MAX_EMAIL_BYTES", str(10 * 1024 * 1024)))

# Network timeouts (seconds) so a hung external service can't freeze a request.
HTTP_TIMEOUT: int = int(os.getenv("HTTP_TIMEOUT", "20"))


def groq_configured() -> bool:
    return bool(GROQ_API_KEY)


def vt_configured() -> bool:
    return bool(VT_API_KEY)
