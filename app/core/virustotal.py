"""Step 4 - URL reputation via VirusTotal API v3.

For each URL: look in the SQLite cache first; otherwise query VirusTotal, respecting
the free-tier rate limit (4 req/min). Results are normalised to small dicts the rest
of the app understands. If no key is configured, every URL comes back as "unchecked"
so the pipeline still runs end-to-end.
"""
from __future__ import annotations

import base64
import os
import threading
import time
from typing import Optional

import requests

from .. import config
from . import cache
from .extractor import ExtractedURL

# --- client-side politeness gap between live lookups -------------------------
# The VirusTotal free tier allows 4 lookups/minute. We keep a small gap between
# calls and cap live lookups per email (see max_live) rather than forcing a full
# 15s wait, which made a single unknown URL stall the whole request for ~15s.
# If the minute budget is exceeded, VT returns 429 and we report it, instead of
# blocking the user.
_MIN_INTERVAL = float(os.getenv("VT_MIN_INTERVAL", "1.0"))
_lock = threading.Lock()
_last_call = [0.0]


def _throttle() -> None:
    with _lock:
        wait = _MIN_INTERVAL - (time.time() - _last_call[0])
        if wait > 0:
            time.sleep(wait)
        _last_call[0] = time.time()


def _url_id(url: str) -> str:
    """VT v3 URL identifier: base64url of the URL, no padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _submit_async(url: str, headers: dict) -> None:
    """Submit an unknown URL to VirusTotal without blocking the caller."""
    def _run():
        try:
            requests.post(
                f"{config.VT_BASE_URL}/urls", headers=headers,
                data={"url": url}, timeout=config.HTTP_TIMEOUT,
            )
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def check_urls(urls: list[ExtractedURL], max_live: int = 4) -> list[dict]:
    """Return one report dict per URL.

    max_live caps how many *uncached* URLs we query live (defaults to the free
    tier's 4/min budget), so one email can't blow the quota or stall. Extras
    beyond the cap are reported as 'skipped'.
    """
    reports: list[dict] = []
    live_used = 0

    for eu in urls:
        base = {
            "url": eu.url,
            "source": eu.source,
            "deceptive": eu.deceptive,
            "deceptive_detail": eu.deceptive_detail,
            "shortener": eu.shortener,
            "raw_ip": eu.raw_ip,
            "lookalike": eu.lookalike,
            "lookalike_detail": eu.lookalike_detail,
            "insecure": eu.insecure,
        }

        cached = cache.get(eu.url)
        if cached is not None:
            reports.append({**base, **cached, "cached": True})
            continue

        if not config.vt_configured():
            reports.append({**base, "status": "unchecked", "malicious": 0,
                            "suspicious": 0, "harmless": 0,
                            "note": "no VirusTotal key configured"})
            continue

        if live_used >= max_live:
            reports.append({**base, "status": "skipped", "malicious": 0,
                            "suspicious": 0, "harmless": 0,
                            "note": "rate-limit budget reached for this email"})
            continue

        result = _query_vt(eu.url)
        live_used += 1
        cache.put(eu.url, result)
        reports.append({**base, **result, "cached": False})

    return reports


def _query_vt(url: str) -> dict:
    headers = {"x-apikey": config.VT_API_KEY}
    try:
        _throttle()
        r = requests.get(
            f"{config.VT_BASE_URL}/urls/{_url_id(url)}",
            headers=headers,
            timeout=config.HTTP_TIMEOUT,
        )
        if r.status_code == 404:
            # Not seen before. Submit it for future analysis in the background
            # (fire-and-forget) so an unknown URL never stalls the user's request,
            # and report "unknown" right away.
            _submit_async(url, headers)
            return {"status": "unknown", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "note": "not yet in VirusTotal (submitted for analysis)"}
        r.raise_for_status()
        stats = (
            r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        harm = int(stats.get("harmless", 0))
        status = "malicious" if mal else "suspicious" if sus else "harmless"
        return {"status": status, "malicious": mal, "suspicious": sus, "harmless": harm}
    except Exception as exc:
        return {"status": "error", "malicious": 0, "suspicious": 0, "harmless": 0,
                "note": f"VirusTotal error: {type(exc).__name__}"}
