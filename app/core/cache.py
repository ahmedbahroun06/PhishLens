"""SQLite cache for VirusTotal answers.

VirusTotal's free tier allows only 4 requests/minute, so we never ask about the
same URL twice. The cache is keyed by URL and stores the small result dict as JSON.
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Optional

from .. import config

_TTL_SECONDS = 7 * 24 * 3600  # re-check a URL at most once a week


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.CACHE_PATH, timeout=10)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vt_cache (
               url   TEXT PRIMARY KEY,
               data  TEXT NOT NULL,
               ts    INTEGER NOT NULL
           )"""
    )
    return conn


def get(url: str) -> Optional[dict]:
    """Return a cached result dict, or None if absent / expired."""
    try:
        conn = _connect()
        row = conn.execute(
            "SELECT data, ts FROM vt_cache WHERE url = ?", (url,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        data, ts = row
        if time.time() - ts > _TTL_SECONDS:
            return None
        return json.loads(data)
    except Exception:
        return None


def put(url: str, data: dict) -> None:
    try:
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO vt_cache (url, data, ts) VALUES (?, ?, ?)",
            (url, json.dumps(data), int(time.time())),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
