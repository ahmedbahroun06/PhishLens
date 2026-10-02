"""The conductor. Runs steps 1-6 in order and returns the full JSON report.

This is the single "brain" that both doors (web + CLI) call, so no logic is
duplicated. It never stores the email; everything happens in memory.
"""
from __future__ import annotations

import time

from .. import config
from .parser import parse_email
from .headers import check_headers
from .extractor import extract_urls_and_qr
from .virustotal import check_urls
from .llm import ask_llm
from .scoring import build_verdict


def analyze(raw_email: bytes) -> dict:
    if raw_email and len(raw_email) > config.MAX_EMAIL_BYTES:
        raise ValueError(
            f"Email too large ({len(raw_email)} bytes; limit {config.MAX_EMAIL_BYTES})."
        )

    started = time.time()

    email_obj = parse_email(raw_email)                 # Step 1
    header_signals = check_headers(email_obj)          # Step 2
    extraction = extract_urls_and_qr(email_obj)        # Step 3
    url_reports = check_urls(extraction.urls)          # Step 4
    llm_result = ask_llm(                              # Step 5
        header_signals, url_reports, email_obj.body
    )
    report = build_verdict(                            # Step 6
        header_signals, url_reports, llm_result
    )

    # Attach lightweight metadata (handy for the UI header and debugging).
    report["meta"] = {
        "from": email_obj.from_address,
        "from_display": email_obj.from_display,
        "subject": email_obj.subject,
        "reply_to": email_obj.reply_to_address,
        "qr_codes_found": extraction.qr_count,
        "urls_found": len(extraction.urls),
        "elapsed_seconds": round(time.time() - started, 2),
        "notes": header_signals.notes + extraction.notes,
        "services": {
            "virustotal": config.vt_configured(),
            "groq": config.groq_configured(),
        },
    }
    return report
