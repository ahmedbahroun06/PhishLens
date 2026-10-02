"""Step 6 - Turn all signals into points, a capped score, and a verdict.

Weights come straight from the Project Guide (section 7). The AI is one voice
among several and never decides the verdict alone. Output matches the JSON shape
documented in the guide so the web page and CLI render identically.
"""
from __future__ import annotations

from typing import Any

# Verdict thresholds (section 7).
PHISHING_MIN = 60
SUSPICIOUS_MIN = 30


def _brand_of(detail: str) -> str | None:
    """Pull the brand out of a lookalike detail string like 'x ~ paypal (why)'."""
    if detail and "~" in detail:
        return detail.split("~", 1)[1].strip().split(" ", 1)[0] or None
    return None


def build_verdict(header_signals: Any, url_reports: list[dict], llm_result: dict) -> dict:
    signals: list[dict] = []
    score = 0

    def add(name: str, status: str, points: int, detail: str = "") -> None:
        nonlocal score
        score += points
        signals.append(
            {"name": name, "status": status, "detail": detail, "points": points}
        )

    h = header_signals

    # --- authentication --------------------------------------------------
    add("SPF", h.spf, 20 if h.spf in ("fail", "softfail") else 0)
    add("DKIM", h.dkim, 15 if h.dkim == "fail" else 0)
    dmarc_detail = f"policy: {h.dmarc_policy}" if h.dmarc_policy else ""
    add("DMARC", h.dmarc, 20 if h.dmarc == "fail" else 0, dmarc_detail)

    # --- identity --------------------------------------------------------
    if h.reply_to_mismatch:
        add("Reply-To mismatch", "fail", 15, h.reply_to_detail)
    if h.display_name_spoof:
        add("Display-name spoofing", "fail", 10, h.display_name_detail)
    if h.lookalike:
        add("Lookalike domain", "fail", 15, h.lookalike_detail)

    # --- links -----------------------------------------------------------
    worst_url_pts = 0
    deceptive = any(u.get("deceptive") for u in url_reports)
    malicious_urls = [u for u in url_reports if u.get("malicious", 0) > 0]
    if malicious_urls:
        worst = max(malicious_urls, key=lambda u: u.get("malicious", 0))
        add(
            "Malicious URL",
            "fail",
            40,
            f"{worst.get('malicious')}/70 engines flag {worst.get('url')}",
        )
        worst_url_pts = 40
    if deceptive:
        d = next(u for u in url_reports if u.get("deceptive"))
        add("Deceptive link", "fail", 15, d.get("deceptive_detail", "text != href"))

    # Link domain imitating a brand. Don't double-count when it repeats the brand
    # the sender domain already imitated (phish that links to its own lookalike).
    sender_brand = _brand_of(h.lookalike_detail) if h.lookalike else None
    lookalike_urls = [u for u in url_reports
                      if u.get("lookalike") and _brand_of(u.get("lookalike_detail")) != sender_brand]
    if lookalike_urls:
        lu = lookalike_urls[0]
        add("Lookalike link", "fail", 15,
            lu.get("lookalike_detail", "link domain imitates a known brand"))

    insecure_urls = [u for u in url_reports if u.get("insecure")]
    if insecure_urls:
        add("Insecure link (http)", "warn", 5,
            f"{len(insecure_urls)} link(s) use http:// instead of https")

    # --- QR --------------------------------------------------------------
    qr_urls = [u for u in url_reports if u.get("source") == "qr"]
    if qr_urls:
        add("QR code", "warn", 10, f"{len(qr_urls)} QR link(s) found")

    # --- AI voices -------------------------------------------------------
    bec = (llm_result or {}).get("bec_likelihood", "low")
    add(
        "Phishing intent (AI)",
        "fail" if bec == "high" else "warn" if bec == "medium" else "pass",
        20 if bec == "high" else 10 if bec == "medium" else 0,
        f"AI assessment: {bec}",
    )
    ai_text = (llm_result or {}).get("ai_generated_likelihood", "low")
    add(
        "AI-generated text",
        "warn" if ai_text == "high" else "pass",
        5 if ai_text == "high" else 0,
        f"AI assessment: {ai_text}",
    )

    score = min(score, 100)
    if score >= PHISHING_MIN:
        verdict = "phishing"
    elif score >= SUSPICIOUS_MIN:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "score": score,
        "signals": signals,
        "urls": [
            {
                "url": u.get("url"),
                "source": u.get("source"),
                "malicious": u.get("malicious", 0),
                "suspicious": u.get("suspicious", 0),
                "status": u.get("status"),
                "deceptive": u.get("deceptive", False),
            }
            for u in url_reports
        ],
        "llm": {
            "bec_likelihood": bec,
            "ai_generated_likelihood": ai_text,
            "explanation": (llm_result or {}).get("explanation", ""),
            "source": (llm_result or {}).get("source", ""),
        },
    }
