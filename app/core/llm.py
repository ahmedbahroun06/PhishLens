"""Step 5 - AI reasoning with Groq.

The model reads the *structured evidence* (header signals + URL reports) plus the
body text and returns a strict JSON object: BEC likelihood, AI-generated-text
likelihood, and a plain-language explanation. It never sees raw bytes and is only
one voice in the final score.

Two offline statistical hints (sentence-length uniformity, formal-phrase density)
are computed here and handed to the model as extra context. If no Groq key is set,
we return a deterministic fallback built from those hints so the app still works.
"""
from __future__ import annotations

import json
import re
import statistics
from typing import Any

import requests

from .. import config

_SYSTEM = (
    "You are PhishLens, a precise email-security analyst. You are given verified "
    "technical evidence about ONE email and its body text. Reason over the evidence "
    "and the EMAIL BODY. Judge two things: "
    "(1) bec_likelihood = the likelihood this email is a PHISHING or social-"
    "engineering attempt of ANY kind — wire-transfer/BEC fraud, credential "
    "harvesting, fake account/security/storage/'mailbox full'/password-expiry "
    "notices, prize/invoice scams — based on cues like urgency or threats, requests "
    "to click a link and sign in or 'verify', impersonation of a brand or executive, "
    "payment or credential requests, and secrecy. "
    "(2) ai_generated_likelihood = whether the text was likely written by an AI. "
    "IMPORTANT: the numeric hint counts you are given are crude keyword heuristics "
    "that frequently MISS real lures; a zero count is NOT evidence that the email is "
    "safe — judge the actual wording of the body yourself. "
    "Respond with STRICT JSON only, no prose outside it."
)

_SCHEMA_HINT = (
    '{"bec_likelihood":"low|medium|high",'
    '"ai_generated_likelihood":"low|medium|high",'
    '"explanation":"2-4 sentences in plain language citing the concrete evidence"}'
)


def ask_llm(header_signals: Any, url_reports: list[dict], body: str) -> dict:
    hints = _text_hints(body)
    evidence = _build_evidence(header_signals, url_reports, hints)

    if not config.groq_configured():
        return _fallback(hints, note="no Groq key configured")

    payload = {
        "model": config.GROQ_MODEL,
        "temperature": 0,
        "max_tokens": 1024,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {
                "role": "user",
                "content": (
                    f"EVIDENCE:\n{evidence}\n\n"
                    f"EMAIL BODY (truncated):\n{body[:6000]}\n\n"
                    f"Return JSON exactly matching this shape: {_SCHEMA_HINT}"
                ),
            },
        ],
    }

    try:
        content = _groq_chat(payload)
        data = _coerce_json(content)
        explanation = str(data.get("explanation", "")).strip()
        if not (data.get("bec_likelihood") or data.get("ai_generated_likelihood") or explanation):
            # Valid HTTP but unparseable/empty JSON -> treat as failure, use fallback.
            return _fallback(hints, note="Groq returned no usable JSON")
        return {
            "bec_likelihood": _norm_level(data.get("bec_likelihood")),
            "ai_generated_likelihood": _norm_level(data.get("ai_generated_likelihood")),
            "explanation": explanation or "The model returned no explanation.",
            "source": "groq",
        }
    except Exception as exc:
        return _fallback(hints, note=str(exc))


# Retry transient failures (rate limits, brief 5xx) before giving up.
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_RETRIES = 2
_MAX_BACKOFF = 8.0


def _groq_chat(payload: dict) -> str:
    """POST to Groq with retry/backoff. Returns the message content, or raises a
    RuntimeError whose message states the real HTTP status and reason."""
    import time

    url = f"{config.GROQ_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    last = "unknown error"
    for attempt in range(_MAX_RETRIES + 1):
        try:
            r = requests.post(url, headers=headers, json=payload,
                              timeout=config.HTTP_TIMEOUT)
        except requests.RequestException as exc:
            last = f"network {type(exc).__name__}"
            if attempt < _MAX_RETRIES:
                time.sleep(min(2 ** attempt, _MAX_BACKOFF))
                continue
            raise RuntimeError(f"Groq error: {last}")

        if r.status_code == 200:
            try:
                return r.json()["choices"][0]["message"]["content"]
            except Exception:
                raise RuntimeError("Groq error: 200 but unexpected response shape")

        reason = _extract_api_error(r)
        last = f"Groq error: {r.status_code} {reason}"
        if r.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
            wait = _retry_after(r, attempt)
            time.sleep(wait)
            continue
        raise RuntimeError(last)

    raise RuntimeError(last)


def _extract_api_error(r) -> str:
    try:
        msg = r.json().get("error", {}).get("message", "")
        if msg:
            return msg[:200]
    except Exception:
        pass
    return (r.text or "")[:200]


def _retry_after(r, attempt: int) -> float:
    ra = r.headers.get("Retry-After")
    if ra:
        try:
            return min(float(ra), _MAX_BACKOFF)
        except ValueError:
            pass
    return min(2 ** attempt, _MAX_BACKOFF)


# --------------------------------------------------------------------------- #
# Offline helpers                                                             #
# --------------------------------------------------------------------------- #
_FORMAL_PHRASES = [
    "i hope this email finds you well", "please do not hesitate", "kindly",
    "as per", "at your earliest convenience", "i am writing to", "rest assured",
    "furthermore", "moreover", "in order to", "we would like to inform you",
]
_URGENCY = ["urgent", "immediately", "today", "right now", "before", "asap",
            "as soon as", "warning", "alert", "action required", "final notice",
            "expire", "expiring", "suspend", "suspended", "deactivat", "within 24",
            "last chance", "act now", "failure to", "avoid", "almost full"]
_PAYMENT = ["wire", "transfer", "gift card", "bank details", "invoice", "payment",
            "iban", "bitcoin", "crypto", "refund", "overdue", "billing"]
_CRED = ["password", "login", "log in", "verify your", "verify account",
         "verification code", "credentials", "sign in", "confirm your",
         "update your", "re-activate", "reactivate", "validate", "click on",
         "click here", "mailbox", "quota", "storage", "account will", "unlock"]


def _text_hints(body: str) -> dict:
    sentences = [s.strip() for s in re.split(r"[.!?\n]+", body) if s.strip()]
    lengths = [len(s.split()) for s in sentences] or [0]
    uniformity = 0.0
    if len(lengths) >= 3 and statistics.mean(lengths) > 0:
        # Low coefficient of variation => very uniform => more AI-like.
        cv = statistics.pstdev(lengths) / statistics.mean(lengths)
        uniformity = max(0.0, min(1.0, 1.0 - cv))
    low = body.lower()
    formal = sum(low.count(p) for p in _FORMAL_PHRASES)
    return {
        "sentence_uniformity": round(uniformity, 2),
        "formal_phrase_hits": formal,
        "urgency_hits": sum(low.count(w) for w in _URGENCY),
        "payment_hits": sum(low.count(w) for w in _PAYMENT),
        "credential_hits": sum(low.count(w) for w in _CRED),
    }


def _build_evidence(header_signals: Any, url_reports: list[dict], hints: dict) -> str:
    h = header_signals
    lines = [
        f"SPF={getattr(h, 'spf', '?')}  DKIM={getattr(h, 'dkim', '?')}  "
        f"DMARC={getattr(h, 'dmarc', '?')} (policy={getattr(h, 'dmarc_policy', '') or 'n/a'})",
        f"Reply-To mismatch={getattr(h, 'reply_to_mismatch', False)} "
        f"({getattr(h, 'reply_to_detail', '') or 'none'})",
        f"Display-name spoof={getattr(h, 'display_name_spoof', False)} "
        f"({getattr(h, 'display_name_detail', '') or 'none'})",
        f"Lookalike domain={getattr(h, 'lookalike', False)} "
        f"({getattr(h, 'lookalike_detail', '') or 'none'})",
    ]
    for u in url_reports[:10]:
        lines.append(
            f"URL[{u.get('source')}] {u.get('url')} -> {u.get('status')} "
            f"(mal={u.get('malicious', 0)}, susp={u.get('suspicious', 0)}, "
            f"deceptive={u.get('deceptive', False)})"
        )
    lines.append(f"TEXT HINTS: {json.dumps(hints)}")
    return "\n".join(lines)


def _fallback(hints: dict, note: str) -> dict:
    bec_score = hints["urgency_hits"] + hints["payment_hits"] + hints["credential_hits"]
    bec = "high" if bec_score >= 3 else "medium" if bec_score >= 1 else "low"
    ai = "high" if hints["sentence_uniformity"] >= 0.7 else (
        "medium" if hints["sentence_uniformity"] >= 0.45 else "low"
    )
    return {
        "bec_likelihood": bec,
        "ai_generated_likelihood": ai,
        "explanation": (
            f"AI reasoning unavailable ({note}); this estimate is from offline text "
            f"statistics only. Urgency/payment/credential cue count: {bec_score}; "
            f"sentence-length uniformity: {hints['sentence_uniformity']}."
        ),
        "source": "offline-fallback",
    }


def _coerce_json(content: str) -> dict:
    try:
        return json.loads(content)
    except Exception:
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return {}


def _norm_level(value: Any) -> str:
    v = str(value or "").strip().lower()
    return v if v in ("low", "medium", "high") else "low"
