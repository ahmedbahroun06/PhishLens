"""Step 1 - Parse the raw .eml into a clean, structured object.

Uses only Python's built-in `email` module, so there is no extra dependency.
Everything downstream (headers, extractor, llm) reads from the ParsedEmail
produced here instead of touching raw bytes again.
"""
from __future__ import annotations

import email
from email import policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Image:
    """One image found in the email (inline or attachment)."""

    filename: str
    content_type: str
    data: bytes


@dataclass
class ParsedEmail:
    from_display: str = ""          # "Sarah Klein, CEO"
    from_address: str = ""          # ceo@company.com
    from_domain: str = ""           # company.com
    reply_to_address: str = ""
    reply_to_domain: str = ""
    subject: str = ""
    to: str = ""
    date: str = ""
    authentication_results: str = ""  # raw Authentication-Results header(s)
    received_spf: str = ""            # raw Received-SPF header, if any
    text_body: str = ""               # plain-text part(s)
    html_body: str = ""               # html part(s)
    images: list[Image] = field(default_factory=list)
    raw: bytes = b""

    @property
    def body(self) -> str:
        """Best-effort human-readable body: prefer text, fall back to stripped HTML."""
        if self.text_body.strip():
            return self.text_body
        return _strip_html(self.html_body)


def _domain_of(address: str) -> str:
    if "@" in address:
        return address.rsplit("@", 1)[1].strip().lower().rstrip(">").strip()
    return ""


def _strip_html(html: str) -> str:
    """Very small HTML -> text reducer (no extra dependency). Good enough for the LLM."""
    import re

    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


def parse_email(raw_email: bytes) -> ParsedEmail:
    """Turn raw .eml bytes into a ParsedEmail. Never raises on malformed input."""
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8", errors="replace")

    msg: EmailMessage = email.message_from_bytes(raw_email, policy=policy.default)

    parsed = ParsedEmail(raw=raw_email)

    # --- addresses -------------------------------------------------------
    from_display, from_addr = parseaddr(msg.get("From", ""))
    parsed.from_display = from_display.strip()
    parsed.from_address = from_addr.strip().lower()
    parsed.from_domain = _domain_of(parsed.from_address)

    reply_tos = getaddresses(msg.get_all("Reply-To", []))
    if reply_tos:
        parsed.reply_to_address = (reply_tos[0][1] or "").strip().lower()
        parsed.reply_to_domain = _domain_of(parsed.reply_to_address)

    parsed.subject = str(msg.get("Subject", "")).strip()
    parsed.to = str(msg.get("To", "")).strip()
    parsed.date = str(msg.get("Date", "")).strip()

    # Authentication-Results can appear several times; keep them all.
    parsed.authentication_results = "\n".join(
        str(h) for h in msg.get_all("Authentication-Results", [])
    )
    parsed.received_spf = "\n".join(str(h) for h in msg.get_all("Received-SPF", []))

    # --- bodies + images -------------------------------------------------
    _walk_parts(msg, parsed)

    return parsed


def _walk_parts(msg: EmailMessage, parsed: ParsedEmail) -> None:
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disp = (part.get_content_disposition() or "").lower()

        if ctype == "text/plain" and disp != "attachment":
            parsed.text_body += _decode_text(part) + "\n"
        elif ctype == "text/html" and disp != "attachment":
            parsed.html_body += _decode_text(part) + "\n"
        elif ctype.startswith("image/"):
            payload = part.get_payload(decode=True)
            if payload:
                parsed.images.append(
                    Image(
                        filename=part.get_filename() or "inline-image",
                        content_type=ctype,
                        data=payload,
                    )
                )


def _decode_text(part: EmailMessage) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    except Exception:
        return ""
