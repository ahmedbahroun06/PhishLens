"""Step 3 - Extract every link, including deceptive links and links hidden in QR codes.

Three sources of URLs:
  * plain text body (regex)
  * HTML anchors (compare visible text vs real href -> "deceptive link")
  * QR codes decoded from inline / attached images (pyzbar + Pillow)

pyzbar needs the native `zbar` library; the Docker image installs it. If zbar is
missing locally, QR decoding is skipped with a note instead of crashing.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from .parser import ParsedEmail
from . import brands

URL_RE = re.compile(r"""https?://[^\s<>"')\]]+""", re.IGNORECASE)
# A bare host shown as link text, e.g. "www.acme-corp.com" or "paypal.com/login".
VISIBLE_HOST_RE = re.compile(
    r"""(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)""",
    re.IGNORECASE,
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}


@dataclass
class ExtractedURL:
    url: str
    source: str              # "text" | "link" | "qr"
    deceptive: bool = False
    deceptive_detail: str = ""
    shortener: bool = False
    raw_ip: bool = False
    lookalike: bool = False
    lookalike_detail: str = ""
    insecure: bool = False   # http:// (not https) to a login-looking page


@dataclass
class ExtractionResult:
    urls: list[ExtractedURL] = field(default_factory=list)
    qr_count: int = 0
    deceptive_count: int = 0
    notes: list[str] = field(default_factory=list)


class _AnchorParser(HTMLParser):
    """Collect (href, visible_text) pairs from <a> tags."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def extract_urls_and_qr(email_obj: ParsedEmail) -> ExtractionResult:
    result = ExtractionResult()
    seen: set[tuple[str, str]] = set()

    def add(url: str, source: str, **kw) -> ExtractedURL | None:
        url = url.strip().rstrip(".,;)")
        if not url.lower().startswith(("http://", "https://")):
            return None
        key = (url, source)
        if key in seen:
            return None
        seen.add(key)
        eu = ExtractedURL(url=url, source=source, **kw)
        _annotate(eu)
        result.urls.append(eu)
        return eu

    # 1) plain text
    for m in URL_RE.findall(email_obj.text_body or ""):
        add(m, "text")

    # 2) HTML anchors (deceptive link detection)
    if email_obj.html_body:
        p = _AnchorParser()
        try:
            p.feed(email_obj.html_body)
        except Exception as exc:
            result.notes.append(f"HTML parse issue: {type(exc).__name__}")
        for href, text in p.links:
            eu = add(href, "link")
            if eu is None:
                continue
            vis_dom = _visible_host(text or "")
            real_dom = _host(href)
            if vis_dom and real_dom and not _same_site(vis_dom, real_dom):
                eu.deceptive = True
                eu.deceptive_detail = f"text shows {vis_dom}, link goes to {real_dom}"
                result.deceptive_count += 1

    # 3) QR codes inside images
    _extract_qr(email_obj, result, add)

    return result


def _annotate(eu: ExtractedURL) -> None:
    host = _host(eu.url)
    if host in SHORTENERS:
        eu.shortener = True
    try:
        ipaddress.ip_address(host)
        eu.raw_ip = True
    except ValueError:
        pass
    hit = brands.lookalike_domain(host)
    if hit:
        brand, why = hit
        eu.lookalike = True
        eu.lookalike_detail = f"{host} ~ {brand} ({why})"
    if eu.url.lower().startswith("http://"):
        eu.insecure = True


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _visible_host(text: str) -> str:
    """Pull a hostname out of anchor text, with or without an http scheme."""
    text = text.strip()
    if not text:
        return ""
    m = URL_RE.search(text)
    if m:
        return _host(m.group(0))
    m = VISIBLE_HOST_RE.search(text)
    if m:
        # Reject things like "click here" where the regex matched a non-domain word.
        host = m.group(1).lower()
        return host if "." in host else ""
    return ""


def _same_site(a: str, b: str) -> bool:
    """Compare registrable-ish domain (last two labels) so mail.x.com ~ x.com."""
    if a == b:
        return True
    return a.split(".")[-2:] == b.split(".")[-2:]


def _extract_qr(email_obj, result, add) -> None:
    if not email_obj.images:
        return
    try:
        from io import BytesIO

        from PIL import Image as PILImage
        from pyzbar.pyzbar import decode as zbar_decode
    except Exception as exc:
        result.notes.append(
            f"QR decoding unavailable ({type(exc).__name__}); zbar library missing?"
        )
        return

    for img in email_obj.images:
        try:
            pil = PILImage.open(BytesIO(img.data))
            for code in zbar_decode(pil):
                payload = code.data.decode("utf-8", "ignore").strip()
                if payload.lower().startswith(("http://", "https://")):
                    result.qr_count += 1
                    add(payload, "qr")
        except Exception as exc:
            result.notes.append(
                f"image {img.filename} not decoded: {type(exc).__name__}"
            )
