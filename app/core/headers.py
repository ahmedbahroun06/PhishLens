"""Step 2 - Header & identity checks: SPF, DKIM, DMARC, Reply-To, spoofing, lookalike.

Where possible we read the result the receiving server already wrote into the
`Authentication-Results` header (fast, offline). DKIM is additionally re-verified
with dkimpy, and the DMARC policy is fetched live over DNS with dnspython.
Every check is wrapped so a failure (e.g. no network) degrades to "unknown",
never crashes the pipeline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .parser import ParsedEmail
from . import brands

# Internal titles commonly impersonated in display names (BEC). Brand list lives
# in brands.py and is shared with the URL lookalike check.
EXEC_TITLES = ["ceo", "cfo", "coo", "cto", "president", "director", "manager", "hr"]
_FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me",
             "protonmail.com", "icloud.com", "aol.com", "gmx.com", "mail.com"}


@dataclass
class HeaderSignals:
    spf: str = "unknown"            # pass / fail / softfail / neutral / none / unknown
    dkim: str = "unknown"          # pass / fail / none / unknown
    dmarc: str = "unknown"         # pass / fail / none / unknown
    dmarc_policy: str = ""         # none / quarantine / reject / ""
    reply_to_mismatch: bool = False
    reply_to_detail: str = ""
    display_name_spoof: bool = False
    display_name_detail: str = ""
    lookalike: bool = False
    lookalike_detail: str = ""
    notes: list[str] = field(default_factory=list)


def check_headers(email_obj: ParsedEmail) -> HeaderSignals:
    sig = HeaderSignals()

    _read_auth_results(email_obj, sig)
    _reverify_dkim(email_obj, sig)
    _fetch_dmarc_policy(email_obj, sig)
    _check_reply_to(email_obj, sig)
    _check_display_name(email_obj, sig)
    _check_lookalike(email_obj, sig)

    return sig


# --------------------------------------------------------------------------- #
# Authentication-Results parsing (offline, trusts the receiving mail server)   #
# --------------------------------------------------------------------------- #
def _read_auth_results(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    blob = (email_obj.authentication_results or "").lower()
    if not blob and email_obj.received_spf:
        # Fall back to a Received-SPF header for SPF only.
        m = re.search(r"received-spf:\s*(\w+)", email_obj.received_spf.lower())
        if m:
            sig.spf = _norm_spf(m.group(1))

    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", blob)
        if m:
            value = m.group(1)
            if mech == "spf":
                sig.spf = _norm_spf(value)
            elif mech == "dkim":
                sig.dkim = value if value in ("pass", "fail", "none") else "unknown"
            elif mech == "dmarc":
                sig.dmarc = value if value in ("pass", "fail", "none") else "unknown"


def _norm_spf(value: str) -> str:
    value = value.lower()
    return value if value in ("pass", "fail", "softfail", "neutral", "none") else "unknown"


# --------------------------------------------------------------------------- #
# DKIM re-verification with dkimpy                                             #
# --------------------------------------------------------------------------- #
def _reverify_dkim(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    if not email_obj.raw:
        return
    try:
        import dkim  # dkimpy

        ok = dkim.verify(email_obj.raw)
        # Only upgrade/confirm; don't overwrite a server 'none' with a crypto fail
        # when there simply was no signature.
        if ok:
            sig.dkim = "pass"
        else:
            if "dkim-signature" in email_obj.raw.lower().decode("latin-1", "ignore"):
                sig.dkim = "fail"
            elif sig.dkim == "unknown":
                sig.dkim = "none"
    except Exception as exc:  # no signature, bad key fetch, offline, etc.
        sig.notes.append(f"DKIM re-verify skipped: {type(exc).__name__}")


# --------------------------------------------------------------------------- #
# DMARC policy lookup over DNS                                                 #
# --------------------------------------------------------------------------- #
def _fetch_dmarc_policy(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    domain = email_obj.from_domain
    if not domain:
        return
    try:
        import dns.resolver

        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", "ignore").lower()
            if "v=dmarc1" in txt:
                m = re.search(r"\bp=(\w+)", txt)
                if m:
                    sig.dmarc_policy = m.group(1)
                if sig.dmarc == "unknown":
                    # We have a published policy but no receiver verdict in headers.
                    sig.notes.append("DMARC policy found; no receiver result in headers")
                return
    except Exception as exc:
        sig.notes.append(f"DMARC DNS lookup skipped: {type(exc).__name__}")


# --------------------------------------------------------------------------- #
# Reply-To mismatch                                                           #
# --------------------------------------------------------------------------- #
def _check_reply_to(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    f, r = email_obj.from_domain, email_obj.reply_to_domain
    if f and r and f != r:
        sig.reply_to_mismatch = True
        sig.reply_to_detail = f"{f} -> {r}"


# --------------------------------------------------------------------------- #
# Display-name spoofing                                                       #
# --------------------------------------------------------------------------- #
def _check_display_name(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    display = email_obj.from_display or ""
    domain = email_obj.from_domain or ""
    if not display:
        return

    # 1) Display name imitates a brand (exact or typo/homoglyph) while the sending
    #    domain is unrelated to that brand. Works even if the domain is unknown.
    hit = brands.lookalike_in_text(display)
    if not hit:
        # also catch an exact brand word in the display name (e.g. "PayPal Support")
        for brand in brands.KNOWN_BRANDS:
            if re.search(rf"\b{re.escape(brand)}\b", display.lower()):
                hit = (brand, "brand name in display")
                break
    if hit:
        brand, why = hit
        if brands.normalize(brand) not in brands.normalize(domain):
            sig.display_name_spoof = True
            sig.display_name_detail = (
                f'display name imitates "{brand}" ({why})'
                + (f' but domain is {domain}' if domain else " but domain is unrelated")
            )
            return

    # 2) An executive title in the display name sent from a free-mail account.
    if domain in _FREEMAIL:
        for title in EXEC_TITLES:
            if re.search(rf"\b{title}\b", display.lower()):
                sig.display_name_spoof = True
                sig.display_name_detail = f'"{title}" in display name sent from free-mail {domain}'
                return


# --------------------------------------------------------------------------- #
# Lookalike sender domain (typo/homoglyph against known brands)               #
# --------------------------------------------------------------------------- #
def _check_lookalike(email_obj: ParsedEmail, sig: HeaderSignals) -> None:
    domain = email_obj.from_domain or ""
    hit = brands.lookalike_domain(domain)
    if hit:
        brand, why = hit
        sig.lookalike = True
        sig.lookalike_detail = f"{domain} ~ {brand} ({why})"
