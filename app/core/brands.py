"""Brand lookalike / typo detection, shared by headers.py and extractor.py.

Catches domains and display-name words that imitate a known brand by:
  * character homoglyphs / digit swaps  (paypa1 -> paypal, g00gle -> google)
  * common letter confusions            (mlcrosoft -> microsoft, rn -> m)
  * small edit distance                 (micros0ft-support, faceboook)

An exact brand token is treated as legitimate (not a lookalike), since we have
no allowlist of real domains; only near-misses are flagged.
"""
from __future__ import annotations

import re

# Brand tokens attackers impersonate (second-level label form, no TLD).
KNOWN_BRANDS = [
    "paypal", "microsoft", "microsoftonline", "office365", "office", "outlook",
    "onedrive", "sharepoint", "windows", "live", "msn", "apple", "icloud",
    "amazon", "aws", "google", "gmail", "youtube", "facebook", "instagram",
    "whatsapp", "netflix", "spotify", "linkedin", "twitter", "dropbox",
    "docusign", "adobe", "dhl", "fedex", "ups", "dpd", "usps", "chase",
    "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays", "santander",
    "stripe", "coinbase", "binance", "metamask", "steam", "discord",
]

# Homoglyph / leetspeak folding applied before comparison.
_HOMOGLYPH = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "9": "g", "$": "s", "@": "a", "|": "l",
})


def normalize(label: str) -> str:
    s = label.lower().translate(_HOMOGLYPH)
    s = s.replace("rn", "m").replace("vv", "w")
    return re.sub(r"[^a-z0-9]", "", s)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _match_token(token: str) -> tuple[str, str] | None:
    """Return (brand, reason) if `token` imitates a brand, else None."""
    base = re.split(r"[-_]", token.lower())[0]
    if len(base) < 4:
        return None
    nb = normalize(base)
    if not nb:
        return None
    for brand in KNOWN_BRANDS:
        if base == brand:
            return None  # exact, legitimate token
        nbrand = normalize(brand)
        if nb == nbrand:
            return (brand, "character/digit lookalike")
        if len(brand) >= 5:
            d = levenshtein(nb, nbrand)
            if 0 < d <= 2 and abs(len(nb) - len(nbrand)) <= 2:
                return (brand, f"edit distance {d}")
    return None


def lookalike_domain(host: str) -> tuple[str, str] | None:
    """Check a hostname (e.g. quota.mlcrosoftonline.com) for a brand lookalike.
    Looks at the second-level label and the left-most label."""
    host = (host or "").lower().strip().rstrip(".")
    if not host:
        return None
    labels = host.split(".")
    candidates = []
    if len(labels) >= 2:
        candidates.append(labels[-2])          # registrable label
    candidates.append(labels[0])               # left-most (subdomain abuse)
    seen = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        hit = _match_token(cand)
        if hit:
            return hit
    return None


def lookalike_in_text(text: str) -> tuple[str, str] | None:
    """Check display-name words (e.g. 'Offlce 365 Team') for a brand lookalike."""
    for word in re.findall(r"[A-Za-z0-9]{4,}", text or ""):
        hit = _match_token(word)
        if hit:
            return hit
    return None
