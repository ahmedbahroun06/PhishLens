#!/usr/bin/env python3
"""Build the bundled sample .eml files (one phishing, one suspicious, one clean).

Run once from the project root:  python tests/make_samples.py
(The generated samples are already bundled, so you normally don't need this.
 Regenerating requires the dev-only QR generator:  pip install qrcode)
Regenerating is safe and idempotent. The phishing sample embeds a *real* QR code
(generated with the qrcode lib) so the QR-decoding path is exercised end to end.
These are synthetic teaching samples; all domains/links are fictitious.
"""
from __future__ import annotations

import io
from email.message import EmailMessage
from pathlib import Path

SAMPLES = Path(__file__).resolve().parent / "samples"
SAMPLES.mkdir(parents=True, exist_ok=True)


def _qr_png(data: str) -> bytes:
    import qrcode

    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build_phishing() -> None:
    msg = EmailMessage()
    msg["From"] = '"Sarah Klein, CEO" <ceo@acme-corp.com>'
    msg["Reply-To"] = "sarah.klein.private@gmail.com"
    msg["To"] = "finance@acme-corp.com"
    msg["Subject"] = "Urgent — confidential wire transfer before 5 pm today"
    msg["Date"] = "Tue, 30 Sep 2026 09:14:02 +0000"
    # Receiving server verdicts: SPF + DMARC fail, DKIM none. Classic spoof.
    msg["Authentication-Results"] = (
        "mx.acme-corp.com; spf=fail smtp.mailfrom=bounce@mailer-hub.net; "
        "dkim=none; dmarc=fail (p=reject) header.from=acme-corp.com"
    )

    body_text = (
        "Hi,\n\n"
        "I'm in back-to-back meetings and can't take calls. I need you to process a "
        "confidential wire transfer today before 5 pm. Our supplier's bank details "
        "changed — new account below. Please keep this between us for now.\n\n"
        "To confirm your identity on the finance portal, scan the QR code in this "
        "email and sign in.\n\n"
        "Thanks,\nSarah Klein\nChief Executive Officer\n"
    )
    msg.set_content(body_text)

    qr = _qr_png("http://secure-login-verify.xyz/auth?id=8812")
    html = (
        "<html><body style='font-family:Arial'>"
        "<p>Hi,</p>"
        "<p>I'm in back-to-back meetings and can't take calls. I need you to process a "
        "<b>confidential wire transfer today before 5 pm</b>. Our supplier's bank details "
        "changed. Please keep this between us for now.</p>"
        "<p>To confirm your identity on the finance portal, scan this QR code and sign in:</p>"
        "<p><img src='cid:qr001' width='160' height='160' alt='verify'></p>"
        "<p>You can also <a href='http://secure-login-verify.xyz/auth?id=8812'>"
        "www.acme-corp.com/portal</a>.</p>"  # deceptive: text says acme-corp, href is xyz
        "<p>Thanks,<br>Sarah Klein<br>Chief Executive Officer</p>"
        "</body></html>"
    )
    msg.add_alternative(html, subtype="html")
    # Attach the QR as an inline (cid) image on the HTML alternative part.
    html_part = msg.get_payload()[-1]
    html_part.add_related(qr, maintype="image", subtype="png", cid="<qr001>",
                          filename="verify.png")

    (SAMPLES / "phishing_bec_qr.eml").write_bytes(msg.as_bytes())


def build_suspicious() -> None:
    msg = EmailMessage()
    msg["From"] = '"PayPal Billing" <service@paypa1-billing.com>'  # lookalike: paypa1
    msg["Reply-To"] = "service@paypa1-billing.com"
    msg["To"] = "user@example.com"
    msg["Subject"] = "Your invoice #2291 is ready — please confirm"
    msg["Date"] = "Mon, 29 Sep 2026 17:40:11 +0000"
    msg["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=paypa1-billing.com; "
        "dkim=none; dmarc=fail (p=none) header.from=paypa1-billing.com"
    )
    msg.set_content(
        "Hello,\n\nYour invoice #2291 is ready. Please confirm the payment details "
        "at the link below.\n\nhttps://paypa1-billing.com/invoice/2291\n\n"
        "Thank you,\nBilling Team\n"
    )
    (SAMPLES / "suspicious_lookalike.eml").write_bytes(msg.as_bytes())


def build_clean() -> None:
    msg = EmailMessage()
    msg["From"] = '"Example Weekly" <news@news.example.com>'
    msg["Reply-To"] = "news@news.example.com"
    msg["To"] = "user@example.com"
    msg["Subject"] = "Your weekly digest from Example"
    msg["Date"] = "Sun, 28 Sep 2026 08:00:00 +0000"
    msg["Authentication-Results"] = (
        "mx.example.com; spf=pass smtp.mailfrom=news.example.com; "
        "dkim=pass header.d=example.com; dmarc=pass (p=reject) header.from=news.example.com"
    )
    msg.set_content(
        "Hi there,\n\nHere's what's new this week. Read the latest articles and "
        "updates below.\n\nTop story: https://news.example.com/weekly\n"
        "Manage your subscription: https://example.com/unsubscribe\n\n"
        "Cheers,\nThe Example Team\n"
    )
    html = (
        "<html><body>"
        "<p>Hi there,</p><p>Here's what's new this week.</p>"
        "<p><a href='https://news.example.com/weekly'>https://news.example.com/weekly</a></p>"
        "<p><a href='https://example.com/unsubscribe'>Unsubscribe</a></p>"
        "<p>Cheers,<br>The Example Team</p></body></html>"
    )
    msg.add_alternative(html, subtype="html")
    (SAMPLES / "clean_newsletter.eml").write_bytes(msg.as_bytes())


if __name__ == "__main__":
    build_phishing()
    build_suspicious()
    build_clean()
    for p in sorted(SAMPLES.glob("*.eml")):
        print(f"wrote {p.relative_to(Path.cwd())}  ({p.stat().st_size} bytes)")
