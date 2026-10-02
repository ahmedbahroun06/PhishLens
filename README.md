# PhishLens 🔍

**See what's really behind the email.**

PhishLens analyzes one suspicious email and returns a clear verdict — **Phishing**,
**Suspicious**, or **Clean** — with every reason explained. It checks the technical
evidence first (sender authentication, links, QR codes, URL reputation), then an AI
model reasons over that evidence in plain language.

It is an on-demand forensic tool — one email at a time, like a malware sandbox for
emails. It informs; **you** decide what to do. Emails are analyzed in memory and
never stored.

---

## ⚡ Quick start with Docker (recommended)

You need only **Docker Desktop** and **two free API keys**. Nothing else to install.

```bash
# 1. Put in your API keys
cp .env.example .env          # Windows cmd:  copy .env.example .env
#    then open .env and paste your two keys (see "API keys" below)

# 2. Build and run
docker compose up --build

# 3. Open the app
#    http://localhost:8000
```

To stop: `Ctrl+C`, then `docker compose down`.

---

## 🔑 API keys — **read this first**

PhishLens uses two free services. **Each person uses their own keys.**

| Key | Where to get it (free) | Used for |
| --- | --- | --- |
| `GROQ_API_KEY` | https://console.groq.com/keys | AI reasoning & explanation |
| `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey | URL reputation |

### 👉 Where to put YOUR keys (for my teammate)

1. In the project folder, copy `.env.example` to a new file named exactly **`.env`**.
2. Open `.env` and replace the placeholders with your own keys:
   ```
   GROQ_API_KEY=gsk_your_actual_groq_key
   VT_API_KEY=your_actual_virustotal_key
   ```
3. Save. That's it — `docker compose up --build` will pick them up automatically.

> 🔒 **Security:** `.env` is listed in `.gitignore` **and** `.dockerignore`, so your
> keys are never committed to Git and never baked into the Docker image. This shared
> package contains **no keys** — you add your own. Never send your `.env` to anyone.

The app still **runs without keys** — the header, lookalike-domain, deceptive-link
and QR checks all work offline. Without keys it simply skips VirusTotal and falls
back to an offline estimate for the AI step (the banner tells you which services are
live).

---

## 🖥️ Run without Docker (local Python)

Requires **Python 3.11+** and the native **zbar** library (for QR decoding).

```bash
# zbar:  Ubuntu/Debian -> sudo apt install libzbar0
#        macOS         -> brew install zbar
#        Windows       -> bundled with the pyzbar wheel; if QR decoding is skipped,
#                         use the Docker route, which always has zbar.

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env             # add your keys
uvicorn app.web.main:app --reload
# open http://localhost:8000
```

---

## 🧪 Command line (same engine, no web)

```bash
python analyze.py tests/samples/phishing_bec_qr.eml       # pretty report
python analyze.py some_email.eml --json                   # JSON only
cat some_email.eml | python analyze.py -                  # from stdin
```

Exit code encodes the verdict (0 = clean, 1 = suspicious, 2 = phishing), so it drops
into scripts.

Inside Docker:
```bash
docker compose run --rm phishlens python analyze.py tests/samples/phishing_bec_qr.eml
```

---

## 📊 Evaluation (precision / recall)

```bash
python eval/evaluate.py
```

Runs every labelled email in `eval/labels.csv` through the real analyzer and prints a
confusion matrix plus precision, recall and F1. Add more `.eml` files to
`tests/samples/` and rows to `eval/labels.csv` to grow the test set (the guide suggests
the Nazario phishing corpus for phishing, and your own newsletters/receipts for clean).

Regenerate the bundled synthetic samples any time with:
```bash
python tests/make_samples.py
```

---

## 🧠 How it works — the six-step pipeline

One "brain" (`app/core/analyzer.py`) runs six steps in order; two "doors" (the web
page and the CLI) call it, so no logic is written twice.

1. **Parse** (`parser.py`) — read the `.eml`: sender, reply-to, body, images.
2. **Headers** (`headers.py`) — SPF, DKIM, DMARC, Reply-To mismatch, display-name
   spoofing, lookalike domain.
3. **Extract** (`extractor.py`) — every link, including deceptive links and links
   hidden in **QR codes**.
4. **VirusTotal** (`virustotal.py` + `cache.py`) — URL reputation, cached in SQLite to
   respect the free-tier rate limit (4 req/min).
5. **AI reasoning** (`llm.py`) — Groq reads the *structured evidence* (not the raw
   email) and judges BEC likelihood, AI-generated-text likelihood, and explains why.
6. **Score** (`scoring.py`) — each bad signal adds points; the total (capped at 100)
   decides the verdict. The AI is one voice among several, never the sole judge.

**Key design choice:** the AI comes *after* the technical checks and reasons over
verifiable facts. That's what makes PhishLens different from a "ChatGPT wrapper".

### Scoring

| Signal | Points | | Total | Verdict |
| --- | --- | --- | --- | --- |
| Malicious URL (VirusTotal) | +40 | | 60–100 | 🔴 Phishing |
| DMARC fail | +20 | | 30–59 | 🟠 Suspicious |
| SPF fail/softfail | +20 | | 0–29 | 🟢 Clean |
| BEC likelihood high (medium +10) | +20 | | | |
| DKIM fail | +15 | | | |
| Reply-To mismatch | +15 | | | |
| Lookalike domain | +15 | | | |
| Deceptive link | +15 | | | |
| Display-name spoofing | +10 | | | |
| QR code with a URL | +10 | | | |
| AI-generated text high | +5 | | | |

---

## 📁 Project structure

```
phishlens/
├── app/
│   ├── core/            # THE BRAIN (pure Python, no web code)
│   │   ├── analyzer.py  # conductor: steps 1-6
│   │   ├── parser.py    ├── headers.py    ├── extractor.py
│   │   ├── virustotal.py├── cache.py      ├── llm.py   └── scoring.py
│   ├── web/             # THE WEBSITE DOOR
│   │   ├── main.py      # FastAPI routes
│   │   ├── templates/index.html
│   │   └── static/style.css, app.js
│   └── config.py        # loads API keys from .env
├── analyze.py           # THE CLI DOOR
├── tests/
│   ├── samples/         # bundled test emails (phishing / suspicious / clean)
│   └── make_samples.py  # regenerates them (incl. a real QR code)
├── eval/
│   ├── evaluate.py      # precision / recall
│   └── labels.csv
├── Dockerfile           # self-contained image (bundles zbar)
├── docker-compose.yml   # one-command run; mounts .env, persists cache
├── .env.example         # copy to .env and add YOUR keys
├── .gitignore / .dockerignore
└── requirements.txt
```

---

## 🔐 Privacy & limits

- Emails are analyzed **in memory** and not stored on disk.
- Only **URLs** go to VirusTotal; only **signals + body text** go to Groq.
- A brand-new phishing URL may be unknown to VirusTotal — that's why the other
  signals matter.
- Forwarding an email can break DKIM even when it's legitimate.
- AI-text detection is the weakest signal (only +5) and never decides the verdict.
