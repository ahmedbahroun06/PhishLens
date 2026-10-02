/* PhishLens front end — real pipeline.
   The six stages animate while the request is in flight; when the backend returns
   the real JSON report we collapse the pipeline and paint the result. */

const STEPS = [
  ["Parse", "reads .eml", "M4 6h16v12H4zM4 7l8 6 8-6"],
  ["Headers", "SPF · DKIM · DMARC", "M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"],
  ["URLs + QR", "extract links", "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2M18 14h2v2M14 18h2v2h4"],
  ["VirusTotal", "reputation", "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"],
  ["AI reasoning", "Groq LLM", "M9 3h6M12 3v3M5 9h14v9H5zM9 13h.01M15 13h.01M9 21h6"],
  ["Verdict", "score 0–100", "M5 13l4 4L19 7"],
];
const COL = { phishing: ["var(--red)", "Phishing"], suspicious: ["var(--amber)", "Suspicious"], clean: ["var(--green)", "Clean"] };
const SUBTITLE = {
  phishing: "Do not reply, click links or scan any QR code. Report it to your IT/security team.",
  suspicious: "Some warning signs. Verify with the sender through another channel before acting.",
  clean: "No significant phishing indicators found.",
};
const LEVEL_PCT = { low: 20, medium: 55, high: 90 };
const LEVEL_COL = { low: "var(--green)", medium: "var(--amber)", high: "var(--red)" };

const $ = (id) => document.getElementById(id);
let current = null, timer = null, scoreIv = null, pipeStop = null, busy = false;

$("stepWrap").innerHTML = STEPS.map((s, i) =>
  `<div class="step" id="s${i}"><div class="dot"><svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24" aria-hidden="true"><path d="${s[2]}"/></svg></div><b>${s[0]}</b><small>${s[1]}</small></div>`
).join("");

// Mode tag: ask the backend which services are live.
let SERVICES = { virustotal: null, groq: null };
fetch("/health").then(r => r.json()).then(h => {
  SERVICES = (h && h.services) || SERVICES;
  const tag = $("modeTag");
  if (SERVICES.virustotal && SERVICES.groq) { tag.textContent = "Live"; tag.className = "tag live"; }
  else {
    const missing = [];
    if (!SERVICES.virustotal) missing.push("VirusTotal");
    if (!SERVICES.groq) missing.push("Groq");
    tag.textContent = "Keys needed: " + missing.join(" + ");
    tag.className = "tag off";
  }
}).catch(() => { $("modeTag").textContent = "Offline"; $("modeTag").className = "tag off"; });

/* ---- input handling ---- */
function tab(n) {
  $("t1").classList.toggle("on", n == 1); $("t2").classList.toggle("on", n == 2);
  $("p1").hidden = n != 1; $("p2").hidden = n != 2; check();
  if (n == 2) $("raw").focus();
}
function check() { $("go").disabled = busy || !($("fileIn").files.length || $("raw").value.trim()); }

$("fileIn").onchange = (e) => {
  const f = e.target.files[0]; if (!f) return;
  $("fname").textContent = "📎 " + f.name; check();
};
$("raw").oninput = check;
// Ctrl/Cmd+Enter analyzes from the textarea.
$("raw").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !$("go").disabled) analyze();
});

const d = $("drop");
["dragover", "dragenter"].forEach(ev => d.addEventListener(ev, e => { e.preventDefault(); d.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => d.addEventListener(ev, e => { e.preventDefault(); d.classList.remove("over"); }));
d.addEventListener("drop", e => {
  const f = e.dataTransfer.files[0];
  if (f) { const dt = new DataTransfer(); dt.items.add(f); $("fileIn").files = dt.files; $("fileIn").onchange({ target: $("fileIn") }); }
});

function setBusy(b) {
  busy = b;
  document.querySelectorAll(".chip").forEach(c => c.disabled = b);
  check();
}

function showError(msg) {
  stopTimers();
  setBusy(false);
  $("pipe").hidden = true; $("report").hidden = true;
  $("hero").hidden = false; $("upload").hidden = false;
  const e = $("err"); e.textContent = msg; e.hidden = false;
}

function stopTimers() {
  clearInterval(timer); clearInterval(scoreIv);
  if (pipeStop) pipeStop();
}

/* ---- live pipeline animation that waits for the real response ---- */
function startPipe() {
  $("err").hidden = true; $("notice").hidden = true;
  $("hero").hidden = true; $("how").hidden = true; $("upload").hidden = true; $("report").hidden = true;
  $("pipe").hidden = false; $("pipeTitle").textContent = "Analyzing email…";
  STEPS.forEach((_, k) => $("s" + k).className = "step"); $("fill").style.width = "0";
  setBusy(true);
  let i = 0; const t0 = Date.now();
  clearInterval(timer);
  timer = setInterval(() => $("pipeTime").textContent = ((Date.now() - t0) / 1000).toFixed(1) + " s", 100);
  let stopped = false; pipeStop = () => { stopped = true; };
  const step = () => {
    if (stopped) return;
    if (i > 0) $("s" + (i - 1)).className = "step done";
    // Hold on the last stage (network-bound) until the response arrives.
    if (i >= STEPS.length) { $("s" + (STEPS.length - 1)).className = "step active"; return; }
    $("s" + i).className = "step active";
    $("fill").style.width = (i / (STEPS.length - 1) * 100) + "%"; i++;
    setTimeout(step, i >= 4 ? 1100 : 500);
  };
  step();
}
function finishPipe(done) {
  clearInterval(timer); if (pipeStop) pipeStop();
  STEPS.forEach((_, k) => $("s" + k).className = "step done");
  $("fill").style.width = "100%"; $("pipeTitle").textContent = "Analysis complete";
  setTimeout(done, 350);
}

/* ---- requests ---- */
async function runAnalyze(fd, failMsg) {
  startPipe();
  try {
    const r = await fetch("/analyze", { method: "POST", body: fd });
    if (!r.ok) {
      let detail = failMsg + " (" + r.status + ").";
      try { const j = await r.json(); if (j.detail) detail = j.detail; } catch (_) {}
      throw new Error(detail);
    }
    const report = await r.json();
    current = report;
    finishPipe(() => render(report));
  } catch (err) {
    showError(err.message || "Network error — is the server running?");
  }
}

function analyze() {
  if (busy) return;
  const fd = new FormData();
  if ($("fileIn").files.length) fd.append("file", $("fileIn").files[0]);
  else if ($("raw").value.trim()) fd.append("raw", $("raw").value);
  else return;
  runAnalyze(fd, "Analysis failed");
}

async function runSample(name) {
  if (busy) return;
  startPipe();
  try {
    const res = await fetch("/samples/" + name);
    if (!res.ok) throw new Error("Sample not found: " + name);
    const blob = await res.blob();
    const fd = new FormData();
    fd.append("file", new File([blob], name, { type: "message/rfc822" }));
    const r = await fetch("/analyze", { method: "POST", body: fd });
    if (!r.ok) throw new Error("Analysis failed (" + r.status + ").");
    const report = await r.json(); current = report;
    finishPipe(() => render(report));
  } catch (err) {
    showError(err.message || "Could not run sample.");
  }
}

/* ---- render the real report ---- */
const ICO = { fail: "✕", warn: "!", pass: "✓", none: "–", unknown: "?", softfail: "!", neutral: "–" };
function stClass(s) { return s === "pass" ? "pass" : s === "fail" ? "fail" : "warn"; }

function render(r) {
  stopTimers();
  setBusy(false);
  $("pipe").hidden = true; $("hero").hidden = true;
  $("report").hidden = false;

  const [c, label] = COL[r.verdict] || COL.clean;
  $("banner").className = "banner " + r.verdict;
  $("vTitle").textContent = label; $("vTitle").style.color = c;
  $("vSub").textContent = SUBTITLE[r.verdict] || "";

  // Score ring (count up, no flicker).
  $("arc").style.stroke = c;
  const target = r.score || 0;
  $("score").textContent = "0";
  $("arc").style.strokeDashoffset = "226";
  if (target > 0) {
    let n = 0; const stepv = Math.max(1, Math.ceil(target / 25));
    scoreIv = setInterval(() => { n += stepv; if (n >= target) { n = target; clearInterval(scoreIv); } $("score").textContent = n; }, 30);
  }
  setTimeout(() => $("arc").style.strokeDashoffset = (226 - 226 * target / 100).toFixed(1), 50);

  renderMeta(r.meta || {});
  renderNotice(r);
  renderSignals(r.signals || []);
  renderLLM(r.llm || {}, r.meta || {});
  renderURLs(r.urls || []);

  // Bring the banner to the top. Scrolling to the document top (rather than
  // scrollIntoView on the report) avoids the small "drop" caused by the report's
  // content still growing — meters, text — while a smooth scroll is in flight.
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderMeta(meta) {
  const items = [];
  const sender = [meta.from_display, meta.from ? "<" + meta.from + ">" : ""].filter(Boolean).join(" ");
  if (sender) items.push(["Sender", sender]);
  if (meta.subject) items.push(["Subject", meta.subject]);
  if (meta.reply_to && meta.reply_to !== meta.from) items.push(["Reply-To", meta.reply_to]);
  if (meta.qr_codes_found) items.push(["QR codes", String(meta.qr_codes_found)]);
  if (meta.urls_found != null) items.push(["Links", String(meta.urls_found)]);
  if (meta.elapsed_seconds != null) items.push(["Analyzed in", meta.elapsed_seconds + " s"]);
  $("metaStrip").innerHTML = items.map(([k, v]) =>
    `<div class="mi"><b>${esc(k)}:</b> <span>${esc(v)}</span></div>`).join("");
  $("metaStrip").hidden = items.length === 0;
}

function renderNotice(r) {
  const svc = (r.meta && r.meta.services) || {};
  const missing = [];
  if (svc.virustotal === false) missing.push("VirusTotal (URL reputation)");
  if (svc.groq === false) missing.push("Groq (AI reasoning)");
  const n = $("notice");
  if (missing.length) {
    n.innerHTML = "⚙️ <b>Limited mode:</b> " + missing.join(" and ") +
      (missing.length > 1 ? " were" : " was") +
      " skipped because the API key is not set. The report uses technical signals only" +
      (svc.groq === false ? " plus an offline AI estimate" : "") +
      ". Add your keys to <code>.env</code> to enable full analysis.";
    n.hidden = false;
  } else {
    n.hidden = true;
  }
}

function renderSignals(signals) {
  // Flagged (point-scoring) signals first, highest weight on top; stable otherwise.
  const ordered = signals.map((s, i) => ({ s, i }))
    .sort((a, b) => (b.s.points || 0) - (a.s.points || 0) || a.i - b.i)
    .map(x => x.s);
  const flagged = signals.filter(s => (s.points || 0) > 0).length;
  $("sigSum").textContent = `${flagged} flagged · ${signals.length} checks`;
  $("sigs").innerHTML = ordered.map(s => {
    const cls = stClass(s.status);
    const icon = ICO[s.status] || "?";
    const pts = s.points ? `<span class="pts on">+${s.points} pts</span>` : `<span class="pts">0 pts</span>`;
    return `<div class="sig"><div class="ico ${cls}">${icon}</div>` +
      `<div><div class="n">${esc(s.name)} <span class="pill ${cls}">${esc(s.status)}</span></div>` +
      `<div class="d">${esc(s.detail || "")}</div></div>${pts}</div>`;
  }).join("");
}

function renderLLM(llm, meta) {
  const bec = llm.bec_likelihood || "low", ai = llm.ai_generated_likelihood || "low";
  $("becL").textContent = cap(bec); $("aiL").textContent = cap(ai);
  $("becB").style.width = "0"; $("aiB").style.width = "0";
  setTimeout(() => {
    $("becB").style.width = (LEVEL_PCT[bec] || 10) + "%"; $("becB").style.background = LEVEL_COL[bec];
    $("aiB").style.width = (LEVEL_PCT[ai] || 10) + "%"; $("aiB").style.background = LEVEL_COL[ai];
  }, 80);
  $("expl").textContent = llm.explanation || "No explanation produced.";
  let src = "AI source: " + (llm.source || "n/a");
  if (meta.notes && meta.notes.length) src += " · notes: " + meta.notes.join("; ");
  $("srcline").textContent = src;
}

function renderURLs(urls) {
  $("urls").innerHTML = urls.length ? urls.map(u => {
    const st = u.malicious > 0 ? "fail" : (u.suspicious > 0 || u.deceptive) ? "warn" : "pass";
    let statusText = u.malicious > 0 ? "Malicious"
      : u.suspicious > 0 ? "Suspicious"
      : u.status === "harmless" ? "Harmless"
      : cap(u.status || "unchecked");
    const decep = u.deceptive ? `<span class="tagx">deceptive</span>` : "";
    const det = (u.malicious || 0) + (u.suspicious || 0) > 0 || u.status === "harmless"
      ? `${u.malicious || 0}/70` : "—";
    return `<tr><td class="u">${esc(u.url)}</td>` +
      `<td><span class="src">${esc(u.source)}</span>${decep}</td>` +
      `<td style="font-family:var(--mono)">${det}</td>` +
      `<td><span class="pill ${st}">${statusText}</span></td></tr>`;
  }).join("") : `<tr><td colspan="4" style="color:var(--muted)">No URLs found in this email.</td></tr>`;
}

/* ---- controls ---- */
function reset() {
  stopTimers();
  setBusy(false);
  $("pipe").hidden = true; $("report").hidden = true; $("err").hidden = true; $("how").hidden = true;
  $("hero").hidden = false; $("upload").hidden = false;
  $("fileIn").value = ""; $("raw").value = ""; $("fname").textContent = "";
  check(); window.scrollTo({ top: 0, behavior: "smooth" });
}
function toggleHow() { $("how").hidden = !$("how").hidden; }

function downloadJSON() {
  if (!current) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2)], { type: "application/json" }));
  a.download = "phishlens-report.json"; a.click();
  URL.revokeObjectURL(a.href);
}
function copyJSON() {
  if (!current) return;
  const text = JSON.stringify(current, null, 2);
  const done = () => { const b = $("copyBtn"); const t = b.textContent; b.textContent = "Copied ✓"; setTimeout(() => b.textContent = t, 1400); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
  ta.select(); try { document.execCommand("copy"); done(); } catch (_) {} document.body.removeChild(ta);
}

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }
function cap(s) { s = String(s || ""); return s.charAt(0).toUpperCase() + s.slice(1); }
