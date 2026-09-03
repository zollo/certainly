"use strict";

const state = { maxTargets: 10, polling: null };

const el = (id) => document.getElementById(id);

async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();
    state.maxTargets = cfg.max_targets_per_request;
    el("limit-hint").textContent = `(one per line, up to ${state.maxTargets})`;
  } catch (_e) {
    el("limit-hint").textContent = "(one per line)";
  }
}

function parseTargets() {
  return el("targets").value
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

function showError(msg) {
  const box = el("form-error");
  box.textContent = msg;
  box.hidden = !msg;
}

function setBusy(busy) {
  el("scan-btn").disabled = busy;
  el("scan-btn").textContent = busy ? "Analyzing…" : "Analyze";
  el("status-panel").hidden = !busy;
}

async function startScan() {
  showError("");
  const targets = parseTargets();
  if (targets.length === 0) {
    showError("Enter at least one hostname or URL.");
    return;
  }
  if (targets.length > state.maxTargets) {
    showError(`Too many targets: ${targets.length}. Maximum is ${state.maxTargets}.`);
    return;
  }

  el("results").innerHTML = "";
  setBusy(true);
  el("status-text").textContent = "Submitting…";

  let submit;
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets, bypass_cache: el("bypass-cache").checked }),
    });
    submit = await res.json();
    if (!res.ok) {
      throw new Error(submit.detail || "Scan request failed.");
    }
  } catch (e) {
    setBusy(false);
    showError(e.message || "Could not submit scan.");
    return;
  }

  pollJob(submit.job_id);
}

function pollJob(jobId) {
  const statusUrl = `/api/jobs/${jobId}/status`;
  const resultUrl = `/api/jobs/${jobId}`;
  let attempts = 0;

  const tick = async () => {
    attempts += 1;
    try {
      const res = await fetch(statusUrl);
      const status = await res.json();
      el("status-text").textContent =
        `Status: ${status.status}` +
        (status.total ? ` (${status.completed}/${status.total} hosts)` : "");

      if (status.status === "finished" || status.status === "failed") {
        clearInterval(state.polling);
        const jobRes = await fetch(resultUrl);
        const job = await jobRes.json();
        setBusy(false);
        renderResults(job);
        return;
      }
    } catch (_e) {
      // transient error; keep polling
    }
    if (attempts > 300) {
      clearInterval(state.polling);
      setBusy(false);
      showError("Timed out waiting for results.");
    }
  };

  clearInterval(state.polling);
  state.polling = setInterval(tick, 1000);
  tick();
}

function renderResults(job) {
  const container = el("results");
  container.innerHTML = "";

  if (job.status === "failed") {
    showError(job.error || "The scan job failed.");
    return;
  }
  (job.results || []).forEach((host) => container.appendChild(renderHost(host)));
}

function gradeClass(grade) {
  return "grade-" + grade;
}

function pill(ok, textOk, textBad, warn) {
  const cls = warn ? "warn" : ok ? "ok" : "bad";
  const span = document.createElement("span");
  span.className = "pill " + cls;
  span.textContent = ok ? textOk : textBad;
  return span;
}

function renderHost(host) {
  const card = document.createElement("div");
  card.className = "result-card";

  // ---- Header ----
  const head = document.createElement("div");
  head.className = "result-head";
  head.onclick = () => card.classList.toggle("open");

  const badge = document.createElement("div");
  badge.className = "grade-badge " + gradeClass(host.grade);
  badge.textContent = host.grade;

  const title = document.createElement("div");
  title.className = "result-title";
  const h3 = document.createElement("h3");
  h3.textContent = host.hostname + (host.port !== 443 ? ":" + host.port : "");
  const meta = document.createElement("div");
  meta.className = "result-meta";
  let metaText = host.ip_address ? host.ip_address : "";
  if (host.reachable) {
    metaText += metaText ? " · " : "";
    metaText += `scanned in ${host.duration_seconds}s`;
  }
  meta.textContent = metaText;
  if (host.from_cache) {
    const tag = document.createElement("span");
    tag.className = "cache-tag";
    tag.textContent = "cached";
    meta.appendChild(tag);
  }
  title.append(h3, meta);

  const score = document.createElement("div");
  score.className = "score-big";
  score.innerHTML = `<span class="num">${host.score}</span><span class="den">/100</span>`;

  const caret = document.createElement("span");
  caret.className = "caret";
  caret.textContent = "▸";

  head.append(badge, title, score, caret);
  card.appendChild(head);

  if (!host.reachable) {
    const err = document.createElement("div");
    err.className = "error-banner";
    err.textContent = "⚠ " + (host.error || "Host unreachable.");
    card.appendChild(err);
    return card;
  }

  // ---- Body ----
  const body = document.createElement("div");
  body.className = "result-body";

  body.appendChild(sectionTitle("Score breakdown"));
  body.appendChild(renderBreakdown(host.breakdown));

  if (host.findings && host.findings.length) {
    body.appendChild(sectionTitle("Findings"));
    body.appendChild(renderFindings(host.findings));
  }

  if (host.certificate) {
    body.appendChild(sectionTitle("Certificate"));
    body.appendChild(renderCertificate(host.certificate));
  }

  body.appendChild(sectionTitle("Protocols"));
  body.appendChild(renderProtocols(host.protocols));

  if (host.ciphers && host.ciphers.length) {
    body.appendChild(sectionTitle(`Cipher suites (${host.ciphers.length})`));
    body.appendChild(renderCiphers(host.ciphers));
  }

  card.appendChild(body);
  return card;
}

function sectionTitle(text) {
  const h = document.createElement("div");
  h.className = "section-title";
  h.textContent = text;
  return h;
}

function renderBreakdown(b) {
  const wrap = document.createElement("div");
  wrap.className = "bars";
  if (!b) return wrap;
  const rows = [
    ["Protocol support", b.protocol_support],
    ["Key exchange", b.key_exchange],
    ["Cipher strength", b.cipher_strength],
    ["Certificate", b.certificate],
  ];
  rows.forEach(([label, val]) => {
    const row = document.createElement("div");
    row.className = "bar-row";
    const name = document.createElement("div");
    name.textContent = label;
    const track = document.createElement("div");
    track.className = "bar-track";
    const fill = document.createElement("div");
    fill.className = "bar-fill";
    fill.style.width = Math.max(0, Math.min(100, val)) + "%";
    track.appendChild(fill);
    const num = document.createElement("div");
    num.className = "bar-val";
    num.textContent = val;
    row.append(name, track, num);
    wrap.appendChild(row);
  });
  return wrap;
}

function renderFindings(findings) {
  const wrap = document.createElement("div");
  wrap.className = "findings";
  findings.forEach((f) => {
    const div = document.createElement("div");
    div.className = "finding " + f.severity;
    const sev = document.createElement("span");
    sev.className = "sev-dot " + f.severity;
    sev.textContent = f.severity;
    const text = document.createElement("div");
    const t = document.createElement("div");
    t.className = "f-title";
    t.textContent = f.title;
    const d = document.createElement("div");
    d.className = "f-detail";
    d.textContent = f.detail;
    text.append(t, d);
    div.append(sev, text);
    wrap.appendChild(div);
  });
  return wrap;
}

function renderCertificate(c) {
  const dl = document.createElement("dl");
  dl.className = "kv";
  const add = (k, v) => {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    if (v instanceof Node) dd.appendChild(v);
    else dd.textContent = v;
    dl.append(dt, dd);
  };
  add("Subject", c.subject);
  if (c.subject_alt_names && c.subject_alt_names.length) {
    add("Alt names", c.subject_alt_names.join(", "));
  }
  add("Issuer", c.issuer);
  add("Valid", pill(!c.is_expired && !c.is_not_yet_valid, "Yes", "No"));
  add("Hostname match", pill(c.hostname_matches, "Yes", "No"));
  const expText = `${new Date(c.not_after).toISOString().slice(0, 10)} (${c.days_until_expiry} days)`;
  add("Expires", c.is_expired ? pill(false, "", "Expired") : document.createTextNode(expText));
  add("Key", `${c.key_type}${c.key_bits ? " (" + c.key_bits + " bits)" : ""}`);
  add("Signature", c.weak_signature
    ? pill(false, "", c.signature_algorithm + " (weak)")
    : document.createTextNode(c.signature_algorithm));
  add("Self-signed", pill(!c.is_self_signed, "No", "Yes"));
  add("SHA-256", c.sha256_fingerprint);
  return dl;
}

function renderProtocols(protocols) {
  const wrap = document.createElement("div");
  wrap.className = "proto-list";
  (protocols || []).forEach((p) => {
    const div = document.createElement("div");
    let cls = "proto no";
    if (p.supported) cls = "proto " + (p.secure ? "yes-secure" : "yes-insecure");
    div.className = cls;
    div.textContent = `${p.name} ${p.supported ? "✓" : "✕"}`;
    wrap.appendChild(div);
  });
  return wrap;
}

function renderCiphers(ciphers) {
  const table = document.createElement("table");
  table.className = "cipher-table";
  table.innerHTML =
    "<thead><tr><th>Cipher</th><th>Protocol</th><th>Bits</th><th>FS</th><th>Strength</th></tr></thead>";
  const tbody = document.createElement("tbody");
  ciphers.forEach((c) => {
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td class="cipher-name">${c.name}</td>` +
      `<td>${c.protocol}</td>` +
      `<td>${c.bits ?? "—"}</td>` +
      `<td>${c.forward_secrecy ? "✓" : "—"}</td>` +
      `<td>${c.strong ? "strong" : "⚠ weak"}</td>`;
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

el("scan-btn").addEventListener("click", startScan);
el("targets").addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") startScan();
});
loadConfig();
