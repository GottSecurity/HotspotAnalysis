"use strict";

const ANALYSIS = "/GottSecurity/HotspotAnalysis/Index.html";
const ENTRY = "/GottSecurity/HotspotAnalysis/StatusEntry.html";
const TRACKS = [
  ["needs-review", "Needs Review"],
  ["true-positive", "True Positive"],
  ["confirmed", "Confirmed"],
  ["in-remediation", "In Remediation"],
  ["mitigated", "Mitigated"],
  ["remediated", "Remediated"],
  ["resolved", "Resolved"],
  ["ignored", "Ignored"],
];
const STORED_TRACKS = ["confirmed", "in-remediation", "mitigated", "remediated"];
const SEVERITIES = [
  ["Critical", "C"],
  ["High", "H"],
  ["Medium", "M"],
  ["Low", "L"],
];
const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

const sheet = {
  repo: "",
  repoRoot: "",
  hotspots: [],
  guidance: {},
  triage: {},
  q: "",
  status: "all",
  sort: "file",
  dir: 1,
  error: "",
  saveNote: "",
  github: "",
  printPreview: false,
};

document.addEventListener("change", onChange);
document.addEventListener("input", onInput);
document.addEventListener("click", onClick);

load();

async function load() {
  try {
    const [session, library] = await Promise.all([
      fetch("/api/session").then(readJson),
      fetch("/api/library").then(readJson),
    ]);
    sheet.repo = typeof session.repo === "string" ? session.repo : "";
    sheet.triage = session.triage && typeof session.triage === "object" ? session.triage : {};
    sheet.github = githubFor(session.github, sheet.repo);
    for (const step of library.steps || []) {
      sheet.guidance[step.id] = Array.isArray(step.guidance) ? step.guidance.join(" ") : "";
    }
    if (sheet.repo) {
      const scanResponse = await fetch("/api/scans?repo=" + encodeURIComponent(sheet.repo));
      if (scanResponse.ok) {
        const scan = await scanResponse.json();
        sheet.repoRoot = scan.repoRoot || "";
        sheet.hotspots = Array.isArray(scan.hotspots) ? scan.hotspots : [];
        sheet.github = githubFor(session.github, sheet.repoRoot) || sheet.github;
      } else {
        sheet.error = "No saved scan for this repository. Scan it from the analysis page, then come back.";
      }
    } else {
      sheet.error = "Choose a repository on the analysis page first.";
    }
  } catch (err) {
    sheet.error = "The status sheet could not be loaded.";
  }
  render();
}

function githubFor(map, repo) {
  if (!map || typeof map !== "object" || !repo) return "";
  const want = String(repo).trim().replace(/\//g, "\\").replace(/[\\/]+$/, "").toLowerCase();
  const key = Object.keys(map).find((item) => item.trim().replace(/\//g, "\\").replace(/[\\/]+$/, "").toLowerCase() === want);
  return key ? String(map[key] || "") : "";
}

function parseGithub(input) {
  let url;
  try {
    url = new URL(String(input || "").trim());
  } catch (err) {
    return null;
  }
  if (url.protocol !== "https:" || url.hostname.toLowerCase() !== "github.com") return null;
  const parts = url.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, "");
  if (!owner || !repo) return null;
  const branch = parts[2] === "tree" && parts.length > 3 ? parts.slice(3).join("/") : "main";
  return { owner, repo, branch };
}

function githubFileUrl(file, line) {
  const parsed = parseGithub(sheet.github);
  const number = Number(line);
  if (!parsed || !file || !Number.isInteger(number) || number < 1) return "";
  const filePath = String(file).replace(/\\/g, "/").split("/").filter(Boolean).map(encodeURIComponent).join("/");
  const branch = parsed.branch.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/blob/${branch}/${filePath}#L${number}`;
}

function fileCell(item) {
  const href = githubFileUrl(item.file, item.line);
  if (href) {
    return `<a class="loc" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="Open this line on GitHub">${esc(item.file)}:${item.line}</a>`;
  }
  return `<button type="button" class="loc" data-action="open-file" data-file="${esc(item.file)}" data-line="${item.line}" title="Open this line in Notepad++">${esc(item.file)}:${item.line}</button>`;
}

async function readJson(response) {
  if (!response.ok) throw new Error("request failed");
  return response.json();
}

function markOf(id) {
  const bucket = sheet.repoRoot && sheet.triage[sheet.repoRoot];
  return bucket && bucket[id];
}

function decisionOf(id) {
  const raw = markOf(id);
  const decisions = ["resolved", "ignored", "true-positive"];
  if (decisions.includes(raw)) return { status: raw, track: "" };
  if (raw && typeof raw === "object") {
    return {
      status: decisions.includes(raw.status) ? raw.status : "",
      track: STORED_TRACKS.includes(raw.track) ? raw.track : "",
    };
  }
  return { status: "", track: "" };
}

function workflowOf(id) {
  const record = decisionOf(id);
  if (record.status === "ignored") return "ignored";
  if (record.status === "resolved") return record.track === "remediated" ? "remediated" : "resolved";
  if (record.track) return record.track;
  if (record.status === "true-positive") return "true-positive";
  return "needs-review";
}

function fieldsForWorkflow(value) {
  if (value === "true-positive") return { status: "true-positive", track: "" };
  if (value === "confirmed") return { status: "true-positive", track: "confirmed" };
  if (value === "in-remediation") return { status: "true-positive", track: "in-remediation" };
  if (value === "mitigated") return { status: "true-positive", track: "mitigated" };
  if (value === "remediated") return { status: "resolved", track: "remediated" };
  if (value === "resolved") return { status: "resolved", track: "" };
  if (value === "ignored") return { status: "ignored", track: "" };
  return { status: "", track: "" };
}

function trackOf(id) {
  return workflowOf(id);
}

function severityOf(item) {
  const raw = markOf(item.id);
  if (raw && typeof raw === "object" && SEVERITY_RANK[raw.severity] != null) return raw.severity;
  return SEVERITY_RANK[item.priority] != null ? item.priority : "Medium";
}

function rows() {
  const query = sheet.q.trim().toLowerCase();
  const list = sheet.hotspots.filter((item) => {
    if (sheet.status !== "all" && workflowOf(item.id) !== sheet.status) return false;
    if (!query) return true;
    const blob = [item.title, item.file, String(item.line), item.why, remediationOf(item)]
      .join("\n")
      .toLowerCase();
    return blob.includes(query);
  });
  const dir = sheet.dir;
  list.sort((a, b) => {
    const left = sortValue(a);
    const right = sortValue(b);
    if (left < right) return -1 * dir;
    if (left > right) return 1 * dir;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.line - b.line;
  });
  return list;
}

function sortValue(item) {
  if (sheet.sort === "title") return item.title.toLowerCase();
  if (sheet.sort === "line") return item.line;
  if (sheet.sort === "synopsis") return (item.why || "").toLowerCase();
  if (sheet.sort === "general") return remediationOf(item).toLowerCase();
  if (sheet.sort === "status") return TRACKS.findIndex(([value]) => value === workflowOf(item.id));
  if (sheet.sort === "severity") return SEVERITY_RANK[severityOf(item)] ?? 9;
  return item.file.toLowerCase();
}

function generalOf(item) {
  return sheet.guidance[item.stepId] || "";
}

function remediationOf(item) {
  const general = String(generalOf(item) || "").trim();
  const specific = String(item.secureAlternative || "").trim();
  if (!specific || specific === general) return general;
  if (!general) return specific;
  return `${general}\n\n${specific}`;
}

function remediationHtml(text) {
  return String(text || "")
    .split(/\n\n/)
    .filter((part) => part.trim())
    .map((part) => `<p>${esc(part)}</p>`)
    .join("");
}

function render() {
  document.title = "Scan status";
  const shown = rows();
  document.getElementById("sheet").innerHTML = `
    <header class="sheet-head">
      <div>
        <p class="byline">Gott Security</p>
        <h1>Status</h1>
        <p class="lede">Findings from the saved scan. A hotspot is not necessarily a vulnerability.</p>
        <p class="meta">${esc(sheet.repoRoot || sheet.repo || "No repository selected")}</p>
        <p class="meta">${shown.length} of ${sheet.hotspots.length} findings. ${esc(sheet.saveNote)}</p>
        ${sheet.error ? `<p class="error">${esc(sheet.error)}</p>` : ""}
      </div>
      <div class="sheet-links">
        <a class="ghost" href="${ENTRY}">User Status</a>
        <a class="ghost" href="${ANALYSIS}">Back to analysis</a>
      </div>
    </header>
    <div class="sheet-tools">
      <label class="field">Find
        <input id="sheet-q" type="search" placeholder="Name, file, or synopsis" value="${esc(sheet.q)}">
      </label>
      <label class="field">Status
        <select id="sheet-status">
          <option value="all"${sheet.status === "all" ? " selected" : ""}>All</option>
          ${TRACKS.map(([value, label]) => `<option value="${value}"${sheet.status === value ? " selected" : ""}>${label}</option>`).join("")}
        </select>
      </label>
      <button type="button" class="ghost" data-action="print-view">${sheet.printPreview ? "Back to table" : "Print view"}</button>
      <button type="button" class="ghost" data-action="print-now">Print</button>
    </div>
    <div class="sheet-scroll">
      <table class="sheet-table">
        <thead>
          <tr>
            ${header("title", "Finding Name")}
            ${header("file", "File")}
            ${header("line", "Line")}
            ${header("synopsis", "Synopsis")}
            ${header("general", "Recommended remediation")}
            ${header("severity", "Severity")}
            ${header("status", "Status")}
          </tr>
        </thead>
        <tbody>
          ${shown.map(rowHtml).join("")}
        </tbody>
      </table>
    </div>
    <div class="print-deck">
      ${printDeck(shown)}
    </div>
  `;
  document.body.classList.toggle("print-preview", sheet.printPreview);
}

function header(key, label) {
  const mark = sheet.sort === key ? (sheet.dir > 0 ? " ↑" : " ↓") : "";
  return `<th data-sort="${key}" scope="col">${label}${mark}</th>`;
}

function trackLabel(value) {
  return (TRACKS.find(([id]) => id === value) || ["", value])[1];
}

function printSection(title, text) {
  const value = String(text || "").trim();
  if (!value) return "";
  return `<h3>${esc(title)}</h3><p>${esc(value)}</p>`;
}

function printDeck(items) {
  if (!items.length) return `<p class="print-empty">Nothing to print.</p>`;
  return items
    .map((item) => {
      const where = [item.file, item.line].filter((part) => String(part || "").trim()).join(":");
      return `
        <article class="print-card">
          <p class="print-kicker">Gott Security · Scan status</p>
          <h2>${esc(item.title || "Untitled finding")}</h2>
          ${where ? `<p class="print-where">${esc(where)}</p>` : ""}
          <p class="print-meta">${esc(severityOf(item))} · ${esc(trackLabel(trackOf(item.id)))}</p>
          ${printSection("Synopsis", item.why)}
          ${printSection("Recommended remediation", remediationOf(item))}
        </article>
      `;
    })
    .join("");
}

function rowHtml(item) {
  const track = trackOf(item.id);
  const severity = severityOf(item);
  return `
    <tr>
      <td>${esc(item.title)}</td>
      <td>${fileCell(item)}</td>
      <td class="col-line">${item.line}</td>
      <td>${esc(item.why || "")}</td>
      <td class="remediation">${remediationHtml(remediationOf(item))}</td>
      <td class="col-sev">
        <select class="sev-${severity.toLowerCase()}" data-action="severity" data-id="${esc(item.id)}" data-original="${esc(item.priority || "")}" aria-label="Severity for ${esc(item.title)}" title="${esc(severity)}">
          ${SEVERITIES.map(([value, label]) => `<option value="${value}"${severity === value ? " selected" : ""}>${label}</option>`).join("")}
        </select>
      </td>
      <td class="col-status">
        <select class="track-${track}" data-action="workflow" data-id="${esc(item.id)}" aria-label="Status for ${esc(item.title)}" title="Shared with Analysis. True Positive accepts the finding. Later stages keep that acceptance. Remediated closes it as resolved.">
          ${TRACKS.map(([value, label]) => `<option value="${value}"${track === value ? " selected" : ""}>${label}</option>`).join("")}
        </select>
      </td>
    </tr>
  `;
}

function onInput(event) {
  if (event.target.id !== "sheet-q") return;
  sheet.q = event.target.value;
  paintBody();
}

function onChange(event) {
  if (event.target.id === "sheet-status") {
    sheet.status = event.target.value;
    paintBody();
    return;
  }
  if (event.target.dataset.action === "workflow") {
    saveMark(event.target.dataset.id, { workflow: event.target.value });
    return;
  }
  if (event.target.dataset.action === "severity") {
    const chosen = event.target.value;
    const stored = chosen === event.target.dataset.original ? "" : chosen;
    saveMark(event.target.dataset.id, { severity: stored });
  }
}

function onClick(event) {
  if (event.target.closest("[data-action='print-now']")) {
    window.print();
    return;
  }
  if (event.target.closest("[data-action='print-view']")) {
    sheet.printPreview = !sheet.printPreview;
    render();
    return;
  }
  const headerCell = event.target.closest("th[data-sort]");
  if (headerCell) {
    const key = headerCell.dataset.sort;
    if (sheet.sort === key) sheet.dir = -sheet.dir;
    else {
      sheet.sort = key;
      sheet.dir = 1;
    }
    render();
    return;
  }
  const open = event.target.closest("[data-action='open-file']");
  if (!open) return;
  openFile(open.dataset.file, Number(open.dataset.line));
}

function paintBody() {
  const body = document.querySelector(".sheet-table tbody");
  const meta = document.querySelector(".sheet-head .meta + .meta");
  const shown = rows();
  if (body) body.innerHTML = shown.map(rowHtml).join("");
  const deck = document.querySelector(".print-deck");
  if (deck) deck.innerHTML = printDeck(shown);
  if (meta) meta.textContent = `${shown.length} of ${sheet.hotspots.length} findings. ${sheet.saveNote}`;
}

async function saveMark(hotId, patch) {
  sheet.saveNote = "Saving…";
  paintNote();
  try {
    const session = await fetch("/api/session").then(readJson);
    if (!session.triage || typeof session.triage !== "object" || Array.isArray(session.triage)) session.triage = {};
    if (!session.triage[sheet.repoRoot]) session.triage[sheet.repoRoot] = {};
    const next = applyMark(session.triage[sheet.repoRoot][hotId], patch);
    if (next == null) delete session.triage[sheet.repoRoot][hotId];
    else session.triage[sheet.repoRoot][hotId] = next;
    if (!Object.keys(session.triage[sheet.repoRoot]).length) delete session.triage[sheet.repoRoot];
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(session),
    });
    if (!response.ok) throw new Error("save failed");
    const saved = await response.json();
    sheet.triage = saved.triage && typeof saved.triage === "object" ? saved.triage : {};
    sheet.saveNote = "Saved on this server.";
  } catch (err) {
    sheet.saveNote = "This change could not be saved.";
  }
  paintNote();
  paintSelects(hotId);
}

function paintSelects(hotId) {
  const item = sheet.hotspots.find((row) => row.id === hotId);
  const track = document.querySelector(`select[data-action="workflow"][data-id="${cssEscape(hotId)}"]`);
  if (track) {
    const current = workflowOf(hotId);
    track.className = `track-${current}`;
    track.value = current;
  }
  const severity = document.querySelector(`select[data-action="severity"][data-id="${cssEscape(hotId)}"]`);
  if (severity && item) {
    const current = severityOf(item);
    severity.className = `sev-${current.toLowerCase()}`;
    severity.title = current;
    severity.value = current;
  }
}

function paintNote() {
  const meta = document.querySelector(".sheet-head .meta + .meta");
  if (!meta) return;
  const shown = rows().length;
  meta.textContent = `${shown} of ${sheet.hotspots.length} findings. ${sheet.saveNote}`;
}

function applyMark(raw, patch) {
  const statuses = ["resolved", "ignored", "true-positive"];
  const severities = ["Critical", "High", "Medium", "Low"];
  let status = "";
  let needsReview = false;
  let severity = "";
  let track = "";
  if (statuses.includes(raw)) status = raw;
  else if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    if (statuses.includes(raw.status)) status = raw.status;
    needsReview = raw.needsReview === true;
    if (severities.includes(raw.severity)) severity = raw.severity;
    if (STORED_TRACKS.includes(raw.track)) track = raw.track;
  }
  if (Object.prototype.hasOwnProperty.call(patch, "workflow")) {
    const next = fieldsForWorkflow(patch.workflow);
    status = next.status;
    track = next.track;
  } else if (Object.prototype.hasOwnProperty.call(patch, "track")) track = STORED_TRACKS.includes(patch.track) ? patch.track : "";
  if (Object.prototype.hasOwnProperty.call(patch, "severity")) severity = severities.includes(patch.severity) ? patch.severity : "";
  if (!status && !needsReview && !severity && !track) return null;
  if (status && !needsReview && !severity && !track) return status;
  const mark = {};
  if (status) mark.status = status;
  if (needsReview) mark.needsReview = true;
  if (severity) mark.severity = severity;
  if (track) mark.track = track;
  return mark;
}

async function openFile(file, line) {
  const href = githubFileUrl(file, line);
  if (href) {
    window.open(href, "_blank", "noopener");
    return;
  }
  sheet.error = "";
  try {
    const response = await fetch("/api/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo: sheet.repoRoot, file, line }),
    });
    const body = await response.json();
    if (!response.ok) sheet.error = body.error || "Notepad++ could not open that file.";
  } catch (err) {
    sheet.error = "Notepad++ could not open that file.";
  }
  const error = document.querySelector(".sheet-head .error");
  if (sheet.error) {
    if (error) error.textContent = sheet.error;
    else {
      const meta = document.querySelector(".sheet-head .meta");
      if (meta) meta.insertAdjacentHTML("afterend", `<p class="error">${esc(sheet.error)}</p>`);
    }
  } else if (error) error.remove();
}

function cssEscape(value) {
  if (window.CSS && CSS.escape) return CSS.escape(value);
  return String(value).replace(/["\\]/g, "\\$&");
}

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
