"use strict";

const ANALYSIS = "/GottSecurity/HotspotAnalysis/Index.html";
const TRACKS = [
  ["needs-review", "Needs Review"],
  ["confirmed", "Confirmed"],
  ["in-remediation", "In Remediation"],
  ["mitigated", "Mitigated"],
  ["remediated", "Remediated"],
];
const STORED_TRACKS = ["confirmed", "in-remediation", "mitigated", "remediated"];

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
    for (const step of library.steps || []) {
      sheet.guidance[step.id] = Array.isArray(step.guidance) ? step.guidance.join(" ") : "";
    }
    if (sheet.repo) {
      const scanResponse = await fetch("/api/scans?repo=" + encodeURIComponent(sheet.repo));
      if (scanResponse.ok) {
        const scan = await scanResponse.json();
        sheet.repoRoot = scan.repoRoot || "";
        sheet.hotspots = Array.isArray(scan.hotspots) ? scan.hotspots : [];
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

async function readJson(response) {
  if (!response.ok) throw new Error("request failed");
  return response.json();
}

function trackOf(id) {
  const bucket = sheet.repoRoot && sheet.triage[sheet.repoRoot];
  const raw = bucket && bucket[id];
  if (raw && typeof raw === "object" && STORED_TRACKS.includes(raw.track)) return raw.track;
  return "needs-review";
}

function rows() {
  const query = sheet.q.trim().toLowerCase();
  const list = sheet.hotspots.filter((item) => {
    if (sheet.status !== "all" && trackOf(item.id) !== sheet.status) return false;
    if (!query) return true;
    const blob = [item.title, item.file, String(item.line), item.why, generalOf(item), item.secureAlternative]
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
  if (sheet.sort === "general") return generalOf(item).toLowerCase();
  if (sheet.sort === "specific") return (item.secureAlternative || "").toLowerCase();
  if (sheet.sort === "status") return trackOf(item.id);
  return item.file.toLowerCase();
}

function generalOf(item) {
  return sheet.guidance[item.stepId] || "";
}

function render() {
  document.title = "Security Hotspot Analysis — Status";
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
      <a class="ghost" href="${ANALYSIS}">Back to analysis</a>
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
    </div>
    <div class="sheet-scroll">
      <table class="sheet-table">
        <thead>
          <tr>
            ${header("title", "Finding Name")}
            ${header("file", "File")}
            ${header("line", "Line")}
            ${header("synopsis", "Synopsis")}
            ${header("general", "Recommended remediation (general)")}
            ${header("specific", "Recommended remediation (specific)")}
            ${header("status", "Status")}
          </tr>
        </thead>
        <tbody>
          ${shown.map(rowHtml).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function header(key, label) {
  const mark = sheet.sort === key ? (sheet.dir > 0 ? " ↑" : " ↓") : "";
  return `<th data-sort="${key}" scope="col">${label}${mark}</th>`;
}

function rowHtml(item) {
  const track = trackOf(item.id);
  const general = generalOf(item);
  const specific = item.secureAlternative || "";
  return `
    <tr>
      <td>${esc(item.title)}</td>
      <td><button type="button" class="loc" data-action="open-file" data-file="${esc(item.file)}" data-line="${item.line}">${esc(item.file)}</button></td>
      <td class="col-line">${item.line}</td>
      <td>${esc(item.why || "")}</td>
      <td>${esc(general)}</td>
      <td>${esc(specific)}</td>
      <td class="col-status">
        <select class="track-${track}" data-action="track" data-id="${esc(item.id)}" aria-label="Status for ${esc(item.title)}">
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
  if (event.target.dataset.action === "track") {
    saveTrack(event.target.dataset.id, event.target.value);
  }
}

function onClick(event) {
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
  if (meta) meta.textContent = `${shown.length} of ${sheet.hotspots.length} findings. ${sheet.saveNote}`;
}

async function saveTrack(hotId, track) {
  sheet.saveNote = "Saving…";
  paintNote();
  try {
    const session = await fetch("/api/session").then(readJson);
    if (!session.triage || typeof session.triage !== "object" || Array.isArray(session.triage)) session.triage = {};
    if (!session.triage[sheet.repoRoot]) session.triage[sheet.repoRoot] = {};
    const next = applyTrack(session.triage[sheet.repoRoot][hotId], track);
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
    sheet.saveNote = "This status could not be saved.";
  }
  paintNote();
  const select = document.querySelector(`select[data-id="${cssEscape(hotId)}"]`);
  if (select) {
    const current = trackOf(hotId);
    select.className = `track-${current}`;
    select.value = current;
  }
}

function paintNote() {
  const meta = document.querySelector(".sheet-head .meta + .meta");
  if (!meta) return;
  const shown = rows().length;
  meta.textContent = `${shown} of ${sheet.hotspots.length} findings. ${sheet.saveNote}`;
}

function applyTrack(raw, track) {
  const statuses = ["resolved", "ignored", "true-positive"];
  const severities = ["Critical", "High", "Medium", "Low"];
  const nextTrack = STORED_TRACKS.includes(track) ? track : "";
  let status = "";
  let needsReview = false;
  let severity = "";
  if (statuses.includes(raw)) status = raw;
  else if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    if (statuses.includes(raw.status)) status = raw.status;
    needsReview = raw.needsReview === true;
    if (severities.includes(raw.severity)) severity = raw.severity;
  }
  if (!status && !needsReview && !severity && !nextTrack) return null;
  if (status && !needsReview && !severity && !nextTrack) return status;
  const mark = {};
  if (status) mark.status = status;
  if (needsReview) mark.needsReview = true;
  if (severity) mark.severity = severity;
  if (nextTrack) mark.track = nextTrack;
  return mark;
}

async function openFile(file, line) {
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
