"use strict";

const ANALYSIS = "/GottSecurity/HotspotAnalysis/Index.html";
const STATUS = "/GottSecurity/HotspotAnalysis/Status.html";
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
const FIELDS = ["name", "file", "line", "synopsis", "general"];
const SEVERITIES = [
  ["Critical", "C"],
  ["High", "H"],
  ["Medium", "M"],
  ["Low", "L"],
];
const SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };

const entry = {
  repo: "",
  rows: [],
  triage: {},
  saveNote: "",
  sort: "",
  dir: 1,
  printPreview: false,
};

let saveTimer = 0;

document.addEventListener("input", onInput);
document.addEventListener("change", onChange);
document.addEventListener("click", onClick);

load();

async function load() {
  try {
    const session = await fetch("/api/session").then(readJson);
    entry.repo = typeof session.repo === "string" ? session.repo : "";
    entry.triage = session.triage && typeof session.triage === "object" ? session.triage : {};
    const saved = await fetch("/api/entries?repo=" + encodeURIComponent(entry.repo)).then(readJson);
    entry.rows = Array.isArray(saved.rows) ? saved.rows.map(copyRow) : [];
    applySharedMarks();
  } catch (err) {
    entry.saveNote = "User Status could not be loaded.";
  }
  if (!entry.rows.length) entry.rows.push(blankRow());
  render();
}

async function readJson(response) {
  if (!response.ok) throw new Error("request failed");
  return response.json();
}

function joinRemediation(general, specific) {
  const left = String(general || "").trim();
  const right = String(specific || "").trim();
  if (!right || right === left) return left;
  if (!left) return right;
  return `${left}\n\n${right}`;
}

function blankRow() {
  return {
    id: crypto.randomUUID(),
    name: "",
    file: "",
    line: "",
    synopsis: "",
    general: "",
    specific: "",
    status: "needs-review",
    severity: "Medium",
    source: "",
  };
}

function copyRow(raw) {
  const row = blankRow();
  row.id = typeof raw.id === "string" && raw.id ? raw.id : row.id;
  for (const field of FIELDS) row[field] = typeof raw[field] === "string" ? raw[field] : "";
  row.general = joinRemediation(row.general, raw.specific);
  row.specific = "";
  if (TRACKS.some(([value]) => value === raw.status)) row.status = raw.status;
  if (SEVERITY_RANK[raw.severity] != null) row.severity = raw.severity;
  row.source = typeof raw.source === "string" ? raw.source : "";
  return row;
}

function canonicalProject(path) {
  return String(path || "").trim().replace(/\//g, "\\").replace(/[\\/]+$/, "").toLowerCase();
}

function triageKey() {
  const want = canonicalProject(entry.repo);
  return Object.keys(entry.triage).find((key) => canonicalProject(key) === want) || entry.repo;
}

function sharedMark(source) {
  if (!source) return null;
  const bucket = entry.triage[triageKey()];
  return bucket && bucket[source];
}

function workflowFromMark(raw) {
  const decisions = ["resolved", "ignored", "true-positive"];
  const stages = ["confirmed", "in-remediation", "mitigated", "remediated"];
  let status = "";
  let track = "";
  if (decisions.includes(raw)) status = raw;
  else if (raw && typeof raw === "object") {
    if (decisions.includes(raw.status)) status = raw.status;
    if (stages.includes(raw.track)) track = raw.track;
  }
  if (status === "ignored") return "ignored";
  if (status === "resolved") return track === "remediated" ? "remediated" : "resolved";
  if (track) return track;
  if (status === "true-positive") return "true-positive";
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

function applySharedMarks() {
  for (const row of entry.rows) {
    if (!row.source) continue;
    const raw = sharedMark(row.source);
    if (!raw) continue;
    row.status = workflowFromMark(raw);
    if (raw && typeof raw === "object" && SEVERITY_RANK[raw.severity] != null) row.severity = raw.severity;
  }
}

function filledRows() {
  return entry.rows.filter((row) => FIELDS.some((field) => row[field].trim()) || row.status !== "needs-review" || row.severity !== "Medium");
}

function shownRows() {
  const list = entry.rows.slice();
  if (!entry.sort) return list;
  const dir = entry.dir;
  list.sort((a, b) => {
    const diff = compareField(a, b);
    if (diff) return diff * dir;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  });
  return list;
}

function compareField(a, b) {
  if (entry.sort === "line") return compareLine(a.line, b.line);
  if (entry.sort === "severity") return (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
  const left = String(a[entry.sort] || "").toLowerCase();
  const right = String(b[entry.sort] || "").toLowerCase();
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function compareLine(left, right) {
  const a = String(left).trim();
  const b = String(right).trim();
  const aNum = /^\d+$/.test(a) ? Number(a) : null;
  const bNum = /^\d+$/.test(b) ? Number(b) : null;
  if (aNum != null && bNum != null) return aNum - bNum;
  const aText = a.toLowerCase();
  const bText = b.toLowerCase();
  if (aText < bText) return -1;
  if (aText > bText) return 1;
  return 0;
}

function render() {
  document.title = "User Status";
  const filled = filledRows().length;
  document.getElementById("sheet").innerHTML = `
    <header class="sheet-head">
      <div>
        <p class="byline">Gott Security</p>
        <h1>User Status</h1>
        <p class="lede">Type findings here. This sheet does not come from a scan. Rows stay on this server.</p>
        <p class="meta">${esc(entry.repo || "No repository selected. Rows are still saved for this empty path.")}</p>
        <p class="meta" id="entry-note">${filled} saved ${filled === 1 ? "row" : "rows"}. ${esc(entry.saveNote)}</p>
      </div>
      <div class="sheet-links">
        <a class="ghost" href="${STATUS}">Scan status</a>
        <a class="ghost" href="${ANALYSIS}">Back to analysis</a>
      </div>
    </header>
    <div class="sheet-tools">
      <button type="button" class="primary" data-action="add-row">Add row</button>
      <button type="button" class="ghost" data-action="print-view">${entry.printPreview ? "Back to table" : "Print view"}</button>
      <button type="button" class="ghost" data-action="print-now">Print</button>
    </div>
    <div class="sheet-scroll">
      <table class="sheet-table">
        <thead>
          <tr>
            ${header("name", "Finding Name")}
            ${header("file", "File")}
            ${header("line", "Line")}
            ${header("synopsis", "Synopsis")}
            ${header("general", "Recommended remediation")}
            ${header("severity", "Severity")}
            ${header("status", "Status")}
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${shownRows().map(rowHtml).join("")}
        </tbody>
      </table>
    </div>
    <div class="print-deck">
      ${printDeck(printableRows(), "User Status")}
    </div>
  `;
  document.body.classList.toggle("print-preview", entry.printPreview);
}

function header(key, label) {
  const mark = entry.sort === key ? (entry.dir > 0 ? " ↑" : " ↓") : "";
  return `<th data-sort="${key}" scope="col">${label}${mark}</th>`;
}

function printableRows() {
  const filled = new Set(filledRows().map((row) => row.id));
  return shownRows().filter((row) => filled.has(row.id));
}

function trackLabel(value) {
  return (TRACKS.find(([id]) => id === value) || ["", value])[1];
}

function printSection(title, text) {
  const value = String(text || "").trim();
  if (!value) return "";
  return `<h3>${esc(title)}</h3><p>${esc(value)}</p>`;
}

function printDeck(rows, pageTitle) {
  if (!rows.length) return `<p class="print-empty">Nothing to print.</p>`;
  return rows
    .map((row) => {
      const where = [row.file, row.line].filter((part) => String(part || "").trim()).join(":");
      return `
        <article class="print-card">
          <p class="print-kicker">Gott Security · ${esc(pageTitle)}</p>
          <h2>${esc(row.name || "Untitled finding")}</h2>
          ${where ? `<p class="print-where">${esc(where)}</p>` : ""}
          <p class="print-meta">${esc(row.severity || "Medium")} · ${esc(trackLabel(row.status))}</p>
          ${printSection("Synopsis", row.synopsis)}
          ${printSection("Recommended remediation", row.general)}
        </article>
      `;
    })
    .join("");
}

function rowHtml(row) {
  return `
    <tr data-id="${esc(row.id)}">
      <td><input data-field="name" data-id="${esc(row.id)}" type="text" value="${esc(row.name)}" aria-label="Finding name"></td>
      <td><input data-field="file" data-id="${esc(row.id)}" type="text" value="${esc(row.file)}" aria-label="File"></td>
      <td class="col-line"><input data-field="line" data-id="${esc(row.id)}" type="text" value="${esc(row.line)}" aria-label="Line"></td>
      <td><textarea data-field="synopsis" data-id="${esc(row.id)}" aria-label="Synopsis">${esc(row.synopsis)}</textarea></td>
      <td><textarea data-field="general" data-id="${esc(row.id)}" aria-label="Recommended remediation">${esc(row.general)}</textarea></td>
      <td class="col-sev">
        <select class="sev-${esc(row.severity.toLowerCase())}" data-field="severity" data-id="${esc(row.id)}" aria-label="Severity" title="${esc(row.severity)}">
          ${SEVERITIES.map(([value, label]) => `<option value="${value}"${row.severity === value ? " selected" : ""}>${label}</option>`).join("")}
        </select>
      </td>
      <td class="col-status">
        <select class="track-${esc(row.status)}" data-field="status" data-id="${esc(row.id)}" aria-label="Status" title="Linked findings use the same status as Analysis and Scan Status. The finding id stays hidden.">
          ${TRACKS.map(([value, label]) => `<option value="${value}"${row.status === value ? " selected" : ""}>${label}</option>`).join("")}
        </select>
      </td>
      <td><button type="button" class="ghost row-remove" data-action="remove-row" data-id="${esc(row.id)}">Remove</button></td>
    </tr>
  `;
}

function onInput(event) {
  const field = event.target.dataset.field;
  const row = findRow(event.target.dataset.id);
  if (!row || !FIELDS.includes(field)) return;
  row[field] = event.target.value;
  scheduleSave();
}

function onChange(event) {
  const field = event.target.dataset.field;
  if (field !== "status" && field !== "severity") return;
  const row = findRow(event.target.dataset.id);
  if (!row) return;
  if (field === "severity" && SEVERITY_RANK[event.target.value] == null) return;
  row[field] = event.target.value;
  if (field === "status") event.target.className = `track-${row.status}`;
  else {
    event.target.className = `sev-${row.severity.toLowerCase()}`;
    event.target.title = row.severity;
  }
  if (row.source) syncLinked(row);
  scheduleSave();
}

async function syncLinked(row) {
  try {
    const session = await fetch("/api/session").then(readJson);
    if (!session.triage || typeof session.triage !== "object" || Array.isArray(session.triage)) session.triage = {};
    const key = Object.keys(session.triage).find((item) => canonicalProject(item) === canonicalProject(entry.repo)) || entry.repo;
    if (!session.triage[key]) session.triage[key] = {};
    const raw = session.triage[key][row.source];
    let needsReview = false;
    if (raw && typeof raw === "object") needsReview = raw.needsReview === true;
    const nextFields = fieldsForWorkflow(row.status);
    const severity = SEVERITY_RANK[row.severity] != null ? row.severity : "";
    let next = null;
    if (nextFields.status || needsReview || severity || nextFields.track) {
      if (nextFields.status && !needsReview && !severity && !nextFields.track) next = nextFields.status;
      else {
        next = {};
        if (nextFields.status) next.status = nextFields.status;
        if (needsReview) next.needsReview = true;
        if (severity) next.severity = severity;
        if (nextFields.track) next.track = nextFields.track;
      }
    }
    if (next == null) delete session.triage[key][row.source];
    else session.triage[key][row.source] = next;
    if (session.triage[key] && !Object.keys(session.triage[key]).length) delete session.triage[key];
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(session),
    });
    if (!response.ok) throw new Error("save failed");
    const saved = await response.json();
    entry.triage = saved.triage && typeof saved.triage === "object" ? saved.triage : {};
  } catch (err) {
    entry.saveNote = "The shared status could not be saved.";
    paintNote();
  }
}

function onClick(event) {
  if (event.target.closest("[data-action='print-now']")) {
    window.print();
    return;
  }
  if (event.target.closest("[data-action='print-view']")) {
    entry.printPreview = !entry.printPreview;
    render();
    return;
  }
  const headerCell = event.target.closest("th[data-sort]");
  if (headerCell) {
    const key = headerCell.dataset.sort;
    if (entry.sort === key) entry.dir = -entry.dir;
    else {
      entry.sort = key;
      entry.dir = 1;
    }
    render();
    return;
  }
  const add = event.target.closest("[data-action='add-row']");
  if (add) {
    entry.rows.push(blankRow());
    render();
    const inputs = document.querySelectorAll("tbody input[data-field='name']");
    inputs[inputs.length - 1]?.focus();
    return;
  }
  const remove = event.target.closest("[data-action='remove-row']");
  if (!remove) return;
  entry.rows = entry.rows.filter((row) => row.id !== remove.dataset.id);
  if (!entry.rows.length) entry.rows.push(blankRow());
  render();
  scheduleSave();
}

function findRow(id) {
  return entry.rows.find((row) => row.id === id);
}

function scheduleSave() {
  window.clearTimeout(saveTimer);
  entry.saveNote = "Saving…";
  paintNote();
  saveTimer = window.setTimeout(save, 300);
}

async function save() {
  try {
    const response = await fetch("/api/entries", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo: entry.repo, rows: filledRows() }),
    });
    if (!response.ok) throw new Error("save failed");
    entry.saveNote = "Saved on this server.";
  } catch (err) {
    entry.saveNote = "These rows could not be saved.";
  }
  paintNote();
}

function paintNote() {
  const note = document.getElementById("entry-note");
  if (!note) return;
  const filled = filledRows().length;
  note.textContent = `${filled} saved ${filled === 1 ? "row" : "rows"}. ${entry.saveNote}`;
}

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
