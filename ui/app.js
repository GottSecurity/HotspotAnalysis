"use strict";

const CONFIDENCE_NOTE = {
  High: "A request source and this sink are within 40 lines in the same file. Confirm the value actually reaches the sink.",
  Medium: "A request source exists elsewhere in this file. It may not reach this sink.",
  Low: "A security-sensitive API is here. The match alone does not show that it is exploitable.",
};

const TOOLS = {
  vscode: "VS Code: Find in Files (Ctrl+Shift+F), then turn on Use Regular Expression.",
  notepad: "Notepad++: Search > Find in Files (Ctrl+Shift+F), Search mode Regular expression.",
  ripgrep: "ripgrep: run the rg command from the repository root.",
};

const SORTS = [
  ["priority", "Priority"],
  ["confidence", "Confidence"],
  ["category", "Category"],
  ["file", "File"],
  ["step", "Checklist step"],
  ["line", "Line number"],
];

const state = {
  mode: "passive",
  catalog: null,
  repo: "",
  language: "all",
  category: "All",
  searchType: "all",
  tool: "vscode",
  priority: "All",
  q: "",
  filename: "",
  sinks: false,
  sources: false,
  linked: false,
  hideResolved: true,
  hideIgnored: true,
  hideDuplicates: false,
  triage: {},
  marksByRepo: {},
  githubByRepo: {},
  github: "",
  sort: "priority",
  view: "findings",
  scan: null,
  scanning: false,
  scanError: "",
  history: [],
  open: {},
  strategyOpen: {},
  marks: {},
  leftOpen: true,
  rightOpen: true,
  activeProject: "",
  sentToUser: new Set(),
  currentStep: "",
  holdClosed: false,
  browseOpen: false,
  browse: null,
  browseError: "",
};

document.addEventListener("click", onClick);
document.addEventListener("change", onChange);
document.addEventListener("input", onInput);
document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && event.target.id === "repo-path") {
    event.preventDefault();
    runScan();
  }
});

load();

async function load() {
  const app = document.getElementById("app");
  try {
    const [libraryResponse, sessionResponse] = await Promise.all([
      fetch("/api/library"),
      fetch("/api/session"),
    ]);
    state.catalog = await libraryResponse.json();
    applySession(await sessionResponse.json());
    await refreshHistory();
    if (state.repo) {
      const restored = await restoreScan(state.repo);
      if (!restored) switchProject(state.repo);
    }
    renderShell();
  } catch (err) {
    app.textContent = "The review guide could not be loaded. Start it with node server.js and open http://127.0.0.1:3000.";
  }
}

function canonicalProject(path) {
  return String(path || "").trim().replace(/\//g, "\\").replace(/[\\/]+$/, "");
}

function sameProject(a, b) {
  return canonicalProject(a).toLowerCase() === canonicalProject(b).toLowerCase();
}

function projectKey() {
  return state.activeProject || canonicalProject(state.repo);
}

function findMarksKey(path) {
  const want = canonicalProject(path);
  if (!want) return "";
  return Object.keys(state.marksByRepo).find((key) => sameProject(key, want)) || "";
}

function applyProjectMarks() {
  const stored = findMarksKey(projectKey());
  const bucket = stored && state.marksByRepo[stored];
  state.marks = bucket && typeof bucket === "object" ? { ...bucket } : {};
}

function findGithubKey(path) {
  const want = canonicalProject(path);
  if (!want) return "";
  return Object.keys(state.githubByRepo).find((key) => sameProject(key, want)) || "";
}

function applyProjectGithub() {
  const stored = findGithubKey(projectKey());
  state.github = stored ? state.githubByRepo[stored] : "";
}

function storeProjectGithub() {
  const key = projectKey();
  if (!key) return;
  const previous = findGithubKey(key);
  if (previous && previous !== key) delete state.githubByRepo[previous];
  const url = String(state.github || "").trim();
  if (!url) delete state.githubByRepo[key];
  else state.githubByRepo[key] = url;
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
  const parsed = parseGithub(state.github);
  const number = Number(line);
  if (!parsed || !file || !Number.isInteger(number) || number < 1) return "";
  const filePath = String(file)
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .map(encodeURIComponent)
    .join("/");
  const branch = parsed.branch.split("/").map(encodeURIComponent).join("/");
  return `https://github.com/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/blob/${branch}/${filePath}#L${number}`;
}

function storeProjectMarks() {
  const key = projectKey();
  if (!key) return;
  const previous = findMarksKey(key);
  if (previous && previous !== key) delete state.marksByRepo[previous];
  if (!Object.keys(state.marks).length) delete state.marksByRepo[key];
  else state.marksByRepo[key] = { ...state.marks };
}

function switchProject(nextPath) {
  const next = canonicalProject(nextPath);
  if (!next) return;
  const stored = findMarksKey(next);
  const resolved = state.scan && sameProject(state.scan.repoRoot, next) ? state.scan.repoRoot : stored || next;
  if (state.activeProject && sameProject(state.activeProject, resolved)) {
    state.repo = resolved;
    return;
  }
  if (state.activeProject) {
    storeProjectMarks();
    storeProjectGithub();
  }
  state.activeProject = resolved;
  state.repo = resolved;
  if (state.scan && !sameProject(state.scan.repoRoot, resolved)) state.scan = null;
  applyProjectMarks();
  applyProjectGithub();
}

function applySession(saved) {
  if (!saved || typeof saved !== "object") return;
  if (saved.mode === "passive" || saved.mode === "active") state.mode = saved.mode;
  if (typeof saved.repo === "string") state.repo = saved.repo;
  if (typeof saved.language === "string") state.language = saved.language;
  if (typeof saved.category === "string") state.category = saved.category;
  if (typeof saved.searchType === "string") state.searchType = saved.searchType;
  if (typeof saved.tool === "string") state.tool = saved.tool;
  if (typeof saved.priority === "string") state.priority = saved.priority;
  if (typeof saved.q === "string") state.q = saved.q;
  if (typeof saved.filename === "string") state.filename = saved.filename;
  state.sinks = saved.sinks === true;
  state.sources = saved.sources === true;
  state.linked = saved.linked === true;
  state.hideResolved = saved.hideResolved !== false;
  state.hideIgnored = saved.hideIgnored !== false;
  state.hideDuplicates = saved.hideDuplicates === true;
  state.triage = saved.triage && typeof saved.triage === "object" && !Array.isArray(saved.triage) ? saved.triage : {};
  state.marksByRepo = saved.marks && typeof saved.marks === "object" && !Array.isArray(saved.marks) ? saved.marks : {};
  state.githubByRepo = saved.github && typeof saved.github === "object" && !Array.isArray(saved.github) ? saved.github : {};
  if (SORTS.some(([value]) => value === saved.sort)) state.sort = saved.sort;
  if (saved.view === "findings" || saved.view === "checklist" || saved.view === "top") state.view = saved.view;
}

let saveTimer = 0;

function scheduleSave() {
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(saveSession, 250);
}

async function saveSession() {
  const status = document.getElementById("session-status");
  try {
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode: state.mode,
        repo: state.repo,
        language: state.language,
        category: state.category,
        searchType: state.searchType,
        tool: state.tool,
        priority: state.priority,
        q: state.q,
        filename: state.filename,
        sinks: state.sinks,
        sources: state.sources,
        linked: state.linked,
        hideResolved: state.hideResolved,
        hideIgnored: state.hideIgnored,
        hideDuplicates: state.hideDuplicates,
        triage: state.triage,
        marks: state.marksByRepo,
        github: state.githubByRepo,
        sort: state.sort,
        view: state.view,
      }),
    });
    if (status) status.textContent = response.ok ? "Saved on this server." : "These choices could not be saved.";
  } catch (err) {
    if (status) status.textContent = "These choices could not be saved.";
  }
}

function renderShell() {
  document.getElementById("app").innerHTML = `
    <div class="shell">
      <aside id="side-left" class="side side-left">
        <div class="side-scroll" id="left-body"></div>
        <button type="button" class="chevron" data-action="collapse" data-side="left" aria-label="Collapse left panel">&lt;</button>
      </aside>
      <div class="center">
        <main id="main"></main>
      </div>
      <aside id="side-right" class="side side-right">
        <button type="button" class="chevron" data-action="collapse" data-side="right" aria-label="Collapse right panel">&gt;</button>
        <div class="side-scroll" id="right-body"></div>
      </aside>
    </div>
    <div id="browser" class="browser" hidden>
      <button type="button" class="browser-backdrop" data-action="browse-close" aria-label="Close folder browser"></button>
      <div class="browser-card" role="dialog" aria-modal="true" aria-labelledby="browser-title">
        <div class="browser-head">
          <h2 id="browser-title">Choose a folder</h2>
          <button type="button" class="ghost" data-action="browse-close">Close</button>
        </div>
        <p class="browser-path" id="browser-path"></p>
        <div class="browser-actions">
          <button type="button" class="ghost" id="browse-up" data-action="browse-up">Up</button>
          <button type="button" class="primary" id="browse-use" data-action="browse-use">Use this folder</button>
        </div>
        <p class="error" id="browser-error"></p>
        <div id="browser-list" class="browser-list"></div>
      </div>
    </div>
  `;
  renderMain();
}

function renderMain() {
  if (state.catalog) ensureCurrentStep();
  paintMode();
  paintSides();
  renderLeft();
  document.getElementById("right-body").innerHTML = state.mode === "passive" ? passiveControls() : activeControls();
  const note = state.mode === "passive"
    ? "Passive mode does not read your repository. Copy a regex, then use Find in Files. The editor shows the line number and can jump to it."
    : "";
  document.title = "Hotspot Analysis";
  document.getElementById("main").innerHTML = `
    ${brandHtml()}
    ${note ? `<p class="note">${esc(note)}</p>` : ""}
    <div class="center-tools">
      <a class="ghost" href="/GottSecurity/HotspotAnalysis/Status.html">Status</a>
      <a class="ghost" href="/GottSecurity/HotspotAnalysis/StatusEntry.html">User Status</a>
      <button type="button" class="ghost" data-action="collapse-all">Collapse all</button>
    </div>
    <div id="list"></div>
  `;
  if (state.mode === "passive") renderGuide();
  else renderActiveList();
  updateProgress();
}

function paintSides() {
  const left = document.getElementById("side-left");
  const right = document.getElementById("side-right");
  left.classList.toggle("collapsed", !state.leftOpen);
  right.classList.toggle("collapsed", !state.rightOpen);
  const leftButton = left.querySelector(".chevron");
  const rightButton = right.querySelector(".chevron");
  leftButton.textContent = state.leftOpen ? "<" : ">";
  rightButton.textContent = state.rightOpen ? ">" : "<";
  leftButton.setAttribute("aria-label", state.leftOpen ? "Collapse left panel" : "Expand left panel");
  rightButton.setAttribute("aria-label", state.rightOpen ? "Collapse right panel" : "Expand right panel");
  leftButton.setAttribute("aria-expanded", state.leftOpen ? "true" : "false");
  rightButton.setAttribute("aria-expanded", state.rightOpen ? "true" : "false");
}

function renderLeft() {
  const body = document.getElementById("left-body");
  if (!body || !state.catalog) return;
  body.innerHTML = `
    <p class="side-label">Checklist</p>
    <nav class="jump-list" aria-label="Review steps">
      ${state.catalog.steps
        .map((step) => {
          const mark = state.marks[step.id] || "not-reviewed";
          const current = state.currentStep === step.id ? " current" : "";
          const tone = stepTone(step.id);
          return `<button type="button" class="jump mark-${esc(mark)}${tone ? ` tone-${tone}` : ""}${current}" data-action="jump" data-step="${esc(step.id)}"><span class="num">${step.order}</span><span>${esc(step.title)}</span></button>`;
        })
        .join("")}
    </nav>
  `;
}

function paintMode() {
  document.querySelectorAll("[data-action='mode']").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.mode === state.mode ? "true" : "false");
  });
}

function brandHtml() {
  return `
    <header class="brand">
      <p class="byline">Gott Security</p>
      <p class="tagline">Protecting You Most of the Time</p>
      <h1>Security Hotspot Analysis</h1>
      <p class="lede">A local review guide for Node.js, JavaScript, Java, Spring, and Python. Work the checklist in order, and paste each regex into your editor.</p>
      <p class="disclaimer">${esc(state.catalog.disclaimer)}</p>
      <p class="page-urls">
        <a href="/GottSecurity/HotspotAnalysis/Status.html">/GottSecurity/HotspotAnalysis/Status.html</a>
        <a href="/GottSecurity/HotspotAnalysis/StatusEntry.html">/GottSecurity/HotspotAnalysis/StatusEntry.html</a>
      </p>
    </header>
  `;
}

function passiveControls() {
  return `
    <div class="mode" role="group" aria-label="Operating mode">
      <button type="button" data-action="mode" data-mode="passive" aria-pressed="${state.mode === "passive" ? "true" : "false"}">Passive</button>
      <button type="button" data-action="mode" data-mode="active" aria-pressed="${state.mode === "active" ? "true" : "false"}">Active</button>
    </div>
    <section class="toolbar">
      <p class="side-label">Filters</p>
      <div class="filters">
        ${languageField()}
        ${categoryField()}
        <label class="field">Show
          <select id="search-type">
            ${selectOptions(
              [
                ["all", "All"],
                ["keywords", "Keywords"],
                ["regex", "Regex"],
                ["checklist", "Checklist"],
              ],
              state.searchType
            )}
          </select>
        </label>
        <label class="field">Editor
          <select id="tool">
            ${selectOptions(
              [
                ["vscode", "VS Code"],
                ["notepad", "Notepad++"],
                ["ripgrep", "ripgrep"],
              ],
              state.tool
            )}
          </select>
        </label>
        <label class="field">Find
          <input id="q" type="search" placeholder="Filter the guide" value="${esc(state.q)}">
        </label>
      </div>
      <p class="meta" id="tool-hint"></p>
      <p class="meta" id="session-status"></p>
    </section>
    ${progressHtml()}
  `;
}

function activeControls() {
  return `
    <div class="mode" role="group" aria-label="Operating mode">
      <button type="button" data-action="mode" data-mode="passive" aria-pressed="${state.mode === "passive" ? "true" : "false"}">Passive</button>
      <button type="button" data-action="mode" data-mode="active" aria-pressed="${state.mode === "active" ? "true" : "false"}">Active</button>
    </div>
    <section class="scan-bar">
      <div class="scan-row">
        <label class="field">Repository path
          <input id="repo-path" type="text" spellcheck="false" value="${esc(state.repo)}" placeholder="Browse or paste a folder path">
        </label>
        <button type="button" class="ghost" data-action="browse-open">Browse</button>
        <button type="button" class="primary" id="scan-button" data-action="scan">Scan</button>
      </div>
      <label class="field">GitHub link
        <input id="github-link" type="url" spellcheck="false" value="${esc(state.github)}" placeholder="https://github.com/owner/repo" title="Filename links open this repository. Add /tree/branch to pin a branch. Otherwise the link uses main.">
      </label>
      ${historyField()}
      <p class="meta" id="scan-meta">Active mode reads files and runs the same regexes. It does not lint, modify, or rewrite anything.</p>
      <p class="error" id="scan-error"></p>
    </section>
    <section class="toolbar">
      <p class="side-label">Filters</p>
      <div class="filters">
        ${languageField()}
        ${categoryField()}
        <label class="field">Sort by
          <select id="sort">
            ${selectOptions(SORTS, state.sort)}
          </select>
        </label>
        <label class="field">Priority
          <select id="priority">
            ${state.catalog.priorities
              .map((item) => `<option${item === state.priority ? " selected" : ""}>${esc(item)}</option>`)
              .join("")}
          </select>
        </label>
        <label class="field">Find
          <input id="q" type="search" placeholder="Text or category" value="${esc(state.q)}">
        </label>
        <label class="field">Filename
          <input id="filename" type="search" placeholder="path contains" value="${esc(state.filename)}">
        </label>
      </div>
      <div class="check-row">
        <label><input id="only-sinks" type="checkbox"${state.sinks ? " checked" : ""}> Show only likely sinks</label>
        <label><input id="only-sources" type="checkbox"${state.sources ? " checked" : ""}> Show only likely sources</label>
        <label><input id="only-linked" type="checkbox"${state.linked ? " checked" : ""}> Show sinks with nearby input (flow unverified)</label>
        <label><input id="hide-resolved" type="checkbox"${state.hideResolved ? " checked" : ""}> Hide resolved</label>
        <label><input id="hide-ignored" type="checkbox"${state.hideIgnored ? " checked" : ""}> Hide ignored</label>
        <label><input id="hide-duplicates" type="checkbox"${state.hideDuplicates ? " checked" : ""}> Hide duplicates</label>
      </div>
      <div class="view-row">
        <button type="button" class="tab" data-action="view" data-view="findings" aria-pressed="${state.view === "findings" ? "true" : "false"}">Findings</button>
        <button type="button" class="tab" data-action="view" data-view="checklist" aria-pressed="${state.view === "checklist" ? "true" : "false"}">Checklist</button>
        <button type="button" class="tab" data-action="view" data-view="top" aria-pressed="${state.view === "top" ? "true" : "false"}">Top hotspots</button>
      </div>
      <p class="meta" id="session-status"></p>
    </section>
    ${progressHtml()}
  `;
}

function historyField() {
  const current = state.scan && state.scan.repoRoot;
  const options = state.history
    .map((item) => {
      const selected = item.repo === current ? " selected" : "";
      return `<option value="${esc(item.repo)}"${selected}>${esc(item.repo)} · ${item.hotspotCount} matches</option>`;
    })
    .join("");
  return `
    <label class="field">Recent projects
      <select id="repo-history">
        <option value="">Switch saved project</option>
        ${options}
      </select>
    </label>
  `;
}

function languageField() {
  return `
    <label class="field">Language
      <select id="language">
        ${state.catalog.languages
          .map((item) => `<option value="${esc(item.id)}"${item.id === state.language ? " selected" : ""}>${esc(item.label)}</option>`)
          .join("")}
      </select>
    </label>
  `;
}

function categoryField() {
  return `
    <label class="field">Category
      <select id="category">
        ${state.catalog.categories
          .map((item) => `<option${item === state.category ? " selected" : ""}>${esc(item)}</option>`)
          .join("")}
      </select>
    </label>
  `;
}

function selectOptions(pairs, current) {
  return pairs
    .map(([value, label]) => `<option value="${esc(value)}"${value === current ? " selected" : ""}>${esc(label)}</option>`)
    .join("");
}

function progressHtml() {
  return `
    <div class="progress">
      <div>
        <strong id="progress-label">0 / 19 categories reviewed</strong>
        <div class="track" aria-hidden="true"><span id="progress-bar"></span></div>
      </div>
      <button type="button" class="ghost" data-action="reset-marks">Reset marks</button>
    </div>
  `;
}

function ensureCurrentStep() {
  const steps = state.catalog.steps;
  if (!steps.length) return;
  if (!steps.some((step) => step.id === state.currentStep)) state.currentStep = steps[0].id;
  if (!state.holdClosed && state.open[state.currentStep] === undefined) state.open[state.currentStep] = true;
}

function renderGuide() {
  const hint = document.getElementById("tool-hint");
  if (hint) {
    const caseNote = " When a pattern says case insensitive, turn off Match case in the editor.";
    hint.textContent = TOOLS[state.tool] + caseNote;
    if (state.language === "spring") {
      hint.textContent += " Spring review includes the Java searches plus Spring Framework, Spring Boot, Spring Security, and Spring HTTP API patterns.";
    }
    if (state.language === "python") {
      hint.textContent += " Python review covers Flask, Django, and FastAPI request entry, queries, commands, and template output.";
    }
    if (state.language === "javascript") {
      hint.textContent += " JavaScript review covers browser sources, DOM HTML writes, redirects, postMessage, storage, and prototype pollution.";
    }
  }
  ensureCurrentStep();
  const list = document.getElementById("list");
  if (!list) return;
  list.innerHTML = state.catalog.steps.map((step) => stepHtml(guideStep(step))).join("");
  updateProgress();
}

function guideStep(step) {
  const searches = step.searches.filter(searchVisible);
  return { ...step, searches, searchCount: searches.length };
}

function stepTone(stepId) {
  if (!state.scan) return "";
  const items = matchingHotspots().filter((item) => item.stepId === stepId);
  if (!items.length) return "quiet";
  const statuses = items.map(triageStatus);
  const todo = statuses.some((status) => status !== "resolved" && status !== "ignored" && status !== "true-positive");
  if (todo) return "todo";
  if (statuses.some((status) => status === "true-positive")) return "open";
  return "quiet";
}

function searchVisible(item) {
  if (!passiveLanguage(item)) return false;
  if (state.category !== "All" && item.category !== state.category) return false;
  if (!state.q.trim()) return true;
  const blob = [
    item.title,
    item.category,
    item.regex,
    item.keywords.join(" "),
    item.why,
    item.whatToCheck,
    item.falsePositives,
  ]
    .join("\n")
    .toLowerCase();
  return blob.includes(state.q.trim().toLowerCase());
}

function passiveLanguage(item) {
  if (state.language === "all") return true;
  if (state.language === "spring") {
    return item.languages.includes("spring") || item.languages.includes("java");
  }
  return item.languages.includes(state.language);
}

function stepHtml(step) {
  const open = Boolean(state.open[step.id]);
  const shown = step.id === state.currentStep;
  const searches = state.searchType === "checklist"
    ? ""
    : step.searches.length
      ? step.searches.map(searchHtml).join("")
      : `<p>No searches match these filters.</p>`;
  const tone = stepTone(step.id);
  return `
    <section class="step${tone ? ` tone-${tone}` : ""}" id="step-${esc(step.id)}" ${shown ? "" : "hidden"}>
      <div class="step-bar">
        <button type="button" class="step-toggle" data-action="toggle-step" data-step="${esc(step.id)}" aria-expanded="${open ? "true" : "false"}">
          <span class="num">${step.order}</span>
          <span>
            <strong>${esc(step.title)}</strong>
            <span class="summary"> ${esc(step.summary)} · ${step.searchCount === 1 ? "1 search" : `${step.searchCount} searches`}</span>
          </span>
        </button>
        ${marksHtml(step.id)}
      </div>
      <div class="step-body" id="body-${esc(step.id)}" ${open ? "" : "hidden"}>
        <ol>${step.guidance.map((line) => `<li>${esc(line)}</li>`).join("")}</ol>
        ${state.searchType === "checklist" ? floorsBlock(step) : ""}
        ${searches}
      </div>
    </section>
  `;
}

function marksHtml(stepId) {
  const current = state.marks[stepId] || "not-reviewed";
  const options = [
    ["not-reviewed", "Not reviewed"],
    ["reviewing", "Reviewing"],
    ["issue", "Issue found"],
    ["reviewed", "Reviewed"],
  ];
  return `
    <div class="mark-row" role="group" aria-label="Review status">
      ${options
        .map(
          ([id, label]) =>
            `<button type="button" class="mark" data-action="mark" data-step="${esc(stepId)}" data-status="${id}" aria-pressed="${current === id ? "true" : "false"}">${label}</button>`
        )
        .join("")}
    </div>
  `;
}

function floorsHtml(item) {
  if (!item.floors || !item.floors.length) return "";
  const rows = item.floors
    .map(
      (row) =>
        `<tr><td>${esc(row.name)}</td><td>${esc(row.floor)}</td><td>${esc(row.note || (row.always ? "Review any version." : ""))}</td></tr>`
    )
    .join("");
  return `
    <div class="kicker">Registry release ${esc(item.floorDate || "")}. Passive mode: compare by hand.</div>
    <table class="floors">
      <thead><tr><th>Package</th><th>Last Known Good</th><th>Note</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function floorsBlock(step) {
  return step.searches.map(floorsHtml).join("");
}

function searchHtml(item) {
  const showKeywords = state.mode === "active" || state.searchType === "all" || state.searchType === "keywords";
  const showRegex = state.mode === "active" || state.searchType === "all" || state.searchType === "regex";
  const caseNote = item.flags && item.flags.includes("i") ? "Case insensitive." : "";
  return `
    <article class="search-card">
      <h3>${esc(item.title)}</h3>
      <p>${esc(item.why)}</p>
      ${floorsHtml(item)}
      ${
        showKeywords
          ? `<div class="kicker">Keywords</div>
             <ul class="chips">${item.keywords.map((word) => `<li>${esc(word)}</li>`).join("")}</ul>
             <div class="copy-row"><button type="button" class="copy" data-action="copy" data-text="${esc(item.keywords.join(", "))}">Copy keywords</button></div>`
          : ""
      }
      ${
        showRegex
          ? `<div class="kicker">${item.matchFile ? "Filename regex" : "Regex"} ${esc(caseNote)}</div>
             <div class="pattern"><code id="re-${esc(item.id)}">${esc(item.regex)}</code>
             <button type="button" class="copy" data-action="copy-target" data-target="re-${esc(item.id)}">Copy search</button></div>
             <div class="kicker">ripgrep</div>
             <div class="pattern rg"><code id="rg-${esc(item.id)}">${esc(rgCommand(item))}</code>
             <button type="button" class="copy" data-action="copy-target" data-target="rg-${esc(item.id)}">Copy rg command</button></div>`
          : ""
      }
      <div class="kicker">What to check</div>
      <p>${esc(item.whatToCheck)}</p>
      <div class="kicker">False positives</div>
      <p>${esc(item.falsePositives)}</p>
      <div class="kicker">Safer approach</div>
      <p>${esc(item.secureAlternative)}</p>
    </article>
  `;
}

function rgCommand(item) {
  if (Array.isArray(item.files) && item.files.length) {
    const globs = item.files.map((name) => `--glob '${String(name).replace(/'/g, "''")}'`).join(" ");
    return `rg --files --hidden --glob '!.git/**' --glob '!node_modules/**' ${globs}`;
  }
  const insensitive = item.flags && item.flags.includes("i") ? "-i " : "";
  const quoted = item.regex.replace(/'/g, "''");
  return `rg -n ${insensitive}--regexp '${quoted}' .`;
}

function renderActiveList() {
  paintScanChrome();
  ensureCurrentStep();
  const list = document.getElementById("list");
  if (!list) return;
  document.querySelectorAll("[data-action='view']").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.view === state.view ? "true" : "false");
  });
  const matches = state.scan ? filteredHotspots() : [];
  const note = triageNote();
  list.innerHTML = state.view === "top"
    ? `<section class="step"><div class="step-bar"><h2>Top hotspots</h2></div>
        <div class="results"><p class="note">Across all checklist categories, subject to the current filters. Up to 20 matches, at most 4 per category. Context still decides the risk.${note}</p>
        ${!state.scan ? '<p>Choose a repository and scan to see hotspots.</p>' : selectTop(matches).map(hotspotHtml).join("") || '<p>No hotspots match these filters.</p>'}</div></section>`
    : state.catalog.steps.map((step) => activeStepHtml(step, matches, note)).join("");
  renderLeft();
  updateProgress();
}

function activeStepHtml(step, matches, note) {
  const shown = step.id === state.currentStep;
  const strategyOpen = Boolean(state.strategyOpen[step.id]);
  const guide = guideStep(step);
  const group = state.view === "top" && shown
    ? selectTop(matches)
    : matches.filter((item) => item.stepId === step.id);
  const cards = guide.searches.length
    ? guide.searches.map(searchHtml).join("")
    : `<p>No searches match these filters.</p>`;
  const topNote = state.view === "top" && shown
    ? `<p class="note">Up to 20 high-value matches, at most 4 from any one category, so one noisy pattern cannot take the whole list. Context still decides the risk.${note}</p>`
    : "";
  const countNote = state.view !== "top" && shown && group.length > 25
    ? `<p class="note">${group.length} matches in this step. Use Top hotspots for a short list, or narrow by category.${note}</p>`
    : shown && note && state.view !== "top"
      ? `<p class="note">${note.trim()}</p>`
      : "";
  const results = !state.scan
    ? `<p class="note">Choose a repository and scan when you want matches with file names and line numbers. Until then, this page has not read the filesystem.</p>`
    : group.length
      ? group.map(hotspotHtml).join("")
      : `<p class="note">No hotspots match these filters.</p>`;
  const tone = stepTone(step.id);
  return `
    <section class="step${tone ? ` tone-${tone}` : ""}" id="step-${esc(step.id)}" ${shown ? "" : "hidden"}>
      <div class="step-bar">
        <div class="step-title">
          <span class="num">${step.order}</span>
          <span><strong>${esc(step.title)}</strong> <span class="summary">${esc(step.summary)}</span></span>
        </div>
        ${marksHtml(step.id)}
      </div>
      <section class="strategy">
        <button type="button" class="step-toggle" data-action="toggle-strategy" data-step="${esc(step.id)}" aria-expanded="${strategyOpen ? "true" : "false"}">
          <span><strong class="strategy-label">Regex and strategy</strong> <span class="summary">${guide.searchCount === 1 ? "1 search" : `${guide.searchCount} searches`}</span></span>
        </button>
        <div class="step-body" ${strategyOpen ? "" : "hidden"}>
          <ol>${step.guidance.map((line) => `<li>${esc(line)}</li>`).join("")}</ol>
          ${cards}
        </div>
      </section>
      <div class="results">
        <p class="side-label">Results</p>
        ${topNote}
        ${countNote}
        ${results}
      </div>
    </section>
  `;
}

function compareBySort(a, b) {
  const confidence = { High: 0, Medium: 1, Low: 2 };
  const byFile = a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line;
  if (state.sort === "file") return byFile;
  if (state.sort === "line") return a.line - b.line || byFile;
  let diff = 0;
  if (state.sort === "confidence") diff = (confidence[a.confidence] ?? 3) - (confidence[b.confidence] ?? 3);
  else if (state.sort === "category") diff = a.category.localeCompare(b.category);
  else if (state.sort === "step") diff = a.stepOrder - b.stepOrder;
  else diff = a.rank - b.rank;
  if (diff) return diff;
  if (a.rank !== b.rank) return a.rank - b.rank;
  if (a.sourceToSink !== b.sourceToSink) return a.sourceToSink ? -1 : 1;
  return byFile;
}

const WORKFLOW = [
  ["needs-review", "Needs Review"],
  ["true-positive", "True Positive"],
  ["confirmed", "Confirmed"],
  ["in-remediation", "In Remediation"],
  ["mitigated", "Mitigated"],
  ["remediated", "Remediated"],
  ["resolved", "Resolved"],
  ["ignored", "Ignored"],
];

function workflowValue(record) {
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

function triageRecord(item) {
  const repo = state.scan && state.scan.repoRoot;
  const bucket = repo && state.triage[repo];
  const raw = bucket && bucket[item.id];
  const statuses = ["resolved", "ignored", "true-positive"];
  const severities = ["Critical", "High", "Medium", "Low"];
  const tracks = ["confirmed", "in-remediation", "mitigated", "remediated"];
  if (statuses.includes(raw)) return { status: raw, needsReview: false, severity: "", track: "" };
  if (raw && typeof raw === "object") {
    return {
      status: statuses.includes(raw.status) ? raw.status : "",
      needsReview: raw.needsReview === true,
      severity: severities.includes(raw.severity) ? raw.severity : "",
      track: tracks.includes(raw.track) ? raw.track : "",
    };
  }
  return { status: "", needsReview: false, severity: "", track: "" };
}

function shownPriority(item) {
  return triageRecord(item).severity || item.priority;
}

function triageStatus(item) {
  return triageRecord(item).status;
}

function writeTriage(repo, hotId, mark) {
  if (!state.triage[repo]) state.triage[repo] = {};
  const severities = ["Critical", "High", "Medium", "Low"];
  const tracks = ["confirmed", "in-remediation", "mitigated", "remediated"];
  const severity = severities.includes(mark.severity) ? mark.severity : "";
  const prior = triageRecord({ id: hotId }).track;
  const track = Object.prototype.hasOwnProperty.call(mark, "track")
    ? tracks.includes(mark.track) ? mark.track : ""
    : prior;
  if (!mark.status && !mark.needsReview && !severity && !track) delete state.triage[repo][hotId];
  else if (mark.status && !mark.needsReview && !severity && !track) state.triage[repo][hotId] = mark.status;
  else {
    const next = {};
    if (mark.status) next.status = mark.status;
    if (mark.needsReview) next.needsReview = true;
    if (severity) next.severity = severity;
    if (track) next.track = track;
    state.triage[repo][hotId] = next;
  }
  if (!Object.keys(state.triage[repo]).length) delete state.triage[repo];
}

function triageNote() {
  if (!state.scan) return "";
  let resolved = 0;
  let ignored = 0;
  for (const item of matchingHotspots()) {
    const status = triageStatus(item);
    if (status === "resolved" && state.hideResolved) resolved += 1;
    if (status === "ignored" && state.hideIgnored) ignored += 1;
  }
  const parts = [];
  if (resolved) parts.push(`${resolved} resolved`);
  if (ignored) parts.push(`${ignored} ignored`);
  return parts.length ? ` Hiding ${parts.join(" and ")}.` : "";
}

function matchingHotspots() {
  if (!state.scan) return [];
  return state.scan.hotspots.filter((item) => {
    if (!activeLanguage(item)) return false;
    if (state.category !== "All" && item.category !== state.category) return false;
    if (state.priority !== "All" && shownPriority(item) !== state.priority) return false;
    if (state.filename && !item.file.toLowerCase().includes(state.filename.trim().toLowerCase())) return false;
    if (state.linked && !item.sourceToSink) return false;
    if (state.sinks && state.sources) {
      if (item.role !== "sink" && item.role !== "source") return false;
    } else if (state.sinks && item.role !== "sink") return false;
    else if (state.sources && item.role !== "source") return false;
    if (state.q.trim()) {
      const blob = [item.file, item.category, item.title, item.match, item.why, item.whatToCheck]
        .join("\n")
        .toLowerCase();
      if (!blob.includes(state.q.trim().toLowerCase())) return false;
    }
    return true;
  });
}

function lineKey(item) {
  return `${item.file}:${item.line}`;
}

function filteredHotspots() {
  const shown = matchingHotspots()
    .filter((item) => {
      const status = triageStatus(item);
      if (state.hideResolved && status === "resolved") return false;
      if (state.hideIgnored && status === "ignored") return false;
      return true;
    })
    .sort(compareBySort);
  const counts = new Map();
  for (const item of shown) counts.set(lineKey(item), (counts.get(lineKey(item)) || 0) + 1);
  state.lineCounts = counts;
  if (!state.hideDuplicates) return shown;
  const seen = new Set();
  return shown.filter((item) => {
    const key = lineKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function activeLanguage(item) {
  if (state.language === "all") return true;
  if (item.language === "config") {
    return item.tags.includes(state.language) || (state.language === "spring" && item.tags.includes("java"));
  }
  if (state.language === "node") return item.language === "node" && item.tags.includes("node");
  if (state.language === "javascript") {
    return item.tags.includes("javascript") && (item.language === "node" || item.language === "javascript");
  }
  if (state.language === "java") {
    return item.language === "java" || (item.language === "spring" && item.tags.includes("java"));
  }
  if (state.language === "spring") return item.language === "spring";
  if (state.language === "python") return item.language === "python";
  return false;
}

function selectTop(list) {
  const counts = new Map();
  const picked = [];
  for (const item of list) {
    if (!item.top) continue;
    const seen = counts.get(item.category) || 0;
    if (seen >= 4) continue;
    counts.set(item.category, seen + 1);
    picked.push(item);
    if (picked.length >= 20) break;
  }
  return picked;
}

function versionSummary(item) {
  if (item.reportedVersion && item.knownGood) {
    const note = item.versionNote ? ` ${item.versionNote}` : "";
    return `Reported Version: ${item.reportedVersion}, Last Known Good: ${item.knownGood}.${note}`;
  }
  return item.why || "";
}

function hotspotHtml(item) {
  const rows = item.snippet
    .map(
      (row) =>
        `<span class="row${row.hit ? " hit" : ""}"><span class="ln">${row.line}</span>${esc(row.text)}</span>`
    )
    .join("");
  const record = triageRecord(item);
  const status = record.status;
  const priority = shownPriority(item);
  const tone = status === "true-positive" ? "tone-open" : status === "resolved" || status === "ignored" ? "tone-quiet" : "";
  const severityOptions = ["Critical", "High", "Medium", "Low"]
    .map((level) => `<option${level === priority ? " selected" : ""}>${esc(level)}</option>`)
    .join("");
  const shared = (state.lineCounts && state.lineCounts.get(lineKey(item))) || 1;
  return `
    <article class="hot ${tone}${status ? ` is-${status}` : ""}">
      <div class="triage-row">
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="needs-review"${record.needsReview ? " checked" : ""}> Needs Review</label>
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="resolved"${status === "resolved" ? " checked" : ""}> Resolved</label>
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="ignored"${status === "ignored" ? " checked" : ""}> Ignored</label>
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="true-positive"${status === "true-positive" ? " checked" : ""}> True Positive</label>
        <label class="triage severity">Severity
          <select data-action="severity" data-id="${esc(item.id)}" data-original="${esc(item.priority)}">${severityOptions}</select>
        </label>
        <label class="triage severity">Status
          <select data-action="workflow" data-id="${esc(item.id)}" title="True Positive accepts the finding. Confirmed, In Remediation, and Mitigated keep that acceptance. Remediated closes it as resolved. Ignored clears the stage.">${WORKFLOW.map(([value, label]) => `<option value="${value}"${workflowValue(record) === value ? " selected" : ""}>${label}</option>`).join("")}</select>
        </label>
        <button type="button" class="to-user" data-action="to-user" data-id="${esc(item.id)}"${state.sentToUser.has(item.id) ? " disabled" : ""}>${state.sentToUser.has(item.id) ? "In User Status" : "To User Status"}</button>
      </div>
      <div class="hot-main">
      ${shared > 1 ? `<span class="multiple" title="This line has ${shared} findings">(Multiple)</span>` : ""}
      <button type="button" class="hot-toggle" data-action="toggle-hot" aria-expanded="false">
        <span class="badge-row">
          <span class="pri pri-${esc(priority.toLowerCase())}">${esc(priority)}</span>
          <span>${esc(item.category)}</span>
          <span class="conf conf-${esc(item.confidence.toLowerCase())}">Confidence: ${esc(item.confidence)}</span>
          ${item.sourceToSink ? `<span class="flag">Nearby input, flow unverified</span>` : ""}
          ${record.needsReview ? `<span class="flag">Needs review</span>` : ""}
        </span>
      </button>
      ${locationControl(item)}
      <button type="button" class="hot-more" data-action="toggle-hot" aria-expanded="false">
        <span class="hot-match">${esc(item.match)}</span>
        <span class="hot-why">${esc(versionSummary(item))}</span>
      </button>
      <div class="hot-body" hidden>
        <p><strong>${esc(languageName(item.language))}</strong> · ${esc(item.title)} · ${esc(item.role)}</p>
        ${item.sourcePattern ? `<p>Source pattern: ${esc(item.sourcePattern)}</p>` : ""}
        ${item.sinkPattern ? `<p>Sink pattern: ${esc(item.sinkPattern)}</p>` : ""}
        <div class="snippet">${rows}</div>
        <div class="kicker">Why this is sensitive</div>
        <p>${esc(versionSummary(item))}</p>
        <div class="kicker">Confidence</div>
        <p>${esc(item.sourceToSink ? "A source pattern is within 40 lines. This is proximity only; no value flow or shared execution path has been established." : CONFIDENCE_NOTE[item.confidence] || "")}</p>
        <div class="kicker">What to verify</div>
        <p>${esc(item.whatToCheck)} ${esc(item.verify)}</p>
        <div class="kicker">False positives</div>
        <p>${esc(item.falsePositives)}</p>
        <div class="kicker">Typical safer approach</div>
        <p>${esc(item.secureAlternative)}</p>
      </div>
      </div>
    </article>
  `;
}

function languageName(id) {
  if (id === "node") return "Node.js";
  if (id === "javascript") return "JavaScript";
  if (id === "java") return "Java";
  if (id === "spring") return "Spring / Spring Boot";
  if (id === "python") return "Python";
  if (id === "config") return "Configuration";
  return id;
}

function updateProgress() {
  const label = document.getElementById("progress-label");
  const bar = document.getElementById("progress-bar");
  if (!label || !state.catalog) return;
  const total = state.catalog.steps.length;
  const done = state.catalog.steps.filter((step) => {
    const mark = state.marks[step.id];
    return mark === "reviewed" || mark === "issue";
  }).length;
  label.textContent = `${done} / ${total} categories reviewed`;
  if (bar) bar.style.width = `${Math.round((done / total) * 100)}%`;
}

function paintScanChrome() {
  const button = document.getElementById("scan-button");
  const meta = document.getElementById("scan-meta");
  const error = document.getElementById("scan-error");
  if (button) {
    button.disabled = state.scanning;
    button.textContent = state.scanning ? "Scanning…" : "Scan";
  }
  if (error) error.textContent = state.scanError;
  if (!meta) return;
  if (state.scan) {
    const trimmed = state.scan.truncated ? " Results were capped." : "";
    const saved = state.scan.savedAt ? " Loaded from the saved scan." : "";
    meta.textContent = `Scanned ${state.scan.filesScanned} files. ${state.scan.hotspotCount} matches in ${state.scan.repoRoot}.${trimmed}${saved} Reading only. Nothing was modified.`;
  } else if (!state.scanning) {
    meta.textContent = "Active mode reads files and runs the same regexes. It does not lint, modify, or rewrite anything.";
  }
}

function joinRemediation(general, specific) {
  const left = String(general || "").trim();
  const right = String(specific || "").trim();
  if (!right || right === left) return left;
  if (!left) return right;
  return `${left}\n\n${right}`;
}

function locationControl(item) {
  const href = githubFileUrl(item.file, item.line);
  const label = `${item.file}:${item.line}`;
  if (href) {
    return `<a class="loc" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="Open this line on GitHub">${esc(label)}</a>`;
  }
  return `<button type="button" class="loc" data-action="open-file" data-file="${esc(item.file)}" data-line="${item.line}" title="Open this line in Notepad++">${esc(label)}</button>`;
}

async function sendToUserStatus(button) {
  const repo = state.repo || (state.scan && state.scan.repoRoot) || "";
  const item = state.scan && state.scan.hotspots.find((hotspot) => hotspot.id === button.dataset.id);
  if (!repo || !item) return;
  button.disabled = true;
  const line = String(item.line);
  try {
    const saved = await fetch("/api/entries?repo=" + encodeURIComponent(repo)).then(readJsonResponse);
    const rows = Array.isArray(saved.rows) ? saved.rows : [];
    const record = triageRecord(item);
    const existing = rows.find((row) => row.source === item.id || (row.name === item.title && row.file === item.file && String(row.line) === line));
    if (existing) {
      existing.source = item.id;
      existing.status = workflowValue(record);
      existing.severity = shownPriority(item) || existing.severity || "Medium";
      const response = await fetch("/api/entries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo, rows }),
      });
      if (!response.ok) throw new Error("save failed");
      state.sentToUser.add(item.id);
      button.textContent = "In User Status";
      return;
    }
    if (rows.length >= 400) {
      button.disabled = false;
      button.textContent = "Sheet is full";
      return;
    }
    const step = state.catalog && state.catalog.steps.find((entry) => entry.id === item.stepId);
    rows.push({
      id: crypto.randomUUID(),
      source: item.id,
      name: item.title,
      file: item.file,
      line,
      synopsis: item.why || "",
      general: joinRemediation(step && Array.isArray(step.guidance) ? step.guidance.join(" ") : "", item.secureAlternative || ""),
      specific: "",
      status: workflowValue(record),
      severity: shownPriority(item) || "Medium",
    });
    const response = await fetch("/api/entries", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo, rows }),
    });
    if (!response.ok) throw new Error("save failed");
    state.sentToUser.add(item.id);
    button.textContent = "In User Status";
  } catch (err) {
    button.disabled = false;
    button.textContent = "Could not add";
  }
}

async function readJsonResponse(response) {
  if (!response.ok) throw new Error("request failed");
  return response.json();
}

async function openInNotepad(button) {
  const repo = state.scan && state.scan.repoRoot;
  const file = button.dataset.file;
  const line = Number(button.dataset.line);
  const error = document.getElementById("scan-error");
  if (!repo || !file || !Number.isInteger(line)) return;
  try {
    const response = await fetch("/api/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo, file, line }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Notepad++ could not open that file.");
    if (error) error.textContent = "";
  } catch (err) {
    if (error) error.textContent = err.message || "Notepad++ could not open that file.";
  }
}

async function onClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "triage" || action === "severity") return;
  if (action === "mode") {
    state.mode = button.dataset.mode;
    renderMain();
    scheduleSave();
    return;
  }
  if (action === "toggle-strategy") {
    const body = button.closest(".strategy").querySelector(".step-body");
    const willOpen = body.hidden;
    body.hidden = !willOpen;
    button.setAttribute("aria-expanded", willOpen ? "true" : "false");
    state.strategyOpen[button.dataset.step] = willOpen;
    return;
  }
  if (action === "toggle-step") {
    const body = button.closest(".step").querySelector(".step-body");
    const willOpen = body.hidden;
    body.hidden = !willOpen;
    button.setAttribute("aria-expanded", willOpen ? "true" : "false");
    state.open[button.dataset.step] = willOpen;
    return;
  }
  if (action === "to-user") {
    await sendToUserStatus(button);
    return;
  }
  if (action === "open-file") {
    const href = githubFileUrl(button.dataset.file, Number(button.dataset.line));
    if (href) {
      window.open(href, "_blank", "noopener");
      return;
    }
    await openInNotepad(button);
    return;
  }
  if (action === "toggle-hot") {
    const hot = button.closest(".hot");
    const body = hot.querySelector(".hot-body");
    const willOpen = body.hidden;
    body.hidden = !willOpen;
    hot.querySelectorAll("[data-action='toggle-hot']").forEach((item) => {
      item.setAttribute("aria-expanded", willOpen ? "true" : "false");
    });
    return;
  }
  if (action === "mark") {
    if (button.dataset.status === "not-reviewed") delete state.marks[button.dataset.step];
    else state.marks[button.dataset.step] = button.dataset.status;
    storeProjectMarks();
    scheduleSave();
    document.querySelectorAll(`[data-action="mark"][data-step="${cssEscape(button.dataset.step)}"]`).forEach((item) => {
      item.setAttribute("aria-pressed", item.dataset.status === button.dataset.status ? "true" : "false");
    });
    updateProgress();
    renderLeft();
    return;
  }
  if (action === "reset-marks") {
    state.marks = {};
    storeProjectMarks();
    scheduleSave();
    if (state.mode === "passive") renderGuide();
    else renderActiveList();
    updateProgress();
    renderLeft();
    return;
  }
  if (action === "collapse-all") {
    state.holdClosed = true;
    for (const step of state.catalog.steps) {
      state.open[step.id] = false;
      state.strategyOpen[step.id] = false;
    }
    if (state.mode === "passive") renderGuide();
    else renderActiveList();
    return;
  }
  if (action === "collapse") {
    if (button.dataset.side === "left") state.leftOpen = !state.leftOpen;
    else state.rightOpen = !state.rightOpen;
    paintSides();
    return;
  }
  if (action === "jump") {
    const stepId = button.dataset.step;
    state.currentStep = stepId;
    state.holdClosed = false;
    state.open[stepId] = true;
    if (state.mode === "passive") renderGuide();
    else renderActiveList();
    renderLeft();
    document.getElementById(`step-${stepId}`)?.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  if (action === "copy-target") {
    const node = document.getElementById(button.dataset.target);
    if (node) copyText(node.textContent, button);
    return;
  }
  if (action === "copy") {
    copyText(button.dataset.text, button);
    return;
  }
  if (action === "view") {
    state.view = button.dataset.view;
    renderActiveList();
    scheduleSave();
    return;
  }
  if (action === "scan") {
    await runScan();
    return;
  }
  if (action === "browse-open") {
    await openBrowse();
    return;
  }
  if (action === "browse-close") {
    closeBrowse();
    return;
  }
  if (action === "browse-up") {
    if (state.browse && state.browse.parent != null) await loadBrowse(state.browse.parent);
    return;
  }
  if (action === "browse-enter") {
    await loadBrowse(button.dataset.path || "");
    return;
  }
  if (action === "browse-use") {
    if (!state.browse || !state.browse.path) return;
    const chosen = state.browse.path;
    closeBrowse();
    await loadProject(chosen);
  }
}

function closeBrowse() {
  state.browseOpen = false;
  const box = document.getElementById("browser");
  if (box) box.hidden = true;
}

async function openBrowse() {
  state.browseOpen = true;
  state.browseError = "";
  const box = document.getElementById("browser");
  if (box) box.hidden = false;
  const typed = document.getElementById("repo-path");
  const start = (typed && typed.value.trim()) || state.repo.trim();
  await loadBrowse(start);
}

async function loadBrowse(dirPath, options = {}) {
  try {
    const response = await fetch(`/api/browse?path=${encodeURIComponent(dirPath || "")}`);
    const body = await response.json();
    if (!response.ok) {
      const message = body.error || "Could not open that folder.";
      if (dirPath) {
        state.browseError = message;
        await loadBrowse("", { keepError: true });
        return;
      }
      state.browseError = message;
      renderBrowser();
      return;
    }
    state.browse = body;
    if (!options.keepError) state.browseError = "";
    renderBrowser();
  } catch (err) {
    state.browseError = "The folder list could not be loaded.";
    renderBrowser();
  }
}

function renderBrowser() {
  const box = document.getElementById("browser");
  if (!box) return;
  box.hidden = !state.browseOpen;
  const listing = state.browse;
  const pathLabel = document.getElementById("browser-path");
  const error = document.getElementById("browser-error");
  const list = document.getElementById("browser-list");
  const up = document.getElementById("browse-up");
  const use = document.getElementById("browse-use");
  if (pathLabel) pathLabel.textContent = listing && listing.path ? listing.path : "This PC";
  if (error) error.textContent = state.browseError || "";
  if (up) up.disabled = !listing || listing.parent == null;
  if (use) use.disabled = !listing || !listing.path;
  if (!list) return;
  const entries = listing && listing.entries ? listing.entries : [];
  list.innerHTML = entries.length
    ? entries
        .map(
          (entry) =>
            `<button type="button" class="browse-row" data-action="browse-enter" data-path="${esc(entry.path)}">${esc(entry.name)}</button>`
        )
        .join("")
    : `<p class="meta">No subfolders in this location.</p>`;
}

function onChange(event) {
  if (event.target.dataset.action === "workflow") {
    const repo = state.scan && state.scan.repoRoot;
    const hotId = event.target.dataset.id;
    if (!repo || !hotId) return;
    const current = triageRecord({ id: hotId });
    const next = fieldsForWorkflow(event.target.value);
    writeTriage(repo, hotId, {
      status: next.status,
      track: next.track,
      needsReview: current.needsReview,
      severity: current.severity,
    });
    scheduleSave();
    renderActiveList();
    return;
  }
  if (event.target.dataset.action === "severity") {
    const repo = state.scan && state.scan.repoRoot;
    const hotId = event.target.dataset.id;
    if (!repo || !hotId) return;
    const current = triageRecord({ id: hotId });
    const chosen = event.target.value;
    writeTriage(repo, hotId, {
      status: current.status,
      needsReview: current.needsReview,
      severity: chosen === event.target.dataset.original ? "" : chosen,
    });
    scheduleSave();
    renderActiveList();
    return;
  }
  if (event.target.dataset.action === "triage") {
    const repo = state.scan && state.scan.repoRoot;
    const hotId = event.target.dataset.id;
    if (!repo || !hotId) return;
    const current = triageRecord({ id: hotId });
    if (event.target.dataset.status === "needs-review") {
      writeTriage(repo, hotId, { status: current.status, track: current.track, needsReview: event.target.checked, severity: current.severity });
    } else if (event.target.checked) {
      const decision = event.target.dataset.status;
      const keepStage = decision === "true-positive" && ["confirmed", "in-remediation", "mitigated"].includes(current.track);
      writeTriage(repo, hotId, {
        status: decision,
        track: keepStage ? current.track : "",
        needsReview: current.needsReview,
        severity: current.severity,
      });
    } else {
      writeTriage(repo, hotId, { status: "", track: "", needsReview: current.needsReview, severity: current.severity });
    }
    scheduleSave();
    renderActiveList();
    return;
  }
  const id = event.target.id;
  if (id === "language") state.language = event.target.value;
  else if (id === "category") state.category = event.target.value;
  else if (id === "search-type") state.searchType = event.target.value;
  else if (id === "tool") state.tool = event.target.value;
  else if (id === "priority") state.priority = event.target.value;
  else if (id === "sort") state.sort = event.target.value;
  else if (id === "only-sinks") state.sinks = event.target.checked;
  else if (id === "only-sources") state.sources = event.target.checked;
  else if (id === "only-linked") state.linked = event.target.checked;
  else if (id === "hide-resolved") state.hideResolved = event.target.checked;
  else if (id === "hide-ignored") state.hideIgnored = event.target.checked;
  else if (id === "hide-duplicates") state.hideDuplicates = event.target.checked;
  else if (id === "repo-history") {
    if (!event.target.value) return;
    loadProject(event.target.value, { missingScan: true });
    return;
  } else if (id === "repo-path") {
    loadProject(event.target.value);
    return;
  } else if (id === "github-link") {
    state.github = event.target.value;
    storeProjectGithub();
    scheduleSave();
    if (state.mode === "active") renderActiveList();
    return;
  } else return;
  state.holdClosed = false;
  scheduleSave();
  if (state.mode === "passive") renderGuide();
  else renderActiveList();
}

function onInput(event) {
  if (event.target.id === "github-link") {
    state.github = event.target.value;
    storeProjectGithub();
    scheduleSave();
    return;
  }
  if (event.target.id === "repo-path") {
    state.repo = event.target.value;
    scheduleSave();
    return;
  }
  if (event.target.id === "q") state.q = event.target.value;
  else if (event.target.id === "filename") state.filename = event.target.value;
  else return;
  state.holdClosed = false;
  scheduleSave();
  if (state.mode === "passive") renderGuide();
  else renderActiveList();
}

async function refreshHistory() {
  try {
    const response = await fetch("/api/scans");
    state.history = response.ok ? await response.json() : [];
    if (!Array.isArray(state.history)) state.history = [];
  } catch (err) {
    state.history = [];
  }
}

async function loadProject(path, options = {}) {
  switchProject(path);
  const input = document.getElementById("repo-path");
  if (input) input.value = state.repo;
  const github = document.getElementById("github-link");
  if (github) github.value = state.github;
  const ok = await restoreScan(state.repo);
  if (!ok) state.scanError = options.missingScan ? "No saved scan for that folder." : "";
  scheduleSave();
  if (state.mode === "passive") renderGuide();
  else renderActiveList();
}

async function restoreScan(repo) {
  try {
    const response = await fetch(`/api/scans?repo=${encodeURIComponent(repo)}`);
    if (!response.ok) return false;
    const body = await response.json();
    if (!body || typeof body.repoRoot !== "string" || !Array.isArray(body.hotspots)) return false;
    state.scan = body;
    state.scanError = "";
    switchProject(body.repoRoot);
    return true;
  } catch (err) {
    return false;
  }
}

async function runScan() {
  state.scanning = true;
  state.scanError = "";
  paintScanChrome();
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo: state.repo }),
    });
    const body = await response.json();
    if (!response.ok) {
      state.scan = null;
      state.scanError = body.error || "Scan failed.";
    } else {
      state.scan = body;
      state.scanError = "";
      switchProject(body.repoRoot);
      await refreshHistory();
    }
  } catch (err) {
    state.scan = null;
    state.scanError = "The scan request failed.";
  } finally {
    state.scanning = false;
    renderActiveList();
  }
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (err) {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
  const previous = button.textContent;
  button.textContent = "Copied";
  window.setTimeout(() => {
    button.textContent = previous;
  }, 1200);
}

function esc(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cssEscape(value) {
  if (window.CSS && CSS.escape) return CSS.escape(value);
  return String(value).replace(/[^a-zA-Z0-9_-]/g, "\\$&");
}
