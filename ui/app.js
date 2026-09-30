"use strict";

const MARK_KEY = "security-hotspot-navigator-marks";
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
  triage: {},
  sort: "priority",
  view: "findings",
  scan: null,
  scanning: false,
  scanError: "",
  open: {},
  marks: loadMarks(),
  leftOpen: true,
  rightOpen: true,
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
    renderShell();
  } catch (err) {
    app.textContent = "The review guide could not be loaded. Start it with node server.js and open http://127.0.0.1:3000.";
  }
}

function loadMarks() {
  try {
    const parsed = JSON.parse(localStorage.getItem(MARK_KEY) || "{}");
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (err) {
    return {};
  }
}

function saveMarks() {
  localStorage.setItem(MARK_KEY, JSON.stringify(state.marks));
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
  state.triage = saved.triage && typeof saved.triage === "object" && !Array.isArray(saved.triage) ? saved.triage : {};
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
        triage: state.triage,
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
  paintMode();
  paintSides();
  renderLeft();
  document.getElementById("right-body").innerHTML = state.mode === "passive" ? passiveControls() : activeControls();
  const note = state.mode === "passive"
    ? "Passive mode does not read your repository. Copy a regex, then use Find in Files. The editor shows the line number and can jump to it."
    : "";
  document.getElementById("main").innerHTML = `
    ${note ? `<p class="note">${esc(note)}</p>` : ""}
    <div class="center-tools">
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
          return `<button type="button" class="jump mark-${esc(mark)}${current}" data-action="jump" data-step="${esc(step.id)}"><span class="num">${step.order}</span><span>${esc(step.title)}</span></button>`;
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
      <h1>Security Hotspot Navigator</h1>
      <p class="lede">A local review guide for Node.js, Java, and Spring Boot. Work the checklist in order, and paste each regex into your editor.</p>
      <p class="disclaimer">${esc(state.catalog.disclaimer)}</p>
    </header>
  `;
}

function passiveControls() {
  return `
    ${brandHtml()}
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
    ${brandHtml()}
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
        <label><input id="only-linked" type="checkbox"${state.linked ? " checked" : ""}> Show source-to-sink candidates</label>
        <label><input id="hide-resolved" type="checkbox"${state.hideResolved ? " checked" : ""}> Hide resolved</label>
        <label><input id="hide-ignored" type="checkbox"${state.hideIgnored ? " checked" : ""}> Hide ignored</label>
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
        <strong id="progress-label">0 / 16 categories reviewed</strong>
        <div class="track" aria-hidden="true"><span id="progress-bar"></span></div>
      </div>
      <button type="button" class="ghost" data-action="reset-marks">Reset marks</button>
    </div>
  `;
}

function renderGuide() {
  const hint = document.getElementById("tool-hint");
  if (hint) {
    const caseNote = " When a pattern says case insensitive, turn off Match case in the editor.";
    hint.textContent = TOOLS[state.tool] + caseNote;
    if (state.language === "spring") {
      hint.textContent += " Spring Boot review includes the Java searches.";
    }
  }
  if (!state.holdClosed && state.open.entry === undefined) state.open.entry = true;
  const steps = visibleSteps();
  if (!state.holdClosed && narrowed()) {
    steps.forEach((step) => {
      state.open[step.id] = true;
    });
  }
  const list = document.getElementById("list");
  if (!steps.length) {
    list.innerHTML = `<p class="note">No checklist items match these filters.</p>`;
    return;
  }
  list.innerHTML = steps.map((step) => stepHtml(step)).join("");
}

function visibleSteps() {
  return state.catalog.steps
    .map((step) => {
      const searches = step.searches.filter(searchVisible);
      if (state.searchType === "checklist") {
        const showAllSteps = state.category === "All" && !state.q.trim() && state.language === "all";
        if (!searches.length && !showAllSteps) return null;
        return { ...step, searches: [], searchCount: searches.length };
      }
      if (!searches.length) return null;
      return { ...step, searches, searchCount: searches.length };
    })
    .filter(Boolean);
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

function narrowed() {
  return state.category !== "All" || state.searchType !== "all" || state.q.trim() !== "" || state.language !== "all";
}

function stepHtml(step) {
  const open = Boolean(state.open[step.id]);
  const searches = state.searchType === "checklist" ? "" : step.searches.map(searchHtml).join("");
  return `
    <section class="step" id="step-${esc(step.id)}">
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

function searchHtml(item) {
  const showKeywords = state.searchType === "all" || state.searchType === "keywords";
  const showRegex = state.searchType === "all" || state.searchType === "regex";
  const caseNote = item.flags && item.flags.includes("i") ? "Case insensitive." : "";
  return `
    <article class="search-card">
      <h3>${esc(item.title)}</h3>
      <p>${esc(item.why)}</p>
      ${
        showKeywords
          ? `<div class="kicker">Keywords</div>
             <ul class="chips">${item.keywords.map((word) => `<li>${esc(word)}</li>`).join("")}</ul>
             <div class="copy-row"><button type="button" class="copy" data-action="copy" data-text="${esc(item.keywords.join(", "))}">Copy keywords</button></div>`
          : ""
      }
      ${
        showRegex
          ? `<div class="kicker">Regex ${esc(caseNote)}</div>
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
  const insensitive = item.flags && item.flags.includes("i") ? "-i " : "";
  const quoted = item.regex.replace(/'/g, "''");
  return `rg -n ${insensitive}--regexp '${quoted}' .`;
}

function renderActiveList() {
  paintScanChrome();
  const list = document.getElementById("list");
  if (!list) return;
  document.querySelectorAll("[data-action='view']").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.view === state.view ? "true" : "false");
  });
  if (!state.scan) {
    list.innerHTML = `<p class="note">Choose a repository and scan when you want matches with file names and line numbers. Until then, this page has not read the filesystem.</p>`;
    return;
  }
  const matches = filteredHotspots();
  const hidden = triageNote();
  if (state.view === "top") {
    const top = selectTop(matches);
    list.innerHTML = `
      <p class="note">Up to 20 high-value matches, at most 4 from any one category, so one noisy pattern cannot take the whole list. Context still decides the risk.${hidden}</p>
      ${top.length ? top.map(hotspotHtml).join("") : `<p class="note">No top hotspots match these filters.</p>`}
    `;
    return;
  }
  if (state.view === "checklist") {
    list.innerHTML = (hidden ? `<p class="note">${hidden.trim()}</p>` : "") + state.catalog.steps
      .map((step) => {
        const group = matches.filter((item) => item.stepId === step.id);
        const body = group.length
          ? group.map(hotspotHtml).join("")
          : `<p>No regex matches for this step in the current filters. Review it in the editor with the passive guide.</p>`;
        const open = Boolean(state.open[step.id]);
        return `
          <section class="step" id="step-${esc(step.id)}">
            <div class="step-bar">
              <button type="button" class="step-toggle" data-action="toggle-step" data-step="${esc(step.id)}" aria-expanded="${open ? "true" : "false"}">
                <span class="num">${step.order}</span>
                <span><strong>${esc(step.title)}</strong> <span class="summary">${group.length} matches</span></span>
              </button>
              ${marksHtml(step.id)}
            </div>
            <div class="step-body" ${open ? "" : "hidden"}>
              <ol>${step.guidance.map((line) => `<li>${esc(line)}</li>`).join("")}</ol>
              ${body}
            </div>
          </section>
        `;
      })
      .join("");
    return;
  }
  const hint = matches.length > 25
    ? `<p class="note">${matches.length} matches. Use Top hotspots for a short list, or narrow by category.${hidden}</p>`
    : hidden
      ? `<p class="note">${hidden.trim()}</p>`
      : "";
  list.innerHTML = matches.length
    ? hint + matches.map(hotspotHtml).join("")
    : `<p class="note">No hotspots match these filters.${hidden}</p>`;
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

function triageStatus(item) {
  const repo = state.scan && state.scan.repoRoot;
  const bucket = repo && state.triage[repo];
  return bucket && bucket[item.id] ? bucket[item.id] : "";
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
    if (state.priority !== "All" && item.priority !== state.priority) return false;
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

function filteredHotspots() {
  return matchingHotspots()
    .filter((item) => {
      const status = triageStatus(item);
      if (state.hideResolved && status === "resolved") return false;
      if (state.hideIgnored && status === "ignored") return false;
      return true;
    })
    .sort(compareBySort);
}

function activeLanguage(item) {
  if (state.language === "all") return true;
  if (item.language === "config") {
    return item.tags.includes(state.language) || (state.language === "spring" && item.tags.includes("java"));
  }
  if (state.language === "node") return item.language === "node";
  if (state.language === "java") {
    return item.language === "java" || (item.language === "spring" && item.tags.includes("java"));
  }
  if (state.language === "spring") return item.language === "spring";
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

function hotspotHtml(item) {
  const rows = item.snippet
    .map(
      (row) =>
        `<span class="row${row.hit ? " hit" : ""}"><span class="ln">${row.line}</span>${esc(row.text)}</span>`
    )
    .join("");
  const status = triageStatus(item);
  return `
    <article class="hot${status ? ` is-${status}` : ""}">
      <div class="triage-row">
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="resolved"${status === "resolved" ? " checked" : ""}> Resolved</label>
        <label class="triage"><input type="checkbox" data-action="triage" data-id="${esc(item.id)}" data-status="ignored"${status === "ignored" ? " checked" : ""}> Ignored</label>
      </div>
      <div class="hot-main">
      <button type="button" class="hot-toggle" data-action="toggle-hot" aria-expanded="false">
        <span class="badge-row">
          <span class="pri pri-${esc(item.priority.toLowerCase())}">${esc(item.priority)}</span>
          <span>${esc(item.category)}</span>
          <span class="conf conf-${esc(item.confidence.toLowerCase())}">Confidence: ${esc(item.confidence)}</span>
          ${item.sourceToSink ? `<span class="flag">Source nearby</span>` : ""}
        </span>
        <span class="loc">${esc(item.file)}:${item.line}</span>
        <span class="hot-match">${esc(item.match)}</span>
        <span class="hot-why">${esc(item.why)}</span>
      </button>
      <div class="hot-body" hidden>
        <p><strong>${esc(languageName(item.language))}</strong> · ${esc(item.title)} · ${esc(item.role)}</p>
        ${item.sourcePattern ? `<p>Source pattern: ${esc(item.sourcePattern)}</p>` : ""}
        ${item.sinkPattern ? `<p>Sink pattern: ${esc(item.sinkPattern)}</p>` : ""}
        <div class="snippet">${rows}</div>
        <div class="kicker">Why this is sensitive</div>
        <p>${esc(item.why)}</p>
        <div class="kicker">Confidence</div>
        <p>${esc(CONFIDENCE_NOTE[item.confidence] || "")}</p>
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
  if (id === "java") return "Java";
  if (id === "spring") return "Spring Boot";
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
    meta.textContent = `Scanned ${state.scan.filesScanned} files. ${state.scan.hotspotCount} matches in ${state.scan.repoRoot}.${trimmed} Reading only. Nothing was modified.`;
  } else if (!state.scanning) {
    meta.textContent = "Active mode reads files and runs the same regexes. It does not lint, modify, or rewrite anything.";
  }
}

async function onClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  const action = button.dataset.action;
  if (action === "triage") return;
  if (action === "mode") {
    state.mode = button.dataset.mode;
    renderMain();
    scheduleSave();
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
  if (action === "toggle-hot") {
    const body = button.closest(".hot").querySelector(".hot-body");
    const willOpen = body.hidden;
    body.hidden = !willOpen;
    button.setAttribute("aria-expanded", willOpen ? "true" : "false");
    return;
  }
  if (action === "mark") {
    state.marks[button.dataset.step] = button.dataset.status;
    saveMarks();
    document.querySelectorAll(`[data-action="mark"][data-step="${cssEscape(button.dataset.step)}"]`).forEach((item) => {
      item.setAttribute("aria-pressed", item.dataset.status === button.dataset.status ? "true" : "false");
    });
    updateProgress();
    renderLeft();
    return;
  }
  if (action === "reset-marks") {
    state.marks = {};
    saveMarks();
    if (state.mode === "passive") renderGuide();
    else renderActiveList();
    updateProgress();
    renderLeft();
    return;
  }
  if (action === "collapse-all") {
    state.holdClosed = true;
    for (const step of state.catalog.steps) state.open[step.id] = false;
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
    state.open[stepId] = true;
    if (state.mode === "active" && state.view !== "checklist") {
      state.view = "checklist";
      scheduleSave();
    }
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
    state.repo = state.browse.path;
    const input = document.getElementById("repo-path");
    if (input) input.value = state.repo;
    closeBrowse();
    scheduleSave();
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
  if (event.target.dataset.action === "triage") {
    const repo = state.scan && state.scan.repoRoot;
    const hotId = event.target.dataset.id;
    if (!repo || !hotId) return;
    if (!state.triage[repo]) state.triage[repo] = {};
    if (event.target.checked) state.triage[repo][hotId] = event.target.dataset.status;
    else delete state.triage[repo][hotId];
    if (!Object.keys(state.triage[repo]).length) delete state.triage[repo];
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
  else return;
  state.holdClosed = false;
  scheduleSave();
  if (state.mode === "passive") renderGuide();
  else renderActiveList();
}

function onInput(event) {
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
