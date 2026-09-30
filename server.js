"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");
const { execFile, spawn } = require("child_process");
const { assertCatalog, toClientCatalog, CATEGORIES, PRIORITIES } = require("./library/catalog");
const { scanRepo } = require("./scanner/scan");

assertCatalog();

const uiRoot = path.resolve(__dirname, "ui");
const sessionPath = path.resolve(__dirname, "data", "session.json");
const catalog = toClientCatalog();
const options = parseArgs(process.argv);
const CHOICES = {
  mode: ["passive", "active"],
  language: ["all", "node", "java", "spring"],
  searchType: ["all", "keywords", "regex", "checklist"],
  tool: ["vscode", "notepad", "ripgrep"],
  sort: ["priority", "confidence", "category", "file", "step", "line"],
  view: ["findings", "checklist", "top"],
};

function parseArgs(argv) {
  const parsed = { repo: "", port: 3000 };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--repo") {
      parsed.repo = argv[i + 1] || "";
      i += 1;
    } else if (arg === "--port") {
      parsed.port = Number(argv[i + 1]);
      i += 1;
    }
  }
  if (!Number.isInteger(parsed.port) || parsed.port < 1 || parsed.port > 65535) {
    parsed.port = 3000;
  }
  return parsed;
}

function contentType(file) {
  if (file.endsWith(".css")) return "text/css; charset=utf-8";
  if (file.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (file.endsWith(".html")) return "text/html; charset=utf-8";
  return "application/octet-stream";
}

function send(res, status, body, type) {
  res.writeHead(status, {
    "Content-Type": type,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  res.end(body);
}

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), "application/json; charset=utf-8");
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) {
        reject(new Error("Request too large."));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function uiFile(urlPath) {
  const requested = urlPath === "/" ? "/index.html" : urlPath;
  const decoded = decodeURIComponent(requested);
  if (decoded.includes("\0")) return null;
  const abs = path.resolve(uiRoot, `.${decoded}`);
  const relative = path.relative(uiRoot, abs);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return abs;
}

function windowsRoots() {
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "[System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady } | ForEach-Object { $_.Name }",
      ],
      { timeout: 5000, windowsHide: true },
      (err, stdout) => {
        if (err || !stdout) {
          resolve(["C:\\"]);
          return;
        }
        const roots = String(stdout)
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);
        resolve(roots.length ? roots : ["C:\\"]);
      }
    );
  });
}

async function browseDirectory(inputPath) {
  const requested = typeof inputPath === "string" ? inputPath.trim() : "";
  if (!requested) {
    const roots = process.platform === "win32" ? await windowsRoots() : ["/"];
    return {
      path: "",
      parent: null,
      entries: roots.map((root) => ({ name: root, path: root })),
    };
  }

  const resolved = path.resolve(requested);
  let stat;
  try {
    stat = await fs.promises.stat(resolved);
  } catch (err) {
    const missing = err && err.code === "ENOENT";
    const error = new Error(missing ? "That folder was not found." : "That folder could not be opened.");
    error.status = 400;
    throw error;
  }
  if (!stat.isDirectory()) {
    const error = new Error("That path is not a folder.");
    error.status = 400;
    throw error;
  }

  const parsed = path.parse(resolved);
  const parent = resolved === parsed.root ? "" : path.dirname(resolved);
  let listing;
  try {
    listing = await fs.promises.readdir(resolved, { withFileTypes: true });
  } catch (err) {
    const error = new Error("That folder could not be read.");
    error.status = 400;
    throw error;
  }

  const entries = [];
  for (const entry of listing) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) continue;
    entries.push({ name: entry.name, path: path.join(resolved, entry.name) });
    if (entries.length >= 400) break;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  return { path: resolved, parent, entries };
}

async function handleBrowse(req, res, url) {
  try {
    const listing = await browseDirectory(url.searchParams.get("path") || "");
    sendJson(res, 200, listing);
  } catch (err) {
    sendJson(res, err.status || 400, { error: err.message || "Could not list that folder." });
  }
}

function defaultSession() {
  return {
    mode: "passive",
    repo: options.repo || "",
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
    sort: "priority",
    view: "findings",
    triage: {},
  };
}

function normalizeMark(value) {
  const statuses = ["resolved", "ignored", "true-positive"];
  const severities = ["Critical", "High", "Medium", "Low"];
  let status = "";
  let needsReview = false;
  let severity = "";
  if (statuses.includes(value)) status = value;
  else if (value && typeof value === "object" && !Array.isArray(value)) {
    if (statuses.includes(value.status)) status = value.status;
    needsReview = value.needsReview === true;
    if (severities.includes(value.severity)) severity = value.severity;
  }
  if (!status && !needsReview && !severity) return null;
  if (!needsReview && !severity) return status;
  const mark = {};
  if (status) mark.status = status;
  if (needsReview) mark.needsReview = true;
  if (severity) mark.severity = severity;
  return mark;
}

function normalizeTriage(raw) {
  const triage = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return triage;
  let count = 0;
  for (const repo of Object.keys(raw)) {
    if (count >= 4000) break;
    const cleanRepo = textValue(repo, 1024);
    const bucket = raw[repo];
    if (!cleanRepo || !bucket || typeof bucket !== "object" || Array.isArray(bucket)) continue;
    const next = {};
    for (const id of Object.keys(bucket)) {
      if (count >= 4000) break;
      const cleanId = textValue(id, 500);
      const mark = normalizeMark(bucket[id]);
      if (!cleanId || !mark) continue;
      next[cleanId] = mark;
      count += 1;
    }
    if (Object.keys(next).length) triage[cleanRepo] = next;
  }
  return triage;
}

function choice(value, allowed, fallback) {
  return typeof value === "string" && allowed.includes(value) ? value : fallback;
}

function textValue(value, max) {
  if (typeof value !== "string" || value.includes("\0")) return "";
  return value.trim().slice(0, max);
}

function normalizeSession(raw) {
  const base = defaultSession();
  const source = raw && typeof raw === "object" ? raw : {};
  return {
    mode: choice(source.mode, CHOICES.mode, base.mode),
    repo: textValue(source.repo, 1024),
    language: choice(source.language, CHOICES.language, base.language),
    category: choice(source.category, CATEGORIES, base.category),
    searchType: choice(source.searchType, CHOICES.searchType, base.searchType),
    tool: choice(source.tool, CHOICES.tool, base.tool),
    priority: choice(source.priority, PRIORITIES, base.priority),
    q: textValue(source.q, 200),
    filename: textValue(source.filename, 200),
    sinks: source.sinks === true,
    sources: source.sources === true,
    linked: source.linked === true,
    hideResolved: source.hideResolved !== false,
    hideIgnored: source.hideIgnored !== false,
    sort: choice(source.sort, CHOICES.sort, base.sort),
    view: choice(source.view, CHOICES.view, base.view),
    triage: normalizeTriage(source.triage),
  };
}

async function readSession() {
  try {
    const raw = await fs.promises.readFile(sessionPath, "utf8");
    return normalizeSession(JSON.parse(raw));
  } catch (err) {
    return defaultSession();
  }
}

async function writeSession(raw) {
  const next = normalizeSession(raw);
  await fs.promises.mkdir(path.dirname(sessionPath), { recursive: true });
  await fs.promises.writeFile(sessionPath, JSON.stringify(next, null, 2));
  return next;
}

async function handleSession(req, res) {
  if (req.method === "GET") {
    sendJson(res, 200, await readSession());
    return;
  }
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    sendJson(res, 400, { error: "Send the choices as JSON." });
    return;
  }
  sendJson(res, 200, await writeSession(payload));
}

function registryValue(key) {
  return new Promise((resolve) => {
    execFile("reg", ["query", key, "/ve"], { windowsHide: true, timeout: 5000 }, (err, stdout) => {
      if (err || typeof stdout !== "string") {
        resolve("");
        return;
      }
      const match = stdout.match(/REG_SZ\s+(.+)/);
      resolve(match ? match[1].trim() : "");
    });
  });
}

let notepadExe = "";

async function findNotepad() {
  if (notepadExe) return notepadExe;
  const appPath = await registryValue("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\notepad++.exe");
  const installDir = await registryValue("HKLM\\SOFTWARE\\Notepad++");
  const candidates = [
    appPath,
    installDir ? path.join(installDir, "notepad++.exe") : "",
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Notepad++", "notepad++.exe"),
    path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Notepad++", "notepad++.exe"),
    path.join(process.env.LOCALAPPDATA || "", "Programs", "Notepad++", "notepad++.exe"),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      const stat = await fs.promises.stat(candidate);
      if (stat.isFile()) {
        notepadExe = candidate;
        return notepadExe;
      }
    } catch (err) {
      // Try the next install location.
    }
  }
  throw new Error("Notepad++ was not found.");
}

async function fileInsideRepo(repoInput, relInput) {
  if (typeof repoInput !== "string" || typeof relInput !== "string") {
    throw new Error("Send the scanned folder and a file path.");
  }
  if (repoInput.includes("\0") || relInput.includes("\0")) throw new Error("That file path is not valid.");
  const rel = relInput.trim();
  if (!rel || path.isAbsolute(rel)) throw new Error("That file path is not valid.");
  const root = path.resolve(repoInput.trim());
  if (root === path.parse(root).root) throw new Error("Refusing to open a file from a drive root.");
  const rootStat = await fs.promises.stat(root);
  if (!rootStat.isDirectory()) throw new Error("Repository path is not a directory.");
  const abs = path.resolve(root, rel);
  const relative = path.relative(root, abs);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("That file is outside the scanned folder.");
  }
  const realRoot = await fs.promises.realpath(root);
  const realFile = await fs.promises.realpath(abs);
  const fromRoot = path.relative(realRoot, realFile);
  if (!fromRoot || fromRoot.startsWith("..") || path.isAbsolute(fromRoot)) {
    throw new Error("That file is outside the scanned folder.");
  }
  const stat = await fs.promises.stat(realFile);
  if (!stat.isFile()) throw new Error("That path is not a file.");
  return realFile;
}

function launchNotepad(exe, file, line) {
  return new Promise((resolve, reject) => {
    const child = spawn(exe, [`-n${line}`, file], { detached: true, stdio: "ignore", windowsHide: true });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

async function handleOpen(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    sendJson(res, 400, { error: "Send the file to open as JSON." });
    return;
  }
  const line = Number(payload && payload.line);
  if (!Number.isInteger(line) || line < 1 || line > 1_000_000) {
    sendJson(res, 400, { error: "That line number is not valid." });
    return;
  }
  try {
    const file = await fileInsideRepo(payload.repo, payload.file);
    const exe = await findNotepad();
    await launchNotepad(exe, file, line);
    sendJson(res, 200, { ok: true });
  } catch (err) {
    const missing = err && err.code === "ENOENT";
    sendJson(res, 400, {
      error: missing ? "That file was not found." : err.message || "Notepad++ could not open that file.",
    });
  }
}

async function handleScan(req, res) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    sendJson(res, 400, { error: "Send a JSON body with a repo path." });
    return;
  }
  const repo = payload && typeof payload.repo === "string" ? payload.repo.trim() : "";
  if (!repo) {
    sendJson(res, 400, { error: "Enter a repository path to scan." });
    return;
  }
  try {
    const result = await scanRepo(repo);
    sendJson(res, 200, result);
  } catch (err) {
    const missing = err && err.code === "ENOENT";
    sendJson(res, 400, {
      error: missing ? "That path was not found." : err.message || "Scan failed.",
    });
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  try {
    if (req.method === "GET" && url.pathname === "/api/library") {
      sendJson(res, 200, catalog);
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/config") {
      sendJson(res, 200, { repo: options.repo });
      return;
    }
    if ((req.method === "GET" || req.method === "POST") && url.pathname === "/api/session") {
      await handleSession(req, res);
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/browse") {
      await handleBrowse(req, res, url);
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/scan") {
      await handleScan(req, res);
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/open") {
      await handleOpen(req, res);
      return;
    }
    if (req.method === "GET" && url.pathname === "/favicon.ico") {
      res.writeHead(204);
      res.end();
      return;
    }
    if (req.method !== "GET") {
      sendJson(res, 405, { error: "Method not allowed." });
      return;
    }
    const file = uiFile(url.pathname);
    if (!file) {
      send(res, 404, "Not found", "text/plain; charset=utf-8");
      return;
    }
    const data = await fs.promises.readFile(file);
    send(res, 200, data, contentType(file));
  } catch (err) {
    if (err && err.code === "ENOENT") {
      send(res, 404, "Not found", "text/plain; charset=utf-8");
      return;
    }
    sendJson(res, 500, { error: "The local server hit an unexpected error." });
  }
});

server.on("error", (err) => {
  console.error(err.message);
  process.exit(1);
});

server.listen(options.port, "127.0.0.1", () => {
  console.log(`Security Hotspot Navigator at http://127.0.0.1:${options.port}`);
  console.log("Passive mode does not read a repository. Active scan runs only when you ask.");
  if (options.repo) console.log(`Default repo path: ${options.repo}`);
});
