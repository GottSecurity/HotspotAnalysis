"use strict";

const fs = require("fs");
const path = require("path");
const { allSearches } = require("../library/catalog");
const { correlate } = require("./sourceSink");

const SKIP_DIRS = new Set([
  "node_modules",
  "target",
  "build",
  "dist",
  ".git",
  "coverage",
  ".idea",
  ".gradle",
  "out",
  "vendor",
  "generated",
  "generated-sources",
  "__pycache__",
  "venv",
  ".venv",
]);

const SOURCE_EXT = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".jsx",
  ".java",
  ".properties",
  ".yml",
  ".yaml",
  ".py",
]);

const MAX_FILE_BYTES = 1_000_000;
const MAX_FILES = 8000;
const MAX_HOTSPOTS = 1500;
const MAX_LINE_LENGTH = 2000;

function isConfigName(base) {
  return (
    base === "package.json" ||
    base === "pom.xml" ||
    base.startsWith("build.gradle") ||
    base.startsWith(".env") ||
    /^application.*\.(yml|yaml|properties)$/.test(base)
  );
}

function includedFile(base) {
  if (base.endsWith(".min.js") || base.includes(".generated.")) return false;
  if (base === "package-lock.json" || base === "yarn.lock" || base === "pnpm-lock.yaml") {
    return false;
  }
  if (isConfigName(base)) return true;
  return SOURCE_EXT.has(path.extname(base));
}

function classify(rel, text) {
  const base = path.basename(rel).toLowerCase();
  const ext = path.extname(base);
  if (isConfigName(base) || ext === ".yml" || ext === ".yaml" || ext === ".properties" || base.startsWith(".env")) {
    return "config";
  }
  if ([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"].includes(ext)) return "node";
  if (ext === ".py") return "python";
  if (ext === ".java") {
    if (
      /@(RestController|Controller|SpringBootApplication|RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|Service|Repository|Configuration|EnableWebSecurity)\b/.test(
        text
      ) ||
      text.includes("org.springframework")
    ) {
      return "spring";
    }
    return "java";
  }
  return null;
}

function applies(family, search) {
  if (search.active === false) return false;
  if (family === "config") return search.onConfig === true;
  if (family === "node") return search.languages.includes("node") || search.languages.includes("javascript");
  if (family === "java") return search.languages.includes("java");
  if (family === "spring") {
    return search.languages.includes("spring") || search.languages.includes("java");
  }
  if (family === "python") return search.languages.includes("python");
  return false;
}

function snippetFor(lines, lineNumber) {
  const index = lineNumber - 1;
  const start = Math.max(0, index - 4);
  const end = Math.min(lines.length, index + 5);
  const rows = [];
  for (let i = start; i < end; i += 1) {
    rows.push({ line: i + 1, text: lines[i], hit: i === index });
  }
  return rows;
}

async function walkFiles(root) {
  const files = [];
  async function walk(dir) {
    if (files.length >= MAX_FILES) return;
    const entries = await fs.promises.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      if (entry.isSymbolicLink()) continue;
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        await walk(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!includedFile(entry.name)) continue;
      files.push(abs);
    }
  }
  await walk(root);
  return files;
}

function compileSearches() {
  return allSearches()
    .filter((item) => item.active !== false)
    .map((item) => ({
      ...item,
      compiled: new RegExp(item.regex, (item.flags || "").replace(/[gy]/g, "")),
    }));
}

async function scanRepo(repoInput) {
  const root = path.resolve(repoInput);
  const parsed = path.parse(root);
  if (root === parsed.root) {
    throw new Error("Refusing to scan a drive root. Choose a repository directory.");
  }
  const stat = await fs.promises.stat(root);
  if (!stat.isDirectory()) {
    throw new Error("Repository path is not a directory.");
  }

  const searches = compileSearches();
  const files = await walkFiles(root);
  const hotspots = [];
  let filesScanned = 0;
  let truncated = false;

  for (const abs of files) {
    if (hotspots.length >= MAX_HOTSPOTS) {
      truncated = true;
      break;
    }
    const info = await fs.promises.stat(abs);
    if (info.size > MAX_FILE_BYTES) continue;
    const buffer = await fs.promises.readFile(abs);
    if (buffer.includes(0)) continue;
    const text = buffer.toString("utf8");
    const lines = text.split(/\r?\n/);
    if (lines.some((line) => line.length > MAX_LINE_LENGTH)) continue;

    const rel = path.relative(root, abs);
    const family = classify(rel, text);
    if (!family) continue;
    filesScanned += 1;

    const applicable = searches.filter((item) => applies(family, item));
    for (let index = 0; index < lines.length; index += 1) {
      if (hotspots.length >= MAX_HOTSPOTS) {
        truncated = true;
        break;
      }
      const line = lines[index];
      if (!line.trim()) continue;
      for (const item of applicable) {
        if (hotspots.length >= MAX_HOTSPOTS) {
          truncated = true;
          break;
        }
        if (!item.compiled.test(line)) continue;
        const lineNumber = index + 1;
        hotspots.push({
          id: `${rel}:${lineNumber}:${item.id}`,
          file: rel,
          line: lineNumber,
          language: family,
          tags: item.languages,
          category: item.category,
          priority: item.priority,
          rank: item.rank,
          top: item.top,
          role: item.role,
          confidence: "Low",
          title: item.title,
          stepId: item.stepId,
          stepOrder: item.stepOrder,
          stepTitle: item.stepTitle,
          match: line.trim().slice(0, 180),
          sinkPattern: item.role === "sink" ? line.trim().slice(0, 180) : "",
          sourcePattern: "",
          sourceToSink: false,
          snippet: snippetFor(lines, lineNumber),
          why: item.why,
          whatToCheck: item.whatToCheck,
          falsePositives: item.falsePositives,
          verify: item.verify,
          secureAlternative: item.secureAlternative,
        });
      }
    }
  }

  correlate(hotspots);
  hotspots.sort(compareHotspots);

  return {
    repoRoot: root,
    filesScanned,
    hotspotCount: hotspots.length,
    truncated,
    hotspots,
  };
}

function compareHotspots(a, b) {
  if (a.rank !== b.rank) return a.rank - b.rank;
  if (a.sourceToSink !== b.sourceToSink) return a.sourceToSink ? -1 : 1;
  const confidence = { High: 0, Medium: 1, Low: 2 };
  if (confidence[a.confidence] !== confidence[b.confidence]) {
    return confidence[a.confidence] - confidence[b.confidence];
  }
  if (a.file !== b.file) return a.file < b.file ? -1 : 1;
  return a.line - b.line;
}

function languageMatch(hotspot, selected) {
  if (!selected || selected === "all") return true;
  if (hotspot.language === "config") {
    return hotspot.tags.includes(selected) || (selected === "spring" && hotspot.tags.includes("java"));
  }
  if (selected === "node") return hotspot.language === "node" && hotspot.tags.includes("node");
  if (selected === "javascript") {
    return hotspot.tags.includes("javascript") && (hotspot.language === "node" || hotspot.language === "javascript");
  }
  if (selected === "java") {
    return hotspot.language === "java" || (hotspot.language === "spring" && hotspot.tags.includes("java"));
  }
  if (selected === "spring") return hotspot.language === "spring";
  if (selected === "python") return hotspot.language === "python";
  return false;
}

function topHotspots(hotspots) {
  const perCategory = new Map();
  const picked = [];
  for (const hotspot of hotspots) {
    if (!hotspot.top) continue;
    const seen = perCategory.get(hotspot.category) || 0;
    if (seen >= 4) continue;
    perCategory.set(hotspot.category, seen + 1);
    picked.push(hotspot);
    if (picked.length >= 20) break;
  }
  return picked;
}

module.exports = {
  scanRepo,
  languageMatch,
  topHotspots,
  compareHotspots,
};
